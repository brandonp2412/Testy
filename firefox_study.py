#!/usr/bin/env python3
"""Reproducible Firefox unit-suite coverage vs CVE disclosure study."""

from __future__ import annotations

import argparse
import csv
import html
import json
import math
import re
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Iterable
from urllib.parse import quote, urljoin

import numpy as np
import pandas as pd
import requests
import zstandard as zstd
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent
BASE = ROOT / "data" / "firefox"
RAW = BASE / "raw"
PROCESSED = BASE / "processed"
CHARTS = ROOT / "charts" / "firefox"

GCS_API = "https://storage.googleapis.com/storage/v1/b/relman-code-coverage-prod/o"
GCS_MEDIA = "https://storage.googleapis.com/download/storage/v1/b/relman-code-coverage-prod/o"
GCS_PREFIX = "mozilla-central/"
ADVISORY_INDEX = "https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/"
COVERAGE_DOC = "https://firefox-source-docs.mozilla.org/tools/code-coverage/index.html"
XPCSHELL_DOC = "https://firefox-source-docs.mozilla.org/testing/xpcshell/index.html"
GTEST_DOC = "https://firefox-source-docs.mozilla.org/gtest/index.html"
TASK_ATTR_DOC = "https://firefox-source-docs.mozilla.org/taskcluster/attributes.html"

REQUIRED_STREAMS = ("all:all", "all:gtest", "all:cppunittest", "all:xpcshell")
UNIT_STREAMS = ("all:gtest", "all:cppunittest", "all:xpcshell")
PRIMARY_START = pd.Timestamp("2019-10-01")
PRIMARY_END = pd.Timestamp("2025-12-31")

USER_AGENT = "Testy Firefox coverage/CVE study (+https://github.com/brandonp2412/Testy)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)
ADVISORY_RE = re.compile(r"/security/advisories/mfsa\d{4}-\d+/", re.I)

BG = "#0b1020"
PANEL = "#11182b"
GRID = "#26314d"
TEXT = "#eef3ff"
MUTED = "#9daac5"
BLUE = "#69a7ff"
CYAN = "#5de4c7"
CORAL = "#ff7b7b"
GOLD = "#f8c555"


def get(url: str, **kwargs) -> requests.Response:
    last = None
    for attempt in range(6):
        try:
            r = SESSION.get(url, timeout=kwargs.pop("timeout", 120), **kwargs)
            r.raise_for_status()
            return r
        except requests.RequestException as exc:
            last = exc
            if attempt == 5:
                raise
            time.sleep(1.2 * (attempt + 1))
    raise RuntimeError(last)


def list_coverage_objects() -> list[dict]:
    """List Mozilla's public historical coverage archive."""
    token = None
    rows: list[dict] = []
    page = 0
    while True:
        params = {
            "prefix": GCS_PREFIX,
            "maxResults": 1000,
            "fields": "items(name,updated,size),nextPageToken",
        }
        if token:
            params["pageToken"] = token
        data = get(GCS_API, params=params).json()
        rows.extend(data.get("items", []))
        token = data.get("nextPageToken")
        page += 1
        if page == 1 or page % 50 == 0 or not token:
            print(f"firefox coverage archive: page {page}, {len(rows):,} objects", flush=True)
        if not token:
            break
    return rows


def select_monthly_revisions(objects: list[dict]) -> pd.DataFrame:
    pat = re.compile(r"^mozilla-central/([^/]+)/([^/:]+):([^/]+)\.json\.zstd$")
    by_revision: dict[str, dict[str, dict]] = {}
    for obj in objects:
        match = pat.match(obj.get("name", ""))
        if not match:
            continue
        revision, platform, suite = match.groups()
        stream = f"{platform}:{suite}"
        if stream not in REQUIRED_STREAMS:
            continue
        by_revision.setdefault(revision, {})[stream] = obj

    candidates = []
    for revision, streams in by_revision.items():
        if not all(stream in streams for stream in REQUIRED_STREAMS):
            continue
        timestamps = [pd.to_datetime(streams[s]["updated"], utc=True) for s in REQUIRED_STREAMS]
        report_time = max(timestamps)
        row = {"revision": revision, "report_time": report_time}
        for stream in REQUIRED_STREAMS:
            row[stream] = streams[stream]["name"]
        candidates.append(row)

    frame = pd.DataFrame(candidates).sort_values("report_time")
    if frame.empty:
        raise RuntimeError("No revisions contain all required Firefox coverage streams")
    frame["month"] = frame["report_time"].dt.to_period("M")

    selected = []
    for month, group in frame.groupby("month"):
        target = pd.Timestamp(month.start_time, tz="UTC") + pd.Timedelta(days=14, hours=12)
        idx = (group["report_time"] - target).abs().idxmin()
        selected.append(frame.loc[idx])
    result = pd.DataFrame(selected).sort_values("report_time").reset_index(drop=True)
    result["month"] = result["month"].astype(str)
    return result


def media_url(object_name: str) -> str:
    return f"{GCS_MEDIA}/{quote(object_name, safe='')}?alt=media"


def download_zstd_json(object_name: str) -> dict:
    compressed = get(media_url(object_name), timeout=240).content
    raw = zstd.ZstdDecompressor().decompress(compressed)
    return json.loads(raw)


def _walk_covered_lines(node: dict, prefix: str, out: set[tuple[str, int]]) -> None:
    children = node.get("children")
    if isinstance(children, dict):
        for name, child in children.items():
            child_path = f"{prefix}/{name}" if prefix else name
            _walk_covered_lines(child, child_path, out)
        return
    coverage = node.get("coverage")
    if not isinstance(coverage, list):
        return
    for i, count in enumerate(coverage, start=1):
        if isinstance(count, int) and count > 0:
            out.add((prefix, i))


def coverage_observation(row: pd.Series) -> dict:
    revision = row["revision"]
    print(f"coverage sample {row['month']} {revision[:12]}", flush=True)

    with ThreadPoolExecutor(max_workers=4) as pool:
        futures = {
            stream: pool.submit(download_zstd_json, row[stream]) for stream in REQUIRED_STREAMS
        }
        reports = {stream: future.result() for stream, future in futures.items()}

    denominator = int(reports["all:all"].get("linesTotal", 0))
    if denominator <= 0:
        raise RuntimeError(f"No all:all denominator for {revision}")

    covered: set[tuple[str, int]] = set()
    suite_values = {}
    for stream in UNIT_STREAMS:
        report = reports[stream]
        _walk_covered_lines(report, "", covered)
        key = stream.split(":", 1)[1]
        suite_values[f"{key}_root_coverage_pct"] = float(report.get("coveragePercent", 0.0))
        suite_values[f"{key}_root_lines_covered"] = int(report.get("linesCovered", 0))
        suite_values[f"{key}_root_lines_total"] = int(report.get("linesTotal", 0))

    unit_lines_covered = len(covered)
    if unit_lines_covered > denominator:
        raise RuntimeError(
            f"Unit-covered line union exceeds all:all denominator at {revision}: "
            f"{unit_lines_covered} > {denominator}"
        )

    return {
        "month": row["month"],
        "report_time_utc": pd.Timestamp(row["report_time"]).isoformat(),
        "revision": revision,
        "unit_union_lines_covered": unit_lines_covered,
        "all_tests_lines_total": denominator,
        "unit_union_coverage_pct": 100.0 * unit_lines_covered / denominator,
        "all_tests_root_coverage_pct": float(reports["all:all"].get("coveragePercent", 0.0)),
        "all_tests_root_lines_covered": int(reports["all:all"].get("linesCovered", 0)),
        **suite_values,
        "all_object": row["all:all"],
        "gtest_object": row["all:gtest"],
        "cppunittest_object": row["all:cppunittest"],
        "xpcshell_object": row["all:xpcshell"],
    }


def collect_coverage() -> pd.DataFrame:
    RAW.mkdir(parents=True, exist_ok=True)
    objects = list_coverage_objects()
    selected = select_monthly_revisions(objects)
    selected.to_csv(RAW / "coverage_sample_manifest.csv", index=False)
    observations = []
    for _, row in selected.iterrows():
        observations.append(coverage_observation(row))
        pd.DataFrame(observations).to_csv(RAW / "unit_coverage_monthly.csv", index=False)
    return pd.DataFrame(observations)


def advisory_urls() -> list[str]:
    soup = BeautifulSoup(get(ADVISORY_INDEX).text, "html.parser")
    urls = []
    seen = set()
    for link in soup.find_all("a", href=True):
        href = link["href"]
        if not ADVISORY_RE.search(href):
            continue
        url = urljoin(ADVISORY_INDEX, href)
        if url not in seen:
            seen.add(url)
            urls.append(url)
    return urls


def parse_advisory(url: str) -> list[dict]:
    soup = BeautifulSoup(get(url).text, "html.parser")
    title = soup.find("h1")
    heading = soup.find("h2")
    page_title = " ".join(heading.stripped_strings) if heading else ""
    text = " ".join(soup.stripped_strings)

    announced = re.search(
        r"\bAnnounced\s+([A-Z][a-z]+\s+\d{1,2},\s+\d{4})\b", text
    )
    if not announced:
        return []
    announced_date = pd.to_datetime(announced.group(1)).date().isoformat()

    # The source page is Firefox-specific; additionally require the advisory itself
    # to list Firefox as a product/fixed target so Android-only and unrelated advisories
    # are not pulled in merely through cross-links.
    product_match = re.search(r"\bProducts\s+(.+?)\s+Fixed in\b", text)
    products = product_match.group(1).strip() if product_match else ""
    if "Firefox" not in products and "Firefox" not in page_title:
        return []

    rows = []
    for cve in sorted(set(x.upper() for x in CVE_RE.findall(text))):
        cve_heading = soup.find(id=cve)
        description = ""
        if cve_heading:
            description = " ".join(cve_heading.stripped_strings)
        if not description:
            match = re.search(re.escape(cve) + r"\s*:\s*([^#]{0,500})", text, re.I)
            description = match.group(1).strip() if match else ""
        rows.append(
            {
                "cve": cve,
                "announced_date": announced_date,
                "year": int(announced_date[:4]),
                "advisory": title.get_text(" ", strip=True) if title else "",
                "title": page_title,
                "products": products,
                "description": description[:500],
                "url": url,
            }
        )
    return rows


def collect_cves() -> pd.DataFrame:
    RAW.mkdir(parents=True, exist_ok=True)
    urls = advisory_urls()
    print(f"Firefox advisories: {len(urls)}", flush=True)
    rows = []
    with ThreadPoolExecutor(max_workers=12) as pool:
        for i, result in enumerate(pool.map(parse_advisory, urls), start=1):
            rows.extend(result)
            if i % 25 == 0 or i == len(urls):
                print(f"advisories {i}/{len(urls)}; CVE mentions {len(rows)}", flush=True)
    frame = pd.DataFrame(rows)
    if frame.empty:
        raise RuntimeError("Mozilla Firefox advisories yielded no CVEs")
    frame = (
        frame.sort_values(["announced_date", "cve"])
        .drop_duplicates(subset=["cve"], keep="first")
        .reset_index(drop=True)
    )
    frame.to_csv(RAW / "firefox_cves.csv", index=False)
    return frame


def pearson(x: Iterable[float], y: Iterable[float]) -> float:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 2 or np.std(xa) == 0 or np.std(ya) == 0:
        return float("nan")
    return float(np.corrcoef(xa, ya)[0, 1])


def spearman(x: Iterable[float], y: Iterable[float]) -> float:
    return pearson(
        pd.Series(list(x), dtype=float).rank(method="average"),
        pd.Series(list(y), dtype=float).rank(method="average"),
    )


def linear_fit(x: Iterable[float], y: Iterable[float]) -> tuple[float, float]:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 2 or np.std(xa) == 0:
        return float("nan"), float("nan")
    slope, intercept = np.polyfit(xa, ya, 1)
    return float(slope), float(intercept)


def bootstrap_ci(x: Iterable[float], y: Iterable[float], n_iter: int = 10_000) -> tuple[float, float]:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 4:
        return float("nan"), float("nan")
    rng = np.random.default_rng(2412)
    vals = []
    for _ in range(n_iter):
        idx = rng.integers(0, len(xa), len(xa))
        if np.std(xa[idx]) and np.std(ya[idx]):
            vals.append(float(np.corrcoef(xa[idx], ya[idx])[0, 1]))
    return float(np.quantile(vals, 0.025)), float(np.quantile(vals, 0.975))


def association(frame: pd.DataFrame, x: str, y: str) -> dict:
    clean = frame[[x, y]].dropna()
    low, high = bootstrap_ci(clean[x], clean[y])
    slope, intercept = linear_fit(clean[x], clean[y])
    return {
        "n": int(len(clean)),
        "pearson_r": pearson(clean[x], clean[y]),
        "pearson_bootstrap_95pct_ci": [low, high],
        "spearman_rho": spearman(clean[x], clean[y]),
        "ols_slope_cves_per_coverage_point": slope,
        "ols_intercept": intercept,
    }


def aggregate(coverage: pd.DataFrame, cves: pd.DataFrame, freq: str) -> pd.DataFrame:
    cov = coverage.copy()
    cv = cves.copy()
    cov["date"] = pd.to_datetime(cov["report_time_utc"], utc=True).dt.tz_convert(None)
    cv["date"] = pd.to_datetime(cv["announced_date"])
    cov["period"] = cov["date"].dt.to_period(freq)
    cv["period"] = cv["date"].dt.to_period(freq)
    cov_agg = (
        cov.groupby("period")
        .agg(
            unit_coverage_pct=("unit_union_coverage_pct", "mean"),
            unit_coverage_min=("unit_union_coverage_pct", "min"),
            unit_coverage_max=("unit_union_coverage_pct", "max"),
            all_tests_coverage_pct=("all_tests_root_coverage_pct", "mean"),
            coverage_observations=("revision", "count"),
        )
        .reset_index()
    )
    cve_agg = cv.groupby("period").agg(cves_reported=("cve", "nunique")).reset_index()
    out = cov_agg.merge(cve_agg, on="period", how="left")
    out["cves_reported"] = out["cves_reported"].fillna(0).astype(int)
    out["period_start"] = out["period"].dt.start_time.dt.date.astype(str)
    out["period_end"] = out["period"].dt.end_time.dt.date.astype(str)
    out["period"] = out["period"].astype(str)
    return out


def lag_quarters(frame: pd.DataFrame) -> pd.DataFrame:
    out = frame.copy()
    out["next_quarter_cves"] = out["cves_reported"].shift(-1)
    out["next_quarter"] = out["period"].shift(-1)
    out = out.dropna(subset=["next_quarter_cves"]).copy()
    out["next_quarter_cves"] = out["next_quarter_cves"].astype(int)
    return out


def analyze() -> dict:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    coverage = pd.read_csv(RAW / "unit_coverage_monthly.csv")
    cves = pd.read_csv(RAW / "firefox_cves.csv")
    coverage_dates = pd.to_datetime(coverage["report_time_utc"], utc=True).dt.tz_convert(None)
    cve_dates = pd.to_datetime(cves["announced_date"])

    primary_cov = coverage[(coverage_dates >= PRIMARY_START) & (coverage_dates <= PRIMARY_END)].copy()
    primary_cves = cves[(cve_dates >= PRIMARY_START) & (cve_dates <= PRIMARY_END)].copy()

    monthly = aggregate(primary_cov, primary_cves, "M")
    quarterly = aggregate(primary_cov, primary_cves, "Q")
    quarterly = quarterly[pd.to_datetime(quarterly["period_start"]) >= PRIMARY_START].copy()
    annual = aggregate(primary_cov, primary_cves, "Y")
    # Only complete calendar years belong in the annual headline table.
    annual = annual[(annual["period"].astype(int) >= 2020) & (annual["period"].astype(int) <= 2025)]
    lagged = lag_quarters(quarterly)

    monthly.to_csv(PROCESSED / "monthly.csv", index=False)
    quarterly.to_csv(PROCESSED / "quarterly.csv", index=False)
    annual.to_csv(PROCESSED / "annual.csv", index=False)
    lagged.to_csv(PROCESSED / "quarterly_lag1.csv", index=False)

    # Full available series is retained separately for audit/reuse.
    aggregate(coverage, cves, "M").to_csv(PROCESSED / "monthly_all.csv", index=False)
    q_all = aggregate(coverage, cves, "Q")
    q_all.to_csv(PROCESSED / "quarterly_all.csv", index=False)
    aggregate(coverage, cves, "Y").to_csv(PROCESSED / "annual_all.csv", index=False)

    stats = {
        "metric": "union of lines covered by all:gtest, all:cppunittest and all:xpcshell divided by all:all linesTotal at the same revision",
        "primary_window": {"start": "2019-10-01", "end": "2025-12-31"},
        "coverage_archive_first_sample": str(coverage["month"].min()),
        "coverage_archive_last_sample": str(coverage["month"].max()),
        "coverage_monthly_samples": int(len(coverage)),
        "primary_unique_cves": int(primary_cves["cve"].nunique()),
        "quarterly_same_period": association(quarterly, "unit_coverage_pct", "cves_reported"),
        "quarterly_next_period": association(lagged, "unit_coverage_pct", "next_quarter_cves"),
        "annual_same_period": association(annual, "unit_coverage_pct", "cves_reported"),
    }
    (PROCESSED / "stats.json").write_text(json.dumps(stats, indent=2) + "\n")
    return stats


def axis_ticks(lo: float, hi: float, count: int = 5) -> list[float]:
    if hi == lo:
        return [lo]
    return [lo + (hi - lo) * i / count for i in range(count + 1)]


def svg_start(title: str, subtitle: str, width: int = 1400, height: int = 820) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{BG}"/>',
        f'<text x="70" y="72" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="36" font-weight="700">{html.escape(title)}</text>',
        f'<text x="70" y="108" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="18">{html.escape(subtitle)}</text>',
    ]


def scatter_svg(frame: pd.DataFrame, y_col: str, title: str, subtitle: str, out: Path) -> None:
    x_col = "unit_coverage_pct"
    width, height = 1400, 820
    left, right, top, bottom = 120, 70, 150, 100
    plot_w, plot_h = width - left - right, height - top - bottom
    clean = frame[[x_col, y_col, "period"]].dropna()
    x = clean[x_col].astype(float).to_numpy()
    y = clean[y_col].astype(float).to_numpy()
    xpad = max((x.max() - x.min()) * 0.12, 0.3)
    ypad = max((y.max() - y.min()) * 0.12, 2.0)
    x0, x1 = x.min() - xpad, x.max() + xpad
    y0, y1 = max(0.0, y.min() - ypad), y.max() + ypad
    sx = lambda v: left + (v - x0) / (x1 - x0) * plot_w
    sy = lambda v: top + plot_h - (v - y0) / (y1 - y0) * plot_h
    parts = svg_start(title, subtitle, width, height)
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in axis_ticks(y0, y1):
        yy = sy(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left-18}" y="{yy+5:.1f}" text-anchor="end" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}</text>')
    for tick in axis_ticks(x0, x1):
        xx = sx(tick)
        parts.append(f'<text x="{xx:.1f}" y="{top+plot_h+34}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')
    slope, intercept = linear_fit(x, y)
    parts.append(f'<line x1="{sx(x0):.1f}" y1="{sy(slope*x0+intercept):.1f}" x2="{sx(x1):.1f}" y2="{sy(slope*x1+intercept):.1f}" stroke="{CORAL}" stroke-width="4" stroke-linecap="round"/>')
    for _, row in clean.iterrows():
        xx, yy = sx(float(row[x_col])), sy(float(row[y_col]))
        parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="7" fill="{CYAN}" stroke="{BG}" stroke-width="3"/>')
        parts.append(f'<text x="{xx+9:.1f}" y="{yy-9:.1f}" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="11">{html.escape(str(row["period"]))}</text>')
    parts.append(f'<text x="{left+24}" y="{top+38}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="20" font-weight="600">Pearson r = {pearson(x,y):+.3f} · n = {len(clean)}</text>')
    parts.append(f'<text x="{left+plot_w/2}" y="{height-32}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="17">Firefox unit-suite line coverage</text>')
    parts.append(f'<text transform="translate(32 {top+plot_h/2}) rotate(-90)" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="17">CVEs reported{(" in Q+1" if y_col == "next_quarter_cves" else "")}</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts))


def annual_svg(frame: pd.DataFrame, out: Path) -> None:
    width, height = 1400, 820
    left, right, top, bottom = 110, 110, 150, 110
    plot_w, plot_h = width - left - right, height - top - bottom
    coverage = frame["unit_coverage_pct"].astype(float).to_numpy()
    cves = frame["cves_reported"].astype(float).to_numpy()
    labels = frame["period"].astype(str).tolist()
    n = len(frame)
    cpad = max((coverage.max() - coverage.min()) * 0.25, 1.0)
    c0, c1 = coverage.min() - cpad, coverage.max() + cpad
    vmax = max(cves.max() * 1.18, 1.0)
    sx = lambda i: left + (i + 0.5) * plot_w / n
    syc = lambda v: top + plot_h - (v-c0)/(c1-c0)*plot_h
    syv = lambda v: top + plot_h - v/vmax*plot_h
    parts = svg_start(
        "Firefox unit-suite coverage vs CVE disclosures",
        "Annual primary view: complete years 2020–2025 · unit coverage is the union of GTest, CppUnitTest and XPCShell",
        width,
        height,
    )
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in axis_ticks(c0, c1):
        yy = syc(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{BLUE}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')
    for tick in axis_ticks(0, vmax):
        parts.append(f'<text x="{left+plot_w+16}" y="{syv(tick)+5:.1f}" fill="{CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}</text>')
    bw = plot_w/n*0.38
    for i, value in enumerate(cves):
        yy = syv(value)
        parts.append(f'<rect x="{sx(i)-bw/2:.1f}" y="{yy:.1f}" width="{bw:.1f}" height="{top+plot_h-yy:.1f}" rx="7" fill="{CORAL}" opacity="0.72"/>')
        parts.append(f'<text x="{sx(i):.1f}" y="{yy-10:.1f}" text-anchor="middle" fill="{CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="14" font-weight="600">{int(value)}</text>')
    pts = " ".join(f"{sx(i):.1f},{syc(v):.1f}" for i,v in enumerate(coverage))
    parts.append(f'<polyline points="{pts}" fill="none" stroke="{BLUE}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>')
    for i,v in enumerate(coverage):
        parts.append(f'<circle cx="{sx(i):.1f}" cy="{syc(v):.1f}" r="6" fill="{BLUE}" stroke="{BG}" stroke-width="3"/>')
        parts.append(f'<text x="{sx(i):.1f}" y="{top+plot_h+35}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">{labels[i]}</text>')
    parts.append(f'<circle cx="{left+20}" cy="{top-24}" r="6" fill="{BLUE}"/><text x="{left+34}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">Unit-suite line coverage</text>')
    parts.append(f'<rect x="{left+265}" y="{top-31}" width="14" height="14" rx="3" fill="{CORAL}"/><text x="{left+289}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">CVEs reported</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts))


def history_svg(coverage: pd.DataFrame, out: Path) -> None:
    df = coverage.copy()
    df["date"] = pd.to_datetime(df["report_time_utc"], utc=True).dt.tz_convert(None)
    df = df[(df["date"] >= PRIMARY_START) & (df["date"] <= PRIMARY_END)]
    width, height = 1400, 700
    left, right, top, bottom = 110, 70, 150, 90
    plot_w, plot_h = width-left-right, height-top-bottom
    y = df["unit_union_coverage_pct"].astype(float).to_numpy()
    ypad = max((y.max()-y.min())*0.12, 1.0)
    y0, y1 = max(0,y.min()-ypad), min(100,y.max()+ypad)
    d0,d1=df["date"].min(),df["date"].max()
    sx=lambda d:left+(d-d0).total_seconds()/(d1-d0).total_seconds()*plot_w
    sy=lambda v:top+plot_h-(v-y0)/(y1-y0)*plot_h
    parts=svg_start("Firefox unit-suite coverage history","Monthly samples from Mozilla's original public coverage archive",width,height)
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in axis_ticks(y0,y1):
        yy=sy(tick); parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>'); parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')
    for year in range(2020,2026):
        dt=pd.Timestamp(year=year,month=1,day=1)
        if d0<=dt<=d1:
            xx=sx(dt); parts.append(f'<line x1="{xx:.1f}" y1="{top}" x2="{xx:.1f}" y2="{top+plot_h}" stroke="{GRID}" stroke-dasharray="4 8"/>'); parts.append(f'<text x="{xx:.1f}" y="{top+plot_h+34}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{year}</text>')
    pts=" ".join(f"{sx(r.date):.1f},{sy(float(r.unit_union_coverage_pct)):.1f}" for r in df.itertuples())
    parts.append(f'<polyline points="{pts}" fill="none" stroke="{BLUE}" stroke-width="4" stroke-linejoin="round" stroke-linecap="round"/>')
    parts.append("</svg>"); out.write_text("\n".join(parts))


def render_charts() -> None:
    CHARTS.mkdir(parents=True, exist_ok=True)
    annual = pd.read_csv(PROCESSED / "annual.csv")
    quarterly = pd.read_csv(PROCESSED / "quarterly.csv")
    lagged = pd.read_csv(PROCESSED / "quarterly_lag1.csv")
    coverage = pd.read_csv(RAW / "unit_coverage_monthly.csv")
    annual_svg(annual, CHARTS / "annual_coverage_vs_cves.svg")
    scatter_svg(quarterly, "cves_reported", "Firefox quarterly unit coverage vs CVEs", "2019 Q4–2025 Q4 · descriptive association, not causal", CHARTS / "quarterly_same_period_scatter.svg")
    scatter_svg(lagged, "next_quarter_cves", "Does Firefox unit coverage predict next-quarter CVEs?", "Coverage in quarter Q vs CVEs disclosed in Q+1", CHARTS / "quarterly_lag1_scatter.svg")
    history_svg(coverage, CHARTS / "unit_coverage_history.svg")


def fmt(v: float) -> str:
    return f"{float(v):+.3f}" if v is not None and math.isfinite(float(v)) else "n/a"


def write_results(stats: dict) -> None:
    annual = pd.read_csv(PROCESSED / "annual.csv")
    same = stats["quarterly_same_period"]
    lag = stats["quarterly_next_period"]
    rows = "\n".join(
        f"| {r.period} | {r.unit_coverage_pct:.2f}% | {int(r.cves_reported)} |"
        for r in annual.itertuples()
    )
    text = f"""# Firefox results

This is the Firefox replication of the Chromium study. It uses Mozilla's original public `mozilla-central` coverage archive and Mozilla's Firefox security advisories.

## Coverage metric

For each month, the collector chooses a `mozilla-central` revision near the middle of the month for which these four original coverage streams all exist:

- `all:gtest`
- `all:cppunittest`
- `all:xpcshell`
- `all:all`

It unions the exact source lines covered by **GTest + CppUnitTest + XPCShell**, then divides by the `all:all` executable-line denominator from the same revision. This avoids double-counting lines covered by multiple suites.

Mozilla documents GTest as unit testing and explicitly recommends avoiding integration tests in that suite. XPCShell is used for low-level/unit-style testing, and Mozilla's Taskcluster metadata classifies `cppunittest` as a unit-test suite.

## Primary result

The comparable primary period is **2019 Q4 through 2025 Q4** ({same['n']} quarters). Same-quarter Firefox unit-suite coverage vs CVEs has Pearson **r = {fmt(same['pearson_r'])}** (naive bootstrap 95% CI {fmt(same['pearson_bootstrap_95pct_ci'][0])} to {fmt(same['pearson_bootstrap_95pct_ci'][1])}) and Spearman **rho = {fmt(same['spearman_rho'])}**.

Coverage in quarter Q versus CVEs first disclosed in Q+1 gives Pearson **r = {fmt(lag['pearson_r'])}** across {lag['n']} quarter pairs (naive bootstrap 95% CI {fmt(lag['pearson_bootstrap_95pct_ci'][0])} to {fmt(lag['pearson_bootstrap_95pct_ci'][1])}); Spearman **rho = {fmt(lag['spearman_rho'])}**.

These are observational associations, not causal estimates.

![Firefox annual coverage and CVEs](charts/firefox/annual_coverage_vs_cves.svg)

![Firefox quarterly scatter](charts/firefox/quarterly_same_period_scatter.svg)

![Firefox lagged scatter](charts/firefox/quarterly_lag1_scatter.svg)

![Firefox unit coverage history](charts/firefox/unit_coverage_history.svg)

## Annual data

| Year | Mean unit-suite coverage | Unique Firefox CVEs first reported |
| --- | ---: | ---: |
{rows}

## Dataset

- Monthly coverage samples available: **{stats['coverage_monthly_samples']}**, from **{stats['coverage_archive_first_sample']}** through **{stats['coverage_archive_last_sample']}**.
- Primary Firefox CVEs: **{stats['primary_unique_cves']}**.
- Primary statistical period: **2019-10-01 through 2025-12-31**.
- 2026 is retained in `*_all.csv` but excluded from the primary analysis because it is an incomplete year/quarter at the snapshot date.

## Sources

- Historical raw coverage: `gs://relman-code-coverage-prod/mozilla-central`
- Coverage documentation: {COVERAGE_DOC}
- Firefox advisories: {ADVISORY_INDEX}
- GTest documentation: {GTEST_DOC}
- XPCShell documentation: {XPCSHELL_DOC}
- Taskcluster unit-test metadata: {TASK_ATTR_DOC}

## Interpretation limits

1. CVEs measure discovered/disclosed vulnerabilities, not latent vulnerabilities.
2. This metric covers three long-running unit-oriented suites, not every test Mozilla may describe as a unit test.
3. The denominator is the same-revision `all:all` executable-line universe; changes in build/test composition can still move it.
4. Monthly observations use coverage-report upload time as the sample timestamp; this is very close to the tested revision but is not the Mercurial commit timestamp.
5. IID bootstrap intervals do not account for time-series autocorrelation.
6. Coverage can co-move with code churn, fuzzing, sanitizers, architecture changes, researcher attention, and other security work.
"""
    (ROOT / "FIREFOX_RESULTS.md").write_text(text)


def run_all() -> dict:
    collect_coverage()
    collect_cves()
    stats = analyze()
    render_charts()
    write_results(stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", nargs="?", choices=["collect", "analyze", "charts", "all"], default="all")
    args = parser.parse_args()
    if args.command in {"collect", "all"}:
        collect_coverage(); collect_cves()
    if args.command in {"analyze", "all"}:
        stats = analyze(); write_results(stats)
    if args.command in {"charts", "all"}:
        render_charts()


if __name__ == "__main__":
    main()
