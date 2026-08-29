#!/usr/bin/env python3
"""Reproducible Chromium unit-test coverage vs CVE disclosure study."""

from __future__ import annotations

import argparse
import html
import json
import math
import re
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlencode, urljoin

import numpy as np
import pandas as pd
import requests
from bs4 import BeautifulSoup

ROOT = Path(__file__).resolve().parent
RAW = ROOT / "data" / "raw"
PROCESSED = ROOT / "data" / "processed"
CHARTS = ROOT / "charts"

PRIMARY_START = pd.Timestamp("2021-01-01")
PRIMARY_END = pd.Timestamp("2025-12-31")
PRIMARY_LABEL = "2021–2025"

COVERAGE_SOURCE = "https://analysis.chromium.org/coverage/p/chromium"
COVERAGE_LIST_URL = (
    "https://analysis.chromium.org/coverage/p/chromium/dir?"
    "host=chromium.googlesource.com&project=chromium/src&ref=refs/heads/main&"
    "platform=linux&list_reports=true&test_suite_type=unit&modifier_id=0"
)
BLOG_FEED = "https://chromereleases.googleblog.com/feeds/posts/default"
BLOG_HOME = "https://chromereleases.googleblog.com/"
CHROMIUM_COVERAGE_DOC = (
    "https://chromium.googlesource.com/chromium/src/+/HEAD/docs/testing/code_coverage.md"
)
AI_DISCOVERY_SOURCE = "https://blog.google/security/chrome-stronger-with-every-update/"

USER_AGENT = "Testy Chromium coverage/CVE study (+https://github.com/brandonp2412/Testy)"
SESSION = requests.Session()
SESSION.headers.update({"User-Agent": USER_AGENT})

STAT_RE = re.compile(r"([\d.]+)%\s*\(\s*(\d+)\s*/\s*(\d+)\s*\)")
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,8}\b", re.I)
SEVERITY_RE = re.compile(r"\b(Critical|High|Medium|Moderate|Low)\b", re.I)

BG = "#0b1020"
PANEL = "#11182b"
GRID = "#26314d"
TEXT = "#eef3ff"
MUTED = "#9daac5"
BLUE = "#69a7ff"
CYAN = "#5de4c7"
CORAL = "#ff7b7b"
GOLD = "#f8c555"


@dataclass(frozen=True)
class Stat:
    displayed_pct: float
    covered: int
    total: int

    @property
    def exact_pct(self) -> float:
        return 100.0 * self.covered / self.total if self.total else float("nan")


def _get(url: str, *, timeout: int = 60) -> requests.Response:
    for attempt in range(5):
        try:
            response = SESSION.get(url, timeout=timeout)
            response.raise_for_status()
            return response
        except requests.RequestException:
            if attempt == 4:
                raise
            time.sleep(1.5 * (attempt + 1))
    raise RuntimeError("unreachable")


def parse_stat(text: str) -> Stat | None:
    match = STAT_RE.search(text)
    if not match:
        return None
    return Stat(float(match.group(1)), int(match.group(2)), int(match.group(3)))


def parse_coverage_page(page_html: str, source_url: str) -> tuple[list[dict], str | None]:
    soup = BeautifulSoup(page_html, "html.parser")
    records: list[dict] = []
    for row in soup.find_all("tr"):
        cells = row.find_all("td")
        if len(cells) < 5:
            continue
        values = [" ".join(cell.stripped_strings) for cell in cells]
        if values[0] != "Link":
            continue
        line_stat = parse_stat(values[3])
        branch_stat = parse_stat(values[4])
        if not line_stat or not branch_stat:
            continue
        link = cells[0].find("a")
        report_url = urljoin(source_url, link.get("href")) if link and link.get("href") else ""
        commit_time = values[1]
        records.append(
            {
                "commit_time_pst": commit_time,
                "date": commit_time[:10],
                "revision": values[2],
                "line_covered": line_stat.covered,
                "line_total": line_stat.total,
                "line_coverage_pct": line_stat.exact_pct,
                "branch_covered": branch_stat.covered,
                "branch_total": branch_stat.total,
                "branch_coverage_pct": branch_stat.exact_pct,
                "report_url": report_url,
            }
        )

    next_url = None
    for link in soup.find_all("a"):
        if " ".join(link.stripped_strings).strip().lower() == "next" and link.get("href"):
            next_url = urljoin(source_url, link.get("href"))
            break
    return records, next_url


def collect_coverage() -> pd.DataFrame:
    RAW.mkdir(parents=True, exist_ok=True)
    url = COVERAGE_LIST_URL
    seen: set[str] = set()
    records: list[dict] = []
    page = 0
    while url:
        if url in seen:
            raise RuntimeError("Coverage pagination loop detected")
        seen.add(url)
        response = _get(url)
        page_records, url = parse_coverage_page(response.text, response.url)
        records.extend(page_records)
        page += 1
        if page == 1 or page % 10 == 0 or url is None:
            print(f"coverage: page {page}, {len(records)} reports")
        time.sleep(0.05)

    frame = pd.DataFrame(records)
    if frame.empty:
        raise RuntimeError("Chromium coverage dashboard returned no unit-test reports")
    frame = frame.drop_duplicates(subset=["commit_time_pst", "revision"]).sort_values("date")
    frame.to_csv(RAW / "chromium_unit_coverage_daily.csv", index=False)
    return frame


def _entry_url(entry: dict) -> str:
    for link in entry.get("link", []):
        if link.get("rel") == "alternate":
            return link.get("href", "")
    return ""


def _entry_content(entry: dict) -> str:
    return (entry.get("content") or entry.get("summary") or {}).get("$t", "")


def parse_cves_from_entry(entry: dict) -> list[dict]:
    title = entry.get("title", {}).get("$t", "").strip()
    if title.lower() != "stable channel update for desktop":
        return []
    published = entry.get("published", {}).get("$t", "")
    if not published:
        return []
    published_dt = pd.to_datetime(published, utc=True)
    post_url = _entry_url(entry)
    soup = BeautifulSoup(_entry_content(entry), "html.parser")
    lines = [" ".join(piece.split()) for piece in soup.stripped_strings]

    found: list[dict] = []
    for line in lines:
        for cve in CVE_RE.findall(line):
            canonical = cve.upper()
            index = line.upper().find(canonical)
            before = line[:index]
            after = line[index + len(canonical):].lstrip(" :–—-")
            severity_match = SEVERITY_RE.search(before[-80:])
            severity = severity_match.group(1).title() if severity_match else ""
            if severity == "Moderate":
                severity = "Medium"
            description = after.strip()[:500].rstrip()
            component = ""
            component_match = re.search(r"\bin\s+([^.;]+)", description, re.I)
            if component_match:
                component = component_match.group(1).strip()
            found.append(
                {
                    "cve": canonical,
                    "reported_at_utc": published_dt.isoformat(),
                    "reported_date": published_dt.date().isoformat(),
                    "year": int(published_dt.year),
                    "severity": severity,
                    "description": description,
                    "component_hint": component,
                    "post_title": title,
                    "post_url": post_url,
                }
            )
    return found


def collect_cves(start_year: int = 2018) -> pd.DataFrame:
    RAW.mkdir(parents=True, exist_ok=True)
    start_index = 1
    page_size = 150
    all_records: list[dict] = []
    current_year = datetime.now(timezone.utc).year
    while True:
        params = {
            "alt": "json",
            "max-results": page_size,
            "start-index": start_index,
            "published-min": f"{start_year}-01-01T00:00:00Z",
            "published-max": f"{current_year + 1}-01-01T00:00:00Z",
        }
        response = _get(f"{BLOG_FEED}?{urlencode(params)}")
        feed = response.json().get("feed", {})
        entries = feed.get("entry", [])
        if not entries:
            break
        for entry in entries:
            all_records.extend(parse_cves_from_entry(entry))
        print(
            f"cves: feed entries {start_index}-{start_index + len(entries) - 1}, "
            f"{len(all_records)} CVE mentions"
        )
        start_index += len(entries)
        total = int(feed.get("openSearch$totalResults", {}).get("$t", 0) or 0)
        if total and start_index > total:
            break
        time.sleep(0.05)

    frame = pd.DataFrame(all_records)
    if frame.empty:
        raise RuntimeError("Chrome Releases feed returned no stable desktop CVEs")
    frame = frame.sort_values("reported_at_utc").drop_duplicates(subset=["cve"], keep="first")
    frame.to_csv(RAW / "chrome_stable_desktop_cves.csv", index=False)
    return frame


def aggregate_periods(coverage: pd.DataFrame, cves: pd.DataFrame, frequency: str) -> pd.DataFrame:
    cov = coverage.copy()
    cve = cves.copy()
    cov["date"] = pd.to_datetime(cov["date"])
    cve["reported_date"] = pd.to_datetime(cve["reported_date"])
    cov["period"] = cov["date"].dt.to_period(frequency)
    cve["period"] = cve["reported_date"].dt.to_period(frequency)

    cov_agg = (
        cov.groupby("period")
        .agg(
            unit_line_coverage_pct=("line_coverage_pct", "mean"),
            unit_branch_coverage_pct=("branch_coverage_pct", "mean"),
            coverage_observations=("revision", "count"),
            unit_line_total_mean=("line_total", "mean"),
            unit_branch_total_mean=("branch_total", "mean"),
        )
        .reset_index()
    )
    cve_agg = cve.groupby("period").agg(cves_reported=("cve", "nunique")).reset_index()
    merged = cov_agg.merge(cve_agg, on="period", how="left")
    merged["cves_reported"] = merged["cves_reported"].fillna(0).astype(int)
    merged["period_start"] = merged["period"].dt.start_time.dt.date.astype(str)
    merged["period_end"] = merged["period"].dt.end_time.dt.date.astype(str)

    latest = min(cov["date"].max(), cve["reported_date"].max())
    merged["complete_period"] = merged["period"].map(
        lambda p: p.end_time.normalize() < latest.normalize()
    )
    merged["period"] = merged["period"].astype(str)
    return merged


def _primary(frame: pd.DataFrame) -> pd.DataFrame:
    starts = pd.to_datetime(frame["period_start"])
    ends = pd.to_datetime(frame["period_end"])
    return frame[(starts >= PRIMARY_START) & (ends <= PRIMARY_END)].copy()


def pearson(x: Iterable[float], y: Iterable[float]) -> float:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 2 or np.std(xa) == 0 or np.std(ya) == 0:
        return float("nan")
    return float(np.corrcoef(xa, ya)[0, 1])


def spearman(x: Iterable[float], y: Iterable[float]) -> float:
    xa = pd.Series(list(x), dtype=float).rank(method="average")
    ya = pd.Series(list(y), dtype=float).rank(method="average")
    return pearson(xa, ya)


def linear_fit(x: Iterable[float], y: Iterable[float]) -> tuple[float, float]:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 2 or np.std(xa) == 0:
        return float("nan"), float("nan")
    slope, intercept = np.polyfit(xa, ya, 1)
    return float(slope), float(intercept)


def bootstrap_pearson_ci(
    x: Iterable[float], y: Iterable[float], iterations: int = 10_000
) -> tuple[float, float]:
    xa = np.asarray(list(x), dtype=float)
    ya = np.asarray(list(y), dtype=float)
    if len(xa) < 4:
        return float("nan"), float("nan")
    rng = np.random.default_rng(2412)
    values: list[float] = []
    n = len(xa)
    for _ in range(iterations):
        idx = rng.integers(0, n, n)
        if np.std(xa[idx]) == 0 or np.std(ya[idx]) == 0:
            continue
        values.append(float(np.corrcoef(xa[idx], ya[idx])[0, 1]))
    return (
        float(np.quantile(values, 0.025)),
        float(np.quantile(values, 0.975)),
    )


def association(frame: pd.DataFrame, x_col: str, y_col: str) -> dict:
    clean = frame[[x_col, y_col]].dropna()
    slope, intercept = linear_fit(clean[x_col], clean[y_col])
    low, high = bootstrap_pearson_ci(clean[x_col], clean[y_col])
    return {
        "n": int(len(clean)),
        "pearson_r": pearson(clean[x_col], clean[y_col]),
        "pearson_bootstrap_95pct_ci": [low, high],
        "spearman_rho": spearman(clean[x_col], clean[y_col]),
        "ols_slope_cves_per_coverage_point": slope,
        "ols_intercept": intercept,
    }


def _lag(frame: pd.DataFrame) -> pd.DataFrame:
    result = frame.copy()
    result["next_quarter_cves"] = result["cves_reported"].shift(-1)
    result["next_quarter"] = result["period"].shift(-1)
    result = result.dropna(subset=["next_quarter_cves"]).copy()
    result["next_quarter_cves"] = result["next_quarter_cves"].astype(int)
    return result


def analyze() -> dict:
    PROCESSED.mkdir(parents=True, exist_ok=True)
    coverage = pd.read_csv(RAW / "chromium_unit_coverage_daily.csv")
    cves = pd.read_csv(RAW / "chrome_stable_desktop_cves.csv")

    overlap_start = max(
        pd.to_datetime(coverage["date"]).min(),
        pd.to_datetime(cves["reported_date"]).min(),
    )
    coverage = coverage[pd.to_datetime(coverage["date"]) >= overlap_start].copy()
    cves = cves[pd.to_datetime(cves["reported_date"]) >= overlap_start].copy()

    annual_all = aggregate_periods(coverage, cves, "Y")
    quarterly_all = aggregate_periods(coverage, cves, "Q")
    monthly_all = aggregate_periods(coverage, cves, "M")

    annual = _primary(annual_all)
    quarterly = _primary(quarterly_all)
    monthly = _primary(monthly_all)
    lagged = _lag(quarterly)

    annual.to_csv(PROCESSED / "annual.csv", index=False)
    quarterly.to_csv(PROCESSED / "quarterly.csv", index=False)
    monthly.to_csv(PROCESSED / "monthly.csv", index=False)
    lagged.to_csv(PROCESSED / "quarterly_lag1.csv", index=False)

    annual_all.to_csv(PROCESSED / "annual_all.csv", index=False)
    quarterly_all.to_csv(PROCESSED / "quarterly_all.csv", index=False)
    monthly_all.to_csv(PROCESSED / "monthly_all.csv", index=False)
    _lag(quarterly_all[quarterly_all["complete_period"]].copy()).to_csv(
        PROCESSED / "quarterly_lag1_all.csv", index=False
    )

    complete_full_q = quarterly_all[quarterly_all["complete_period"]].copy()
    full_lag = _lag(complete_full_q)
    break_2026 = quarterly_all[quarterly_all["period"].str.startswith("2026")].copy()

    stats = {
        "primary_window": {"start": "2021-01-01", "end": "2025-12-31"},
        "primary_exclusion": {
            "year": 2026,
            "reason": "documented structural break in Chrome vulnerability discovery and processing",
            "source": AI_DISCOVERY_SOURCE,
        },
        "snapshot_latest_source_date": str(
            min(
                pd.to_datetime(coverage["date"]).max(),
                pd.to_datetime(cves["reported_date"]).max(),
            ).date()
        ),
        "coverage_reports_all": int(len(coverage)),
        "unique_cves_all_overlap": int(cves["cve"].nunique()),
        "primary_quarters": int(len(quarterly)),
        "quarterly_same_period_line": association(
            quarterly, "unit_line_coverage_pct", "cves_reported"
        ),
        "quarterly_same_period_branch": association(
            quarterly, "unit_branch_coverage_pct", "cves_reported"
        ),
        "quarterly_next_period_line": association(
            lagged, "unit_line_coverage_pct", "next_quarter_cves"
        ),
        "quarterly_next_period_branch": association(
            lagged, "unit_branch_coverage_pct", "next_quarter_cves"
        ),
        "annual_same_period_line": association(
            annual, "unit_line_coverage_pct", "cves_reported"
        ),
        "full_series_diagnostic_same_period_line": association(
            complete_full_q, "unit_line_coverage_pct", "cves_reported"
        ),
        "full_series_diagnostic_next_period_line": association(
            full_lag, "unit_line_coverage_pct", "next_quarter_cves"
        ),
        "structural_break_2026": {
            row["period"]: int(row["cves_reported"]) for _, row in break_2026.iterrows()
        },
    }
    (PROCESSED / "stats.json").write_text(
        json.dumps(stats, indent=2) + "\n", encoding="utf-8"
    )
    return stats


def _svg_start(title: str, subtitle: str, width: int = 1400, height: int = 820) -> list[str]:
    return [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}">',
        f'<rect width="{width}" height="{height}" fill="{BG}"/>',
        f'<text x="70" y="72" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="36" font-weight="700">{html.escape(title)}</text>',
        f'<text x="70" y="108" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="18">{html.escape(subtitle)}</text>',
    ]


def _axis_ticks(lo: float, hi: float, count: int = 5) -> list[float]:
    if hi == lo:
        return [lo]
    return [lo + (hi - lo) * i / count for i in range(count + 1)]


def scatter_svg(
    frame: pd.DataFrame,
    x_col: str,
    y_col: str,
    label_col: str,
    title: str,
    subtitle: str,
    out: Path,
) -> None:
    width, height = 1400, 820
    left, right, top, bottom = 120, 70, 150, 100
    plot_w, plot_h = width - left - right, height - top - bottom
    clean = frame[[x_col, y_col, label_col]].dropna().copy()
    x = clean[x_col].astype(float).to_numpy()
    y = clean[y_col].astype(float).to_numpy()
    if not len(x):
        return
    x_pad = max((x.max() - x.min()) * 0.12, 0.6)
    y_pad = max((y.max() - y.min()) * 0.12, 2.0)
    x0, x1 = x.min() - x_pad, x.max() + x_pad
    y0, y1 = max(0.0, y.min() - y_pad), y.max() + y_pad

    sx = lambda v: left + (v - x0) / (x1 - x0) * plot_w
    sy = lambda v: top + plot_h - (v - y0) / (y1 - y0) * plot_h
    parts = _svg_start(title, subtitle, width, height)
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in _axis_ticks(y0, y1):
        yy = sy(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left + plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left - 18}" y="{yy + 6:.1f}" text-anchor="end" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}</text>')
    for tick in _axis_ticks(x0, x1):
        xx = sx(tick)
        parts.append(f'<text x="{xx:.1f}" y="{top + plot_h + 34}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')

    slope, intercept = linear_fit(x, y)
    parts.append(f'<line x1="{sx(x0):.1f}" y1="{sy(slope*x0+intercept):.1f}" x2="{sx(x1):.1f}" y2="{sy(slope*x1+intercept):.1f}" stroke="{CORAL}" stroke-width="4" stroke-linecap="round"/>')
    for _, row in clean.iterrows():
        xx, yy = sx(float(row[x_col])), sy(float(row[y_col]))
        parts.append(f'<circle cx="{xx:.1f}" cy="{yy:.1f}" r="7" fill="{CYAN}" stroke="{BG}" stroke-width="3"/>')
        parts.append(f'<text x="{xx + 10:.1f}" y="{yy - 10:.1f}" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="12">{html.escape(str(row[label_col]))}</text>')

    parts.append(f'<text x="{left + 24}" y="{top + 38}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="20" font-weight="600">Pearson r = {pearson(x,y):+.3f} · n = {len(clean)}</text>')
    parts.append(f'<text x="{left + plot_w/2}" y="{height - 32}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="17">Mean Linux C/C++ unit-test line coverage</text>')
    parts.append(f'<text transform="translate(32 {top + plot_h/2}) rotate(-90)" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="17">CVEs reported</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts), encoding="utf-8")


def annual_dual_svg(frame: pd.DataFrame, out: Path) -> None:
    width, height = 1400, 820
    left, right, top, bottom = 110, 110, 150, 110
    plot_w, plot_h = width - left - right, height - top - bottom
    df = frame.copy()
    labels = df["period"].astype(str).tolist()
    coverage = df["unit_line_coverage_pct"].astype(float).to_numpy()
    cves = df["cves_reported"].astype(float).to_numpy()
    n = len(df)
    cov_pad = max((coverage.max() - coverage.min()) * 0.25, 1.5)
    c0, c1 = coverage.min() - cov_pad, coverage.max() + cov_pad
    v0, v1 = 0.0, max(cves.max() * 1.18, 1.0)
    sx = lambda i: left + (i + 0.5) * plot_w / n
    sy_cov = lambda v: top + plot_h - (v - c0) / (c1 - c0) * plot_h
    sy_cve = lambda v: top + plot_h - v / v1 * plot_h

    parts = _svg_start(
        "Chromium unit-test coverage vs Chrome CVE disclosures",
        "Primary study window: 2021–2025 · 2026 excluded because vulnerability discovery changed materially",
        width,
        height,
    )
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in _axis_ticks(c0, c1):
        yy = sy_cov(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{BLUE}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.1f}%</text>')
    for tick in _axis_ticks(v0, v1):
        parts.append(f'<text x="{left+plot_w+16}" y="{sy_cve(tick)+5:.1f}" fill="{CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}</text>')
    bar_w = plot_w / n * 0.38
    for i, value in enumerate(cves):
        yy = sy_cve(value)
        parts.append(f'<rect x="{sx(i)-bar_w/2:.1f}" y="{yy:.1f}" width="{bar_w:.1f}" height="{top+plot_h-yy:.1f}" rx="7" fill="{CORAL}" opacity="0.72"/>')
        parts.append(f'<text x="{sx(i):.1f}" y="{yy-10:.1f}" text-anchor="middle" fill="{CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="14" font-weight="600">{int(value)}</text>')
    pts = " ".join(f"{sx(i):.1f},{sy_cov(v):.1f}" for i, v in enumerate(coverage))
    parts.append(f'<polyline points="{pts}" fill="none" stroke="{BLUE}" stroke-width="5" stroke-linecap="round" stroke-linejoin="round"/>')
    for i, value in enumerate(coverage):
        parts.append(f'<circle cx="{sx(i):.1f}" cy="{sy_cov(value):.1f}" r="6" fill="{BLUE}" stroke="{BG}" stroke-width="3"/>')
        parts.append(f'<text x="{sx(i):.1f}" y="{top+plot_h+35}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">{labels[i]}</text>')
    parts.append(f'<circle cx="{left+20}" cy="{top-24}" r="6" fill="{BLUE}"/><text x="{left+34}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">Unit-test line coverage</text>')
    parts.append(f'<rect x="{left+250}" y="{top-31}" width="14" height="14" rx="3" fill="{CORAL}" opacity="0.72"/><text x="{left+274}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">CVEs reported</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts), encoding="utf-8")


def coverage_history_svg(coverage: pd.DataFrame, out: Path) -> None:
    df = coverage.copy()
    df["date"] = pd.to_datetime(df["date"])
    df = df[(df["date"] >= PRIMARY_START) & (df["date"] <= PRIMARY_END)]
    df = df.set_index("date").sort_index()
    weekly = df[["line_coverage_pct", "branch_coverage_pct"]].resample("7D").mean().dropna()
    width, height = 1400, 760
    left, right, top, bottom = 110, 70, 150, 90
    plot_w, plot_h = width - left - right, height - top - bottom
    values = np.concatenate([weekly["line_coverage_pct"], weekly["branch_coverage_pct"]])
    ypad = max((values.max() - values.min()) * 0.12, 2.0)
    y0, y1 = max(0.0, values.min() - ypad), min(100.0, values.max() + ypad)
    d0, d1 = weekly.index.min(), weekly.index.max()
    sx = lambda d: left + (d - d0).total_seconds() / (d1 - d0).total_seconds() * plot_w
    sy = lambda v: top + plot_h - (v - y0) / (y1 - y0) * plot_h
    parts = _svg_start(
        "Chromium unit-test coverage history",
        "Primary study window 2021–2025 · official Linux C/C++ Unit Tests Only reports",
        width,
        height,
    )
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    for tick in _axis_ticks(y0, y1):
        yy = sy(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}%</text>')
    for year in range(2021, 2026):
        tick = pd.Timestamp(year=year, month=1, day=1)
        if d0 <= tick <= d1:
            xx = sx(tick)
            parts.append(f'<line x1="{xx:.1f}" y1="{top}" x2="{xx:.1f}" y2="{top+plot_h}" stroke="{GRID}" stroke-dasharray="4 8"/>')
            parts.append(f'<text x="{xx:.1f}" y="{top+plot_h+34}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{year}</text>')
    for col, color in [("line_coverage_pct", BLUE), ("branch_coverage_pct", GOLD)]:
        pts = " ".join(f"{sx(idx):.1f},{sy(float(val)):.1f}" for idx, val in weekly[col].items())
        parts.append(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="4" stroke-linejoin="round" stroke-linecap="round"/>')
    parts.append(f'<line x1="{left+20}" y1="{top-24}" x2="{left+52}" y2="{top-24}" stroke="{BLUE}" stroke-width="4"/><text x="{left+62}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">Line coverage</text>')
    parts.append(f'<line x1="{left+220}" y1="{top-24}" x2="{left+252}" y2="{top-24}" stroke="{GOLD}" stroke-width="4"/><text x="{left+262}" y="{top-18}" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">Branch coverage</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts), encoding="utf-8")


def structural_break_svg(quarterly_all: pd.DataFrame, out: Path) -> None:
    df = quarterly_all[
        quarterly_all["period"].isin(
            ["2025Q1","2025Q2","2025Q3","2025Q4","2026Q1","2026Q2","2026Q3"]
        )
    ].copy()
    width, height = 1400, 760
    left, right, top, bottom = 110, 70, 160, 110
    plot_w, plot_h = width - left - right, height - top - bottom
    vmax = max(float(df["cves_reported"].max()) * 1.14, 1.0)
    n = len(df)
    sx = lambda i: left + (i + 0.5) * plot_w / n
    sy = lambda v: top + plot_h - float(v) / vmax * plot_h
    parts = _svg_start(
        "2026 is a different CVE-discovery regime",
        "Chrome scaled AI-assisted vulnerability discovery and processing in early 2026; this year is excluded from the primary correlation",
        width,
        height,
    )
    parts.append(f'<rect x="{left}" y="{top}" width="{plot_w}" height="{plot_h}" rx="18" fill="{PANEL}"/>')
    break_x = left + 4 * plot_w / n
    parts.append(f'<rect x="{break_x:.1f}" y="{top}" width="{left+plot_w-break_x:.1f}" height="{plot_h}" fill="{CORAL}" opacity="0.07"/>')
    parts.append(f'<line x1="{break_x:.1f}" y1="{top}" x2="{break_x:.1f}" y2="{top+plot_h}" stroke="{CORAL}" stroke-width="3" stroke-dasharray="8 8"/>')
    parts.append(f'<text x="{break_x+16:.1f}" y="{top+32}" fill="{CORAL}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16" font-weight="600">2026 structural break</text>')
    for tick in _axis_ticks(0, vmax):
        yy = sy(tick)
        parts.append(f'<line x1="{left}" y1="{yy:.1f}" x2="{left+plot_w}" y2="{yy:.1f}" stroke="{GRID}"/>')
        parts.append(f'<text x="{left-16}" y="{yy+5:.1f}" text-anchor="end" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="15">{tick:.0f}</text>')
    bar_w = plot_w / n * 0.52
    for i, (_, row) in enumerate(df.iterrows()):
        val = int(row["cves_reported"])
        yy = sy(val)
        opacity = 0.55 if row["period"].startswith("2025") else 0.9
        parts.append(f'<rect x="{sx(i)-bar_w/2:.1f}" y="{yy:.1f}" width="{bar_w:.1f}" height="{top+plot_h-yy:.1f}" rx="8" fill="{CORAL}" opacity="{opacity}"/>')
        parts.append(f'<text x="{sx(i):.1f}" y="{yy-12:.1f}" text-anchor="middle" fill="{TEXT}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="17" font-weight="700">{val}</text>')
        label = str(row["period"]) + ("*" if not bool(row["complete_period"]) else "")
        parts.append(f'<text x="{sx(i):.1f}" y="{top+plot_h+35}" text-anchor="middle" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="16">{label}</text>')
    parts.append(f'<text x="{left}" y="{height-28}" fill="{MUTED}" font-family="Inter,Segoe UI,Arial,sans-serif" font-size="13">* partial quarter · source for regime change: Google Chrome Security Team, July 30 2026</text>')
    parts.append("</svg>")
    out.write_text("\n".join(parts), encoding="utf-8")


def render_charts() -> None:
    CHARTS.mkdir(parents=True, exist_ok=True)
    coverage = pd.read_csv(RAW / "chromium_unit_coverage_daily.csv")
    annual = pd.read_csv(PROCESSED / "annual.csv")
    quarterly = pd.read_csv(PROCESSED / "quarterly.csv")
    lagged = pd.read_csv(PROCESSED / "quarterly_lag1.csv")
    quarterly_all = pd.read_csv(PROCESSED / "quarterly_all.csv")

    annual_dual_svg(annual, CHARTS / "annual_coverage_vs_cves.svg")
    coverage_history_svg(coverage, CHARTS / "unit_coverage_history.svg")
    scatter_svg(
        quarterly,
        "unit_line_coverage_pct",
        "cves_reported",
        "period",
        "Quarterly unit-test coverage vs CVE disclosures",
        "Primary analysis: complete quarters in 2021–2025 · descriptive, not causal",
        CHARTS / "quarterly_same_period_scatter.svg",
    )
    scatter_svg(
        lagged,
        "unit_line_coverage_pct",
        "next_quarter_cves",
        "period",
        "Does unit-test coverage predict next-quarter CVEs?",
        "Primary analysis: coverage in quarter Q vs CVEs in Q+1, entirely within 2021–2025",
        CHARTS / "quarterly_lag1_scatter.svg",
    )
    structural_break_svg(quarterly_all, CHARTS / "2026_structural_break.svg")


def _fmt(value: float) -> str:
    return f"{float(value):+.3f}" if value is not None and math.isfinite(float(value)) else "n/a"


def write_results(stats: dict) -> None:
    annual = pd.read_csv(PROCESSED / "annual.csv")
    q = stats["quarterly_same_period_line"]
    lag = stats["quarterly_next_period_line"]
    branch = stats["quarterly_same_period_branch"]
    rows = [
        f"| {row['period']} | {row['unit_line_coverage_pct']:.2f}% | "
        f"{row['unit_branch_coverage_pct']:.2f}% | {int(row['cves_reported'])} |"
        for _, row in annual.iterrows()
    ]
    text = f"""# Results

The primary study window is **{PRIMARY_LABEL}**. Chromium's 2026 data remains downloaded and reproducible, but it is excluded from the headline correlation because Chrome documented a major change in vulnerability discovery and processing in early 2026.

## Primary result: 2021–2025

Across {q['n']} complete quarters, same-quarter unit-test **line coverage vs reported CVEs** has Pearson **r = {_fmt(q['pearson_r'])}** (naive bootstrap 95% CI {_fmt(q['pearson_bootstrap_95pct_ci'][0])} to {_fmt(q['pearson_bootstrap_95pct_ci'][1])}) and Spearman **rho = {_fmt(q['spearman_rho'])}**.

Unit-test **branch coverage vs reported CVEs** has Pearson **r = {_fmt(branch['pearson_r'])}**.

Coverage in quarter Q versus CVEs first disclosed in **Q+1**, with both quarters restricted to 2021–2025, has Pearson **r = {_fmt(lag['pearson_r'])}** across {lag['n']} quarter pairs (naive bootstrap 95% CI {_fmt(lag['pearson_bootstrap_95pct_ci'][0])} to {_fmt(lag['pearson_bootstrap_95pct_ci'][1])}; Spearman **rho = {_fmt(lag['spearman_rho'])}**).

These are observational associations, not causal estimates.

![Primary annual chart](charts/annual_coverage_vs_cves.svg)

![Primary quarterly scatter](charts/quarterly_same_period_scatter.svg)

![Primary lagged scatter](charts/quarterly_lag1_scatter.svg)

## Why 2026 is separate

Google's Chrome Security Team says it built a Gemini-based vulnerability-finding harness across the broader Chrome codebase in **early 2026**. By March, Chrome was receiving more bug reports than it had in all of 2025, and Chrome 149 plus 150 fixed **1,072 security bugs**, more than the prior 23 milestones combined.

Source: {AI_DISCOVERY_SOURCE}

That is a documented structural break in the process generating the dependent variable: the rate at which vulnerabilities are found, processed, fixed and disclosed changed sharply. Including 2026 in the primary correlation would mix two different discovery regimes.

![2026 structural break](charts/2026_structural_break.svg)

The raw and `*_all.csv` datasets retain 2026 so the exclusion is transparent and reversible. The cutoff was chosen **after the initial analysis revealed the discontinuity**, so this is explicitly a post-hoc comparability decision rather than a preregistered exclusion.

## Annual primary data

| Year | Mean line coverage | Mean branch coverage | Unique CVEs first reported |
| --- | ---: | ---: | ---: |
{chr(10).join(rows)}

## Sources

- Chromium coverage dashboard: {COVERAGE_SOURCE}
- Chromium coverage methodology: {CHROMIUM_COVERAGE_DOC}
- Chrome Stable Desktop disclosures: {BLOG_HOME}
- Google's explanation of the 2026 AI vulnerability-discovery change: {AI_DISCOVERY_SOURCE}

## Interpretation limits

1. CVEs measure discovered and disclosed vulnerabilities, not latent vulnerability prevalence.
2. Chrome Stable Desktop posts can include third-party code shipped with Chrome.
3. Coverage is Linux C/C++ `Unit Tests Only` coverage, not every test on every Chrome platform.
4. The IID bootstrap does not account for time-series autocorrelation.
5. Coverage, CVEs, code churn, fuzzing, sanitizers, researcher attention and architectural hardening can move together.
6. A stronger next stage would map CVEs to Chromium components and compare component-level historical coverage while controlling for LOC, churn, contributors, fuzzing and exposure.
"""
    (ROOT / "RESULTS.md").write_text(text, encoding="utf-8")


def run_all() -> dict:
    collect_coverage()
    collect_cves()
    stats = analyze()
    render_charts()
    write_results(stats)
    return stats


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "command",
        nargs="?",
        choices=["collect", "analyze", "charts", "all"],
        default="all",
    )
    args = parser.parse_args()
    if args.command in {"collect", "all"}:
        collect_coverage()
        collect_cves()
    if args.command in {"analyze", "all"}:
        stats = analyze()
        write_results(stats)
    if args.command in {"charts", "all"}:
        render_charts()


if __name__ == "__main__":
    main()
