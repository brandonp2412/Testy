#!/usr/bin/env python3
import json
import pathlib
import re
import requests
from collections import defaultdict
from datetime import datetime

API = "https://storage.googleapis.com/storage/v1/b/relman-code-coverage-prod/o"
PREFIX = "mozilla-central/"
OUT = pathlib.Path("firefox-discovery.json")

FOCUS_STREAMS = [
    "all:all", "all:gtest", "all:cppunittest", "all:xpcshell",
    "linux:all", "linux:gtest", "linux:cppunittest", "linux:xpcshell",
]
COMBOS = {
    "all_unit": ["all:all", "all:gtest", "all:cppunittest", "all:xpcshell"],
    "linux_unit_with_all_denominator": ["all:all", "linux:gtest", "linux:cppunittest", "linux:xpcshell"],
    "linux_unit": ["linux:all", "linux:gtest", "linux:cppunittest", "linux:xpcshell"],
}


def list_objects():
    token = None
    rows = []
    while True:
        params = {
            "prefix": PREFIX,
            "maxResults": 1000,
            "fields": "items(name,updated,size),nextPageToken",
        }
        if token:
            params["pageToken"] = token
        r = requests.get(API, params=params, timeout=120)
        r.raise_for_status()
        data = r.json()
        rows.extend(data.get("items", []))
        token = data.get("nextPageToken")
        print("objects", len(rows), flush=True)
        if not token:
            break
    return rows


def month_of(updated):
    return updated[:7] if updated else "unknown"


def main():
    rows = list_objects()
    by_key = defaultdict(list)
    revisions = defaultdict(dict)
    malformed = []
    pat = re.compile(r"^mozilla-central/([^/]+)/([^/:]+):([^/]+)\.json\.zstd$")
    for row in rows:
        m = pat.match(row["name"])
        if not m:
            malformed.append(row["name"])
            continue
        rev, platform, suite = m.groups()
        key = f"{platform}:{suite}"
        rec = {
            "revision": rev,
            "platform": platform,
            "suite": suite,
            "updated": row.get("updated"),
            "size": int(row.get("size", 0)),
            "name": row["name"],
        }
        by_key[key].append(rec)
        revisions[rev][key] = rec

    summary = {}
    monthly_stream_counts = {}
    for key, vals in sorted(by_key.items()):
        vals.sort(key=lambda x: x["updated"] or "")
        summary[key] = {
            "count": len(vals),
            "first": vals[0],
            "last": vals[-1],
            "mean_compressed_bytes": int(sum(v["size"] for v in vals) / len(vals)),
        }
        if key in FOCUS_STREAMS:
            counts = defaultdict(int)
            for v in vals:
                counts[month_of(v["updated"])] += 1
            monthly_stream_counts[key] = dict(sorted(counts.items()))

    monthly_combo_counts = {}
    for combo_name, required in COMBOS.items():
        counts = defaultdict(int)
        for rev, streams in revisions.items():
            if all(k in streams for k in required):
                month = max(streams[k]["updated"] for k in required)[:7]
                counts[month] += 1
        monthly_combo_counts[combo_name] = dict(sorted(counts.items()))

    result = {
        "object_count": len(rows),
        "revision_count": len(revisions),
        "coverage_streams": summary,
        "monthly_stream_counts": monthly_stream_counts,
        "monthly_combo_counts": monthly_combo_counts,
        "malformed_count": len(malformed),
        "malformed_examples": malformed[:20],
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2)[:60000])


if __name__ == "__main__":
    main()
