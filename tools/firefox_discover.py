#!/usr/bin/env python3
import json
import pathlib
import re
import requests
from collections import Counter, defaultdict

API = "https://storage.googleapis.com/storage/v1/b/relman-code-coverage-prod/o"
PREFIX = "mozilla-central/"
OUT = pathlib.Path("firefox-discovery.json")


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


def main():
    rows = list_objects()
    by_key = defaultdict(list)
    revisions = defaultdict(list)
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
        revisions[rev].append(rec)

    summary = {}
    for key, vals in sorted(by_key.items()):
        vals.sort(key=lambda x: x["updated"] or "")
        summary[key] = {
            "count": len(vals),
            "first": vals[0],
            "last": vals[-1],
            "mean_compressed_bytes": int(sum(v["size"] for v in vals) / len(vals)),
        }

    result = {
        "object_count": len(rows),
        "revision_count": len(revisions),
        "coverage_streams": summary,
        "malformed_count": len(malformed),
        "malformed_examples": malformed[:20],
    }
    OUT.write_text(json.dumps(result, indent=2) + "\n")
    print(json.dumps(result, indent=2)[:30000])


if __name__ == "__main__":
    main()
