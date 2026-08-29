# Data provenance

## Chromium

### `raw/chromium_unit_coverage_daily.csv`

Scraped from Chromium's official code coverage dashboard using project `chromium/src`, Linux C/C++, `Unit Tests Only`, modifier `0`, and `refs/heads/main`.

Source: https://analysis.chromium.org/coverage/p/chromium

Each row records the dashboard report date/revision plus exact covered/total line and branch counts. Percentages are recomputed from counts rather than the dashboard's rounded displayed percentage.

The first comparable unit-only Linux observation is **2021-01-27**. Chromium commit `61fe0e40252fdf2475926e560f722b558f14e5e4`, landed that day and titled **“generate unit test coverage for linux”**, added separate `overall` and `unit` coverage streams. Older Linux coverage is aggregate all-tests coverage and is not spliced into the study.

Source: https://github.com/chromium/chromium/commit/61fe0e40252fdf2475926e560f722b558f14e5e4

### `raw/chrome_stable_desktop_cves.csv`

Collected from the official Chrome Releases feed, restricted to posts titled exactly **Stable Channel Update for Desktop**. CVE identifiers are deduplicated at their earliest Stable Desktop mention.

Source: https://chromereleases.googleblog.com/

### Processed Chromium data

`annual.csv`, `quarterly.csv`, `monthly.csv` and `quarterly_lag1.csv` are the primary **2021–2025** datasets. Full-series `*_all.csv` diagnostics retain 2026, which is excluded from the primary correlation because Chrome documented a major vulnerability-discovery regime change in early 2026.

Source: https://blog.google/security/chrome-stronger-with-every-update/

## Firefox

Firefox data is under `data/firefox/`.

### `firefox/raw/coverage_candidate_manifest.csv`

Built by listing Mozilla's public historical coverage bucket:

`gs://relman-code-coverage-prod/mozilla-central`

For every `mozilla-central` revision, Testy looks for the original coverage streams:

- `all:all`
- `all:gtest`
- `all:cppunittest`
- `all:xpcshell`

Up to five candidate revisions per month are ranked using robust within-month compressed-report size. This makes obviously partial CI reports less likely to be selected while preserving the original measurements.

### `firefox/raw/coverage_quality_audit.csv`

Records every candidate report actually attempted, its rank, the relevant root coverage metadata, whether it passed quality checks, and any rejection reason.

Static gates reject implausible/incomplete reports. A second longitudinal check rejects isolated executable-line denominator collapses when the adjacent months agree with each other. Missing coverage is never filled by interpolation.

### `firefox/raw/unit_coverage_monthly.csv`

One selected original CI observation per available month. The Firefox exposure metric is:

> unique source lines covered by GTest ∪ CppUnitTest ∪ XPCShell / same-revision `all:all` executable lines

The union is formed from the original per-line execution arrays, so a source line hit by more than one suite is counted once.

Mozilla describes GTest as unit testing and advises against integration tests in that suite. XPCShell is generally used for unit tests, and Taskcluster identifies `cppunittest` as a unit-test suite.

Sources:

- https://firefox-source-docs.mozilla.org/gtest/index.html
- https://firefox-source-docs.mozilla.org/testing/xpcshell/index.html
- https://firefox-source-docs.mozilla.org/taskcluster/attributes.html

### Firefox archive gap

The public archive contains no complete required-stream observations from **2024-10 through 2025-06**. Linux-specific streams have the same hole. Mozilla's own Bugzilla records that code-coverage ingestion was broken after September 2024.

Source: https://bugzilla.mozilla.org/show_bug.cgi?id=1925873

These periods remain absent from the processed data.

### Late-2025 scope break

The selected `all:all` executable-line denominator is approximately 4.76–4.90 million lines from July through October 2025, then falls to roughly 1.71 million in November and 1.74 million in December. Because this is a large measurement-scope break, primary Firefox predictor coverage stops at **2025-09-30**.

Q4 2025 CVEs are still valid as the outcome for Q3 2025 coverage.

### `firefox/raw/firefox_cves.csv`

Collected from Mozilla's official Firefox known-vulnerabilities/advisory pages. CVEs are deduplicated at their first Firefox advisory occurrence.

Source: https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/

### Processed Firefox data

- `firefox/processed/monthly.csv` — quality-eligible primary monthly exposures.
- `firefox/processed/quarterly.csv` — available quarters with at least two monthly coverage observations.
- `firefox/processed/quarterly_lag1.csv` — coverage quarter Q matched to the **actual calendar Q+1** CVE count. A coverage gap never causes Q to be matched to a later available coverage row.
- `firefox/processed/annual.csv` — descriptive years with at least 10 quality-eligible coverage months.
- `firefox/processed/*_all.csv` — retained full selected series for audit/diagnostics.
- `firefox/processed/stats.json` — final associations and data-quality metadata.
