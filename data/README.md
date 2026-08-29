# Data provenance

## `raw/chromium_unit_coverage_daily.csv`

Scraped from Chromium's official code coverage dashboard using:

- Project: `chromium/src`
- Platform: `linux` (C/C++)
- Test suite type: `unit` / **Unit Tests Only**
- Modifier: `0`
- Ref: `refs/heads/main`

Source: https://analysis.chromium.org/coverage/p/chromium

Each row records the dashboard report date/revision plus exact covered/total line and branch counts. Percentages are recomputed from counts rather than the dashboard's rounded displayed percentage.

### Earliest comparable observation

The first unit-only Linux report is **2021-01-27**. This is an upstream feature boundary, not merely a retention boundary: Chromium commit `61fe0e40252fdf2475926e560f722b558f14e5e4`, landed on 27 January 2021 and titled **“generate unit test coverage for linux”**, added `coverage_test_types = ["overall", "unit"]` to `linux-code-coverage`.

Source: https://github.com/chromium/chromium/commit/61fe0e40252fdf2475926e560f722b558f14e5e4

Older Linux coverage exists, but it is aggregate all-tests coverage and is not used as a substitute for unit-only coverage. See `HISTORICAL_DATA.md`.

## `raw/chrome_stable_desktop_cves.csv`

Collected from the official Chrome Releases Blogger feed, restricted to posts whose title is exactly **Stable Channel Update for Desktop**. Every `CVE-YYYY-NNNN...` identifier in those posts is extracted, and duplicate CVE IDs are retained only at their earliest Stable Desktop mention.

Source: https://chromereleases.googleblog.com/

The dataset includes the original post URL for every CVE so individual observations can be audited. `component_hint` is a best-effort string parsed from the disclosure description and is not used in the primary analysis.

## Primary processed data: 2021–2025

`annual.csv`, `quarterly.csv`, `monthly.csv` and `quarterly_lag1.csv` are the primary study datasets and stop at **31 December 2025**. The lagged dataset only contains Q → Q+1 pairs when both quarters fall inside 2021–2025.

The upper cutoff exists because Google documented a major change in Chrome's vulnerability-discovery process in early 2026: a Gemini-based vulnerability-finding harness was scaled across the Chrome codebase, and the resulting report/fix volume changed sharply.

Source: https://blog.google/security/chrome-stronger-with-every-update/

## Full-series diagnostics

The raw data is never truncated. Full processed series including 2026 are retained separately as:

- `annual_all.csv`
- `quarterly_all.csv`
- `monthly_all.csv`
- `quarterly_lag1_all.csv`

This makes the 2026 exclusion transparent and reversible. It is a post-hoc comparability decision made after the initial analysis exposed the discontinuity, not a preregistered exclusion.
