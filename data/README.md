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

## `raw/chrome_stable_desktop_cves.csv`

Collected from the official Chrome Releases Blogger feed, restricted to posts whose title is exactly **Stable Channel Update for Desktop**. Every `CVE-YYYY-NNNN...` identifier in those posts is extracted, and duplicate CVE IDs are retained only at their earliest Stable Desktop mention.

Source: https://chromereleases.googleblog.com/

The dataset includes the original post URL for every CVE so individual observations can be audited. `component_hint` is a best-effort string parsed from the disclosure description and is not used in the primary analysis.

## Processed data

Processed CSVs aggregate daily coverage and CVE disclosure dates by month, quarter, and year. The primary statistical analysis uses complete quarters only. `quarterly_lag1.csv` matches coverage in quarter Q to CVEs disclosed in Q+1.

The collector intentionally preserves 2026 rather than silently excluding it. Chrome's 2026 release posts show an abrupt jump in the number of security fixes/CVEs in several releases, so the analysis reports both the complete available series and a clearly labelled 2021–2025 sensitivity analysis.
