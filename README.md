# Testy

A reproducible observational study of whether Chromium's unit-test coverage is associated with the number of CVEs later reported for Chrome.

The study uses Chromium's official **Linux C/C++ → Unit Tests Only** coverage history and unique CVEs first disclosed in Google Chrome **Stable Channel Update for Desktop** posts.

![Annual unit-test coverage vs CVEs](charts/annual_coverage_vs_cves.svg)

## Run it

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
python study.py all
```

Or run the stages separately:

```bash
python study.py collect
python study.py analyze
python study.py charts
```

The repository commits the downloaded/normalized data and generated charts so the current result is inspectable without re-scraping upstream services.

## Outputs

- `data/raw/chromium_unit_coverage_daily.csv` — one row per official unit-test coverage report.
- `data/raw/chrome_stable_desktop_cves.csv` — one row per unique CVE at its first Stable Desktop disclosure.
- `data/processed/annual.csv` — annual coverage/CVE aggregation.
- `data/processed/quarterly.csv` — quarterly aggregation used for the main association.
- `data/processed/quarterly_lag1.csv` — quarter Q coverage matched to Q+1 CVEs.
- `data/processed/monthly.csv` — monthly aggregation for follow-up analysis.
- `data/processed/stats.json` — machine-readable correlations and bootstrap intervals.
- `charts/` — generated SVG figures.
- `RESULTS.md` — generated human-readable results and methodology caveats.

## Primary analyses

1. Same-quarter mean unit-test line coverage vs unique CVEs first reported that quarter.
2. Same-quarter mean unit-test branch coverage vs CVEs.
3. Quarter-Q coverage vs CVEs first reported in quarter Q+1, reducing (but not eliminating) simultaneity/reverse-causality problems.
4. Annual descriptive trend for readability.

Only complete periods are included in correlation estimates. The current partial year/quarter remains visible in descriptive outputs.

## Sources

- Chromium code coverage dashboard: https://analysis.chromium.org/coverage/p/chromium
- Chromium coverage documentation: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/testing/code_coverage.md
- Chrome Releases blog: https://chromereleases.googleblog.com/

## Important limitation

This is not a causal estimate of the security value of unit tests. CVEs measure **discovered and disclosed** vulnerabilities, not all vulnerabilities. CVE volume is affected by researcher attention, fuzzing, sanitizers, code churn, release cadence, component exposure, third-party dependencies, and disclosure policy. Chrome release posts can also include CVEs in third-party code shipped with Chrome.

A stronger second-stage study would map individual CVEs to Chromium components and compare component-level historical coverage while controlling for LOC, churn, contributors, fuzzing, and exposure.

See [RESULTS.md](RESULTS.md) for the current measured relationship.
