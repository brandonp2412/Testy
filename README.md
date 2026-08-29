# Testy

Reproducible observational studies of whether unit-test coverage is associated with security-vulnerability disclosures in large open-source projects.

## Results

| Project | Coverage window | Same-quarter Pearson r | Coverage Q → CVEs Q+1 | Notes |
| --- | --- | ---: | ---: | --- |
| **Chromium** | 2021–2025 | **-0.279** | **-0.448** | 20 same-period quarters; 19 lagged pairs |
| **Firefox** | 2019 Q4–2025 Q3* | **+0.172** | **+0.195** | 21 available quarters/pairs |

\* Firefox has no usable coverage archive for **2024 Q4–2025 Q2**; those quarters are left missing rather than interpolated.

The projects currently point in different directions. Chromium shows a moderate negative lagged association in its comparable 2021–2025 window; Firefox's quality-gated replication is close to zero and slightly positive. Neither is a causal estimate.

## Chromium

![Chromium unit-test coverage vs CVEs](charts/annual_coverage_vs_cves.svg)

Chromium uses the official Linux C/C++ **Unit Tests Only** coverage series and unique CVEs first disclosed in **Stable Channel Update for Desktop** posts.

- Same-quarter: Pearson **r = -0.279**, Spearman **rho = -0.505** across 20 quarters.
- Q → Q+1: Pearson **r = -0.448**, Spearman **rho = -0.523** across 19 pairs.
- [Full Chromium results](RESULTS.md)
- [Historical coverage boundary](HISTORICAL_DATA.md)

Chromium starts in 2021 because separate Linux unit-only coverage was introduced on **27 January 2021**. It stops before 2026 because Chrome documented a large-scale AI vulnerability-discovery regime change in early 2026.

## Firefox

![Firefox quarterly unit coverage vs CVEs](charts/firefox/quarterly_same_period_scatter.svg)

Firefox is reconstructed from Mozilla's original public `mozilla-central` coverage archive. For each sampled revision, Testy unions exact lines covered by **GTest + CppUnitTest + XPCShell**, then divides by the same-revision `all:all` executable-line denominator.

- Same-quarter: Pearson **r = +0.172**, Spearman **rho = +0.044** across 21 available quarters.
- Strict calendar Q → Q+1: Pearson **r = +0.195**, Spearman **rho = +0.090** across 21 pairs.
- IID bootstrap intervals cross zero for both estimates.
- [Full Firefox results](FIREFOX_RESULTS.md)

Mozilla's coverage ingestion broke after September 2024. The public archive contains no usable complete unit-suite coverage from October 2024 through June 2025, so those periods are explicitly absent. Firefox predictor coverage also stops at September 2025 because the report's executable-line denominator changes sharply in November 2025.

## Reproduce

```bash
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt

# Chromium
python study.py all

# Firefox — downloads and reconstructs original Mozilla coverage reports
python firefox_quality_study.py all
```

The Firefox workflow also runs the regression tests before rebuilding the study.

## Data

Chromium data lives under `data/raw` and `data/processed`. Firefox data lives under `data/firefox/raw` and `data/firefox/processed`.

Firefox retains the candidate manifest and quality audit used to choose monthly CI reports. Missing coverage is never interpolated, and lagging uses the actual next calendar quarter rather than the next row with available coverage.

## Sources

### Chromium

- Coverage dashboard: https://analysis.chromium.org/coverage/p/chromium
- Coverage documentation: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/testing/code_coverage.md
- Linux unit-only coverage launch: https://github.com/chromium/chromium/commit/61fe0e40252fdf2475926e560f722b558f14e5e4
- Chrome Releases: https://chromereleases.googleblog.com/
- 2026 discovery-regime change: https://blog.google/security/chrome-stronger-with-every-update/

### Firefox

- Historical raw coverage: `gs://relman-code-coverage-prod/mozilla-central`
- Coverage documentation: https://firefox-source-docs.mozilla.org/tools/code-coverage/index.html
- Firefox security advisories: https://www.mozilla.org/en-US/security/known-vulnerabilities/firefox/
- GTest: https://firefox-source-docs.mozilla.org/gtest/index.html
- XPCShell: https://firefox-source-docs.mozilla.org/testing/xpcshell/index.html
- Taskcluster test attributes: https://firefox-source-docs.mozilla.org/taskcluster/attributes.html
