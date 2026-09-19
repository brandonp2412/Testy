# Testy

Reproducible observational studies of software testing and quality: coverage versus vulnerability disclosures in large open-source projects, plus CI failure audits that distinguish stale tests from genuine behavior regressions.

## Results

| Project | Coverage window | Same-quarter Pearson r | Coverage Q → CVEs Q+1 | Notes |
| --- | --- | ---: | ---: | --- |
| **Chromium** | 2021–2025 | **-0.279** | **-0.448** | 20 same-period quarters; 19 lagged pairs |
| **Firefox** | 2019 Q4–2025 Q3* | **+0.172** | **+0.195** | 21 available quarters/pairs |

\* Firefox has no usable coverage archive for **2024 Q4–2025 Q2**; those quarters are left missing rather than interpolated.

The projects currently point in different directions. Chromium shows a moderate negative lagged association in its comparable 2021–2025 window; Firefox's quality-gated replication is close to zero and slightly positive. Neither is a causal estimate.

A separate [Flexify CI failure audit](#flexify-when-unit-tests-fail-was-behavior-actually-broken) reviews every Actions run and classifies actual unit/widget-test failures by root cause.

## Direct visual comparison

All comparison plots use the same orientation:

**X-axis = unit-test coverage (%) · Y-axis = CVEs reported**

### Same quarter

#### Chromium

![Chromium quarterly unit-test coverage vs same-quarter CVEs](charts/quarterly_same_period_scatter.svg)

#### Firefox

![Firefox quarterly unit-test coverage vs same-quarter CVEs](charts/firefox/quarterly_same_period_scatter.svg)

### Coverage in Q → CVEs in Q+1

#### Chromium

![Chromium unit-test coverage vs next-quarter CVEs](charts/quarterly_lag1_scatter.svg)

#### Firefox

![Firefox unit-test coverage vs next-quarter CVEs](charts/firefox/quarterly_lag1_scatter.svg)

The charts are stacked at full README width so they remain readable on mobile. The absolute coverage ranges differ between the projects because the coverage metrics come from different test infrastructures, so the X-axis numeric ranges are not forced to be identical. What is directly comparable is the orientation and direction/strength of the within-project relationship.

<!-- flexify-unit-test-failure-study:start -->
## Flexify: when unit tests fail, was behavior actually broken?

The complete [Flexify Actions history](https://github.com/brandonp2412/Flexify/actions) from **2025-08-02 through 2026-09-19** contains **633 workflow runs / 639 execution attempts**, including **258 failed attempts**. The denominator below is narrower: an attempt counts only when the Flutter unit/widget suite itself failed. Deployment, build, analysis, formatting, screenshot, Patrol/device-test, and cancelled failures are excluded.

Method: every failed workflow attempt is inspected at the job/step level, including earlier attempts hidden behind a later GitHub re-run. An explicitly failed unit-test step counts even when GitHub has expired its detailed log; composite quality steps count only when retained job logs or check annotations contain Flutter-test failure evidence. Each confirmed test failure is then classified from the failure evidence and follow-up fix: application-code correction means behavior regression, while a test-only expectation/harness correction means stale or incorrect test assumptions.

| Measure | Result |
| --- | ---: |
| Failed workflow attempts inspected | **258/258 (100.0%)** |
| CI attempts where unit/widget tests actually failed | **5** |
| Reviewed test-failure attempts | **5** |
| Stale/incorrect test assumption or harness | **5/5 (100.0%)** |
| App behavior actually broken | **0/5 (0.0%)** |
| Failed assertions classified | **18** (0 behavior-regression assertions) |
| Unique root-cause incidents | **4** (0 behavior regressions) |
| Awaiting manual review | **0** |
| Ambiguous old composite failures excluded | **2** |

For this sample, the observed behavior-regression rate is **0.0% per failed CI test attempt**, **0.0% per failed assertion**, and **0.0% per unique incident**. The sample is small and repeated CI attempts from one root cause are not independent, so all three denominators are reported.

GitHub no longer retains enough detail to prove whether **2 older composite-job failures** reached the unit-test stage. They remain explicitly recorded in the audit state and are excluded from both the test-failure numerator and classification denominator rather than guessed.

Completeness cross-check: **7 retained composite `Check` failures** were manually reviewed. **1** contained a Flutter unit/widget-test failure and is already counted above; the other **6** stopped before that suite (2 dependency resolution, 4 static analysis), so they are not silently dropped test failures.

### Reviewed failures

| Date | Actions run | Failed assertions | Classification | Evidence |
| --- | --- | ---: | --- | --- |
| 2025-08-13 | [16934023043](https://github.com/brandonp2412/Flexify/actions/runs/16934023043/attempts/1) | 1 | Test assumption/harness | The retained check annotation says 881 tests passed and 1 failed. The follow-up fix changed only test/plan_list_test.dart, adding the ScrollController newly required by PlansList; application behavior was unchanged. ([fix 90ca6a40d4](https://github.com/brandonp2412/Flexify/commit/90ca6a40d4ac4d1edaa57ae1cd0a6c1f649c40a2)) |
| 2026-07-18 | [29629498590](https://github.com/brandonp2412/Flexify/actions/runs/29629498590/attempts/1) | 6 | Test assumption/harness | All six assertions still expected the old generic Search... label. The fix changed only tests to the current Search history..., Search graphs..., and Search plans... labels. ([fix 947e253b8e](https://github.com/brandonp2412/Flexify/commit/947e253b8e82cea4c3343c8daded4723b66ed7ef)) |
| 2026-07-18 | [29630985356](https://github.com/brandonp2412/Flexify/actions/runs/29630985356/attempts/1) | 6 | Test assumption/harness | Same root cause as run 29629498590: six stale Search... text expectations. The eventual fix touched only the test expectations. ([fix 947e253b8e](https://github.com/brandonp2412/Flexify/commit/947e253b8e82cea4c3343c8daded4723b66ed7ef)) |
| 2026-08-27 | [33045818492](https://github.com/brandonp2412/Flexify/actions/runs/33045818492/attempts/1) | 4 | Test assumption/harness | The tests targeted obsolete semantics/weekday presentation. Follow-up commits changed only StartPlanPage test finders/assertions, ultimately locating StepperField controls by component label and descendant EditableText. ([fix 932f808066](https://github.com/brandonp2412/Flexify/commit/932f8080669016081378840c89f1e637dd908779)) |
| 2026-09-05 | [33935285113](https://github.com/brandonp2412/Flexify/actions/runs/33935285113/attempts/1) | 1 | Test assumption/harness | The assertion expected old empty-state copy No data yet for Graph history test. The fix changed only that test expectation to the existing No history yet for Graph history test UI copy. ([fix ecedb171a2](https://github.com/brandonp2412/Flexify/commit/ecedb171a2b207b2ee2a7b9f8713bd79e3a1c4bc)) |

The resumable audit state is in [data/flexify/unit_test_failure_audit.json](data/flexify/unit_test_failure_audit.json). Run python flexify_test_failure_study.py sync to inspect only newly seen failed Actions attempts while preserving existing manual reviews. Use the rescan flag after changing the detector, then render the README again.
<!-- flexify-unit-test-failure-study:end -->

## Chromium

Chromium uses the official Linux C/C++ **Unit Tests Only** coverage series and unique CVEs first disclosed in **Stable Channel Update for Desktop** posts.

- Same-quarter: Pearson **r = -0.279**, Spearman **rho = -0.505** across 20 quarters.
- Q → Q+1: Pearson **r = -0.448**, Spearman **rho = -0.523** across 19 pairs.
- [Full Chromium results](RESULTS.md)
- [Historical coverage boundary](HISTORICAL_DATA.md)

Chromium starts in 2021 because separate Linux unit-only coverage was introduced on **27 January 2021**. It stops before 2026 because Chrome documented a large-scale AI vulnerability-discovery regime change in early 2026.

## Firefox

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
