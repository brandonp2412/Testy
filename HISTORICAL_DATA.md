# Historical coverage boundary

The Chromium coverage infrastructure itself predates this study, but the **Linux C/C++ unit-only metric does not**.

## Definitive lower bound

On **27 January 2021**, Chromium landed commit [`61fe0e40252fdf2475926e560f722b558f14e5e4`](https://github.com/chromium/chromium/commit/61fe0e40252fdf2475926e560f722b558f14e5e4), titled **“generate unit test coverage for linux.”**

The change added this property to the `linux-code-coverage` builder:

```text
coverage_test_types = ["overall", "unit"]
```

Before that change, the Linux builder had `use_clang_coverage = True` but no separate test-type streams. Its historical coverage is therefore **overall/all-tests coverage**, which mixes unit, browser, integration and other tests.

The official unit-only history downloaded by this repository starts on **2021-01-27**, the same day that upstream change landed. This strongly establishes that the lower bound is a feature boundary, not merely dashboard retention.

## What exists before 2021?

Chromium had full-codebase coverage before 2021. Historical documentation and builders show aggregate Linux coverage in 2019–2020. That data is useful for a different question—whether **all-test coverage** is associated with CVEs—but it is not interchangeable with the unit-only series used by Testy.

Chromium's iOS coverage infrastructure already exposed separate unit and overall views by May 2020, but iOS exercises a materially different code/platform subset and cannot be spliced into the Linux C/C++ series.

## Why Testy does not backfill it

Using pre-2021 overall coverage as though it were unit coverage would introduce a measurement break exactly at the point we are trying to measure. Rebuilding old Chromium releases today would create a synthetic series whose toolchain, runnable tests and environment differ from the original CI measurements.

For the primary study, **2021 is therefore the earliest defensible year**. The pre-2021 CVE data remains available upstream, but there is no matching first-party Linux `Unit Tests Only` exposure variable for it.

## Sources

- Linux unit-only coverage launch commit: https://github.com/chromium/chromium/commit/61fe0e40252fdf2475926e560f722b558f14e5e4
- Chromium coverage dashboard: https://analysis.chromium.org/coverage/p/chromium
- Chromium coverage documentation: https://chromium.googlesource.com/chromium/src/+/HEAD/docs/testing/code_coverage.md
- iOS unit/overall coverage announcement (1 May 2020): https://groups.google.com/a/chromium.org/g/code-coverage/c/xna4fDI7RaM
