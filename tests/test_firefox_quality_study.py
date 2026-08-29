import unittest

import pandas as pd

import firefox_quality_study as firefox


class FirefoxQualityStudyTests(unittest.TestCase):
    def test_partial_report_is_rejected(self):
        obs = {
            "all_tests_lines_total": 4_000_000,
            "all_tests_root_lines_covered": 680_000,
            "all_tests_root_coverage_pct": 17.0,
            "unit_union_lines_covered": 400_000,
            "unit_union_coverage_pct": 10.0,
            "gtest_root_lines_total": 1,
            "cppunittest_root_lines_total": 1,
            "xpcshell_root_lines_total": 1,
        }
        self.assertIn("all_tests_coverage_out_of_range", firefox.quality_reasons(obs))

    def test_lag_uses_calendar_next_quarter_not_next_row(self):
        quarterly = pd.DataFrame([
            {"period": "2024Q3", "unit_coverage_pct": 30.0, "cves_reported": 10},
            {"period": "2025Q3", "unit_coverage_pct": 31.0, "cves_reported": 20},
        ])
        cves = pd.DataFrame([
            {"cve": "CVE-2024-0001", "announced_date": "2024-10-01"},
            {"cve": "CVE-2024-0002", "announced_date": "2024-11-01"},
            {"cve": "CVE-2025-0001", "announced_date": "2025-10-01"},
        ])
        lagged = firefox.lag_quarters(quarterly, cves)
        self.assertEqual(lagged["next_quarter"].tolist(), ["2024Q4", "2025Q4"])
        self.assertEqual(lagged["next_quarter_cves"].tolist(), [2, 1])

    def test_isolated_denominator_collapse_is_excluded(self):
        frame = pd.DataFrame([
            {"month": "2020-02", "all_tests_lines_total": 4_000_000},
            {"month": "2020-03", "all_tests_lines_total": 1_000_000},
            {"month": "2020-04", "all_tests_lines_total": 4_100_000},
        ])
        checked = firefox._mark_isolated_denominator_outliers(frame)
        self.assertTrue(bool(checked.loc[0, "analysis_quality_ok"]))
        self.assertFalse(bool(checked.loc[1, "analysis_quality_ok"]))
        self.assertEqual(checked.loc[1, "quality_note"], "isolated_denominator_outlier")
        self.assertTrue(bool(checked.loc[2, "analysis_quality_ok"]))


if __name__ == "__main__":
    unittest.main()
