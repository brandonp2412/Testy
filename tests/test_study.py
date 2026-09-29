import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pandas as pd

import study
from study import (
    _lag,
    bootstrap_pearson_ci,
    parse_cves_from_entry,
    parse_coverage_page,
    parse_stat,
)


class ParsingTests(unittest.TestCase):
    def test_parse_stat_uses_exact_counts(self):
        stat = parse_stat("59% (3576210/5979419)")
        self.assertIsNotNone(stat)
        self.assertEqual(stat.covered, 3576210)
        self.assertEqual(stat.total, 5979419)
        self.assertAlmostEqual(stat.exact_pct, 100 * 3576210 / 5979419)

    def test_parse_coverage_page(self):
        page = """
        <table><tbody><tr>
          <td><a href="/coverage/report?revision=abc">Link</a></td>
          <td>2026-08-27 19:58:19</td>
          <td>abc1234</td>
          <td>59% (590/1000)</td>
          <td>48% (480/1000)</td>
          <td>Build</td>
        </tr></tbody></table>
        <a href="?direction=next&amp;cursor=xyz">Next</a>
        """
        rows, next_url = parse_coverage_page(page, "https://analysis.chromium.org/example")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["revision"], "abc1234")
        self.assertEqual(rows[0]["line_coverage_pct"], 59.0)
        self.assertIn("direction=next", next_url)

    def test_lag_does_not_treat_next_available_row_as_next_quarter(self):
        quarterly = pd.DataFrame([
            {"period": "2024Q3", "cves_reported": 10},
            {"period": "2025Q3", "cves_reported": 20},
        ])

        lagged = _lag(quarterly)

        self.assertTrue(lagged.empty)

    def test_bootstrap_ci_handles_constant_series(self):
        low, high = bootstrap_pearson_ci([1, 1, 1, 1], [1, 2, 3, 4], iterations=100)
        self.assertTrue(pd.isna(low))
        self.assertTrue(pd.isna(high))

    def test_write_results_regenerates_structural_break_context(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            processed = root / "data" / "processed"
            processed.mkdir(parents=True)
            pd.DataFrame([
                {
                    "period": "2025",
                    "unit_line_coverage_pct": 60.9,
                    "unit_branch_coverage_pct": 50.6,
                    "cves_reported": 192,
                }
            ]).to_csv(processed / "annual.csv", index=False)
            pd.DataFrame([
                {"period": "2025Q4", "cves_reported": 54, "complete_period": True},
                {"period": "2026Q1", "cves_reported": 128, "complete_period": True},
                {"period": "2026Q2", "cves_reported": 1511, "complete_period": True},
                {"period": "2026Q3", "cves_reported": 1265, "complete_period": False},
            ]).to_csv(processed / "quarterly_all.csv", index=False)
            stats = {
                "quarterly_same_period_line": {
                    "n": 20,
                    "pearson_r": -0.279,
                    "pearson_bootstrap_95pct_ci": [-0.715, 0.122],
                    "spearman_rho": -0.505,
                },
                "quarterly_next_period_line": {
                    "n": 19,
                    "pearson_r": -0.448,
                    "pearson_bootstrap_95pct_ci": [-0.727, -0.126],
                    "spearman_rho": -0.523,
                },
                "quarterly_same_period_branch": {"pearson_r": -0.276},
                "full_series_diagnostic_same_period_line": {"pearson_r": 0.221},
            }

            with patch.object(study, "ROOT", root), patch.object(study, "PROCESSED", processed):
                study.write_results(stats)

            result = (root / "RESULTS.md").read_text()
            self.assertIn("**20 complete quarters**", result)
            self.assertIn("IID quarter resample", result)
            self.assertIn("| 2026 Q2 | 1,511 |", result)
            self.assertIn("| 2026 Q3* | 1,265 |", result)
            self.assertIn("from **-0.279** to **+0.221**", result)

    def test_cve_parser_filters_to_stable_desktop_and_dedupes_upstream(self):
        entry = {
            "title": {"$t": "Stable Channel Update for Desktop"},
            "published": {"$t": "2026-07-16T10:00:00-07:00"},
            "content": {
                "$t": "<div>[N/A][123] Critical CVE-2026-15900: Use after free in GPU.</div>"
            },
            "link": [
                {"rel": "alternate", "href": "https://chromereleases.googleblog.com/example"}
            ],
        }
        rows = parse_cves_from_entry(entry)
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cve"], "CVE-2026-15900")
        self.assertEqual(rows[0]["severity"], "Critical")
        self.assertEqual(rows[0]["component_hint"], "GPU")


if __name__ == "__main__":
    unittest.main()
