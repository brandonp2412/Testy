import unittest

from study import parse_cves_from_entry, parse_coverage_page, parse_stat


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
