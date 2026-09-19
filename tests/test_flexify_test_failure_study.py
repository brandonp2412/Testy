import unittest

import flexify_test_failure_study as flexify


class FlexifyFailureStudyTests(unittest.TestCase):
    def test_parse_failure_recovers_summary_and_failed_tests(self):
        log = """
        ##[group]❌ /home/runner/work/Flexify/Flexify/test/example_test.dart: widget behaves (failed)
        Expected: exactly one matching candidate
        Actual: none
        ##[error]1576 tests passed, 1 failed.
        """
        tests, count = flexify.parse_failure(log)

        self.assertEqual(count, 1)
        self.assertEqual(
            tests,
            [{"file": "test/example_test.dart", "name": "widget behaves"}],
        )

    def test_parse_failure_ignores_success_only_output(self):
        tests, count = flexify.parse_failure("1577 tests passed, 0 failed.")
        self.assertEqual(tests, [])
        self.assertIsNone(count)

    def test_render_counts_duplicate_runs_as_one_incident(self):
        state = {
            "history": {
                "runs_scanned": 10,
                "oldest_run_at": "2026-01-01T00:00:00Z",
                "newest_run_at": "2026-01-02T00:00:00Z",
                "by_conclusion": {"failure": 2},
                "actions_url": "https://github.com/example/actions",
            },
            "unit_test_failure_events": [
                {
                    "run_id": 1,
                    "run_url": "https://github.com/example/actions/runs/1",
                    "created_at": "2026-01-01T00:00:00Z",
                    "failed_assertion_count": 2,
                    "review": {
                        "classification": "test_assumption_or_harness",
                        "behavior_broken": False,
                        "incident_key": "same-cause",
                        "reason": "stale expectation",
                        "fix_commit": None,
                        "fix_url": None,
                    },
                },
                {
                    "run_id": 2,
                    "run_url": "https://github.com/example/actions/runs/2",
                    "created_at": "2026-01-02T00:00:00Z",
                    "failed_assertion_count": 2,
                    "review": {
                        "classification": "test_assumption_or_harness",
                        "behavior_broken": False,
                        "incident_key": "same-cause",
                        "reason": "same stale expectation",
                        "fix_commit": None,
                        "fix_url": None,
                    },
                },
            ],
        }

        rendered = flexify.render_section(state)

        self.assertIn("**2/2 (100.0%)**", rendered)
        self.assertIn("**1** (0 behavior regressions)", rendered)
        self.assertIn("**0.0% per unique incident**", rendered)


if __name__ == "__main__":
    unittest.main()
