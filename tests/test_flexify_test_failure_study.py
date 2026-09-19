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
            "scanned_failure_attempts": ["1:1", "2:1"],
            "retained_composite_check_reviews": [
                {
                    "run_id": 1,
                    "classification": "unit_test_failure",
                    "failure_stage": "flutter_test",
                },
                {
                    "run_id": 3,
                    "classification": "non_test_failure",
                    "failure_stage": "static_analysis",
                },
            ],
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

        self.assertIn("| Failed workflow attempts inspected | **2/2 (100.0%)** |", rendered)
        self.assertIn("**2/2 (100.0%)**", rendered)
        self.assertIn("**1** (0 behavior regressions)", rendered)
        self.assertIn("**0.0% per unique incident**", rendered)
        self.assertIn("**2 retained composite `Check` failures**", rendered)
        self.assertIn("1 static analysis", rendered)

    def test_direct_test_step_is_failure_even_without_retained_log(self):
        run_data = {
            "id": 123,
            "created_at": "2025-01-01T00:00:00Z",
            "name": "Build",
            "display_title": "change",
            "head_sha": "abc",
            "run_attempt": 1,
        }
        jobs = [{
            "id": 456,
            "name": "quality",
            "conclusion": "failure",
            "steps": [{"name": "Run tests", "conclusion": "failure"}],
        }]

        original_log = flexify.job_log
        original_annotations = flexify.annotations
        try:
            flexify.job_log = lambda run_id, job_id: ""
            flexify.annotations = lambda job_id: []
            event = flexify.discover(run_data, jobs)
        finally:
            flexify.job_log = original_log
            flexify.annotations = original_annotations

        self.assertIsNotNone(event)
        self.assertIsNone(event["failed_assertion_count"])
        self.assertIn("failed test step metadata 456", event["source_evidence"])

    def test_failure_attempt_key_changes_for_rerun(self):
        self.assertEqual(flexify.failure_attempt_key({"id": 9}), "9:1")
        self.assertEqual(
            flexify.failure_attempt_key({"id": 9, "run_attempt": 3}),
            "9:3",
        )

        self.assertEqual(
            flexify.event_attempt_key({"run_id": 9, "run_attempt": 3}),
            "9:3",
        )

    def test_history_counts_hidden_rerun_attempts(self):
        runs = [
            {
                "id": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "name": "Build",
                "conclusion": "success",
            }
        ]
        attempts = [
            {**runs[0], "run_attempt": 1, "conclusion": "failure"},
            {**runs[0], "run_attempt": 2, "conclusion": "success"},
        ]

        history = flexify.summarize_history(runs, attempts)

        self.assertEqual(history["runs_scanned"], 1)
        self.assertEqual(history["attempts_scanned"], 2)
        self.assertEqual(history["by_attempt_conclusion"]["failure"], 1)


if __name__ == "__main__":
    unittest.main()
