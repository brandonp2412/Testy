#!/usr/bin/env python3
"""Incremental Flexify unit/widget-test failure audit.

sync walks the current GitHub Actions history, inspects only failed runs not
already present in the state file, and preserves manual classifications.
render regenerates the README summary from that state.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
from typing import Any

REPO = "brandonp2412/Flexify"
ROOT = Path(__file__).resolve().parent
STATE = ROOT / "data" / "flexify" / "unit_test_failure_audit.json"
README = ROOT / "README.md"
START = "<!-- flexify-unit-test-failure-study:start -->"
END = "<!-- flexify-unit-test-failure-study:end -->"
SUMMARY_RE = re.compile(r"(\d+) tests passed, ([1-9]\d*) failed", re.I)
FAILED_RE = re.compile(r"❌\s+.*?/(test/[^:]+):\s+(.+?)\s+\(failed\)")
DIRECT_STEPS = {"run tests", "test", "run unit tests", "unit tests"}
COMPOSITE_STEPS = {"check", "run tests and analysis"}


def command(args: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(args, cwd=ROOT, text=True, capture_output=True)
    if check and result.returncode:
        raise RuntimeError(
            "command failed: " + " ".join(args) + "\n" + result.stderr
        )
    return result


def gh_json(args: list[str]) -> Any:
    return json.loads(command(["gh", "api", *args]).stdout)


def load_state() -> dict[str, Any]:
    if not STATE.exists():
        return {
            "schema_version": 1,
            "repository": REPO,
            "history": {},
            "scanned_run_ids": [],
            "scanned_failure_attempts": [],
            "unit_test_failure_events": [],
            "manual_exclusions": [],
        }
    return json.loads(STATE.read_text())


def save_state(state: dict[str, Any]) -> None:
    STATE.parent.mkdir(parents=True, exist_ok=True)
    STATE.write_text(json.dumps(state, indent=2, sort_keys=True) + "\n")


def list_runs() -> list[dict[str, Any]]:
    pages = gh_json(
        ["--paginate", "--slurp", f"repos/{REPO}/actions/runs?per_page=100"]
    )
    return [run for page in pages for run in page["workflow_runs"]]


def list_run_attempts(runs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Expand workflow runs so earlier re-run attempts are audited too."""
    attempts: list[dict[str, Any]] = []
    for run in runs:
        latest_attempt = int(run.get("run_attempt") or 1)
        for attempt in range(1, latest_attempt):
            attempts.append(
                gh_json([f"repos/{REPO}/actions/runs/{run['id']}/attempts/{attempt}"])
            )
        attempts.append(run)
    return attempts


def jobs_for(run_id: int, attempt: int | None = None) -> list[dict[str, Any]]:
    if attempt is None:
        endpoint = f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100"
    else:
        endpoint = (
            f"repos/{REPO}/actions/runs/{run_id}/attempts/{attempt}/jobs?per_page=100"
        )
    return gh_json([endpoint])["jobs"]


def job_log(run_id: int, job_id: int) -> str:
    result = command(
        ["gh", "run", "view", str(run_id), "-R", REPO,
         "--job", str(job_id), "--log"],
        check=False,
    )
    return result.stdout if result.returncode == 0 else ""


def annotations(job_id: int) -> list[dict[str, Any]]:
    result = command(
        ["gh", "api", f"repos/{REPO}/check-runs/{job_id}/annotations?per_page=100"],
        check=False,
    )
    return json.loads(result.stdout) if result.returncode == 0 else []


def parse_failure(text: str) -> tuple[list[dict[str, str]], int | None]:
    found: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        match = FAILED_RE.search(line)
        if match:
            key = (match.group(1), match.group(2))
            if key not in seen:
                seen.add(key)
                found.append({"file": key[0], "name": key[1]})
    summaries = [(int(m.group(1)), int(m.group(2)))
                 for m in SUMMARY_RE.finditer(text)]
    count = summaries[-1][1] if summaries else None
    if count is None and found:
        count = len(found)
    return found, count


def failure_attempt_key(run: dict[str, Any]) -> str:
    """Stable checkpoint key that changes when GitHub re-runs the same run."""
    return f"{int(run['id'])}:{int(run.get('run_attempt') or 1)}"


def event_attempt_key(event: dict[str, Any]) -> str:
    return f"{int(event['run_id'])}:{int(event.get('run_attempt') or 1)}"


def discover(run: dict[str, Any], jobs: list[dict[str, Any]]) -> dict[str, Any] | None:
    run_id = int(run["id"])
    failed_tests: list[dict[str, str]] = []
    failed_count: int | None = None
    definite_test_failure = False
    evidence: list[str] = []

    for job in jobs:
        if job.get("conclusion") != "failure":
            continue
        name = job.get("name", "")
        steps = [
            step.get("name", "")
            for step in job.get("steps", [])
            if step.get("conclusion") == "failure"
        ]
        lower = {step.strip().lower() for step in steps}
        patrol = "patrol" in name.lower() or any("patrol" in step.lower() for step in steps)
        direct = bool(lower & DIRECT_STEPS) and not patrol
        composite = bool(lower & COMPOSITE_STEPS) and not patrol

        if direct or composite:
            definite_test_failure = definite_test_failure or direct
            log = job_log(run_id, int(job["id"]))
            tests, count = parse_failure(log)
            sources: list[str] = []
            if log:
                sources.append("retained job log " + str(job["id"]))

            annotation_text = "\n".join(
                item.get("message", "") for item in annotations(int(job["id"]))
            )
            annotation_tests, annotation_count = parse_failure(annotation_text)
            if annotation_count is not None:
                tests.extend(annotation_tests)
                count = max(count or 0, annotation_count)
                sources.append("retained check annotation " + str(job["id"]))

            if count is not None:
                definite_test_failure = True
                failed_tests.extend(tests)
                failed_count = max(failed_count or 0, count)
                evidence.extend(sources)
                continue
            if direct:
                evidence.extend(sources or ["failed test step metadata " + str(job["id"])])
                continue

        if not job.get("steps") and name == "version-and-prepare":
            text = "\n".join(
                item.get("message", "") for item in annotations(int(job["id"]))
            )
            tests, count = parse_failure(text)
            if count:
                definite_test_failure = True
                failed_tests.extend(tests)
                failed_count = max(failed_count or 0, count)
                evidence.append("retained check annotation " + str(job["id"]))

    if not definite_test_failure:
        return None

    unique: list[dict[str, str]] = []
    keys: set[tuple[str, str]] = set()
    for test in failed_tests:
        key = (test["file"], test["name"])
        if key not in keys:
            keys.add(key)
            unique.append(test)

    return {
        "run_id": run_id,
        "run_attempt": int(run.get("run_attempt") or 1),
        "run_url": (
            f"https://github.com/{REPO}/actions/runs/{run_id}/attempts/"
            f"{int(run.get('run_attempt') or 1)}"
        ),
        "created_at": run["created_at"],
        "workflow": run["name"],
        "title": run["display_title"],
        "head_sha": run["head_sha"],
        "head_commit_url": f"https://github.com/{REPO}/commit/{run['head_sha']}",
        "failed_assertion_count": failed_count,
        "failed_tests": unique,
        "source_evidence": evidence,
        "review": {
            "classification": "unreviewed",
            "behavior_broken": None,
            "incident_key": None,
            "reason": "",
            "fix_commit": None,
            "fix_url": None,
        },
    }


def summarize_history(
    runs: list[dict[str, Any]],
    attempts: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    attempts = attempts or runs
    ordered = sorted(runs, key=lambda run: run["created_at"])
    return {
        "runs_scanned": len(runs),
        "attempts_scanned": len(attempts),
        "oldest_run_at": ordered[0]["created_at"] if ordered else None,
        "newest_run_at": ordered[-1]["created_at"] if ordered else None,
        "by_conclusion": dict(sorted(Counter(
            run.get("conclusion") or "unknown" for run in runs
        ).items())),
        "by_attempt_conclusion": dict(sorted(Counter(
            run.get("conclusion") or "unknown" for run in attempts
        ).items())),
        "by_workflow": dict(sorted(Counter(run["name"] for run in runs).items())),
        "actions_url": f"https://github.com/{REPO}/actions",
    }


def sync(rescan: bool = False) -> None:
    state = load_state()
    runs = list_runs()
    attempts = list_run_attempts(runs)
    old = {
        event_attempt_key(event): event
        for event in state.get("unit_test_failure_events", [])
    }

    old_scanned_ids = set(state.get("scanned_run_ids", []))
    scanned_attempts = set(state.get("scanned_failure_attempts", []))
    if not scanned_attempts and old_scanned_ids and not rescan:
        # Legacy state only knew latest run IDs. Do not assume earlier re-run
        # attempts were inspected; leave them eligible for discovery.
        scanned_attempts = {
            failure_attempt_key(run)
            for run in runs
            if run.get("conclusion") == "failure"
            and int(run["id"]) in old_scanned_ids
        }
    if rescan:
        scanned_attempts = set()

    targets = [
        run for run in attempts
        if run.get("conclusion") == "failure"
        and failure_attempt_key(run) not in scanned_attempts
    ]

    state["schema_version"] = max(int(state.get("schema_version", 1)), 3)
    methodology = state.setdefault("methodology", {})
    methodology.update({
        "scope": (
            "Complete GitHub Actions history currently exposed by the repository, "
            "including earlier attempts of re-run workflow runs."
        ),
        "unit_test_definition": (
            "Flutter unit/widget suite (flutter test). Patrol/device integration tests, "
            "analysis, formatting, build, deployment, screenshot and cancellation failures "
            "are excluded."
        ),
        "classification_rule": (
            "App behavior broken only when the failing assertion exposed a behavioral "
            "regression that required application-code correction. A failure fixed solely "
            "by updating stale test expectations or harness setup is test_assumption_or_harness."
        ),
        "detection_rule": (
            "Every failed workflow attempt is inspected. Explicit failed unit-test step metadata "
            "counts even if detailed logs have expired; composite quality steps require retained "
            "flutter-test evidence from job logs or check annotations."
        ),
        "checkpoint_rule": (
            "Each inspected failed run attempt is checkpointed immediately. GitHub re-runs are "
            "tracked by run ID plus run_attempt so a later attempt is inspected again."
        ),
    })
    state["history"] = summarize_history(runs, attempts)
    state["scanned_run_ids"] = sorted(
        int(run["id"]) for run in runs if run.get("status") == "completed"
    )
    state["scanned_failure_attempts"] = sorted(scanned_attempts)

    def checkpoint() -> None:
        state["unit_test_failure_events"] = sorted(
            old.values(), key=lambda event: event["created_at"]
        )
        state["scanned_failure_attempts"] = sorted(scanned_attempts)
        state["updated_at"] = datetime.now(timezone.utc).isoformat()
        save_state(state)

    def inspect(run: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any] | None]:
        return run, discover(
            run,
            jobs_for(int(run["id"]), int(run.get("run_attempt") or 1)),
        )

    if targets:
        with ThreadPoolExecutor(max_workers=8) as pool:
            futures = {pool.submit(inspect, run): run for run in targets}
            for future in as_completed(futures):
                run, event = future.result()
                key = failure_attempt_key(run)
                if event:
                    if key in old:
                        event["review"] = old[key].get("review", event["review"])
                    old[key] = event
                scanned_attempts.add(failure_attempt_key(run))
                checkpoint()

    checkpoint()
    print(
        f"{len(runs)} runs / {len(attempts)} attempts known; "
        f"{len(targets)} failed run attempts inspected; "
        f"{len(old)} unit/widget-test failure runs recorded"
    )


def percent(n: int, d: int) -> str:
    return "n/a" if not d else f"{100 * n / d:.1f}%"


def render_section(state: dict[str, Any]) -> str:
    events = state.get("unit_test_failure_events", [])
    reviewed = [event for event in events
                if event.get("review", {}).get("classification") != "unreviewed"]
    broken = [event for event in reviewed
              if event["review"].get("behavior_broken") is True]
    stale = [event for event in reviewed
             if event["review"].get("behavior_broken") is False]
    assertions = sum(int(event.get("failed_assertion_count") or 0) for event in reviewed)
    broken_assertions = sum(
        int(event.get("failed_assertion_count") or 0) for event in broken
    )
    incidents = {
        event["review"].get("incident_key") for event in reviewed
        if event["review"].get("incident_key")
    }
    broken_incidents = {
        event["review"].get("incident_key") for event in broken
        if event["review"].get("incident_key")
    }
    history = state.get("history", {})
    failed_attempts = history.get(
        "by_attempt_conclusion", history.get("by_conclusion", {})
    ).get("failure", 0)
    attempts_scanned = history.get("attempts_scanned", history.get("runs_scanned", 0))
    failed_attempts_inspected = len(state.get("scanned_failure_attempts", []))
    manual_exclusions = state.get("manual_exclusions", [])
    composite_reviews = state.get("retained_composite_check_reviews", [])
    composite_test_failures = [
        item for item in composite_reviews
        if item.get("classification") == "unit_test_failure"
    ]
    composite_non_test = [
        item for item in composite_reviews
        if item.get("classification") == "non_test_failure"
    ]
    composite_non_test_causes = Counter(
        item.get("failure_stage", "other") for item in composite_non_test
    )
    oldest = (history.get("oldest_run_at") or "")[:10]
    newest = (history.get("newest_run_at") or "")[:10]

    lines = [
        START,
        "## Flexify: when unit tests fail, was behavior actually broken?",
        "",
        (
            f"The complete [Flexify Actions history]({history.get('actions_url')}) "
            f"from **{oldest} through {newest}** contains "
            f"**{history.get('runs_scanned', 0)} workflow runs / "
            f"{attempts_scanned} execution attempts**, including "
            f"**{failed_attempts} failed attempts**. The denominator below is narrower: "
            "an attempt counts only when the Flutter unit/widget suite itself failed. "
            "Deployment, build, analysis, formatting, screenshot, Patrol/device-test, "
            "and cancelled failures are excluded."
        ),
        "",
        (
            "Method: every failed workflow attempt is inspected at the job/step level, "
            "including earlier attempts hidden behind a later GitHub re-run. "
            "An explicitly failed unit-test step counts even when GitHub has expired its "
            "detailed log; composite quality steps count only when retained job logs or "
            "check annotations contain Flutter-test failure evidence. Each confirmed test "
            "failure is then classified from the failure evidence and follow-up fix: "
            "application-code correction means behavior regression, while a test-only "
            "expectation/harness correction means stale or incorrect test assumptions."
        ),
        "",
        "| Measure | Result |",
        "| --- | ---: |",
        (
            "| Failed workflow attempts inspected | "
            f"**{failed_attempts_inspected}/{failed_attempts} "
            f"({percent(failed_attempts_inspected, failed_attempts)})** |"
        ),
        f"| CI attempts where unit/widget tests actually failed | **{len(events)}** |",
        f"| Reviewed test-failure attempts | **{len(reviewed)}** |",
        f"| Stale/incorrect test assumption or harness | **{len(stale)}/{len(reviewed)} ({percent(len(stale), len(reviewed))})** |",
        f"| App behavior actually broken | **{len(broken)}/{len(reviewed)} ({percent(len(broken), len(reviewed))})** |",
        f"| Failed assertions classified | **{assertions}** ({broken_assertions} behavior-regression assertions) |",
        f"| Unique root-cause incidents | **{len(incidents)}** ({len(broken_incidents)} behavior regressions) |",
        f"| Awaiting manual review | **{len(events) - len(reviewed)}** |",
        f"| Ambiguous old composite failures excluded | **{len(manual_exclusions)}** |",
        "",
        (
            "For this sample, the observed behavior-regression rate is "
            f"**{percent(len(broken), len(reviewed))} per failed CI test attempt**, "
            f"**{percent(broken_assertions, assertions)} per failed assertion**, and "
            f"**{percent(len(broken_incidents), len(incidents))} per unique incident**. "
            "The sample is small and repeated CI attempts from one root cause are not independent, "
            "so all three denominators are reported."
        ),
        "",
        (
            f"GitHub no longer retains enough detail to prove whether "
            f"**{len(manual_exclusions)} older composite-job failures** reached the unit-test "
            "stage. They remain explicitly recorded in the audit state and are excluded from "
            "both the test-failure numerator and classification denominator rather than guessed."
            if manual_exclusions
            else "No ambiguous historical composite failures remain."
        ),
        "",
    ]

    if composite_reviews:
        causes = ", ".join(
            f"{count} {stage.replace('_', ' ')}"
            for stage, count in sorted(composite_non_test_causes.items())
        )
        lines.extend([
            (
                "Completeness cross-check: **"
                f"{len(composite_reviews)} retained composite `Check` failures** were manually "
                f"reviewed. **{len(composite_test_failures)}** contained a Flutter unit/widget-test "
                "failure and is already counted above; the other **"
                f"{len(composite_non_test)}** stopped before that suite "
                f"({causes}), so they are not silently dropped test failures."
            ),
            "",
        ])

    lines.extend([
        "### Reviewed failures",
        "",
        "| Date | Actions run | Failed assertions | Classification | Evidence |",
        "| --- | --- | ---: | --- | --- |",
    ])

    for event in reviewed:
        review = event["review"]
        classification = (
            "App behavior broken"
            if review.get("behavior_broken") is True
            else "Test assumption/harness"
        )
        fix = review.get("fix_commit")
        evidence = review.get("reason", "")
        if fix:
            evidence += (
                f" ([fix {fix[:10]}]"
                f"({review.get('fix_url')}))"
            )
        lines.append(
            f"| {event['created_at'][:10]} | "
            f"[{event['run_id']}]({event['run_url']}) | "
            f"{event.get('failed_assertion_count', 0)} | "
            f"{classification} | {evidence} |"
        )

    lines.extend([
        "",
        (
            "The resumable audit state is in "
            "[data/flexify/unit_test_failure_audit.json]"
            "(data/flexify/unit_test_failure_audit.json). "
            "Run python flexify_test_failure_study.py sync to inspect only newly seen "
            "failed Actions attempts while preserving existing manual reviews. "
            "Use the rescan flag after changing the detector, then render the README again."
        ),
        END,
    ])
    return "\n".join(lines)


def render() -> None:
    state = load_state()
    section = render_section(state)
    readme = README.read_text()
    if START in readme and END in readme:
        begin = readme.index(START)
        finish = readme.index(END) + len(END)
        readme = readme[:begin] + section + readme[finish:]
    else:
        anchor = "\n## Chromium\n"
        if anchor in readme:
            readme = readme.replace(anchor, "\n" + section + "\n" + anchor, 1)
        else:
            readme = readme.rstrip() + "\n\n" + section + "\n"
    README.write_text(readme)
    print("README Flexify audit section rendered")


def main() -> None:
    parser = argparse.ArgumentParser()
    commands = parser.add_subparsers(dest="command", required=True)
    sync_parser = commands.add_parser("sync")
    sync_parser.add_argument("--rescan", action="store_true")
    commands.add_parser("render")
    args = parser.parse_args()
    if args.command == "sync":
        sync(rescan=args.rescan)
    else:
        render()


if __name__ == "__main__":
    main()
