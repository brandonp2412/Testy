#!/usr/bin/env python3
"""Incremental Flexify unit/widget-test failure audit.

sync walks the current GitHub Actions history, inspects only failed runs not
already present in the state file, and preserves manual classifications.
render regenerates the README summary from that state.
"""

from __future__ import annotations

import argparse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
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


def jobs_for(run_id: int) -> list[dict[str, Any]]:
    return gh_json([f"repos/{REPO}/actions/runs/{run_id}/jobs?per_page=100"])["jobs"]


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


def discover(run: dict[str, Any], jobs: list[dict[str, Any]]) -> dict[str, Any] | None:
    run_id = int(run["id"])
    failed_tests: list[dict[str, str]] = []
    failed_count: int | None = None
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
            log = job_log(run_id, int(job["id"]))
            tests, count = parse_failure(log)
            if direct or count:
                failed_tests.extend(tests)
                if count is not None:
                    failed_count = max(failed_count or 0, count)
                evidence.append("retained job log " + str(job["id"]))
                continue

        if not job.get("steps") and name == "version-and-prepare":
            text = "\n".join(item.get("message", "") for item in annotations(int(job["id"])))
            tests, count = parse_failure(text)
            if count:
                failed_tests.extend(tests)
                failed_count = max(failed_count or 0, count)
                evidence.append("retained check annotation " + str(job["id"]))

    if failed_count is None:
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
        "run_url": f"https://github.com/{REPO}/actions/runs/{run_id}",
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


def summarize_history(runs: list[dict[str, Any]]) -> dict[str, Any]:
    ordered = sorted(runs, key=lambda run: run["created_at"])
    return {
        "runs_scanned": len(runs),
        "oldest_run_at": ordered[0]["created_at"] if ordered else None,
        "newest_run_at": ordered[-1]["created_at"] if ordered else None,
        "by_conclusion": dict(sorted(Counter(
            run.get("conclusion") or "unknown" for run in runs
        ).items())),
        "by_workflow": dict(sorted(Counter(run["name"] for run in runs).items())),
        "actions_url": f"https://github.com/{REPO}/actions",
    }


def sync(rescan: bool = False) -> None:
    state = load_state()
    runs = list_runs()
    old = {
        int(event["run_id"]): event
        for event in state.get("unit_test_failure_events", [])
    }
    scanned = set() if rescan else set(state.get("scanned_run_ids", []))
    targets = [
        run for run in runs
        if run.get("conclusion") == "failure" and int(run["id"]) not in scanned
    ]

    def inspect(run: dict[str, Any]) -> tuple[int, dict[str, Any] | None]:
        return int(run["id"]), discover(run, jobs_for(int(run["id"])))

    if targets:
        with ThreadPoolExecutor(max_workers=8) as pool:
            for run_id, event in pool.map(inspect, targets):
                if event:
                    if run_id in old:
                        event["review"] = old[run_id].get("review", event["review"])
                    old[run_id] = event

    state["history"] = summarize_history(runs)
    state["scanned_run_ids"] = sorted(int(run["id"]) for run in runs)
    state["unit_test_failure_events"] = sorted(
        old.values(), key=lambda event: event["created_at"]
    )
    state["updated_at"] = datetime.now(timezone.utc).isoformat()
    save_state(state)
    print(
        f"{len(runs)} runs known; {len(targets)} new failed runs inspected; "
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
    failed_runs = history.get("by_conclusion", {}).get("failure", 0)
    oldest = (history.get("oldest_run_at") or "")[:10]
    newest = (history.get("newest_run_at") or "")[:10]

    lines = [
        START,
        "## Flexify: when unit tests fail, was behavior actually broken?",
        "",
        (
            f"The complete [Flexify Actions history]({history.get('actions_url')}) "
            f"from **{oldest} through {newest}** contains "
            f"**{history.get('runs_scanned', 0)} workflow runs**, including "
            f"**{failed_runs} failed runs**. The denominator below is narrower: "
            "a run counts only when the Flutter unit/widget suite itself failed. "
            "Deployment, build, analysis, formatting, screenshot, Patrol/device-test, "
            "and cancelled failures are excluded."
        ),
        "",
        "| Measure | Result |",
        "| --- | ---: |",
        f"| CI runs where unit/widget tests actually failed | **{len(events)}** |",
        f"| Reviewed test-failure runs | **{len(reviewed)}** |",
        f"| Stale/incorrect test assumption or harness | **{len(stale)}/{len(reviewed)} ({percent(len(stale), len(reviewed))})** |",
        f"| App behavior actually broken | **{len(broken)}/{len(reviewed)} ({percent(len(broken), len(reviewed))})** |",
        f"| Failed assertions classified | **{assertions}** ({broken_assertions} behavior-regression assertions) |",
        f"| Unique root-cause incidents | **{len(incidents)}** ({len(broken_incidents)} behavior regressions) |",
        f"| Awaiting manual review | **{len(events) - len(reviewed)}** |",
        "",
        (
            "For this sample, the observed behavior-regression rate is "
            f"**{percent(len(broken), len(reviewed))} per failed CI test run**, "
            f"**{percent(broken_assertions, assertions)} per failed assertion**, and "
            f"**{percent(len(broken_incidents), len(incidents))} per unique incident**. "
            "The sample is small and repeated CI runs from one root cause are not independent, "
            "so all three denominators are reported."
        ),
        "",
        "### Reviewed failures",
        "",
        "| Date | Actions run | Failed assertions | Classification | Evidence |",
        "| --- | --- | ---: | --- | --- |",
    ]

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
            "failed Actions runs while preserving existing manual reviews. "
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
