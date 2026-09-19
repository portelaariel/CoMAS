#!/usr/bin/env python3
"""Validate an authority-dry-run benchmark without trusting its headline."""

import argparse
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List


def read_json(path: Path, default: Any = None) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, TypeError, ValueError):
        return default


def read_ns(path: Path) -> int:
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, TypeError, ValueError):
        return 0


def timeline(path: Path) -> List[Dict[str, Any]]:
    rows = []
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return rows
    for line in lines:
        try:
            row = json.loads(line)
        except (TypeError, ValueError):
            continue
        if isinstance(row, dict):
            rows.append(row)
    return rows


def evaluate(run_dir: Path) -> Dict[str, Any]:
    metadata = read_json(run_dir / "metadata.json", {}) or {}
    workload = read_json(run_dir / "workload_status.json", {}) or {}
    benchmark = read_json(run_dir / "summary.json", {}) or {}
    benchmark_run = ((benchmark.get("runs") or [{}])[0]
                     if isinstance(benchmark, dict) else {})
    flow = str(metadata.get("flow") or "")
    scenario = str(metadata.get("scenario") or "")
    attack_start_ns = read_ns(run_dir / "attack_start_ns.txt")
    try:
        run_started_ns = int(metadata.get("started_ns", 0) or 0)
    except (TypeError, ValueError):
        run_started_ns = 0
    evaluation_start_ns = (
        attack_start_ns if scenario == "ddos" else run_started_ns
    )
    try:
        expected_domains = max(1, int(metadata.get("controller_sets", 2) or 2))
    except (TypeError, ValueError):
        expected_domains = 0
    rows = timeline(run_dir / "timeline.ndjson")
    active_domains = set()
    events: Dict[str, Dict[str, Any]] = {}
    mcda_events: Dict[str, Dict[str, Dict[str, Any]]] = {}
    endpoint_errors = 0
    for row in rows:
        if row.get("error"):
            endpoint_errors += 1
            continue
        cid = str((row.get("status") or {}).get("cid") or row.get("port") or "")
        collaboration = row.get("collaboration") or {}
        for mcda in (
            list(collaboration.get("decision_events") or [])
            + list(collaboration.get("decisions") or [])
        ):
            if not isinstance(mcda, dict) or mcda.get("flow") != flow:
                continue
            mcda_cid = str(collaboration.get("cid") or cid)
            mcda_key = (
                f"{mcda.get('decision')}:{mcda.get('evaluated_ns')}:"
                f"{','.join(str(value) for value in mcda.get('window_ids', []))}"
            )
            mcda_events.setdefault(mcda_cid, {})[mcda_key] = mcda
        agent = row.get("agentic") or {}
        if (agent.get("requested") is True
                and agent.get("active") is True
                and agent.get("mode") == "authority-dry-run"
                and agent.get("authoritative") is True
                and agent.get("actuation_enabled") is False):
            active_cid = str(agent.get("cid") or cid)
            if active_cid:
                active_domains.add(active_cid)
        for event in (
            list(agent.get("decision_events", []))
            + list(agent.get("decisions", []))
        ):
            if not isinstance(event, dict) or event.get("flow") != flow:
                continue
            entered_ns = int(event.get("state_entered_ns", 0) or 0)
            if entered_ns < evaluation_start_ns:
                continue
            copy = dict(event)
            copy["observed_by"] = str(agent.get("cid") or cid)
            event_id = str(copy.get("event_id") or f"{cid}:{entered_ns}")
            events[event_id] = copy

    agreed = [event for event in events.values() if event.get("decision") == "AGREED"]
    authorized = [
        event for event in agreed
        if (event.get("authority") or {}).get("authorized") is True
    ]
    winners = [
        event for event in authorized
        if (((event.get("authority") or {}).get("claim") or {}).get("won") is True)
    ]
    winner_domains = {event.get("observed_by") for event in winners}
    authorized_domains = {
        event.get("observed_by") for event in authorized
    }
    claim_records = [
        (event.get("authority") or {}).get("claim")
        for event in authorized
    ]
    claim_coordinators = {
        claim.get("coordinator")
        for claim in claim_records
        if isinstance(claim, dict) and claim.get("coordinator")
    }
    would_execute = {
        event.get("observed_by") for event in authorized
        if (event.get("execution") or {}).get("would_execute") is True
    }
    attempted_or_executed = [
        event for event in events.values()
        if ((event.get("execution") or {}).get("attempted")
            or (event.get("execution") or {}).get("executed"))
    ]
    degraded_claims = [
        event for event in authorized
        if (((event.get("authority") or {}).get("claim") or {}).get("degraded"))
    ]
    fresh_authorized = [
        event for event in authorized
        if event.get("proposals")
        and all(
            isinstance(proposal, dict)
            and int(proposal.get("observation_ns", 0) or 0) >= attack_start_ns
            and int(proposal.get("created_ns", 0) or 0) >= attack_start_ns
            for proposal in event.get("proposals", [])
        )
    ]
    mcda_records = []
    for event in authorized:
        domain = str(event.get("observed_by") or "")
        authority = event.get("authority") or {}
        frozen_comparison = authority.get("mcda_comparison")
        comparison = (
            frozen_comparison if isinstance(frozen_comparison, dict)
            else event.get("legacy_comparison") or {}
        )
        if comparison.get("available") is True:
            comparison_ns = int(
                comparison.get("captured_ns")
                or authority.get("evaluated_ns")
                or event.get("state_entered_ns")
                or event.get("evaluated_ns")
                or 0
            )
            mcda_records.append({
                "domain": domain,
                "matches": comparison.get("matches"),
                "comparison_ns": comparison_ns,
            })
            continue
        agent_windows = {
            int(value) for value in event.get("window_ids", [])
        }
        matching = [
            candidate
            for candidate in mcda_events.get(domain, {}).values()
            if agent_windows & {
                int(value) for value in candidate.get("window_ids", [])
            }
        ]
        comparison_cutoff_ns = int(
            authority.get("evaluated_ns")
            or event.get("state_entered_ns")
            or event.get("evaluated_ns")
            or 0
        )
        if comparison_cutoff_ns:
            matching_before_authority = [
                candidate for candidate in matching
                if int(candidate.get("evaluated_ns", 0) or 0)
                <= comparison_cutoff_ns
            ]
            if matching_before_authority:
                matching = matching_before_authority
        if matching:
            mcda = max(
                matching,
                key=lambda item: int(item.get("evaluated_ns", 0) or 0),
            )
            mcda_records.append({
                "domain": domain,
                "matches": (
                    (event.get("decision") == "AGREED")
                    == (mcda.get("decision") == "MITIGATE")
                ),
                "comparison_ns": comparison_cutoff_ns,
            })
    # The timeline retains every authorized AGREED transition. An early
    # observational mismatch must not permanently poison a domain after a
    # newer authority evaluation for the same episode records agreement.
    # Select the chronologically latest comparable observation per domain,
    # matching the canonicalization used by the live evaluator. Coverage of
    # every historical authorization is still checked separately below.
    mcda_by_domain = {}
    for record in mcda_records:
        previous = mcda_by_domain.get(record["domain"])
        if (previous is None
                or record["comparison_ns"] >= previous["comparison_ns"]):
            mcda_by_domain[record["domain"]] = record
    blocker_requests = 0
    for path in run_dir.glob("flow-blocker-*.log"):
        blocker_requests += sum(
            "Service request to block traffic" in line
            for line in path.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
        )
    src, dst = flow.split("->", 1) if "->" in flow else ("", "")
    drop_rules = []
    for path in run_dir.glob("ovs-flows-s*.txt"):
        content = path.read_text(encoding="utf-8", errors="replace")
        if (f"nw_src={src}" in content and f"nw_dst={dst}" in content
                and "actions=drop" in content):
            drop_rules.append(str(path))

    common_checks = {
        "metadata_is_authority_dry_run": (
            metadata.get("mode") == "collaborative-dry-run"
            and metadata.get("agentic_enabled") is True
            and metadata.get("agentic_mode") == "authority-dry-run"
            and scenario in {"benign", "ddos"}
        ),
        "workload_valid": workload.get("valid") is True,
        "no_endpoint_errors": endpoint_errors == 0,
        "all_agents_active": len(active_domains) == expected_domains,
        "agent_never_actuated": not attempted_or_executed,
        "no_flowblocker_request": blocker_requests == 0,
        "no_drop_rule": not drop_rules,
    }
    if scenario == "ddos":
        scenario_checks = {
            "attack_timestamp_valid": attack_start_ns > 0,
            "benchmark_tp": benchmark_run.get("classification") == "TP",
            "all_agents_authorized": len(authorized_domains) == expected_domains,
            "fresh_evidence_only": (
                len(fresh_authorized) == len(authorized)
                and len({
                    event.get("observed_by") for event in fresh_authorized
                }) == expected_domains
            ),
            "all_authorizations_have_claim": (
                len(claim_records) == len(authorized)
                and all(isinstance(claim, dict) for claim in claim_records)
            ),
            "single_claim_winner": (
                len(winners) == 1 and len(winner_domains) == 1
            ),
            "claim_owner_consistent": claim_coordinators == winner_domains,
            "winner_matches_would_execute": would_execute == winner_domains,
            "claim_not_degraded": not degraded_claims,
            "mcda_comparison_available": (
                len(mcda_by_domain) == expected_domains
                and len(mcda_records) == len(authorized)
            ),
            "agent_matches_mcda": (
                len(mcda_by_domain) == expected_domains
                and all(
                    record["matches"] is True
                    for record in mcda_by_domain.values()
                )
            ),
        }
    else:
        scenario_checks = {
            "run_timestamp_valid": run_started_ns > 0,
            "benchmark_tn": benchmark_run.get("classification") == "TN",
            "no_agent_agreement": not agreed,
            "no_agent_authorization": not authorized,
            "no_agent_claim": not claim_records,
            "no_would_execute": not would_execute,
        }
    checks = {**common_checks, **scenario_checks}
    return {
        "schema_version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "mode": "authority-dry-run",
        "run": run_dir.name,
        "scenario": scenario,
        "flow": flow,
        "source_host": metadata.get("source_host"),
        "destination_host": metadata.get("destination_host"),
        "baseline_rate": metadata.get("baseline_rate"),
        "attack_rate": metadata.get("attack_rate"),
        "git_commit": metadata.get("git_commit"),
        "model_sha256": metadata.get("model_sha256"),
        "classification": benchmark_run.get("classification"),
        "detection_latency_ms": benchmark_run.get("detection_latency_ms"),
        "agentic_consensus_latency_ms": benchmark_run.get(
            "agentic_consensus_latency_ms"
        ),
        "active_domains": sorted(active_domains),
        "agreed_events": len(agreed),
        "authorized_domains": sorted(str(value) for value in authorized_domains),
        "claim_winner_domains": sorted(str(value) for value in winner_domains),
        "would_execute_domains": sorted(str(value) for value in would_execute),
        "flowblocker_requests": blocker_requests,
        "drop_rule_files": drop_rules,
        "checks": checks,
        "aggregate": {
            "passed": sum(checks.values()),
            "total": len(checks),
            "failed": sum(not value for value in checks.values()),
            "safe": all(checks.values()),
        },
    }


def print_report(report: Dict[str, Any]) -> None:
    print(json.dumps({
        "mode": report["mode"],
        "run": report["run"],
        "scenario": report["scenario"],
        "flow": report["flow"],
        "authorized_domains": report["authorized_domains"],
        "claim_winner_domains": report["claim_winner_domains"],
        "would_execute_domains": report["would_execute_domains"],
        "flowblocker_requests": report["flowblocker_requests"],
        "drop_rules": len(report["drop_rule_files"]),
        "aggregate": report["aggregate"],
    }, indent=2, sort_keys=True, ensure_ascii=False))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("run_dir", type=Path)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.run_dir)
    output = args.output or (args.run_dir / "authority-summary.json")
    output.write_text(
        json.dumps(report, indent=2, sort_keys=True, ensure_ascii=False) + "\n",
        encoding="utf-8",
    )
    print_report(report)
    return 0 if report["aggregate"]["safe"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
