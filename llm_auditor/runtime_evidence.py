"""Translate immutable runtime events into verifier evidence, retaining absence.

No runtime module is imported. Counts describe supplied observations, not the
number of unique agents. Claim owners are identities, not a count of retries.
"""

from __future__ import annotations

from typing import Any, Dict, List, Sequence

from .rules import compute_quorum


def _mapping(value: Any) -> Dict[str, Any]:
    return value if isinstance(value, dict) else {}


def _flag_count(value: Any) -> Any:
    return int(value) if type(value) is bool else None


def _aggregate_counts(rows: List[Dict[str, Any]], key: str) -> Any:
    values = [row.get(key) for row in rows]
    known = sum(value for value in values if type(value) is int)
    # A positive observation proves at least one occurrence even if incomplete;
    # zero is only reported when all relevant observations explicitly say zero.
    return known if known > 0 or (values and all(type(value) is int for value in values)) else None


def normalize_event(event: Dict[str, Any], default_mode: str) -> Dict[str, Any]:
    audit = _mapping(event.get("_audit"))
    layer = audit.get("layer", "unknown")
    state = event.get("decision", "UNKNOWN")
    authority = _mapping(event.get("authority"))
    claim = _mapping(authority.get("claim"))
    execution = _mapping(event.get("execution" if layer == "agentic" else "mitigation"))
    observer = audit.get("observed_by")
    observer = observer if isinstance(observer, str) and observer not in {"", "unknown"} else None
    coordinator = claim.get("coordinator")
    coordinator = coordinator if isinstance(coordinator, str) and coordinator not in {"", "unknown"} else None
    owner = observer or coordinator
    won = claim.get("won")
    authorized = authority.get("authorized")
    agreed = state == "AGREED" and layer == "agentic"
    record: Dict[str, Any] = {
        "source_event_id": event.get("event_id"),
        "scope": "local_agent_observation",
        "transitions": [{"layer": layer, "state": state, "observed_by": observer}],
        "event_counts_by_state": {state: 1},
        "execution_mode": event.get("mode") or default_mode or "unknown",
        "authority_authorized": authorized if type(authorized) is bool else None,
        "claim_winners": [str(owner)] if won is True and owner else [] if won is False else None,
        "local_agent_is_claim_winner": won if type(won) is bool else None,
        "other_coordinator_elected": (
            bool(coordinator) and claim.get("degraded") is not True
            if won is False else False if won is True else None
        ),
        "known_claim_coordinator": coordinator,
        "normalized_facts": {
            "agentic_agreed_events": int(agreed),
            "agentic_authorized_events": _flag_count(authorized) if agreed else 0,
            "atomic_claim_winner_events": _flag_count(won) if agreed else 0,
            "authorized_non_winner_events": (
                int(authorized and not won) if type(authorized) is bool and type(won) is bool else None
            ) if agreed else 0,
            "attempted_execution_events": _flag_count(execution.get("attempted")),
            "executed_events": _flag_count(execution.get("executed")),
            "would_execute_events": _flag_count(execution.get("would_execute")),
        },
        "evidence_sources": {},
    }
    sources = record["evidence_sources"]

    def ref(raw_path: str) -> Dict[str, Any]:
        return {
            "artifact": "timeline.ndjson", "line": audit.get("source_line"),
            "pointer": audit.get("source_pointer", "") + "/" + raw_path.replace(".", "/"),
            "event_id": event.get("event_id"),
        }

    for key in (
        "required_votes", "mitigate_votes", "relevant_domains", "participating_domains",
        "missing_domains", "confirming_domains", "min_domains", "veto_domains",
        "veto_proposals", "policy_veto_received", "normal_votes", "proposal_checks",
        "source_cid", "destination_cid",
    ):
        if key in event:
            record[key] = event[key]
        sources[key] = [ref(key)]
    models = event.get("model_ids")
    proposals = event.get("proposals")
    if isinstance(models, list) and models:
        record["model_ids"] = models
        sources["model_ids"] = [ref("model_ids")]
    if isinstance(proposals, list):
        relevant = record.get("relevant_domains")
        relevant_proposals = [
            item for item in proposals if isinstance(item, dict)
            and (not isinstance(relevant, list) or item.get("cid") in relevant)
        ]
        if "model_ids" not in record:
            record["model_ids"] = sorted({
                str(item["model_id"]) for item in relevant_proposals if item.get("model_id")
            })
            sources["model_ids"] = [ref("proposals")]
        record["veto_proposals"] = [item for item in relevant_proposals if item.get("proposal") == "VETO"]
        record["normal_votes"] = [str(item["cid"]) for item in relevant_proposals
                                  if item.get("proposal") == "NORMAL" and item.get("cid")]
        record["proposal_mitigate_votes"] = [str(item["cid"]) for item in relevant_proposals
                                            if item.get("proposal") == "MITIGATE" and item.get("cid")]
        record["proposal_model_ids"] = sorted({str(item["model_id"]) for item in relevant_proposals
                                               if item.get("model_id")})
        sources["veto_proposals"] = sources["normal_votes"] = [ref("proposals")]
        sources["proposal_mitigate_votes"] = sources["proposal_model_ids"] = [ref("proposals")]
    if "model_ids" not in sources:
        sources["model_ids"] = [ref("model_ids"), ref("proposals")]
    for key, raw_path in {
        "transitions": "decision", "event_counts_by_state": "decision",
        "execution_mode": "mode", "authority_authorized": "authority.authorized",
        "claim_winners": "authority.claim", "other_coordinator_elected": "authority.claim",
        "known_claim_coordinator": "authority.claim.coordinator",
        "local_agent_is_claim_winner": "authority.claim.won",
        "normalized_facts.atomic_claim_winner_events": "authority.claim.won",
        "normalized_facts.authorized_non_winner_events": "authority.claim.won",
        "normalized_facts.would_execute_events": "execution.would_execute",
        "normalized_facts.attempted_execution_events": "execution.attempted" if layer == "agentic" else "mitigation.attempted",
        "normalized_facts.executed_events": "execution.executed" if layer == "agentic" else "mitigation.executed",
    }.items():
        sources[key] = [ref(raw_path)]
    if default_mode:
        sources["execution_mode"].append({"artifact": "metadata.json", "pointer": "/agentic_mode"})
    if isinstance(record.get("proposal_checks"), dict):
        for key in record["proposal_checks"]:
            sources[f"proposal_checks.{key}"] = [ref(f"proposal_checks.{key}")]
    return record


def normalize_episode(
    events: Sequence[Dict[str, Any]], metadata: Dict[str, Any], summary: Dict[str, Any],
) -> Dict[str, Any]:
    mode = str(metadata.get("agentic_mode") or "")
    observations = [normalize_event(event, mode) for event in events]
    agent = [row for row in observations if row["transitions"][0]["layer"] == "agentic"]
    effective_modes = {row["execution_mode"] for row in agent}
    effective_mode = next(iter(effective_modes)) if len(effective_modes) == 1 else "mixed" if effective_modes else mode or "unknown"
    agreed = [row for row in agent if "AGREED" in row["event_counts_by_state"]]
    # MCDA execution is observational when agentic authority owns actuation.
    action_rows = (
        [row for row in agent if row in agreed or any(
            type(row["normalized_facts"].get(key)) is int for key in
            ("attempted_execution_events", "executed_events")
        )] or agent
    ) if agent else observations
    facts = {}
    for key in (
        "agentic_agreed_events", "agentic_authorized_events", "atomic_claim_winner_events",
        "authorized_non_winner_events", "attempted_execution_events", "executed_events", "would_execute_events",
    ):
        facts[key] = _aggregate_counts([row["normalized_facts"] for row in action_rows], key)
    winners = sorted({owner for row in agreed for owner in (row.get("claim_winners") or [])})
    non_winners = [row for row in agreed if row.get("authority_authorized") is True
                   and row.get("local_agent_is_claim_winner") is False]
    known_coordinators = sorted({str(row["known_claim_coordinator"]) for row in non_winners
                                 if row.get("other_coordinator_elected") is True})
    winner_rows = [row for row in agreed if row.get("local_agent_is_claim_winner") is True]
    winner_facts = [row["normalized_facts"] for row in winner_rows]
    winner_behavior = "NO_CLAIM_WINNER"
    if any(row.get("executed_events") for row in winner_facts):
        winner_behavior = "EXECUTED"
    elif any(row.get("attempted_execution_events") for row in winner_facts):
        winner_behavior = "ATTEMPTED_NOT_EXECUTED"
    elif winner_rows:
        winner_behavior = "SELECTED_WITHOUT_EXECUTION_EVIDENCE"
        if all(row.get("execution_mode") == "authority-dry-run"
               and row["normalized_facts"].get("would_execute_events") == 1
               and row["normalized_facts"].get("attempted_execution_events") == 0
               and row["normalized_facts"].get("executed_events") == 0 for row in winner_rows):
            winner_behavior = "SELECTED_WOULD_EXECUTE_DRY_RUN_SUPPRESSED"
    non_winner_behavior = "NO_AUTHORIZED_NON_WINNER"
    if non_winners:
        values = [row["normalized_facts"].get(key) for row in non_winners
                  for key in ("attempted_execution_events", "executed_events", "would_execute_events")]
        non_winner_behavior = (
            "ABSTAINED_OTHER_COORDINATOR" if all(value == 0 for value in values)
            and all(row.get("other_coordinator_elected") is True for row in non_winners)
            else "UNEXPECTED_EXECUTION_EVIDENCE" if any(value == 1 for value in values)
            else "UNKNOWN"
        )
    facts.update(claim_winner_behavior=winner_behavior,
                 authorized_non_winner_behavior=non_winner_behavior)
    quorum_rows = [compute_quorum(row) for row in agreed]
    quorum = (False if False in quorum_rows else
              True if quorum_rows and all(value is True for value in quorum_rows) else None)
    laboratory = {
        "scenario": metadata.get("scenario"), "classification": summary.get("classification"),
        "ground_truth_available": (
            metadata.get("ground_truth_available") is True
            if "ground_truth_available" in metadata else
            metadata.get("scenario") in {"benign", "ddos", "ddos_with_destination_whitelist"}
        ),
        "validation_status": (
            "INVALID" if summary.get("measurement_valid") is False or summary.get("invalid_reasons")
            else "CONTAMINATED" if summary.get("contamination_reasons") else metadata.get("validation_status")
        ),
    }
    sources: Dict[str, Any] = {}
    for row in observations:
        for key, refs in row["evidence_sources"].items():
            sources.setdefault(key, []).extend(refs)
    for key in ("scenario", "ground_truth_available", "validation_status"):
        sources[f"laboratory_context.{key}"] = [{"artifact": "metadata.json", "pointer": f"/{key}"}]
    sources["laboratory_context.ground_truth_available"].append(
        {"artifact": "metadata.json", "pointer": "/scenario"}
    )
    if metadata.get("scenario") == "ddos":
        sources["laboratory_context.ground_truth_available"].append(
            {"artifact": "attack_start_ns.txt", "pointer": ""}
        )
    summary_prefix = "/runs/0" if summary.get("_audit_summary_in_runs") is True else ""
    sources["laboratory_context.validation_status"].extend([
        {"artifact": "summary.json", "pointer": f"{summary_prefix}/{key}"}
        for key in ("measurement_valid", "invalid_reasons", "contamination_reasons")
    ])
    for key in ("attack_disrupted", "observations_available"):
        sources[f"operational_evidence.{key}"] = [{"artifact": "summary.json", "pointer": f"{summary_prefix}/attack_disrupted"}]
    sources["operational_evidence.observations_available"].extend(
        sources["laboratory_context.validation_status"]
    )
    sources["execution_mode"].append({"artifact": "metadata.json", "pointer": "/agentic_mode"})
    sources["claim_records"] = sources.get("claim_winners", [])
    return {
        "scope": "multi_domain_episode", "observations": observations,
        "claim_winners": (winners if all(row.get("claim_winners") is not None for row in agreed) else None),
        "claim_records": [
            {**_mapping(_mapping(event.get("authority")).get("claim")),
             "owner": _mapping(event.get("_audit")).get("observed_by")}
            for event in events if _mapping(_mapping(event.get("authority")).get("claim")).get("won") is True
        ],
        "execution_mode": effective_mode,
        "authority_authorized": all(row.get("authority_authorized") is True for row in agreed) if agreed and all(type(row.get("authority_authorized")) is bool for row in agreed) else None,
        "other_coordinator_elected": bool(known_coordinators) if non_winners else False,
        "known_claim_coordinator": known_coordinators[0] if len(known_coordinators) == 1 else None,
        "normalized_facts": facts, "quorum_reached": quorum,
        "laboratory_context": laboratory,
        "operational_evidence": {
            "observations_available": type(summary.get("attack_disrupted")) is bool and summary.get("measurement_valid") is not False and not summary.get("invalid_reasons") and not summary.get("contamination_reasons") and not summary.get("_audit_outcome_scope_unknown"),
            "attack_disrupted": summary.get("attack_disrupted"),
        },
        "evidence_sources": sources,
    }
