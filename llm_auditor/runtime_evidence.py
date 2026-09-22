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


def _comparison_outcome(comparison: Dict[str, Any]) -> str:
    matches = comparison.get("matches")
    if matches is True:
        return "ALIGNED"
    if matches is False:
        return "DIVERGENT"
    return "INSUFFICIENT_EVIDENCE"


def _exceptional_comparison_groups(
    comparisons: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    groups: List[Dict[str, Any]] = []
    signature_fields = (
        "status", "domain", "agent_decision", "agent_window_ids",
        "mcda_decision", "mcda_window_ids", "reason",
    )
    for comparison in comparisons:
        status = _comparison_outcome(comparison)
        if status == "ALIGNED":
            continue
        signature = {
            "status": status,
            "domain": comparison.get("domain"),
            "agent_decision": comparison.get("agent_decision"),
            "agent_window_ids": list(comparison.get("agent_window_ids") or []),
            "mcda_decision": comparison.get("mcda_decision"),
            "mcda_window_ids": list(comparison.get("mcda_window_ids") or []),
            "reason": comparison.get("reason"),
        }
        group = next((item for item in groups if all(
            item.get(field) == signature.get(field)
            for field in signature_fields
        )), None)
        captured_ns = comparison.get("captured_ns")
        if group is None:
            group = {
                **signature,
                "occurrences": 0,
                "first_captured_ns": captured_ns,
                "last_captured_ns": captured_ns,
                "first_mcda_score": comparison.get("mcda_score"),
                "last_mcda_score": comparison.get("mcda_score"),
                "mcda_decision_threshold": comparison.get(
                    "mcda_decision_threshold"
                ),
            }
            groups.append(group)
        group["occurrences"] += 1
        if type(captured_ns) is int:
            first_ns = group.get("first_captured_ns")
            last_ns = group.get("last_captured_ns")
            if type(first_ns) is not int or captured_ns < first_ns:
                group["first_captured_ns"] = captured_ns
                group["first_mcda_score"] = comparison.get("mcda_score")
            if type(last_ns) is not int or captured_ns >= last_ns:
                group["last_captured_ns"] = captured_ns
                group["last_mcda_score"] = comparison.get("mcda_score")
    return sorted(groups, key=lambda item: (
        item.get("first_captured_ns")
        if type(item.get("first_captured_ns")) is int else -1,
        str(item.get("domain") or ""),
    ))


def _execution_facts(execution: Dict[str, Any], layer: str) -> Dict[str, Any]:
    """Keep the reported flag distinct from a legacy MCDA simulated attempt.

    Mitigator marks attempted=true before its DRY_RUN early return. Only that
    exact MCDA signature proves suppression; the agentic execution contract
    does not have this exception. Missing flags/reasons are not filled in.
    """
    reported = _flag_count(execution.get("attempted"))
    executed = _flag_count(execution.get("executed"))
    attempted = reported
    simulated = 0 if reported is not None else None
    semantics = "REPORTED_ATTEMPT_FLAG"
    if layer == "mcda" and reported == 1 and execution.get("reason") == "DRY_RUN" and executed == 0:
        attempted, simulated = 0, 1
        semantics = "MCDA_MITIGATOR_DRY_RUN_EARLY_RETURN"
    elif layer == "mcda" and reported == 1 and executed != 1 and (
        not execution.get("reason") or execution.get("reason") == "DRY_RUN"
    ):
        attempted, simulated = None, None
        semantics = "UNKNOWN_MCDA_ATTEMPT_OR_SIMULATION"
    elif layer == "mcda" and execution.get("reason") == "DRY_RUN":
        simulated = None  # A malformed/incomplete signature is not a simulation proof.
    return {
        "recorded_attempted_execution_events": reported,
        "attempted_execution_events": attempted, "executed_events": executed,
        "simulated_execution_events": simulated, "attempt_semantics": semantics,
    }


def normalize_event(
    event: Dict[str, Any], default_mode: str, *, mcda_mode: str = "",
) -> Dict[str, Any]:
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
    execution_facts = _execution_facts(execution, layer)
    own_default_mode = mcda_mode if layer == "mcda" else default_mode
    record: Dict[str, Any] = {
        "source_event_id": event.get("event_id"),
        "scope": "local_agent_observation",
        "transitions": [{"layer": layer, "state": state, "observed_by": observer}],
        "event_counts_by_state": {state: 1},
        "execution_mode": event.get("mode") or own_default_mode or "unknown",
        "agentic_policy_mode": default_mode or "unknown",
        "raw_execution": dict(execution),
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
            **execution_facts,
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

    comparison = authority.get("mcda_comparison")
    if layer == "agentic" and isinstance(comparison, dict):
        mcda = _mapping(comparison.get("mcda"))
        mcda_config = _mapping(audit.get("mcda_runtime_config"))
        record["agent_mcda_comparison"] = {
            "available": comparison.get("available")
            if type(comparison.get("available")) is bool else None,
            "matches": comparison.get("matches")
            if type(comparison.get("matches")) is bool else None,
            "basis": comparison.get("basis"),
            "reason": comparison.get("reason"),
            "captured_ns": comparison.get("captured_ns")
            if type(comparison.get("captured_ns")) is int else None,
            "domain": observer,
            "agent_decision": state,
            "agent_window_ids": list(event.get("window_ids") or []),
            "required_votes": event.get("required_votes"),
            "mitigate_votes": list(event.get("mitigate_votes") or []),
            "mcda_decision": mcda.get("decision"),
            "mcda_score": mcda.get("score"),
            "mcda_evaluated_ns": mcda.get("evaluated_ns")
            if type(mcda.get("evaluated_ns")) is int else None,
            "mcda_published_ns": mcda.get("published_ns")
            if type(mcda.get("published_ns")) is int else None,
            "mcda_decision_threshold": mcda_config.get("decision_threshold"),
            "mcda_window_ids": list(mcda.get("window_ids") or []),
        }
        sources["agent_mcda_comparison"] = [ref("authority.mcda_comparison")]
        sources["agent_mcda_comparison.mcda_decision_threshold"] = [{
            "artifact": "timeline.ndjson",
            "line": audit.get("source_line"),
            "pointer": "/collaboration/config/decision_threshold",
        }]

    for key in (
        "required_votes", "mitigate_votes", "relevant_domains", "participating_domains",
        "missing_domains", "confirming_domains", "min_domains", "veto_domains",
        "veto_proposals", "policy_veto_received", "normal_votes", "proposal_checks",
        "source_cid", "destination_cid",
    ):
        if key in event:
            record[key] = event[key]
        sources[key] = [ref(key)]
    if layer == "mcda":
        runtime_config = _mapping(audit.get("runtime_config"))
        if type(event.get("score")) in (int, float):
            record["mcda_score"] = event["score"]
        sources["mcda_score"] = [ref("score")]
        for config_key, record_key in (
            ("alert_threshold", "mcda_alert_threshold"),
            ("decision_threshold", "mcda_decision_threshold"),
        ):
            if type(runtime_config.get(config_key)) in (int, float):
                record[record_key] = runtime_config[config_key]
            sources[record_key] = [{
                "artifact": "timeline.ndjson",
                "line": audit.get("source_line"),
                "pointer": f"/collaboration/config/{config_key}",
            }]
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
    if own_default_mode:
        sources["execution_mode"].append({
            "artifact": "metadata.json", "pointer": "/mode" if layer == "mcda" else "/agentic_mode",
        })
    sources["agentic_policy_mode"] = [{"artifact": "metadata.json", "pointer": "/agentic_mode"}]
    execution_path = "execution" if layer == "agentic" else "mitigation"
    for key in ("attempted", "executed", "reason"):
        sources[f"raw_execution.{key}"] = [ref(f"{execution_path}.{key}")]
    sources["normalized_facts.recorded_attempted_execution_events"] = [ref(f"{execution_path}.attempted")]
    interpretation_refs = [ref(f"{execution_path}.{key}") for key in ("attempted", "executed", "reason")]
    sources["normalized_facts.simulated_execution_events"] = interpretation_refs
    sources["normalized_facts.attempt_semantics"] = interpretation_refs
    if layer == "mcda":
        sources["normalized_facts.attempted_execution_events"] = interpretation_refs
    if isinstance(record.get("proposal_checks"), dict):
        for key in record["proposal_checks"]:
            sources[f"proposal_checks.{key}"] = [ref(f"proposal_checks.{key}")]
    return record


def normalize_episode(
    events: Sequence[Dict[str, Any]], metadata: Dict[str, Any], summary: Dict[str, Any],
) -> Dict[str, Any]:
    mode = str(metadata.get("agentic_mode") or "")
    observations = [normalize_event(event, mode, mcda_mode=str(metadata.get("mode") or "")) for event in events]
    agent = [row for row in observations if row["transitions"][0]["layer"] == "agentic"]
    mcda = [row for row in observations if row["transitions"][0]["layer"] == "mcda"]
    effective_modes = {row["execution_mode"] for row in (agent or mcda)}
    effective_mode = next(iter(effective_modes)) if len(effective_modes) == 1 else "mixed" if effective_modes else mode or "unknown"
    agreed = [row for row in agent if "AGREED" in row["event_counts_by_state"]]
    authority_rows = agreed or agent or observations
    # Include MCDA execution in shared data-plane outcomes. An observational
    # baseline must never hide a real request or execution. Non-action states
    # without execution records do not manufacture zero observations.
    action_rows = (
        [row for row in agent if row in agreed or any(
            type(row["normalized_facts"].get(key)) is int for key in
            ("attempted_execution_events", "executed_events")
        )] or agent
    ) if agent else []
    action_rows += [row for row in mcda if "MITIGATE" in row["event_counts_by_state"] or row["raw_execution"]]
    if not action_rows:
        action_rows = agent or observations
    facts = {}
    for key in (
        "agentic_agreed_events", "agentic_authorized_events", "atomic_claim_winner_events",
        "authorized_non_winner_events", "would_execute_events",
    ):
        facts[key] = _aggregate_counts([row["normalized_facts"] for row in authority_rows], key)
    execution_keys = (
        "recorded_attempted_execution_events", "attempted_execution_events",
        "executed_events", "simulated_execution_events",
    )
    for key in execution_keys:
        facts[key] = _aggregate_counts([row["normalized_facts"] for row in action_rows], key)
    counts_by_layer = {
        layer: {key: _aggregate_counts([row["normalized_facts"] for row in action_rows
                                      if row["transitions"][0]["layer"] == layer], key)
                for key in execution_keys}
        for layer in ("agentic", "mcda")
    }
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

    comparison_records: List[Dict[str, Any]] = []
    latest_comparison_by_domain: Dict[str, Dict[str, Any]] = {}
    for row in agent:
        comparison = row.get("agent_mcda_comparison")
        if not isinstance(comparison, dict):
            continue
        domain = comparison.get("domain")
        if not isinstance(domain, str) or not domain:
            continue
        comparison_records.append(comparison)
        previous = latest_comparison_by_domain.get(domain)
        current_ns = comparison.get("captured_ns")
        previous_ns = previous.get("captured_ns") if previous else None
        current_order = current_ns if type(current_ns) is int else -1
        previous_order = previous_ns if type(previous_ns) is int else -1
        if previous is None or current_order >= previous_order:
            latest_comparison_by_domain[domain] = comparison
    comparisons = [latest_comparison_by_domain[key]
                   for key in sorted(latest_comparison_by_domain)]
    known_matches = [item.get("matches") for item in comparisons
                     if type(item.get("matches")) is bool]
    if any(value is False for value in known_matches):
        comparative_alignment = "DIVERGENT"
    elif comparisons and len(known_matches) == len(comparisons) and all(known_matches):
        comparative_alignment = "ALIGNED"
    else:
        comparative_alignment = "INSUFFICIENT_EVIDENCE"
    comparison_counts = {
        status: sum(
            _comparison_outcome(item) == status
            for item in comparison_records
        )
        for status in (
            "ALIGNED", "DIVERGENT", "INSUFFICIENT_EVIDENCE",
        )
    }
    transient_divergence_observed = (
        comparative_alignment == "ALIGNED"
        and comparison_counts["DIVERGENT"] > 0
    )
    comparison_sources = []
    for row in agent:
        comparison_sources.extend(
            row.get("evidence_sources", {}).get("agent_mcda_comparison", [])
        )
        comparison_sources.extend(
            row.get("evidence_sources", {}).get(
                "agent_mcda_comparison.mcda_decision_threshold", []
            )
        )
    sources["agent_mcda_comparison"] = comparison_sources
    return {
        "scope": "multi_domain_episode", "observations": observations,
        "claim_winners": (winners if all(row.get("claim_winners") is not None for row in agreed) else None),
        "claim_records": [
            {**_mapping(_mapping(event.get("authority")).get("claim")),
             "owner": _mapping(event.get("_audit")).get("observed_by")}
            for event in events if _mapping(_mapping(event.get("authority")).get("claim")).get("won") is True
        ],
        "execution_mode": effective_mode,
        "agentic_policy_mode": mode or "unknown",
        "authority_authorized": all(row.get("authority_authorized") is True for row in agreed) if agreed and all(type(row.get("authority_authorized")) is bool for row in agreed) else None,
        "other_coordinator_elected": bool(known_coordinators) if non_winners else False,
        "known_claim_coordinator": known_coordinators[0] if len(known_coordinators) == 1 else None,
        "normalized_facts": facts, "quorum_reached": quorum,
        "execution_counts_by_layer": counts_by_layer,
        "laboratory_context": laboratory,
        "operational_evidence": {
            "observations_available": type(summary.get("attack_disrupted")) is bool and summary.get("measurement_valid") is not False and not summary.get("invalid_reasons") and not summary.get("contamination_reasons") and not summary.get("_audit_outcome_scope_unknown"),
            "attack_disrupted": summary.get("attack_disrupted"),
        },
        "comparative_alignment": comparative_alignment,
        "agent_mcda_comparison": {
            "status": comparative_alignment,
            "aggregation": "latest_comparison_per_domain",
            "final_alignment": comparative_alignment,
            "records_total": len(comparison_records),
            "comparison_counts": comparison_counts,
            "transient_divergence_observed": transient_divergence_observed,
            "incomplete_observation_observed": (
                comparison_counts["INSUFFICIENT_EVIDENCE"] > 0
            ),
            "domains": comparisons,
            "exceptional_groups": _exceptional_comparison_groups(
                comparison_records
            ),
        },
        "evidence_sources": sources,
    }
