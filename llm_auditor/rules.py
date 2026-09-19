"""Pure, evidence-based verifier. No LLM, network or CoMAS runtime imports.

An absent/null fact is unknown, not a negative observation. Protocol checks
are evaluated per observation; votes from different windows are never pooled.
The other four dimensions describe the reported decision, laboratory context
and recorded execution independently of protocol validity.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Set


RULES_VERSION = "2.2"
VERDICT_FIELDS = [
    "protocol_consistency", "scenario_correctness", "decision_stage",
    "execution_status", "operational_effectiveness",
]
INTERMEDIATE_STATES = {
    "NO_EVIDENCE", "NO_PROPOSALS", "SUSPECT", "CORROBORATED", "WAITING",
    "WAITING_PROPOSALS", "WAITING_QUORUM", "WAITING_TOPOLOGY", "WAITING_WINDOW",
}
FINAL_STATES = {
    "AGREED", "DISAGREED", "MITIGATE", "MODEL_MISMATCH", "NORMAL",
    "TOPOLOGY_MISMATCH", "VETOED",
}


def _get(record: Dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return value


def _count(value: Any) -> Optional[int]:
    # bool is a subclass of int; accepting it would turn True into a count.
    return value if type(value) is int and value >= 0 else None


def _number(value: Any) -> Optional[float]:
    if type(value) not in (int, float):
        return None
    parsed = float(value)
    return parsed if math.isfinite(parsed) else None


def _names(value: Any) -> Optional[Set[str]]:
    if not isinstance(value, list) or any(
        not isinstance(item, str) or not item for item in value
    ):
        return None
    return set(value)


def compute_quorum(record: Dict[str, Any]) -> Optional[bool]:
    """Recompute quorum from distinct votes, not a supplied verdict flag."""
    required = _count(record.get("required_votes"))
    votes = _names(record.get("mitigate_votes"))
    relevant = _names(record.get("relevant_domains"))
    if required is None or votes is None or relevant is None:
        return None
    return 0 < required <= len(relevant) and votes <= relevant and len(votes) >= required


def _states(record: Dict[str, Any], layer: Optional[str] = None) -> Set[str]:
    transitions = record.get("transitions") or []
    states = {
        str(item.get("state")) for item in transitions
        if isinstance(item, dict) and item.get("state")
        and (layer is None or item.get("layer") == layer)
    }
    if layer is None:
        states.update(
            state for state, count in (record.get("event_counts_by_state") or {}).items()
            if _count(count) is not None and count > 0
        )
    return states


def _status(condition: Optional[bool]) -> str:
    return "UNKNOWN" if condition is None else "PASS" if condition else "FAIL"


class _Checks:
    def __init__(self) -> None:
        self.items: List[Dict[str, Any]] = []

    def add(
        self, record: Dict[str, Any], name: str, dimension: str,
        status: str, reason: str, paths: List[str], *,
        details: Optional[Dict[str, Any]] = None,
    ) -> str:
        sources = record.get("evidence_sources") or {}
        refs: List[Dict[str, Any]] = []
        missing = []
        values = {}
        for path in paths:
            value = _get(record, path)
            values[path] = value
            if value is None:
                missing.append(path)
            mapped = sources.get(path)
            if isinstance(mapped, list):
                refs.extend(mapped)
            else:
                refs.append({
                    "artifact": record.get("evidence_artifact", "provided_evidence"),
                    "pointer": "/" + path.replace(".", "/"),
                    **({"event_id": record["source_event_id"]}
                       if record.get("source_event_id") else {}),
                })
        # Preserve order while removing duplicate artifact/pointer references.
        unique_refs = []
        for ref in refs:
            if ref not in unique_refs:
                unique_refs.append(ref)
        check_id = f"{name}:{len(self.items) + 1}"
        self.items.append({
            "check_id": check_id, "name": name,
            "rule_id": f"comas-audit/{RULES_VERSION}/{name}",
            "dimension": dimension, "status": status, "reason": reason,
            "evidence": {"values": values, **(details or {})},
            "missing_fields": missing, "source_refs": unique_refs,
        })
        return check_id


def _protocol(record: Dict[str, Any], checks: _Checks) -> None:
    first_check = len(checks.items)
    states = _states(record)
    mode = record.get("execution_mode")
    facts = record.get("normalized_facts") or {}

    def add(name: str, condition: Optional[bool], reason: str,
            paths: List[str], **details: Any) -> None:
        checks.add(record, name, "protocol_consistency", _status(condition),
                   reason, paths, details=details)

    if "AGREED" in states:
        required = _count(record.get("required_votes"))
        votes = _names(record.get("mitigate_votes"))
        quorum = compute_quorum(record)
        add("agreed_has_required_quorum", quorum,
            "AGREED requires distinct mitigation votes from the responsible domains; "
            "the state label and quorum_reached flag are not proof of quorum.",
            ["required_votes", "mitigate_votes", "relevant_domains"],
            distinct_votes=len(votes) if votes is not None else None,
            computed_quorum=quorum)
        models = _names(record.get("model_ids"))
        add("agreed_uses_one_model_per_event",
            len(models) == 1 if models else None,
            "An AGREED observation requires one known model identity.", ["model_ids"])
        if "normal_votes" in record:
            normal = _names(record["normal_votes"])
            add("agreed_has_no_normal_proposal", not normal if normal is not None else None,
                "A responsible domain's NORMAL proposal contradicts AGREED.", ["normal_votes"])
        if "proposal_mitigate_votes" in record:
            proposal_votes = _names(record["proposal_mitigate_votes"])
            add("agreed_votes_match_proposals",
                votes == proposal_votes if votes is not None and proposal_votes is not None else None,
                "Reported mitigation votes must match the supplied responsible-domain proposals.",
                ["mitigate_votes", "proposal_mitigate_votes"])
        if "proposal_model_ids" in record:
            proposal_models = _names(record["proposal_model_ids"])
            add("agreed_models_match_proposals",
                models == proposal_models if models and proposal_models else None,
                "Reported model identities must match the supplied responsible-domain proposals.",
                ["model_ids", "proposal_model_ids"])
        for key in ("freshness_valid", "topology_matches", "model_identity_matches"):
            value = _get(record, f"proposal_checks.{key}")
            if isinstance(record.get("proposal_checks"), dict) and key in record["proposal_checks"]:
                add(f"agreed_proposal_{key}", value if type(value) is bool else None,
                    "An explicitly recorded proposal validity check must be true.",
                    [f"proposal_checks.{key}"])
        if mode in {"authority-dry-run", "authority-live"}:
            authorized = record.get("authority_authorized")
            add("agreed_authorized_by_authority_gate",
                authorized if type(authorized) is bool else None,
                "The authority gate must explicitly authorize AGREED.",
                ["authority_authorized"])
            winners = _names(record.get("claim_winners"))
            other = record.get("other_coordinator_elected")
            coordinator = record.get("known_claim_coordinator")
            unique = None
            if winners is not None:
                unique = (True if len(winners) == 1 else False if len(winners) > 1 else
                          True if other is True and bool(coordinator) else None)
            add("single_atomic_claim_winner", unique,
                "A claim must identify one owner; a local non-winner may identify "
                "the other coordinator without observing its execution.",
                ["claim_winners", "other_coordinator_elected", "known_claim_coordinator"])
            if record.get("local_agent_is_claim_winner") is True:
                # A normalized fixture may expose ownership only through its
                # named winner. Runtime records retain the claim coordinator
                # field explicitly (including null when it was missing).
                named_owner = coordinator
                if "known_claim_coordinator" not in record and winners and len(winners) == 1:
                    named_owner = next(iter(winners))
                observer = next((item.get("observed_by") for item in record.get("transitions", [])
                                 if item.get("layer") == "agentic"), None)
                add("claim_owner_matches_observer",
                    observer == named_owner if observer and named_owner else None,
                    "A local won=true claim must name that observing agent as its coordinator.",
                    ["transitions", "claim_winners", "known_claim_coordinator", "local_agent_is_claim_winner"])
            winner_count = _count(facts.get("atomic_claim_winner_events"))
            would = _count(facts.get("would_execute_events"))
            if winner_count is None or winner_count > 0:
                add("claim_winner_matches_would_execute",
                    would > 0 if winner_count is not None and would is not None else None,
                    "A selected winner must record its execution intent.",
                    ["normalized_facts.atomic_claim_winner_events",
                     "normalized_facts.would_execute_events"])
            non_winners = _count(facts.get("authorized_non_winner_events"))
            if non_winners is not None and non_winners > 0:
                # Runtime aggregate adapters provide separate counts; a local
                # fixture's counts describe that non-winner alone.
                separate = record.get("non_winner_execution_facts")
                paths = (
                    [f"non_winner_execution_facts.{key}" for key in
                     ("attempted_execution_events", "executed_events", "would_execute_events")]
                    if isinstance(separate, dict) else
                    [f"normalized_facts.{key}" for key in
                     ("attempted_execution_events", "executed_events", "would_execute_events")]
                )
                values = [_count(_get(record, path)) for path in paths]
                abstained = False if any(value and value > 0 for value in values) else (
                    True if all(value == 0 for value in values) else None
                )
                add("non_winners_do_not_actuate", abstained,
                    "Non-winners must explicitly record no attempt, execution or local intent.", paths)
        else:
            add("agreed_execution_mode_is_known", None,
                "The authority mode is missing or outside the verified authority contract.",
                ["execution_mode"])

    if "WAITING_PROPOSALS" in states:
        missing = _names(record.get("missing_domains"))
        condition = bool(missing) if missing is not None else None
        relevant = _names(record.get("relevant_domains"))
        participating = _names(record.get("participating_domains"))
        if missing is not None and relevant is not None and participating is not None:
            condition = bool(missing) and missing == relevant - participating
        add("waiting_proposals_identifies_missing_domains", condition,
            "WAITING_PROPOSALS must identify at least one absent responsible domain.",
            ["missing_domains", "relevant_domains", "participating_domains"])

    if "VETOED" in states:
        domains = _names(record.get("veto_domains"))
        proposals = record.get("veto_proposals")
        policy = record.get("policy_veto_received")
        present = bool(domains) or (isinstance(proposals, list) and bool(proposals)) or policy is True
        known = domains is not None or isinstance(proposals, list) or type(policy) is bool
        relevant = _names(record.get("relevant_domains"))
        valid = True if present else False if known else None
        if domains and relevant is not None and not domains <= relevant:
            valid = False
        add("vetoed_has_veto_evidence", valid,
            "VETOED requires an explicit veto; an absent veto field is not an implicit veto.",
            ["veto_domains", "veto_proposals", "policy_veto_received"])

    if "DISAGREED" in states:
        normal = _names(record.get("normal_votes"))
        add("disagreed_has_normal_proposal", bool(normal) if normal is not None else None,
            "DISAGREED requires a recorded NORMAL proposal.", ["normal_votes"])
    if "MODEL_MISMATCH" in states:
        models = _names(record.get("model_ids"))
        add("model_mismatch_has_distinct_models", len(models) > 1 if models is not None else None,
            "MODEL_MISMATCH requires distinct recorded model identities.", ["model_ids"])

    mcda = _states(record, "mcda")
    if "NORMAL" in mcda:
        confirming = _names(record.get("confirming_domains"))
        add("mcda_normal_has_no_confirming_domain", not confirming if confirming is not None else None,
            "MCDA NORMAL requires an explicitly empty confirming-domain set.", ["confirming_domains"])
    if "MITIGATE" in mcda:
        confirming = _names(record.get("confirming_domains"))
        minimum = _count(record.get("min_domains", record.get("required_votes")))
        condition = None
        if confirming is not None and minimum is not None and minimum > 0:
            condition = len(confirming) >= minimum
        add("mcda_mitigate_has_required_domains", condition,
            "MCDA MITIGATE requires the configured number of confirming domains.",
            ["confirming_domains", "min_domains", "required_votes"])
        score = _number(record.get("mcda_score"))
        decision_threshold = _number(record.get("mcda_decision_threshold"))
        if score is not None or decision_threshold is not None:
            add("mcda_mitigate_meets_decision_threshold",
                score >= decision_threshold
                if score is not None and decision_threshold is not None else None,
                "MCDA MITIGATE requires a score at or above its decision threshold.",
                ["mcda_score", "mcda_decision_threshold"])

    if "CORROBORATED" in mcda:
        confirming = _names(record.get("confirming_domains"))
        add("corroborated_has_confirming_domain",
            bool(confirming) if confirming is not None else None,
            "MCDA CORROBORATED requires at least one confirming domain.",
            ["confirming_domains"])
        score = _number(record.get("mcda_score"))
        alert_threshold = _number(record.get("mcda_alert_threshold"))
        decision_threshold = _number(record.get("mcda_decision_threshold"))
        if any(value is not None for value in (
                score, alert_threshold, decision_threshold)):
            add("corroborated_score_is_intermediate",
                (alert_threshold <= score < decision_threshold)
                if (score is not None and alert_threshold is not None
                    and decision_threshold is not None
                    and alert_threshold < decision_threshold) else None,
                "MCDA CORROBORATED requires a score from the alert threshold "
                "up to, but not including, the decision threshold.",
                ["mcda_score", "mcda_alert_threshold",
                 "mcda_decision_threshold"])

    attempted = _count(facts.get("attempted_execution_events"))
    executed = _count(facts.get("executed_events"))
    raw_execution = record.get("raw_execution") or {}
    if mcda and raw_execution.get("reason") == "DRY_RUN":
        signature = (
            raw_execution.get("attempted") is True and raw_execution.get("executed") is False
        )
        add("mcda_simulated_attempt_has_dry_run_evidence",
            False if raw_execution.get("executed") is True else True if signature else None,
            "The legacy MCDA Mitigator's exact attempted=true, executed=false, reason=DRY_RUN signature "
            "records intent before an early return, not a FlowBlocker request. Raw flags remain preserved.",
            ["raw_execution.attempted", "raw_execution.executed", "raw_execution.reason",
             "normalized_facts.recorded_attempted_execution_events", "normalized_facts.simulated_execution_events",
             "normalized_facts.attempted_execution_events"])
    policy_mode = record.get("agentic_policy_mode")
    if mode in {"authority-dry-run", "collaborative-dry-run"} or policy_mode == "authority-dry-run":
        no_actuation = False if (attempted and attempted > 0) or (executed and executed > 0) else (
            True if attempted == 0 and executed == 0 else None
        )
        # Non-action states can still be checked without fabricated zero counts.
        if attempted is not None or executed is not None or states & {"AGREED", "MITIGATE"}:
            add("dry_run_does_not_actuate", no_actuation,
                "Dry-run forbids actual requests and execution in either layer. Confirmed legacy MCDA simulations "
                "are intent records, not actual requests; an agentic attempted=true flag has no such exception.",
                ["execution_mode", "agentic_policy_mode", "normalized_facts.attempted_execution_events",
                 "normalized_facts.executed_events"])
    if mcda and policy_mode == "authority-live" and (
        attempted is not None or executed is not None or "MITIGATE" in mcda
    ):
        no_actuation = False if (attempted and attempted > 0) or (executed and executed > 0) else (
            True if attempted == 0 and executed == 0 else None
        )
        add("mcda_does_not_actuate_under_agentic_live_authority", no_actuation,
            "The MCDA baseline may observe decisions, but actual actuation belongs exclusively to the agents in authority-live.",
            ["agentic_policy_mode", "normalized_facts.attempted_execution_events", "normalized_facts.executed_events"])
    if states & (INTERMEDIATE_STATES | (FINAL_STATES - {"AGREED", "MITIGATE"})):
        if "AGREED" not in states and "MITIGATE" not in states:
            if attempted is not None or executed is not None:
                add("non_mitigation_state_does_not_actuate",
                    False if (attempted and attempted > 0) or (executed and executed > 0) else (
                        True if attempted == 0 and executed == 0 else None
                    ), "A non-mitigation decision must not actuate.",
                    ["transitions", "normalized_facts.attempted_execution_events",
                     "normalized_facts.executed_events"])
    if "NORMAL" in _states(record, "agentic"):
        normal = _names(record.get("normal_votes"))
        add("agentic_normal_has_normal_proposal", bool(normal) if normal is not None else None,
            "Agentic NORMAL requires a recorded NORMAL proposal.", ["normal_votes"])
    if not any(item["dimension"] == "protocol_consistency" for item in checks.items[first_check:]):
        add("intermediate_state_is_non_terminal", True if states & INTERMEDIATE_STATES else None,
            "An intermediate state is not itself a completed mitigation decision.", ["transitions"])


def verify_evidence(record: Dict[str, Any]) -> Dict[str, Any]:
    """Compute five dimensions and a traceable proof without an expected oracle.

    ``observations`` is optional and contains individual normalized runtime
    events. Synthetic cases use their own evidence object directly. Source
    references identify supplied artifacts, not independently verified traffic.
    """
    checks = _Checks()
    observations = record.get("observations")
    if isinstance(observations, list) and observations:
        for observation in observations:
            _protocol(observation, checks)
        winners = _names(record.get("claim_winners"))
        if winners is not None and len(winners) > 1:
            claims = record.get("claim_records") or []
            complete = bool(claims) and all(
                isinstance(item, dict) and item.get("owner") and item.get("key")
                and _count(item.get("claimed_ns")) is not None
                and _count(item.get("expires_ns")) is not None
                and item["expires_ns"] > item["claimed_ns"] for item in claims
            )
            overlaps = []
            if complete:
                for index, left in enumerate(claims):
                    for right in claims[index + 1:]:
                        if left["owner"] != right["owner"] and left["key"] == right["key"] and (
                            max(left["claimed_ns"], right["claimed_ns"]) < min(left["expires_ns"], right["expires_ns"])
                        ):
                            overlaps.append([left["owner"], right["owner"]])
            checks.add(record, "single_atomic_claim_winner", "protocol_consistency",
                       _status(not overlaps) if complete else "UNKNOWN",
                       "Different owners may succeed each other after lease expiry, but must not overlap. "
                       "Missing lease intervals cannot prove simultaneous winners.",
                       ["claim_winners", "claim_records"], details={"overlapping_owners": overlaps})
    else:
        _protocol(record, checks)
    statuses = {item["status"] for item in checks.items
                if item["dimension"] == "protocol_consistency"}
    protocol = "INCONSISTENT" if "FAIL" in statuses else (
        "INSUFFICIENT_EVIDENCE" if "UNKNOWN" in statuses or not statuses else "CONSISTENT"
    )
    states = _states(record)
    stage = "FINAL" if states & FINAL_STATES else "INTERMEDIATE" if states & INTERMEDIATE_STATES else "NO_DECISION"
    checks.add(record, "reported_decision_stage", "decision_stage", "PASS",
               "Stage describes the recorded state, not whether its prerequisites were valid.",
               ["transitions", "event_counts_by_state"], details={"computed": stage})

    laboratory = record.get("laboratory_context") or {}
    scenario = laboratory.get("scenario")
    trusted = laboratory.get("ground_truth_available") is True
    trusted = trusted and laboratory.get("validation_status") not in {"INVALID", "CONTAMINATED"}
    # An authoritative agent decision takes precedence over the observational MCDA baseline.
    decision_states = _states(record, "agentic") or _states(record, "mcda") or states
    scenario_result = "UNKNOWN"
    if stage == "FINAL" and trusted:
        mitigation = bool(decision_states & {"AGREED", "MITIGATE"})
        normal = "NORMAL" in decision_states
        if scenario == "benign" and (mitigation or normal):
            scenario_result = "INCORRECT" if mitigation else "CORRECT"
        elif scenario == "ddos" and (mitigation or normal):
            scenario_result = "CORRECT" if mitigation else "INCORRECT"
        elif scenario == "ddos_with_destination_whitelist" and (
            mitigation or "VETOED" in decision_states
        ):
            scenario_result = "INCORRECT" if mitigation else "CORRECT"
    checks.add(record, "decision_matches_laboratory_context", "scenario_correctness",
               "UNKNOWN" if scenario_result == "UNKNOWN" else _status(scenario_result == "CORRECT"),
               "Compare the decision with explicit laboratory labels/policy, never with the run-level TP/TN label. "
               "Intermediate states and unknown/invalid ground truth cannot establish correctness.",
               ["transitions", "laboratory_context.scenario", "laboratory_context.ground_truth_available",
                "laboratory_context.validation_status"], details={"computed": scenario_result})

    facts = record.get("normalized_facts") or {}
    executed = _count(facts.get("executed_events"))
    attempted = _count(facts.get("attempted_execution_events"))
    would = _count(facts.get("would_execute_events"))
    winners = _count(facts.get("atomic_claim_winner_events"))
    simulated = _count(facts.get("simulated_execution_events"))
    mode = record.get("execution_mode")
    execution = "UNKNOWN"
    if executed is not None and executed > 0:
        execution = "EXECUTED"
    elif attempted is not None and attempted > 0 and executed == 0:
        execution = "FAILED"
    elif attempted == 0 and executed == 0:
        if mode == "authority-dry-run" and winners is not None and winners > 0 and would is not None and would > 0:
            execution = "DRY_RUN_SUPPRESSED"
        elif "AGREED" in decision_states and record.get("authority_authorized") is True and (
            record.get("other_coordinator_elected") is True and bool(record.get("known_claim_coordinator"))
        ) and winners == 0:
            execution = "SKIPPED_OTHER_COORDINATOR"
        elif simulated is not None and simulated > 0:
            execution = "DRY_RUN_SUPPRESSED"
        elif decision_states and not decision_states & {"AGREED", "MITIGATE"}:
            execution = "NOT_REQUESTED"
    elif attempted is None and executed is None and decision_states and not decision_states & {"AGREED", "MITIGATE"}:
        execution = "NOT_REQUESTED"
    checks.add(record, "recorded_execution_outcome", "execution_status",
               "UNKNOWN" if execution == "UNKNOWN" else "PASS",
               "Observed execution takes precedence over intended mode. A recorded attempt without an outcome is unknown; "
               "NOT_REQUESTED differs from selected-but-suppressed and skipped-for-another-coordinator.",
               ["execution_mode", "normalized_facts.executed_events", "normalized_facts.attempted_execution_events",
                "normalized_facts.would_execute_events", "normalized_facts.atomic_claim_winner_events",
                "normalized_facts.simulated_execution_events",
                "authority_authorized", "other_coordinator_elected", "known_claim_coordinator"],
               details={"computed": execution})

    operational = record.get("operational_evidence") or {}
    effectiveness = "UNKNOWN"
    if execution in {"DRY_RUN_SUPPRESSED", "SKIPPED_OTHER_COORDINATOR", "NOT_REQUESTED"}:
        effectiveness = "NOT_APPLICABLE"
    elif execution == "FAILED":
        effectiveness = "INEFFECTIVE"
    elif execution == "EXECUTED" and operational.get("observations_available") is True:
        if type(operational.get("attack_disrupted")) is bool:
            effectiveness = "EFFECTIVE" if operational["attack_disrupted"] else "INEFFECTIVE"
    checks.add(record, "recorded_operational_outcome", "operational_effectiveness",
               "UNKNOWN" if effectiveness == "UNKNOWN" else "PASS",
               "Installation/execution alone does not prove mitigation effectiveness. No local actuation is not applicable; "
               "a failed actuation is ineffective. Executed actions require an explicit outcome observation.",
               ["normalized_facts.executed_events", "normalized_facts.attempted_execution_events",
                "operational_evidence.observations_available", "operational_evidence.attack_disrupted"],
               details={"computed": effectiveness})
    return {
        "rules_version": RULES_VERSION, "protocol_consistency": protocol,
        "scenario_correctness": scenario_result, "decision_stage": stage,
        "execution_status": execution, "operational_effectiveness": effectiveness,
        "checks": checks.items,
        "verdict_support": {
            dimension: [item["check_id"] for item in checks.items if item["dimension"] == dimension]
            for dimension in VERDICT_FIELDS
        },
        "limitations": [
            "Verdicts are conditional on the supplied artifacts, not independent verification of network events.",
            "CONSISTENT means that the applicable documented predicates passed, not a complete formal verification of the protocol.",
            "Optional freshness/topology validity fields are checked when supplied; absent fields do not prove those properties.",
            "Operational outcomes are reported observations; execution flags alone do not establish data-plane effectiveness.",
        ],
    }
