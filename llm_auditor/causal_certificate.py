"""Version 2 explanation certificate with verifier-derived causes.

The v1 certificate, full checks and source references remain unchanged. This
module adds a deterministic causal index; it does not infer causes with an LLM.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from .certificate import build_certificate, digest
from .rules import VERDICT_FIELDS


CAUSAL_CERTIFICATE_VERSION = "2.1"


CAUSE_CODES = {
    "protocol_consistency": {
        "CONSISTENT": "applicable_protocol_checks_passed",
        "INCONSISTENT": "recorded_protocol_violation",
        "INSUFFICIENT_EVIDENCE": "protocol_prerequisites_unavailable",
    },
    "decision_stage": {
        "FINAL": "reported_final_state",
        "INTERMEDIATE": "reported_intermediate_state",
        "NO_DECISION": "no_recorded_decision_state",
    },
    "execution_status": {
        "EXECUTED": "recorded_execution",
        "FAILED": "recorded_attempt_without_execution",
        "DRY_RUN_SUPPRESSED": "recorded_dry_run_suppression",
        "SKIPPED_OTHER_COORDINATOR": "recorded_other_coordinator",
        "NOT_REQUESTED": "decision_did_not_request_actuation",
        "UNKNOWN": "execution_evidence_incomplete",
    },
    "operational_effectiveness": {
        "EFFECTIVE": "recorded_disruption_after_execution",
        "INEFFECTIVE": "recorded_ineffective_or_failed_actuation",
        "NOT_APPLICABLE": "no_applicable_local_actuation",
        "UNKNOWN": "operational_outcome_unavailable",
    },
}


def _scenario_cause(audit: Dict[str, Any]) -> str:
    verdict = audit["scenario_correctness"]
    if verdict == "CORRECT":
        return "decision_matches_declared_laboratory_context"
    if verdict == "INCORRECT":
        return "decision_conflicts_with_declared_laboratory_context"
    if audit.get("decision_stage") != "FINAL":
        return "non_final_decision_cannot_establish_scenario_correctness"
    laboratory = audit.get("laboratory_context") or {}
    if laboratory.get("ground_truth_available") is not True:
        return "declared_ground_truth_unavailable"
    if laboratory.get("validation_status") in {"INVALID", "CONTAMINATED"}:
        return "declared_ground_truth_invalid_or_contaminated"
    return "scenario_evidence_incomplete"


def _get(record: Dict[str, Any], path: str) -> Any:
    value: Any = record
    for part in path.split("."):
        if not isinstance(value, dict) or part not in value:
            return None
        value = value[part]
    return copy.deepcopy(value)


def _known_values(value: Any) -> Any:
    """Remove nulls from causal facts; false, zero and empty lists are evidence."""
    if isinstance(value, dict):
        return {key: cleaned for key, item in value.items()
                if (cleaned := _known_values(item)) is not None}
    if isinstance(value, list):
        return [_known_values(item) for item in value]
    return None if value is None else copy.deepcopy(value)


def _facts_for(field: str, cause_code: str, audit: Dict[str, Any],
               decisive_entries: List[Dict[str, Any]]) -> Dict[str, Any]:
    paths = {
        "recorded_execution": ["normalized_facts.executed_events"],
        "recorded_attempt_without_execution": [
            "normalized_facts.attempted_execution_events",
            "normalized_facts.executed_events",
        ],
        "recorded_dry_run_suppression": [
            "execution_mode", "normalized_facts.atomic_claim_winner_events",
            "normalized_facts.would_execute_events",
            "normalized_facts.attempted_execution_events",
            "normalized_facts.executed_events",
            "normalized_facts.simulated_execution_events",
        ],
        "recorded_other_coordinator": [
            "authority_authorized", "other_coordinator_elected",
            "known_claim_coordinator", "normalized_facts.executed_events",
        ],
        "decision_did_not_request_actuation": [
            "transitions", "normalized_facts.attempted_execution_events",
            "normalized_facts.executed_events",
        ],
        "execution_evidence_incomplete": [
            "execution_mode", "normalized_facts.attempted_execution_events",
            "normalized_facts.executed_events",
        ],
        "recorded_disruption_after_execution": [
            "normalized_facts.executed_events", "operational_evidence.observations_available",
            "operational_evidence.attack_disrupted",
        ],
        "recorded_ineffective_or_failed_actuation": [
            "execution_status", "normalized_facts.executed_events",
            "normalized_facts.attempted_execution_events",
            "operational_evidence.observations_available", "operational_evidence.attack_disrupted",
        ],
        "no_applicable_local_actuation": ["execution_status"],
        "operational_outcome_unavailable": [
            "execution_status", "operational_evidence.observations_available",
            "operational_evidence.attack_disrupted",
        ],
        "decision_matches_declared_laboratory_context": [
            "laboratory_context.scenario", "laboratory_context.ground_truth_available",
            "laboratory_context.validation_status", "transitions",
        ],
        "decision_conflicts_with_declared_laboratory_context": [
            "laboratory_context.scenario", "laboratory_context.ground_truth_available",
            "laboratory_context.validation_status", "transitions",
        ],
        "non_final_decision_cannot_establish_scenario_correctness": ["decision_stage", "transitions"],
        "declared_ground_truth_unavailable": [
            "laboratory_context.scenario", "laboratory_context.ground_truth_available",
        ],
        "declared_ground_truth_invalid_or_contaminated": ["laboratory_context.validation_status"],
        "reported_final_state": ["transitions", "event_counts_by_state"],
        "reported_intermediate_state": ["transitions", "event_counts_by_state"],
        "no_recorded_decision_state": ["transitions", "event_counts_by_state"],
    }.get(cause_code, [])
    facts = {path: _get(audit, path) for path in paths}
    # Derived verdicts are legitimate deterministic facts for dependent
    # dimensions, not observations invented by the model.
    facts.update({key: audit[key] for key in ("decision_stage", "execution_status")
                  if key in paths or key in {path.split(".")[0] for path in paths}})
    facts = _known_values(facts)
    if field == "protocol_consistency" and cause_code == "recorded_protocol_violation":
        facts["violations"] = [{
            "evidence_id": entry["id"], "rule": entry["rule"],
            "triggering_values": _known_values((entry.get("witness") or {}).get("values") or {}),
        } for entry in decisive_entries]
    if field == "protocol_consistency" and cause_code == "protocol_prerequisites_unavailable":
        facts["unresolved_checks"] = [{
            "evidence_id": entry["id"], "rule": entry["rule"],
            "unavailable_fields": entry.get("missing_fields") or [],
            "known_values": _known_values((entry.get("witness") or {}).get("values") or {}),
        } for entry in decisive_entries]
    return facts


def build_causal_certificate(audit: Dict[str, Any]) -> Dict[str, Any]:
    base = build_certificate(audit)
    certificate = copy.deepcopy(base["certificate"])
    evidence = certificate["evidence"]
    causes = {}
    for field in VERDICT_FIELDS:
        verdict = audit[field]
        cause_code = (_scenario_cause(audit) if field == "scenario_correctness"
                      else CAUSE_CODES[field][verdict])
        dimension_entries = [entry for entry in evidence if entry["dimension"] == field]
        if field == "protocol_consistency" and verdict == "INCONSISTENT":
            decisive = [entry for entry in dimension_entries if entry["status"] == "FAIL"]
        elif field == "protocol_consistency" and verdict == "INSUFFICIENT_EVIDENCE":
            decisive = [entry for entry in dimension_entries if entry["status"] == "UNKNOWN"]
        else:
            # Other verifier dimensions have one aggregate outcome check. For
            # CONSISTENT protocol, all applicable PASS checks define the scope.
            decisive = dimension_entries
        if not decisive:
            raise ValueError(f"nenhuma evidência decisiva para {field}/{verdict}")
        decisive_ids = [entry["id"] for entry in decisive]
        causes[field] = {
            "verdict": verdict, "cause_code": cause_code,
            "decisive_evidence_ids": decisive_ids,
            "supporting_evidence_ids": [entry["id"] for entry in dimension_entries
                                        if entry["id"] not in decisive_ids],
            "facts": _facts_for(field, cause_code, audit, decisive),
            "null_policy": "null outside unavailable_fields is not a cause",
        }
    v1_sha = certificate["sha256"]
    certificate["certificate_version"] = CAUSAL_CERTIFICATE_VERSION
    certificate["derived_from_certificate_v1_sha256"] = v1_sha
    certificate["decisive_causes"] = causes
    certificate.pop("sha256")
    certificate["sha256"] = digest(certificate)
    ledger = copy.deepcopy(base["ledger"])
    ledger["derived_from_certificate_v1_sha256"] = v1_sha
    ledger["certificate_sha256"] = certificate["sha256"]
    return {"certificate": certificate, "ledger": ledger}


def attach_causal_certificate(audit: Dict[str, Any]) -> Dict[str, Any]:
    bundle = build_causal_certificate(audit)
    audit["explanation_certificate"] = bundle["certificate"]
    audit["certificate_ledger"] = bundle["ledger"]
    return bundle["certificate"]
