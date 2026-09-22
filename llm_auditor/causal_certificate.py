"""Version 2 explanation certificate with verifier-derived causes.

The v1 certificate, full checks and source references remain unchanged. This
module adds a deterministic causal index; it does not infer causes with an LLM.
"""

from __future__ import annotations

import copy
from typing import Any, Dict, List

from .certificate import build_certificate, digest
from .rules import VERDICT_FIELDS


CAUSAL_CERTIFICATE_VERSION = "2.9"
COMPARATIVE_FIELD = "comparative_alignment"
CAUSAL_DIMENSION_FIELDS = [*VERDICT_FIELDS, COMPARATIVE_FIELD]


PROTOCOL_FAILURE_STATEMENTS = {
    "agreed_has_required_quorum":
        "AGREED foi registrado sem o quórum de votos MITIGATE exigido.",
    "agreed_uses_one_model_per_event":
        "AGREED não possui exatamente uma identidade de modelo conhecida.",
    "agreed_has_no_normal_proposal":
        "AGREED contém ao menos uma proposta NORMAL contraditória.",
    "agreed_votes_match_proposals":
        "Os votos MITIGATE registrados em AGREED divergem das propostas fornecidas.",
    "agreed_proposal_model_identity_matches":
        "A identidade de modelo de AGREED diverge das propostas fornecidas.",
    "agreed_proposal_freshness_valid":
        "AGREED contém evidência de proposta fora da validade exigida.",
    "agreed_proposal_topology_matches":
        "AGREED contém evidência topológica incompatível entre as propostas.",
    "agreed_authorized_by_authority_gate":
        "AGREED foi registrado sem autorização válida do authority gate.",
    "single_atomic_claim_winner":
        "Mais de um vencedor simultâneo do claim foi registrado.",
    "claim_owner_matches_observer":
        "O agente registrado como vencedor não corresponde ao coordenador do claim.",
    "claim_winner_matches_would_execute":
        "O vencedor do claim não corresponde ao agente marcado para executar.",
    "non_winners_do_not_actuate":
        "Um agente que não venceu o claim registrou atuação.",
    "dry_run_does_not_actuate":
        "Foi registrada atuação em modo dry-run, violando a regra de não atuação.",
    "waiting_proposals_identifies_missing_domains":
        "WAITING_PROPOSALS foi registrado sem identificar os domínios ausentes.",
    "corroborated_has_confirming_domain":
        "CORROBORATED foi registrado sem domínio confirmador.",
    "corroborated_score_is_intermediate":
        "CORROBORATED foi registrado fora da faixa intermediária de pontuação MCDA.",
    "mcda_mitigate_has_required_domains":
        "MITIGATE foi registrado sem o número exigido de domínios confirmadores.",
    "mcda_mitigate_meets_decision_threshold":
        "MITIGATE foi registrado abaixo do limiar de decisão MCDA.",
    "vetoed_has_veto_evidence":
        "VETOED foi registrado sem evidência explícita de veto.",
    "non_mitigation_state_does_not_actuate":
        "Uma decisão que não solicita mitigação registrou atuação.",
    "mcda_normal_has_no_confirming_domain":
        "NORMAL no MCDA contém confirmação de domínio incompatível com esse estado.",
}


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

COMPARATIVE_CAUSE_CODES = {
    "ALIGNED": "recorded_agent_mcda_alignment",
    "DIVERGENT": "recorded_agent_mcda_divergence",
    "INSUFFICIENT_EVIDENCE": "agent_mcda_comparison_incomplete",
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


def _causal_statement(field: str, cause_code: str,
                      decisive_entries: List[Dict[str, Any]],
                      audit: Dict[str, Any]) -> str:
    if field == "protocol_consistency":
        if cause_code == "applicable_protocol_checks_passed":
            return "As verificações protocolares aplicáveis foram aprovadas."
        if cause_code == "protocol_prerequisites_unavailable":
            return "As evidências obrigatórias são insuficientes para concluir a consistência protocolar."
        statements = []
        for entry in decisive_entries:
            statement = PROTOCOL_FAILURE_STATEMENTS.get(
                entry["rule"], f"A regra protocolar {entry['rule']} falhou."
            )
            if statement not in statements:
                statements.append(statement)
        return " ".join(statements)
    statements = {
        "decision_matches_declared_laboratory_context":
            "A decisão final coincide com o cenário de laboratório declarado.",
        "decision_conflicts_with_declared_laboratory_context":
            "A decisão final contradiz o cenário de laboratório declarado.",
        "non_final_decision_cannot_establish_scenario_correctness":
            "Uma decisão não final não permite concluir a correção do cenário.",
        "declared_ground_truth_unavailable":
            "O ground truth declarado não está disponível para avaliar a correção do cenário.",
        "declared_ground_truth_invalid_or_contaminated":
            "O ground truth declarado está inválido ou contaminado.",
        "scenario_evidence_incomplete":
            "A evidência disponível não permite concluir a correção do cenário.",
        "reported_final_state": "Foi registrado um estado final de decisão.",
        "reported_intermediate_state": "Foi registrado somente um estado intermediário de decisão.",
        "no_recorded_decision_state": "Nenhum estado de decisão foi registrado.",
        "recorded_execution": "Ao menos uma execução efetiva foi registrada.",
        "recorded_attempt_without_execution":
            "Foi registrada uma tentativa de atuação sem execução bem-sucedida.",
        "recorded_dry_run_suppression":
            "Um vencedor foi selecionado para atuar, mas o modo authority-dry-run suprimiu a execução.",
        "recorded_other_coordinator":
            "A decisão foi autorizada localmente, mas a atuação coube a outro coordenador.",
        "decision_did_not_request_actuation":
            "A decisão final registrada não solicita atuação local.",
        "execution_evidence_incomplete":
            "A evidência disponível não permite determinar o status de execução.",
        "recorded_disruption_after_execution":
            "Após execução registrada, a observação operacional indica interrupção do ataque.",
        "recorded_ineffective_or_failed_actuation":
            "A atuação falhou ou a observação operacional indica que o ataque não foi interrompido.",
        "no_applicable_local_actuation":
            "Não houve atuação local aplicável cuja eficácia pudesse ser avaliada.",
    }
    if cause_code == "operational_outcome_unavailable":
        if audit.get("execution_status") == "EXECUTED":
            return "O resultado operacional da execução registrada não está disponível."
        return "A evidência disponível não permite determinar a execução nem seu resultado operacional."
    return statements[cause_code]


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
        "decision_did_not_request_actuation": ["transitions"],
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
    if cause_code == "decision_did_not_request_actuation":
        facts["actuation_requested_by_final_decision"] = False
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


def _comparison_domains(audit: Dict[str, Any]) -> List[Dict[str, Any]]:
    comparison = audit.get("agent_mcda_comparison") or {}
    domains = comparison.get("domains") or []
    if not isinstance(domains, list):
        return []
    return [item for item in domains if isinstance(item, dict)]


def _windows_are_disjoint_at_authority(audit: Dict[str, Any]) -> bool:
    domains = _comparison_domains(audit)
    if not domains:
        return False
    for item in domains:
        agent_windows = item.get("agent_window_ids")
        mcda_windows = item.get("mcda_window_ids")
        if item.get("available") is not False:
            return False
        if not isinstance(agent_windows, list) or not agent_windows:
            return False
        if not isinstance(mcda_windows, list) or not mcda_windows:
            return False
        try:
            overlap = set(agent_windows) & set(mcda_windows)
        except TypeError:
            return False
        if overlap:
            return False
    return True


def _comparative_cause(audit: Dict[str, Any], verdict: str) -> str:
    comparison = audit.get("agent_mcda_comparison") or {}
    if (verdict == "ALIGNED"
            and comparison.get("transient_divergence_observed") is True):
        return "final_alignment_after_transient_divergence"
    if (verdict == "INSUFFICIENT_EVIDENCE"
            and _windows_are_disjoint_at_authority(audit)):
        return "agent_mcda_window_mismatch_at_authority"
    return COMPARATIVE_CAUSE_CODES[verdict]


def _comparative_statement(
    audit: Dict[str, Any], verdict: str, cause_code: str,
) -> str:
    if verdict == "ALIGNED":
        if cause_code == "final_alignment_after_transient_divergence":
            statement = (
                "A comparação mais recente de cada domínio indica alinhamento "
                "final entre agentes e MCDA, mas comparações divergentes "
                "anteriores também foram registradas no episódio."
            )
            comparison = audit.get("agent_mcda_comparison") or {}
            profile = comparison.get("realignment_profile") or {}
            latency = profile.get("latency_ms") or {}
            values = latency.get("values") or []
            measured = latency.get("measured")
            if measured == 1 and len(values) == 1:
                value = f"{values[0]:.6f}".rstrip("0").rstrip(".")
                statement += (
                    " O primeiro realinhamento posterior foi observado após "
                    f"{value} ms; esse intervalo descreve somente este episódio."
                )
            elif (type(measured) is int and measured > 1
                  and type(latency.get("minimum")) in (int, float)
                  and type(latency.get("maximum")) in (int, float)):
                minimum = f"{latency['minimum']:.6f}".rstrip("0").rstrip(".")
                maximum = f"{latency['maximum']:.6f}".rstrip("0").rstrip(".")
                statement += (
                    f" Para {measured} comparações divergentes, os intervalos "
                    "até o primeiro alinhamento posterior ficaram entre "
                    f"{minimum} e {maximum} ms; esses intervalos descrevem "
                    "somente este episódio."
                )
            return statement
        return (
            "A comparação registrada no instante da autoridade indica "
            "alinhamento entre a decisão dos agentes e o MCDA observacional."
        )
    if verdict == "INSUFFICIENT_EVIDENCE":
        if cause_code == "agent_mcda_window_mismatch_at_authority":
            return (
                "No instante da autoridade, o snapshot MCDA disponível "
                "pertencia a uma janela diferente da decisão dos agentes; "
                "por isso o alinhamento do mesmo episódio não pôde ser "
                "determinado."
            )
        return (
            "A evidência registrada não permite concluir o alinhamento entre "
            "a decisão dos agentes e o MCDA observacional."
        )
    comparison = audit.get("agent_mcda_comparison") or {}
    domains = comparison.get("domains") or []
    valid_domains = _comparison_domains(audit)
    complete_domains = bool(valid_domains) and len(valid_domains) == len(domains)
    agent_agreed = complete_domains and all(
        item.get("agent_decision") == "AGREED" for item in valid_domains
    )
    mcda_corroborated = complete_domains and all(
        item.get("mcda_decision") == "CORROBORATED"
        for item in valid_domains
    )
    quorum = complete_domains and all(
        type(item.get("required_votes")) is int
        and isinstance(item.get("mitigate_votes"), list)
        and len(set(item["mitigate_votes"])) >= item["required_votes"] > 0
        for item in valid_domains
    )
    below_threshold = complete_domains and all(
        type(item.get("mcda_score")) in (int, float)
        and type(item.get("mcda_decision_threshold")) in (int, float)
        and item["mcda_score"] < item["mcda_decision_threshold"]
        for item in valid_domains
    )
    if agent_agreed and mcda_corroborated and quorum and below_threshold:
        return (
            "Os agentes autoritativos registraram AGREED com quórum de "
            "propostas MITIGATE, enquanto o MCDA observacional registrou "
            "CORROBORATED porque sua pontuação permaneceu abaixo do limiar "
            "de decisão."
        )
    return (
        "A comparação registrada no instante da autoridade indica divergência "
        "entre a decisão dos agentes e o MCDA observacional."
    )


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
            "causal_statement": _causal_statement(field, cause_code, decisive, audit),
            "decisive_evidence_ids": decisive_ids,
            "supporting_evidence_ids": [entry["id"] for entry in dimension_entries
                                        if entry["id"] not in decisive_ids],
            "facts": _facts_for(field, cause_code, audit, decisive),
            "null_policy": "null outside unavailable_fields is not a cause",
        }
    comparison = _known_values(audit.get("agent_mcda_comparison") or {})
    comparison_verdict = audit.get("comparative_alignment")
    if comparison_verdict not in COMPARATIVE_CAUSE_CODES:
        comparison_verdict = "INSUFFICIENT_EVIDENCE"
    comparison_cause = _comparative_cause(audit, comparison_verdict)
    comparison_id = "C01"
    comparison_sources = copy.deepcopy(
        (audit.get("evidence_sources") or {}).get("agent_mcda_comparison") or []
    )
    certificate["comparative_evidence"] = [{
        "id": comparison_id,
        "dimension": COMPARATIVE_FIELD,
        "status": comparison_verdict,
        "witness": {"values": comparison},
    }]
    certificate["verdicts"][COMPARATIVE_FIELD] = comparison_verdict
    certificate["verdict_support"][COMPARATIVE_FIELD] = [comparison_id]
    certificate["coverage"]["comparative_evidence_count"] = 1
    causes[COMPARATIVE_FIELD] = {
        "verdict": comparison_verdict,
        "cause_code": comparison_cause,
        "causal_statement": _comparative_statement(
            audit, comparison_verdict, comparison_cause,
        ),
        "decisive_evidence_ids": [comparison_id],
        "supporting_evidence_ids": [],
        "facts": comparison,
        "null_policy": "null fields are omitted and cannot be used as causes",
    }
    v1_sha = certificate["sha256"]
    certificate["certificate_version"] = CAUSAL_CERTIFICATE_VERSION
    certificate["derived_from_certificate_v1_sha256"] = v1_sha
    certificate["decisive_causes"] = causes
    certificate.pop("sha256")
    certificate["sha256"] = digest(certificate)
    ledger = copy.deepcopy(base["ledger"])
    ledger.setdefault("groups", {})[comparison_id] = {
        "origin": "derived_agent_mcda_authority_comparison",
        "source_refs": comparison_sources,
    }
    ledger["derived_from_certificate_v1_sha256"] = v1_sha
    ledger["certificate_sha256"] = certificate["sha256"]
    return {"certificate": certificate, "ledger": ledger}


def attach_causal_certificate(audit: Dict[str, Any]) -> Dict[str, Any]:
    bundle = build_causal_certificate(audit)
    audit["explanation_certificate"] = bundle["certificate"]
    audit["certificate_ledger"] = bundle["ledger"]
    return bundle["certificate"]
