#!/usr/bin/env python3
"""Trace one recorded shadow alert and all its renewals offline; never actuate."""

from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

import predictive_sla_shadow_control_analysis as followup
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_shadow_ramp_analysis as paired
import predictive_sla_shadow_report as cohort
import predictive_sla_validation as provenance


SCHEMA = "comas-shadow-alert-lifecycle/1"
OUTPUT_PREFIX = "qos-shadow-alert-trace-"
CODE_FILES = (*cohort.CODE_FILES, "predictive_sla_shadow_alert_trace.py")
POLICY = dict(
    lifecycle="recorded_activation_then_same_generation_active_records_until_first_clear; reset_or_end_is_incomplete",
    renewals="exact_confirmed_risk_hashes; never_cross_clear_reset_or_next_activation",
    consensus="all_recorded_observer_views_including_after_clear; revalidate_assessment_within_recorded_time_interval",
    joint="unchanged_confirmed_pair_witness_deduplication; classify_each_renewal_from_its_own_observation",
    coverage="missing_native_samples_or_unobserved_pairs_are_not_a_successful_negative",
    interpretation="recorded_evidence_only; no_causal_filtering_deadline_or_generalization_claim",
)
LIMITATIONS = [*followup.LIMITATIONS,
    "The trace follows recorded persistence state, not a new fit or a changed decision/episode policy.",
    "No agreement recorded for the activation pair does not establish no agreement for its renewals.",
    "The same alert may later contain a genuinely supported warning; the initial horizon is not reused for later observations.",
    "Snapshots are logged on assessment changes, not continuously; absence of a recorded agreement is not proof of causal suppression.",
    "A reset, missing reference input, unseen pair or unfinished lifecycle prevents a complete-lifecycle negative interpretation.",
    "Original v4 results and failed/unfinalized campaign attempts are unchanged by this single-alert diagnostic.",
]


def code_snapshot():
    return {name: provenance.digest_file(cohort.ROOT / name) for name in CODE_FILES}


def local_pairs(config, journals, publications):
    result = {}
    for subject in config["subjects"]:
        cid, previous = subject["cid"], 0
        rows = []
        for event in journals[cid]:
            if event["kind"] != "LOCAL_EVALUATION":
                continue
            record, sample = event["record"], event["record"]["sample"]
            ts = protocol.positive_ns(sample["ts_ns"])
            matches = [p for p in publications.values() if p["cid"] == cid and p["risk"]["observed_ns"] == ts]
            if (ts <= previous or event.get("cid") != cid or sample["cid"] != cid
                    or sample["port_id"] != subject["port_id"] or len(matches) != 1):
                raise ValueError("avaliação local sem identidade/ordem/par confirmado únicos")
            pair = matches[0]
            if (pair["risk"]["record"] != record
                    or pair["risk"]["processing_completed_ns"] != event["processing_completed_ns"]
                    or pair["risk"]["forecast_available_ns"] != event["forecast_available_ns"]):
                raise ValueError("avaliação local difere do par confirmado")
            rows.append((event, pair))
            previous = ts
        result[cid] = rows
    return result


def check_assessment(config, run_id, observer, event):
    received = protocol.positive_ns(event["peer_snapshot_received_ns"])
    completed = protocol.positive_ns(event["consensus_completed_ns"])
    if event.get("cid") != observer or completed < received:
        raise ValueError("observador/intervalo do consenso inválido")
    # The runtime's final assessment occurs between snapshot receipt and the
    # journal's completion stamp. Do not invent an exact evaluation timestamp.
    points = {received, completed}
    for item in event["peer_snapshot"]["values"].values():
        if isinstance(item, dict):
            for key in ("observed_ns", "expires_ns", "evaluated_ns"):
                point = item.get(key)
                if type(point) is int:
                    points.update(p for p in (point - 1, point) if received <= p <= completed)
    if not any(protocol.consensus(config, run_id, event["peer_snapshot"], point) == event["assessment"]
               for point in points):
        raise ValueError("avaliação de consenso não reproduzível no intervalo registrado")


def analyze(config, run_id, series, journals, cid, activation_index):
    if type(activation_index) is not int or activation_index < 0:
        raise ValueError("índice de ativação deve ser inteiro não negativo")
    publications = paired.validate_publications(config, run_id, journals)
    agreements = paired.joint_agreements(config, run_id, journals, publications)
    base = paired.analyze(config, run_id, series, journals)
    reports = {row["cid"]: row for row in base["domains"]}
    blocks = {block["cid"]: block for block in series}
    if cid not in reports:
        raise ValueError("domínio não pertence ao piloto")
    targets = [a for a in reports[cid]["strict_activation_episodes"]["activations"]
               if a["activation_index"] == activation_index]
    if len(targets) != 1:
        raise ValueError("índice não identifica uma única ativação registrada")
    target = targets[0]
    by_cid = local_pairs(config, journals, publications)
    for subject, block in zip(config["subjects"], series):
        followup.validate_local_pairs(subject, block, journals, publications)
    local = by_cid[cid]
    start = next(i for i, (_, pair) in enumerate(local) if pair["risk"]["observed_ns"] == target["activation_ts_ns"])
    first_record = local[start][0]["record"]
    generation = first_record["generation"]
    if first_record["activation"] is not True or first_record["active"] is not True:
        raise ValueError("ativação não corresponde ao estado local ativo")
    members, terminal, end_reason = [], None, "JOURNAL_ENDED_WITHOUT_CLEAR"
    for i, (event, pair) in enumerate(local[start:]):
        record = event["record"]
        if record["generation"] != generation:
            terminal, end_reason = event, "GENERATION_CHANGED_WITHOUT_CLEAR"
            break
        if i and record["activation"]:
            terminal, end_reason = event, "NEW_ACTIVATION_WITHOUT_RECORDED_CLEAR"
            break
        if record["clear_transition"]:
            if record["active"]:
                raise ValueError("limpeza registrada com estado ainda ativo")
            terminal, end_reason = event, "CLEAR_RECORDED"
            break
        if record["active"] is not True:
            terminal, end_reason = event, "INACTIVE_WITHOUT_RECORDED_CLEAR"
            break
        members.append(pair)
    identities = {protocol.digest(pair["risk"]): pair for pair in members}
    observations, last_assessment = [], {}
    for observer, events in journals.items():
        previous_completed = 0
        for event in events:
            if event["kind"] != "SHADOW_CONSENSUS":
                continue
            check_assessment(config, run_id, observer, event)
            if event["consensus_completed_ns"] <= previous_completed:
                raise ValueError("consenso registrado fora de ordem no observador")
            previous_completed = event["consensus_completed_ns"]
            last_assessment[observer] = previous_completed
            snapshot = event["peer_snapshot"]
            risk = snapshot["values"].get(f"risks/{cid}")
            identity = protocol.digest(risk) if isinstance(risk, dict) else None
            if identity not in identities:
                continue
            pair = identities[identity]
            valid_binding = (snapshot["values"].get(f"proposals/{cid}") == pair["proposal"]
                and snapshot["mod_revisions"].get(f"risks/{cid}") == pair["pair_mod_revision"]
                and snapshot["mod_revisions"].get(f"proposals/{cid}") == pair["pair_mod_revision"])
            observations.append(dict(observer=observer, local_risk_sha256=identity,
                pair_binding_valid=valid_binding, peer_snapshot_received_ns=event["peer_snapshot_received_ns"],
                consensus_completed_ns=event["consensus_completed_ns"], assessment=event["assessment"],
                assessment_time_validation="REPRODUCIBLE_WITHIN_RECORDED_INTERVAL"))
    observations.sort(key=lambda row: (row["consensus_completed_ns"], row["observer"]))
    witnesses = []
    for agreement in agreements:
        identity = protocol.digest(agreement["risks"][cid])
        if identity not in identities:
            continue
        classifications = []
        for subject in config["subjects"]:
            key = subject["cid"]
            block = blocks[key]
            native = dict(zip(block["timestamps_ns"], block["values"]))
            classifications.append(dict(cid=key, **followup.classify_agreement(
                agreement["risks"][key], agreement, reports[key], native, block["timestamps_ns"])))
        witnesses.append(dict(witness_id=agreement["witness_id"], local_risk_sha256=identity,
            observer=agreement["observer"], consensus_completed_ns=agreement["consensus_completed_ns"],
            classifications=classifications))
    pairs = []
    for ordinal, pair in enumerate(members):
        identity = protocol.digest(pair["risk"])
        views = [row for row in observations if row["local_risk_sha256"] == identity]
        matches = [row for row in witnesses if row["local_risk_sha256"] == identity]
        pairs.append(dict(role="ACTIVATION" if ordinal == 0 else "RENEWAL", risk_sha256=identity,
            observed_ns=pair["risk"]["observed_ns"], expires_ns=pair["risk"]["expires_ns"],
            pair_mod_revision=pair["pair_mod_revision"], vote=pair["proposal"]["decision"],
            vote_reason=pair["proposal"]["reason"], record=pair["risk"]["record"],
            assessment_status_counts=dict(Counter(v["assessment"]["status"] for v in views)),
            valid_bound_assessments=sum(v["pair_binding_valid"] for v in views),
            definitive_bound_assessments=sum(v["pair_binding_valid"] and v["assessment"]["status"] in
                {"SHADOW_PREVENT_AGREED", "OBSERVE", "DISAGREED"} for v in views),
            distinct_joint_witnesses=len(matches)))
    end_ts = terminal["record"]["sample"]["ts_ns"] if terminal else local[-1][1]["risk"]["observed_ns"]
    observed = {pair["risk"]["observed_ns"] for _, pair in local}
    missing = [ts for ts in blocks[cid]["timestamps_ns"] if target["activation_ts_ns"] <= ts <= end_ts and ts not in observed]
    unseen = [p["risk_sha256"] for p in pairs if not p["valid_bound_assessments"]]
    indeterminate = [p["risk_sha256"] for p in pairs if p["valid_bound_assessments"] and not p["definitive_bound_assessments"]]
    expiry = max(p["expires_ns"] for p in pairs)
    short_followup = [s["cid"] for s in config["subjects"] if last_assessment.get(s["cid"], 0) < expiry]
    complete = end_reason == "CLEAR_RECORDED" and not any((missing, unseen, indeterminate, short_followup))
    counts = Counter(c["status"] for w in witnesses for c in w["classifications"] if c["cid"] == cid)
    return dict(schema_version=SCHEMA, status="TRACED" if complete else "TRACED_WITH_INCOMPLETE_COVERAGE",
        policy=POLICY, target=target, generation=generation,
        lifecycle=dict(end_reason=end_reason, terminal_record=None if terminal is None else terminal["record"],
            native_samples_not_seen=missing, pairs_without_valid_bound_assessment=unseen,
            pairs_with_only_indeterminate_assessments=indeterminate,
            required_pair_expiry_followup_ns=expiry, last_assessment_ns_by_observer=last_assessment,
            observers_without_pair_expiry_followup=short_followup,
            local_pairs=len(pairs), renewals=max(0, len(pairs)-1), complete_recorded_lifecycle=complete),
        activation_pair=pairs[0], renewal_pairs=pairs[1:], consensus_observations=observations,
        initial_pair_joint_witnesses=pairs[0]["distinct_joint_witnesses"],
        renewal_joint_witnesses=sum(p["distinct_joint_witnesses"] for p in pairs[1:]),
        distinct_joint_witnesses=len(witnesses), joint_classification_counts_for_target_port=dict(counts),
        joint_witnesses=witnesses, boundary=protocol.BOUNDARY, causal_filtering_established=False,
        deadline_feasibility="UNKNOWN", sla_protection_established=False,
        promotion_eligible=False, deployment_eligible=False, limitations=LIMITATIONS)


def build(path, cid, activation_index, output):
    if path.absolute().is_symlink() or output.absolute().is_symlink():
        raise ValueError("fontes/saídas não podem ser links simbólicos")
    path, output = path.resolve(), output.resolve()
    root = path.parent
    if (output.exists() or output.parent != root.parent or not output.name.startswith(OUTPUT_PREFIX)):
        raise ValueError("use novo diretório qos-shadow-alert-trace-* irmão do piloto")
    raw = cohort.read_json(path)
    modules = {module.SCHEMA: module for module in cohort.MODULES.values()}
    module = modules.get(raw.get("schema_version")) if isinstance(raw, dict) else None
    if module is None:
        raise ValueError("protocolo de piloto shadow não reconhecido")
    sources, code = cohort.inventory([dict(root=str(root))]), code_snapshot()
    p = module.load_protocol(path)
    receipt = cohort.sealed(root / "pilot" / "pilot-run.json", module.RECEIPT_SCHEMA, "run_sha256")
    name = "control-observation.json" if module is cohort.controls else "paired-timing.json"
    original = cohort.sealed(root / "pilot" / name, module.REPORT_SCHEMA, "report_sha256")
    if module.evaluate(path, receipt) != original:
        raise ValueError("relatório original não reproduzido exatamente")
    config = cohort.controls.diagnostic.load_config(root / "shadow-config.json")
    shadow = cohort.shadow_root(root, receipt)
    series, _, _ = provenance._read_case(p, p["case"], root / "pilot" / "workload")
    journals = {s["cid"]: paired.read_journal(shadow / f"{s['cid']}.ndjson") for s in config["subjects"]}
    result = analyze(config, shadow.name, series, journals, cid, activation_index)
    if (module.load_protocol(path) != p or cohort.inventory([dict(root=str(root))]) != sources
            or code_snapshot() != code):
        raise ValueError("fontes/código mudaram durante o diagnóstico")
    result.update(source_protocol=str(path), protocol_sha256=p["protocol_sha256"],
        source_report_sha256=original["report_sha256"], source_receipt_sha256=receipt["run_sha256"],
        shadow_run=str(shadow), source_files_sha256=sources, code_sha256=code,
        protected_lineage_sha256=p["source_artifacts_sha256"], original_v4_status=p["source_criteria_status"],
        originals_unchanged=True, original_report_reproduced=True,
        report_execution=dict(offline=True, source_writes=False, api_calls=False, etcd_writes=False,
                              new_traffic=False, fitting=False, authority=False, actuation=False, llm=False))
    result = provenance.seal(result, "report_sha256")
    output.mkdir()
    provenance.write_new_json(output / "alert-trace.json", result)
    with (output / "alert-trace.md").open("x", encoding="utf-8") as handle:
        handle.write(render_markdown(result))
    return result


def render_markdown(report):
    target, cycle = report["target"], report["lifecycle"]
    lines = ["# CoMAS — ciclo de alerta shadow (offline)", "",
        f"Estado: `{report['status']}`. Não é aprovação de atuação ou prova de filtragem causal.", "",
        f"Alvo: `{target['cid']}/{target['port_id']}`; índice `{target['activation_index']}`; motivo `{target['reason']}`.",
        f"Encerramento registrado: `{cycle['end_reason']}`; pares: {cycle['local_pairs']}; renovações: {cycle['renewals']}.",
        f"Acordos distintos do par inicial: {report['initial_pair_joint_witnesses']}; das renovações: {report['renewal_joint_witnesses']}.",
        "Pares e visões dos observadores não são alarmes, ações ou ensaios independentes.", "",
        "| Par | Observação ns | Voto | Estados registrados | Acordos distintos |",
        "|---|---:|---|---|---:|"]
    for pair in [report["activation_pair"], *report["renewal_pairs"]]:
        lines.append(f"| {pair['role']} | {pair['observed_ns']} | {pair['vote']} | {pair['assessment_status_counts']} | {pair['distinct_joint_witnesses']} |")
    lines.extend(["", f"Classificações por observação do domínio-alvo: `{report['joint_classification_counts_for_target_port']}`.",
        "Cada renovação usa seu próprio horizonte; um acordo posterior pode corresponder a um episódio posterior.",
        f"Amostras nativas não vistas no ciclo: `{cycle['native_samples_not_seen']}`.",
        f"Pares sem avaliação vinculada válida: `{cycle['pairs_without_valid_bound_assessment']}`.",
        f"Pares apenas indeterminados: `{cycle['pairs_with_only_indeterminate_assessments']}`; observadores sem acompanhamento até a expiração: `{cycle['observers_without_pair_expiry_followup']}`.",
        "", "## Proveniência e limites", "", f"Protocolo: `{report.get('source_protocol')}`.",
        f"Relatório original SHA256: `{report.get('source_report_sha256')}`.",
        "O JSON preserva hashes, pares, estados, observadores, tempos inteiros e classificações por domínio.", ""])
    return "\n".join([*lines, *(f"- {item}" for item in report["limitations"])]) + "\n"


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--cid", required=True)
    parser.add_argument("--activation-index", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        report = build(args.protocol, args.cid, args.activation_index, args.output)
        cycle = report["lifecycle"]
        print(f"status={report['status']} end={cycle['end_reason']} pairs={cycle['local_pairs']} renewals={cycle['renewals']} initial_agreements={report['initial_pair_joint_witnesses']} renewal_agreements={report['renewal_joint_witnesses']} originals_unchanged=true offline=true")
        print(f"joint_followup={report['joint_classification_counts_for_target_port']} native_gaps={len(cycle['native_samples_not_seen'])} unassessed_pairs={len(cycle['pairs_without_valid_bound_assessment'])} indeterminate_pairs={len(cycle['pairs_with_only_indeterminate_assessments'])} expiry_followup_gaps={len(cycle['observers_without_pair_expiry_followup'])}")
        renewal_states = Counter()
        for pair in report["renewal_pairs"]:
            renewal_states.update(pair["assessment_status_counts"])
        print(f"initial_states={report['activation_pair']['assessment_status_counts']} renewal_states={dict(renewal_states)}")
        print(f"json={args.output / 'alert-trace.json'}")
        print(f"markdown={args.output / 'alert-trace.md'}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, StopIteration) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
