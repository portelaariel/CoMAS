#!/usr/bin/env python3
"""Freeze the inspected preventive-entry rule for NEW shadow-only QoS traces.

No source result, forecaster, runtime decision path or actuator is modified.
CSV warning lead is not a measurement of consensus/authority/action latency.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from dataclasses import replace
from pathlib import Path
from typing import Any, Dict, Sequence

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import predictive_sla_validation_v3 as v3
import predictive_sla_damped_replay as replay
import predictive_sla_horizon_sensitivity as sensitivity
import predictive_sla_preventive_entry_study as entry
from qos_damped_holt import QosDampedHoltModel
from qos_holt import QosHoltModel


ROOT = Path(__file__).resolve().parent
PROTOCOL_SCHEMA = "comas-predictive-sla-prospective/4"
SUMMARY_SCHEMA = "comas-predictive-sla-validation-summary/4"
PRIMARY, REFERENCE = v3.PRIMARY, v3.REFERENCE
# The forecast gate changes, NOT the observed-future window scoring target.
POLICY = {**v3.POLICY, "required_consecutive_horizons": 1}
SCORING_POLICY = dict(v3.POLICY)
CRITERIA = dict(v3.CRITERIA)
CODE_FILES = (*entry.CODE_FILES, "predictive_sla_validation_v4.py",
              "scripts/collect_qos_validation_campaign_v4.py")
BOUNDARY = dict(mode="shadow_telemetry_collection_then_offline_replay",
                runtime_changed=False, live_risk_publication=False, predictive_agent_consensus=False,
                authority_request=False, actuator_request=False, llm_consulted=False)
LIMITATIONS = [
    "The one-horizon/preventive-entry rule was motivated by inspected v3 results; those results remain post-hoc and NOT_PASSED if originally so.",
    "Only new traces collected after this v4 freeze test the fixed candidate prospectively; no fitting or recalibration uses them.",
    "Both copied models use the same one-horizon and preventive-entry rules on the same fresh traces; primary criteria concern selected_warning90.",
    "Window truth remains the v3 two-adjacent-observed-horizon target; fewer preventive activations do not improve raw forecast accuracy.",
    "Current utilization below .80 permits new entry but does not itself establish anticipation; the strict timestamp episode matcher is unchanged.",
    "All instantaneous observed crossings and two-sample sustained confirmations remain recorded, including priming and unscored tails.",
    "Already-active forecast alerts retain their original renewal/two-window clearing; a current breach alone cannot clear them.",
    "The six acceptance criteria are unchanged; every eligible ramp episode must be anticipated and late/duplicate/control alarms are not excused.",
    "Twelve workloads share a testbed and two correlated ports; new traces are not a guarantee of statistical independence, scalability or generalization.",
    "Warning lead is conditional on matched episodes and measured from CSV timestamps, not from an online alert-publication timestamp.",
    "Consensus, authority, LLM and actuation latencies are NOT_MEASURED, not zero; no end-to-end deadline or SLA protection is established.",
    "No model is loaded into the live CoMAS decision path; even passing warning criteria never automatically enables deployment or promotion.",
]


def code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def _sealed(path: Path, schema: str, field: str) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != schema or payload != v1.seal(payload, field):
        raise ValueError(f"schema/checksum inválido: {path.name}")
    return payload


def _source_state(parent_path: Path, campaign: Path, study_path: Path) -> tuple:
    """Check old lineage/hashes without refitting or selecting a rule again."""
    if any(p.absolute().is_symlink() for p in (parent_path, campaign, study_path)):
        raise ValueError("fontes v3 não podem ser links simbólicos")
    parent_path, campaign, study_path = (p.resolve() for p in (parent_path, campaign, study_path))
    if (campaign != parent_path.parent / "campaign" or study_path.parent != parent_path.parent
            or not study_path.name.startswith("preventive-entry") or study_path.suffix != ".json"):
        raise ValueError("use campanha v3 oficial e preventive-entry*.json junto ao protocolo v3")
    parent = v3.load_protocol(parent_path)
    official = _sealed(campaign / "campaign-summary.json", v3.SUMMARY_SCHEMA, "report_sha256")
    saved = _sealed(study_path, entry.SCHEMA, "report_sha256")
    horizon_path = Path(saved["source_study"]["path"]).resolve()
    if (horizon_path.parent != parent_path.parent or not horizon_path.name.startswith("horizon-sensitivity")
            or horizon_path.suffix != ".json"):
        raise ValueError("estudo de horizontes fora da origem v3")
    horizon = _sealed(horizon_path, sensitivity.SCHEMA, "report_sha256")
    protected = sensitivity._snapshot(parent, parent_path, campaign, official)
    expected_entry_sources = {**protected, str(horizon_path): v1.digest_file(horizon_path)}
    if (official["status"] != "COMPLETED" or official["evaluated_runs"] != 12
            or official["protocol_sha256"] != parent["protocol_sha256"]
            or saved["status"] != "ENTRY_STUDY_COMPLETED" or saved["entry_rule"] != entry.ENTRY_RULE
            or saved["protocol_path"] != str(parent_path) or saved["campaign_root"] != str(campaign)
            or saved["protocol_sha256"] != parent["protocol_sha256"]
            or saved["protected_source_sha256"] != expected_entry_sources
            or saved["code_sha256"] != entry.code_snapshot()
            or saved["source_study"]["sha256"] != v1.digest_file(horizon_path)
            or saved["source_study"]["report_sha256"] != horizon["report_sha256"]
            or saved["selected_variant"] != "NONE"
            or any(saved.get(k) is not False for k in ("refit", "recalibration", "promotion_eligible",
                                                     "deployment_eligible", "runtime_changed", "independent_test"))):
        raise ValueError("campanha/diagnóstico v3 mudou ou não corresponde ao estudo concluído")
    expected_official = dict(status=official["status"], criteria_status=official["criteria_status"],
                            checks=official["checks"], evaluated_runs=12, planned_runs=12,
                            report_sha256=official["report_sha256"],
                            summary_file_sha256=v1.digest_file(campaign / "campaign-summary.json"))
    if saved["official_v3"] != expected_official:
        raise ValueError("diagnóstico não preserva o resultado oficial v3")
    # Run records must also retain their recorded CSV hashes and identities.
    v2._snapshot_sources(parent, campaign)
    for name, model in saved["models"].items():
        if (model["model_id"] != parent["models"][name]["model_id"]
                or model["model_sha256"] != parent["models"][name]["sha256"]):
            raise ValueError("modelo do estudo difere da origem v3")
    if set(saved["models"]) != {PRIMARY, REFERENCE}:
        raise ValueError("modelos incompletos no estudo v3")
    protected = {**expected_entry_sources, str(study_path): v1.digest_file(study_path)}
    if any(v1.digest_file(Path(p)) != sha for p, sha in saved["protected_source_sha256"].items()):
        raise ValueError("fontes protegidas do diagnóstico v3 mudaram")
    latest = max(parent["created_ns"], *(json.loads(
        (campaign / c["case_id"] / "run.json").read_text())["ended_ns"] for c in parent["cases"]))
    excluded = sorted(set(parent["excluded_csv_sha256"]) |
                      {sha for case in official["cases"] for sha in case["source_sha256"]})
    source = dict(protocol_path=str(parent_path), campaign_root=str(campaign), entry_study_path=str(study_path),
                  protocol_sha256=parent["protocol_sha256"], summary_sha256=v1.digest_file(campaign / "campaign-summary.json"),
                  criteria_status=official["criteria_status"], entry_report_sha256=saved["report_sha256"],
                  entry_file_sha256=v1.digest_file(study_path), latest_run_ended_ns=latest)
    return parent, saved, protected, excluded, source


def _expected(parent: Dict[str, Any]) -> Dict[str, Any]:
    return dict(scope="prospective_fixed_preventive_entry_shadow_warning_evaluation",
                promotion_eligible=False, deployment_eligible=False, refit=False, recalibration=False,
                primary_model=PRIMARY, reference_model=REFERENCE, policy=POLICY, scoring_policy=SCORING_POLICY,
                entry_rule=entry.ENTRY_RULE, acceptance_criteria=CRITERIA, execution_boundary=BOUNDARY,
                subjects=v1.SUBJECTS, quality=v1.QUALITY, collection=v1.COLLECTION,
                sample_interval_s=2, horizons_steps=[2, 4, 6], repetitions=3, cases=v1.planned_cases(3),
                evaluation_unit=v3.EVALUATION_UNIT, independence_guaranteed=False,
                selected_parameters=parent["development"]["selected_parameters"], limitations=LIMITATIONS)


def freeze_protocol(source_protocol: Path, source_campaign: Path, entry_study: Path, output: Path) -> Dict[str, Any]:
    requested = output.absolute()
    source_protocol, source_campaign, entry_study, output = (
        p.resolve() for p in (source_protocol, source_campaign, entry_study, output))
    if (requested.is_symlink() or output.exists() or output.parent != source_protocol.parent.parent
            or not output.name.startswith("qos-prospective-v4")):
        raise ValueError("use novo diretório qos-prospective-v4* irmão do protocolo v3; não sobrescreva fontes")
    parent, saved, protected, excluded, source = _source_state(source_protocol, source_campaign, entry_study)
    code = code_snapshot()
    verified = entry.study(source_protocol, source_campaign, Path(saved["source_study"]["path"]))
    # A different Git commit is expected; all previous measured facts must reproduce.
    def facts(payload):
        return {k: v for k, v in payload.items() if k not in ("git_commit", "report_sha256")}
    if facts(saved) != facts(verified):
        raise ValueError("diagnóstico de entrada não reproduz integralmente a origem v3")
    created_ns = time.time_ns()
    if created_ns <= source["latest_run_ended_ns"]:
        raise ValueError("congelamento v4 deve ser posterior ao encerramento v3")
    contents = {name: (source_protocol.parent / m["path"]).read_bytes() for name, m in parent["models"].items()}
    payload = v1.seal(dict(**_expected(parent), schema_version=PROTOCOL_SCHEMA, created_ns=created_ns,
                          models=parent["models"], code_sha256=code, protected_source_sha256=protected,
                          excluded_csv_sha256=excluded, source_v3=source,
                          git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()),
                      "protocol_sha256")
    if (_source_state(source_protocol, source_campaign, entry_study)[2] != protected or code_snapshot() != code):
        raise ValueError("fontes/código mudaram durante o congelamento; nenhum protocolo será publicado")
    output.mkdir(exist_ok=False)
    (output / "models").mkdir()
    for name, content in contents.items():
        with (output / payload["models"][name]["path"]).open("xb") as handle:
            handle.write(content)
    v1.write_new_json(output / "protocol.json", payload)
    load_protocol(output / "protocol.json")
    return payload


def load_protocol(path: Path) -> Dict[str, Any]:
    path = path.resolve()
    p = _sealed(path, PROTOCOL_SCHEMA, "protocol_sha256")
    if p["code_sha256"] != code_snapshot():
        raise ValueError("código mudou desde o congelamento v4")
    source = p["source_v3"]
    parent_path = Path(source["protocol_path"])
    if path.parent.parent != parent_path.resolve().parent.parent or not path.parent.name.startswith("qos-prospective-v4"):
        raise ValueError("protocolo v4 fora do diretório irmão qos-prospective-v4*")
    parent, _, protected, excluded, verified_source = _source_state(
        parent_path, Path(source["campaign_root"]), Path(source["entry_study_path"]))
    if (any(p.get(k) != value for k, value in _expected(parent).items())
            or p["source_v3"] != verified_source or p["protected_source_sha256"] != protected
            or p["excluded_csv_sha256"] != excluded or p["models"] != parent["models"]
            or p["created_ns"] <= verified_source["latest_run_ended_ns"]
            or any(p.get(k) is not False for k in ("refit", "recalibration", "promotion_eligible",
                                                 "deployment_eligible", "independence_guaranteed"))):
        raise ValueError("configuração/fontes divergem do protocolo v4 congelado")
    for name, specification in p["models"].items():
        model_path = (path.parent / specification["path"]).resolve()
        loader = QosDampedHoltModel if name == PRIMARY else QosHoltModel
        if (not model_path.is_relative_to(path.parent) or v1.digest_file(model_path) != specification["sha256"]
                or loader.load(model_path).resolved_model_id() != specification["model_id"]):
            raise ValueError(f"modelo congelado v4 mudou: {name}")
    return p


def campaign_path(protocol_path: Path, campaign: Path, *, new: bool = False) -> Path:
    requested, resolved = campaign.absolute(), campaign.resolve()
    if (requested.is_symlink() or resolved.parent != protocol_path.resolve().parent
            or not (resolved.name == "campaign" or resolved.name.startswith("campaign-"))):
        raise ValueError("v4 exige campaign ou campaign-* diretamente dentro do protocolo")
    if new and resolved.exists():
        raise ValueError("saída já existe; não sobrescreva ou retome campanha")
    return resolved


def replay_candidate(model: QosHoltModel, subject: Dict[str, Any]) -> tuple:
    """Reuse the byte-frozen v3 and diagnostic semantics on fresh values.

    SCORING_POLICY is also the unchanged persistence/observed-channel policy;
    only replay_gate changes the forecast requirement to one horizon. This
    preserves the TWO-horizon truth labels used in the post-hoc comparison.
    """
    baseline = replay.replay_series(model, subject, SCORING_POLICY)
    if type(model) is QosHoltModel:
        replay._check_native_reference(model, subject, SCORING_POLICY, baseline)
    raw = sensitivity.replay_gate(model, subject, baseline, SCORING_POLICY, 1)
    gated = entry.replay_entry(subject, raw, SCORING_POLICY)
    return raw, gated


def operational_timing(summary: Dict[str, Any]) -> Dict[str, Any]:
    return dict(status="NOT_MEASURED", execution_boundary=BOUNDARY,
                csv_warning_lead_time_s=summary["lead_time_s"],
                lead_scope="matched_episodes_only; CSV_acquisition_to_retrospective_episode_onset",
                consensus_latency_s=None, authority_latency_s=None, actuation_latency_s=None,
                llm_inference_latency_s=None, end_to_end_latency_s=None,
                deadline_feasibility="UNKNOWN", sla_protection_established=False)


def evaluate_campaign(protocol_path: Path, campaign: Path) -> Dict[str, Any]:
    protocol_path = protocol_path.resolve()
    campaign = campaign_path(protocol_path, campaign)
    p = load_protocol(protocol_path)
    code, protected = code_snapshot(), dict(p["protected_source_sha256"])
    plan = campaign / "campaign-plan.json"
    new_sources = {}
    if plan.exists():
        if plan.is_symlink() or json.loads(plan.read_text(encoding="utf-8")) != p:
            raise ValueError("plano da campanha diverge do protocolo v4 congelado")
        new_sources[str(plan.resolve())] = v1.digest_file(plan)
    artifacts = {}
    for name, specification in p["models"].items():
        model = (QosDampedHoltModel if name == PRIMARY else QosHoltModel).load(protocol_path.parent / specification["path"])
        artifacts[name] = replace(model, model_id=model.resolved_model_id())
    results, missing, errors, intervals, seen = [], [], [], [], set()
    for case in p["cases"]:
        case_root = campaign / case["case_id"]
        if not (case_root / "run.json").exists():
            missing.append(case["case_id"])
            continue
        try:
            if case_root.is_symlink() or case_root.resolve().parent != campaign:
                raise ValueError("diretório de execução fora da nova campanha")
            record_hash = v1.digest_file(case_root / "run.json")
            subjects, record, hashes = v1._read_case(p, case, case_root)
            if len(set(hashes)) != len(hashes) or seen.intersection(hashes) or set(p["excluded_csv_sha256"]).intersection(hashes):
                raise ValueError("CSV reutilizado; v4 exige novas coletas posteriores ao congelamento")
            if record.get("cleanup_errors"):
                raise ValueError("cleanup incompleto; execução não será aceita")
            interval = record["started_ns"], record["ended_ns"]
            if any(max(interval[0], old[0]) < min(interval[1], old[1]) for old in intervals):
                raise ValueError("execuções sobrepostas não são repetições separadas")
            models = {}
            for name, model in artifacts.items():
                raw_blocks, blocks = [], []
                for subject, source in zip(subjects, record["sources"]):
                    raw, gated = replay_candidate(model, subject)
                    for block in (raw, gated):
                        block.update(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                                     source_sha256=source["sha256"])
                    raw_blocks.append(raw)
                    blocks.append(gated)
                models[name] = dict(model_id=model.resolved_model_id(), series=blocks, aggregate=replay.aggregate(blocks),
                                    ungated_reference=dict(series=raw_blocks, aggregate=replay.aggregate(raw_blocks)),
                                    paired_entry_changes=entry._pair(raw_blocks, blocks))
            pair = replay.paired_changes(models[REFERENCE]["series"], models[PRIMARY]["series"])
            results.append(dict(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                                started_ns=record["started_ns"], ended_ns=record["ended_ns"], run_sha256=record["run_sha256"],
                                source_sha256=hashes, same_series_paired=True, observed_episodes_identical=pair["ground_truth_matches"],
                                delivery_checks=[dict(cid=s["cid"], port_id=s["port_id"], stages=s["delivery_checks"]) for s in subjects],
                                models=models, paired_changes=pair))
            seen.update(hashes)
            intervals.append(interval)
            new_sources[str((case_root / "run.json").resolve())] = record_hash
            new_sources.update({str((case_root / row["csv"]).resolve()): row["sha256"] for row in record["sources"]})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(case_id=case["case_id"], error=str(exc)))
    complete = not missing and not errors and len(results) == 12
    checks = {name: v3.assess_criteria(results, complete, name) for name in artifacts}
    summaries = {}
    for name in artifacts:
        blocks = [s for c in results for s in c["models"][name]["series"]]
        raw = [s for c in results for s in c["models"][name]["ungated_reference"]["series"]]
        summary = v3._summarize(blocks, [c for c in p["cases"] if c["case_id"] in {r["case_id"] for r in results}])
        summaries[name] = {**summary, "ungated_one_horizon": v3._summarize(raw, p["cases"]),
                           "paired_entry_changes": entry._pair(raw, blocks), "operational_timing": operational_timing(summary)}
    pair = replay.paired_changes([s for c in results for s in c["models"][REFERENCE]["series"]],
                                 [s for c in results for s in c["models"][PRIMARY]["series"]])
    load_protocol(protocol_path)
    if code_snapshot() != code or any(v1.digest_file(Path(path)) != sha for path, sha in {**protected, **new_sources}.items()):
        raise ValueError("fontes/código mudaram durante a avaliação")
    return v1.seal(dict(
        schema_version=SUMMARY_SCHEMA, protocol_sha256=p["protocol_sha256"],
        status="COMPLETED" if complete else "INCOMPLETE_OR_INVALID", scope=p["scope"],
        planned_runs=12, evaluated_runs=len(results), missing_runs=missing, invalid_runs=errors,
        primary_model=PRIMARY, reference_model=REFERENCE, promotion_eligible=False, deployment_eligible=False,
        refit=False, recalibration=False, new_data_used_for_fitting=False, statistical_superiority_assessed=False,
        prospective_new_traces=True, independence_guaranteed=False, evaluation_unit=v3.EVALUATION_UNIT,
        criteria_status="PASSED" if all(checks[PRIMARY].values()) else "NOT_PASSED",
        checks=checks[PRIMARY], checks_by_model=checks, acceptance_criteria=CRITERIA,
        policy=POLICY, scoring_policy=SCORING_POLICY, entry_rule=entry.ENTRY_RULE, execution_boundary=BOUNDARY,
        source_v3_criteria_status=p["source_v3"]["criteria_status"], source_v3_unchanged=True,
        models=summaries, paired_changes=pair, cases=results, source_sha256=dict(sorted(new_sources.items())),
        operational_timing=operational_timing(summaries[PRIMARY]), limitations=LIMITATIONS), "report_sha256")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--source-protocol", type=Path, required=True)
    freeze.add_argument("--source-campaign", type=Path, required=True)
    freeze.add_argument("--entry-study", type=Path, required=True)
    freeze.add_argument("--output", type=Path, required=True)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--protocol", type=Path, required=True)
    evaluate.add_argument("--campaign-root", type=Path, required=True)
    evaluate.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            p = freeze_protocol(args.source_protocol, args.source_campaign, args.entry_study, args.output)
            print(f"protocol={args.output.resolve() / 'protocol.json'}")
            print(f"runs=12 traffic_minutes={sum(c['duration_s'] for c in p['cases']) / 60:.1f} models=2 shadow_only=true")
            print("forecast_horizons_required=1 activation_windows=1 new_entry_observed_below=0.8 criteria_unchanged=true")
            print("consensus_actuation_timing=NOT_MEASURED promotion_eligible=false deployment_eligible=false")
            print(f"protocol_sha256={p['protocol_sha256']}")
            return 0
        target, output = args.output.absolute(), args.output.resolve()
        if (target.is_symlink() or output.exists() or output.parent != args.protocol.resolve().parent
                or output.suffix != ".json" or not output.name.startswith("campaign-review")):
            raise ValueError("use novo campaign-review*.json diretamente no diretório v4")
        report = evaluate_campaign(args.protocol, args.campaign_root)
        v1.write_new_json(output, report)
        print(f"status={report['status']} runs={report['evaluated_runs']}/12 criteria={report['criteria_status']}")
        return v3.report_exit_code(report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
