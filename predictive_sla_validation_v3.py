#!/usr/bin/env python3
"""Freeze selected warning parameters and evaluate only new prospective traces.

The model is copied, not fitted or deployed. Both forecasters receive the same
new shadow telemetry and use the existing fixed risk/persistence/episode rules.
"""

from __future__ import annotations

import argparse
import itertools
import json
import subprocess
import sys
import time
from dataclasses import replace
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Sequence

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import predictive_sla_damped_replay as replay
import train_qos_damped_holt_model as previous
import train_qos_warning_model as training
import qos_warning_selection as warning
from qos_damped_holt import QosDampedHoltModel
from qos_holt import QosHoltModel
from sla_episode_evaluation import summarize_episode_reports


ROOT = Path(__file__).resolve().parent
PROTOCOL_SCHEMA = "comas-predictive-sla-prospective/3"
SUMMARY_SCHEMA = "comas-predictive-sla-validation-summary/3"
PRIMARY, REFERENCE = "selected_warning90", "original_holt90"
EVALUATION_UNIT = "whole_workload_run; two_correlated_ports; no_independence_guarantee"
POLICY = dict(warning.WARNING_POLICY)
CRITERIA = dict(v2.CRITERIA)
CODE_FILES = (*training.CODE_FILES, "predictive_sla_validation_v3.py",
              "scripts/collect_qos_validation_campaign_v3.py")
LIMITATIONS = [
    "The model family/objective were developed after inspecting v2; only traces collected after this freeze evaluate the fixed selection prospectively.",
    "The selected model uses v1 repetitions 1/2 for selection and repetition 3 for interval calibration, never the new v3 traces.",
    "All horizons share one selected alpha/beta/phi tuple; the experiment does not test the full horizon-specific model family.",
    "The original and selected models receive identical new series with unchanged warning and episode rules; their forecasts need not coincide.",
    "Twelve workloads share a testbed and each has two correlated ports; windows/episodes are not independent repetitions or proof of generalization.",
    "Strict fresh-activation anticipation differs from coverage by an already active alert; late and unmatched alarms never count as anticipation.",
    "Warning lead time is conditional on anticipated episodes. Interval coverage is descriptive on the new series, not an operational guarantee.",
    "Two-second pulses may be diluted or split by two-second sampling; horizons are nominal sample steps with recorded acquisition jitter.",
    "Passing the selected-model criteria does not establish superiority over the original; no statistical superiority test is performed.",
    "Both models are evaluated offline on collected shadow telemetry, not loaded into the live CoMAS decision path.",
    "No LLM decision, preventive action, actuator timing, application SLA protection, deployment, automatic promotion or scalability is evaluated.",
]


def code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def _development_files(root: Path) -> tuple:
    return tuple(root / name for name in ("development-spec.json", "qos-warning-evaluation.json", "qos-warning-model.json"))


def load_development(root: Path, parent: Dict[str, Any]) -> tuple:
    """Check the existing receipt/selection lineage without re-running the search."""
    root = root.resolve()
    spec_path, report_path, model_path = _development_files(root)
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    report = json.loads(report_path.read_text(encoding="utf-8"))
    model = QosDampedHoltModel.load(model_path)
    if (spec.get("schema_version") != training.SCHEMA or report.get("schema_version") != training.SCHEMA
            or spec != v1.seal(spec, "development_spec_sha256") or report != v1.seal(report, "report_sha256")
            or report.get("status") != "WARNING_DEVELOPMENT_FITTED" or report.get("model_artifact_written") is not True
            or report.get("model_id") != model.resolved_model_id()
            or report.get("development_spec_sha256") != spec["development_spec_sha256"]
            or report.get("created_at") != spec["created_at"] or model.created_at != spec["created_at"]):
        raise ValueError("recibo/modelo selecionado ausente, alterado ou incompatível")
    for item in (spec, report, model.training):
        if item.get("promotion_eligible") is not False or item.get("deployment_eligible") is not False:
            raise ValueError("desenvolvimento não pode declarar promoção/deployment")
    if (spec.get("independent_test_used") is not False or report.get("test_evaluated") is not False
            or model.training.get("test_evaluated") is not False or spec.get("v2_used_for_fitting") is not False
            or report.get("v2_used_for_fitting") is not False or report.get("calibration_used_for_selection") is not False
            or report.get("baseline_exact") is not True or report.get("source_integrity_verified") is not True
            or report.get("original_v1_unchanged") is not True):
        raise ValueError("desenvolvimento não corresponde a seleção de treino v1 separada da calibração")
    source = parent["source_v1"]
    source_path, campaign = Path(source["protocol_path"]).resolve(), Path(source["campaign_root"]).resolve()
    if (root.parent != source_path.parent.parent or not root.name.startswith("qos-warning-development")
            or Path(spec["source_protocol"]).resolve() != source_path
            or Path(spec["source_campaign"]).resolve() != campaign
            or spec["source_protocol_sha256"] != source["protocol_sha256"]):
        raise ValueError("linhagem do modelo selecionado difere da origem v1 da campanha v2")
    for field in ("development_spec_sha256", "partitions", "source_series", "input_sha256", "code_sha256",
                  "source_protocol_sha256", "search_grid", "git_commit", "limitations"):
        if model.training.get(field) != spec[field]:
            raise ValueError(f"proveniência do modelo selecionado diverge: {field}")
    if (spec["code_sha256"] != training.code_snapshot() or spec["objective"] != warning.OBJECTIVE
            or model.training.get("selection_objective") != warning.OBJECTIVE
            or spec["warning_policy"] != POLICY or report["warning_policy"] != POLICY
            or model.training.get("warning_policy") != POLICY or spec["limitations"] != training.LIMITATIONS):
        raise ValueError("código/objetivo/política do desenvolvimento mudou")
    v1_protocol = v1.load_protocol(source_path)
    if previous.source_snapshot(v1_protocol, source_path, campaign) != spec["input_sha256"]:
        raise ValueError("fontes originais do treino/calibração mudaram")
    partitions, provenance = {"train": [], "calibration": []}, []
    for case in v1_protocol["cases"]:
        case_root = campaign / case["case_id"]
        subjects, record, _ = v1._read_case(v1_protocol, case, case_root)
        split = "train" if case["repetition"] in (1, 2) else "calibration"
        for item, raw in zip(subjects, record["sources"]):
            partitions[split].append({**item, "run_id": case["case_id"], "profile": case["profile"]})
            provenance.append(previous._series_provenance(item, case, raw, case_root, record, split))
    counts = {name: previous._partition_summary(items) for name, items in partitions.items()}
    native = QosHoltModel.load(source_path.parent / v1_protocol["models"]["coverage90"]["path"])
    if (spec["partitions"] != counts or report["partitions"] != counts or spec["source_series"] != provenance
            or counts["train"]["workload_runs"] != 8 or counts["calibration"]["workload_runs"] != 4
            or model.sample_interval_s != 2 or model.coverage != .9 or model.priming_samples != native.priming_samples
            or [h.horizon_steps for h in model.horizons] != [2, 4, 6]
            or spec["sample_interval_s"] != 2 or spec["horizons_steps"] != [2, 4, 6]
            or spec["coverage"] != .9 or spec["priming_samples"] != native.priming_samples):
        raise ValueError("partições/horizontes/priming do desenvolvimento incompatíveis")
    grid = spec["search_grid"]
    if grid != dict(alpha=list(training.ALPHAS), beta=list(training.BETAS), phi=list(training.PHIS)):
        raise ValueError("grade de seleção difere do código de treino congelado")
    expected_tuples = set(itertools.product(grid["alpha"], grid["beta"], grid["phi"]))
    search = report["selection"]
    candidates = search["candidates"]
    actual_tuples = [(c["parameters"]["alpha"], c["parameters"]["beta"], c["parameters"]["phi"]) for c in candidates]
    if (len(candidates) != len(expected_tuples) or set(actual_tuples) != expected_tuples
            or search["candidate_count"] != len(candidates) or search["objective"] != warning.OBJECTIVE
            or search["calibration_used_for_selection"] is not False or search["v2_used_for_selection"] is not False
            or search["watch_used_for_selection"] is not False):
        raise ValueError("tabela/contrato da seleção de treino mudou")
    for c in candidates:
        t = c["score"]["totals"]
        if c["score"]["feasible"] != (t["control_activations"] == t["censored_activations"] == 0 and t["anticipated"] > 0):
            raise ValueError("viabilidade do candidato diverge dos fatos registrados")
    feasible = sorted((c for c in candidates if c["score"]["feasible"]), key=warning.selection_key)
    if not feasible or search["feasible_candidates"] != len(feasible) or search["selected"] != feasible[0]:
        raise ValueError("modelo não corresponde à seleção lexicográfica registrada")
    parameters = search["selected"]["parameters"]
    if any(dict(alpha=h.alpha, beta=h.beta, phi=h.phi) != parameters for h in model.horizons):
        raise ValueError("parâmetros do modelo não correspondem à seleção compartilhada")
    expected_horizons = [dict(horizon_s=h.horizon_steps * 2, alpha=h.alpha, beta=h.beta, phi=h.phi,
                             interval_radius=h.interval_radius, calibration_samples=h.calibration_samples,
                             training=h.training_metrics, calibration_descriptive=h.calibration_metrics, test=None)
                         for h in model.horizons]
    if report["horizons"] != expected_horizons:
        raise ValueError("intervalos/métricas do modelo diferem do recibo")
    # Verify saved selected warnings on TRAIN only; no search or recalibration.
    blocks = warning.run_blocks(model, partitions["train"])
    if (report["selected_training"] != dict(summary=replay.aggregate(blocks), series=blocks)
            or warning.score_blocks(blocks) != search["selected"]["score"]):
        raise ValueError("resultados selecionados não reproduzem o recibo de treino")
    return spec, report, model


def source_snapshot(parent_path: Path, campaign: Path, development: Path, parent: Dict[str, Any]) -> Dict[str, str]:
    files = [parent_path, campaign / "campaign-summary.json", parent_path.parent / "selection-analysis.json",
             *_development_files(development)]
    files.extend(parent_path.parent / entry["path"] for entry in parent["models"].values())
    snapshot = {str(p.resolve()): v1.digest_file(p) for p in files}
    native = QosHoltModel.load(parent_path.parent / parent["models"]["coverage90"]["path"])
    for row in native.training.get("source_series", []):
        csv = Path(row["csv"]).resolve()
        checksum = v1.digest_file(csv)
        if checksum != row["csv_sha256"]:
            raise ValueError("CSV congelado do piloto mudou; preserve-o e investigue")
        snapshot[str(csv)] = checksum
    snapshot.update({row["path"]: row["sha256"] for row in v2._snapshot_sources(parent, campaign)})
    path = Path(parent["source_v1"]["protocol_path"])
    snapshot.update(previous.source_snapshot(v1.load_protocol(path), path, Path(parent["source_v1"]["campaign_root"])))
    return dict(sorted(snapshot.items()))


def excluded_csvs(parent: Dict[str, Any], baseline: Dict[str, Any], native: QosHoltModel) -> list:
    hashes = set(parent["source_v1"]["excluded_csv_sha256"])
    hashes.update(sha for case in baseline["cases"] for sha in case["source_sha256"])
    hashes.update(row["csv_sha256"] for row in native.training.get("source_series", []))
    return sorted(hashes)


def _latest_source_ns(parent: Dict[str, Any], campaign: Path, spec: Dict[str, Any]) -> int:
    created = datetime.fromisoformat(spec["created_at"])
    if created.tzinfo is None:
        raise ValueError("recibo de treino deve declarar fuso horário")
    created_ns = int(created.timestamp()) * 1_000_000_000 + created.microsecond * 1000
    return max(created_ns, *(json.loads(
        (campaign / case["case_id"] / "run.json").read_text(encoding="utf-8"))["ended_ns"] for case in parent["cases"]))


def freeze_protocol(source_protocol: Path, source_campaign: Path, development: Path, output: Path) -> Dict[str, Any]:
    requested = output.absolute()
    source_protocol, source_campaign, development, output = (
        p.resolve() for p in (source_protocol, source_campaign, development, output))
    if requested.is_symlink() or output.exists():
        raise ValueError("saída já existe ou é link simbólico; use novo diretório v3")
    if output.parent != source_protocol.parent.parent or not output.name.startswith("qos-prospective-v3"):
        raise ValueError("v3 exige novo diretório qos-prospective-v3* irmão do protocolo v2")
    parent = v2.load_protocol(source_protocol)
    if source_campaign != source_protocol.parent / "campaign":
        raise ValueError("use a campanha v2 oficial dentro do protocolo de origem")
    before, code = source_snapshot(source_protocol, source_campaign, development, parent), code_snapshot()
    baseline = v2.evaluate_campaign(source_protocol, source_campaign)
    if (baseline["status"] != "COMPLETED" or baseline["evaluated_runs"] != 12
            or json.loads((source_campaign / "campaign-summary.json").read_text(encoding="utf-8")) != baseline):
        raise ValueError("campanha/relatório v2 incompleto ou divergente")
    spec, report, selected = load_development(development, parent)
    created_ns = time.time_ns()
    if created_ns <= _latest_source_ns(parent, source_campaign, spec):
        raise ValueError("congelamento v3 deve ser posterior ao treino e encerramento v2")
    native_path = source_protocol.parent / parent["models"]["coverage90"]["path"]
    native = QosHoltModel.load(native_path)
    source_models = {PRIMARY: development / "qos-warning-model.json", REFERENCE: native_path}
    contents = {name: path.read_bytes() for name, path in source_models.items()}
    models = {name: dict(path=f"models/{name}.json", sha256=v1.digest_file(path),
                         model_id=(selected if name == PRIMARY else native).resolved_model_id(),
                         model_type=(selected if name == PRIMARY else native).model_type)
              for name, path in source_models.items()}
    payload = v1.seal(dict(
        schema_version=PROTOCOL_SCHEMA, created_ns=created_ns,
        scope="prospective_fixed_model_shadow_warning_evaluation", promotion_eligible=False, deployment_eligible=False,
        refit=False, recalibration=False, models=models, primary_model=PRIMARY, reference_model=REFERENCE,
        policy=POLICY, acceptance_criteria=CRITERIA, subjects=v1.SUBJECTS, quality=v1.QUALITY, collection=v1.COLLECTION,
        sample_interval_s=2, horizons_steps=[2, 4, 6], repetitions=3, cases=v1.planned_cases(3),
        evaluation_unit=EVALUATION_UNIT,
        code_sha256=code, protected_source_sha256=before,
        excluded_csv_sha256=excluded_csvs(parent, baseline, native),
        source_v2=dict(protocol_path=str(source_protocol), campaign_root=str(source_campaign),
                       protocol_sha256=parent["protocol_sha256"], summary_sha256=v1.digest_file(source_campaign / "campaign-summary.json"),
                       criteria_status=baseline["criteria_status"]),
        development=dict(root=str(development), spec_sha256=spec["development_spec_sha256"], report_sha256=report["report_sha256"],
                         selected_parameters=report["selection"]["selected"]["parameters"]),
        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        limitations=LIMITATIONS), "protocol_sha256")
    if source_snapshot(source_protocol, source_campaign, development, parent) != before or code_snapshot() != code:
        raise ValueError("fontes/código mudaram durante o congelamento; nenhum protocolo será publicado")
    output.mkdir(exist_ok=False)
    (output / "models").mkdir()
    for name, content in contents.items():
        with (output / models[name]["path"]).open("xb") as handle:
            handle.write(content)
    v1.write_new_json(output / "protocol.json", payload)
    load_protocol(output / "protocol.json")
    return payload


def load_protocol(path: Path) -> Dict[str, Any]:
    path = path.resolve()
    p = json.loads(path.read_text(encoding="utf-8"))
    if p.get("schema_version") != PROTOCOL_SCHEMA or p != v1.seal(p, "protocol_sha256"):
        raise ValueError("schema/checksum do protocolo v3 inválido")
    expected = dict(scope="prospective_fixed_model_shadow_warning_evaluation", promotion_eligible=False, deployment_eligible=False,
                    refit=False, recalibration=False, policy=POLICY, acceptance_criteria=CRITERIA,
                    subjects=v1.SUBJECTS, quality=v1.QUALITY, collection=v1.COLLECTION,
                    sample_interval_s=2, horizons_steps=[2, 4, 6], repetitions=3, cases=v1.planned_cases(3),
                    primary_model=PRIMARY, reference_model=REFERENCE, evaluation_unit=EVALUATION_UNIT,
                    limitations=LIMITATIONS)
    if any(p.get(key) != value for key, value in expected.items()) or any(
            p.get(key) is not False for key in ("promotion_eligible", "deployment_eligible", "refit", "recalibration")):
        raise ValueError("configuração diverge do protocolo v3 congelado")
    if p["code_sha256"] != code_snapshot():
        raise ValueError("código mudou desde o congelamento v3")
    source, d = p["source_v2"], p["development"]
    parent_path, campaign, development = Path(source["protocol_path"]), Path(source["campaign_root"]), Path(d["root"])
    parent = v2.load_protocol(parent_path)
    if path.parent.parent != parent_path.resolve().parent.parent or not path.parent.name.startswith("qos-prospective-v3"):
        raise ValueError("protocolo v3 deve permanecer no diretório irmão qos-prospective-v3*")
    if campaign.resolve() != parent_path.resolve().parent / "campaign" or source["protocol_sha256"] != parent["protocol_sha256"]:
        raise ValueError("origem da campanha v2 mudou")
    spec, report, selected = load_development(development, parent)
    baseline = json.loads((campaign / "campaign-summary.json").read_text(encoding="utf-8"))
    if (source_snapshot(parent_path, campaign, development, parent) != p["protected_source_sha256"]
            or source["summary_sha256"] != v1.digest_file(campaign / "campaign-summary.json")
            or source["criteria_status"] != baseline["criteria_status"] or baseline["status"] != "COMPLETED"
            or baseline["protocol_sha256"] != parent["protocol_sha256"]
            or d["spec_sha256"] != spec["development_spec_sha256"] or d["report_sha256"] != report["report_sha256"]
            or d["selected_parameters"] != report["selection"]["selected"]["parameters"]
            or p["created_ns"] <= _latest_source_ns(parent, campaign, spec)):
        raise ValueError("fontes/recibos protegidos mudaram ou congelamento v3 é anterior às fontes")
    native_path = parent_path.parent / parent["models"]["coverage90"]["path"]
    native = QosHoltModel.load(native_path)
    if p["excluded_csv_sha256"] != excluded_csvs(parent, baseline, native):
        raise ValueError("exclusão dos dados de piloto/v1/v2 mudou")
    source_models = {PRIMARY: (development / "qos-warning-model.json", selected), REFERENCE: (native_path, native)}
    expected_models = {name: dict(path=f"models/{name}.json", sha256=v1.digest_file(source_path),
                                  model_id=artifact.resolved_model_id(), model_type=artifact.model_type)
                       for name, (source_path, artifact) in source_models.items()}
    if p["models"] != expected_models:
        raise ValueError("modelos v3 devem ser cópias exatas dos artefatos selecionado e original")
    for name, entry in p["models"].items():
        model_path = (path.parent / entry["path"]).resolve()
        loader = QosDampedHoltModel if name == PRIMARY else QosHoltModel
        if (not model_path.is_relative_to(path.parent) or v1.digest_file(model_path) != entry["sha256"]
                or loader.load(model_path).resolved_model_id() != entry["model_id"]):
            raise ValueError(f"modelo congelado v3 mudou: {name}")
    return p


def campaign_path(protocol_path: Path, campaign: Path, *, new: bool = False) -> Path:
    requested, campaign = campaign.absolute(), campaign.resolve()
    if (requested.is_symlink() or campaign.parent != protocol_path.resolve().parent
            or not (campaign.name == "campaign" or campaign.name.startswith("campaign-"))):
        raise ValueError("v3 exige campaign ou campaign-* diretamente dentro do protocolo")
    if new and campaign.exists():
        raise ValueError("saída já existe; não sobrescreva ou retome campanha")
    return campaign


def assess_criteria(results: Sequence[Dict[str, Any]], complete: bool, model_name: str) -> Dict[str, bool]:
    # Preserve exactly the v2 criteria with only the explicitly named model mapped.
    mapped = [{**c, "models": {"coverage90": {**c["models"][model_name],
                "aggregate": {"episode_events": summarize_episode_reports([
                    s["episode_events"] for s in c["models"][model_name]["series"]])}}}} for c in results]
    return v2.assess_criteria(mapped, complete)


def _summarize(blocks: Sequence[Dict[str, Any]], cases: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    total = replay.aggregate(blocks)
    return {**total, "pooled_window_candidate": total["candidate"],
            "episode_events": summarize_episode_reports([s["episode_events"] for s in blocks]),
            "per_profile": {profile: replay.aggregate([s for s in blocks if s["profile"] == profile]) for profile in v1.profiles()},
            "per_run": {c["case_id"]: replay.aggregate([s for s in blocks if s["case_id"] == c["case_id"]]) for c in cases}}


def evaluate_campaign(protocol_path: Path, campaign: Path) -> Dict[str, Any]:
    protocol_path = protocol_path.resolve()
    campaign = campaign_path(protocol_path, campaign)
    p = load_protocol(protocol_path)
    code, protected = code_snapshot(), dict(p["protected_source_sha256"])
    artifacts = {}
    for name, entry in p["models"].items():
        artifact = (QosDampedHoltModel if name == PRIMARY else QosHoltModel).load(protocol_path.parent / entry["path"])
        artifacts[name] = replace(artifact, model_id=artifact.resolved_model_id())
    results, missing, errors, intervals, seen = [], [], [], [], set()
    new_sources = {}
    for case in p["cases"]:
        case_root = campaign / case["case_id"]
        if not (case_root / "run.json").exists():
            missing.append(case["case_id"])
            continue
        try:
            if case_root.is_symlink() or case_root.resolve().parent != campaign:
                raise ValueError("diretório de execução deve permanecer dentro da nova campanha")
            record_digest = v1.digest_file(case_root / "run.json")
            subjects, record, hashes = v1._read_case(p, case, case_root)
            if seen.intersection(hashes) or set(p["excluded_csv_sha256"]).intersection(hashes):
                raise ValueError("CSV de piloto/v1/v2/outra execução reutilizado; v3 exige novas coletas")
            if record.get("cleanup_errors"):
                raise ValueError("cleanup incompleto; execução não será aceita")
            interval = record["started_ns"], record["ended_ns"]
            if any(max(interval[0], old[0]) < min(interval[1], old[1]) for old in intervals):
                raise ValueError("execuções sobrepostas não são repetições separadas")
            models = {}
            for name, artifact in artifacts.items():
                blocks = []
                for item, source in zip(subjects, record["sources"]):
                    block = replay.replay_series(artifact, item, p["policy"])
                    if name == REFERENCE:
                        replay._check_native_reference(artifact, item, p["policy"], block)
                    block.update(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                                 source_sha256=source["sha256"])
                    blocks.append(block)
                models[name] = dict(model_id=artifact.resolved_model_id(), series=blocks, aggregate=replay.aggregate(blocks))
            paired = replay.paired_changes(models[REFERENCE]["series"], models[PRIMARY]["series"])
            results.append(dict(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                                started_ns=record["started_ns"], ended_ns=record["ended_ns"], run_sha256=record["run_sha256"],
                                source_sha256=hashes, same_series_paired=True, observed_episodes_identical=paired["ground_truth_matches"],
                                delivery_checks=[dict(cid=s["cid"], port_id=s["port_id"], stages=s["delivery_checks"]) for s in subjects],
                                models=models, paired_changes=paired))
            seen.update(hashes)
            intervals.append(interval)
            new_sources[str((case_root / "run.json").resolve())] = record_digest
            new_sources.update({str((case_root / row["csv"]).resolve()): row["sha256"] for row in record["sources"]})
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(case_id=case["case_id"], error=str(exc)))
    complete = not missing and not errors and len(results) == 12
    checks = {name: assess_criteria(results, complete, name) for name in artifacts}
    blocks = {name: [s for c in results for s in c["models"][name]["series"]] for name in artifacts}
    summaries = {name: _summarize(items, [c for c in p["cases"] if c["case_id"] in {r["case_id"] for r in results}])
                 for name, items in blocks.items()}
    paired = replay.paired_changes(blocks[REFERENCE], blocks[PRIMARY])
    load_protocol(protocol_path)
    if code_snapshot() != code or any(v1.digest_file(Path(path)) != sha for path, sha in {**protected, **new_sources}.items()):
        raise ValueError("fontes/código mudaram durante a avaliação")
    return v1.seal(dict(
        schema_version=SUMMARY_SCHEMA, protocol_sha256=p["protocol_sha256"], status="COMPLETED" if complete else "INCOMPLETE_OR_INVALID",
        scope=p["scope"], planned_runs=12, evaluated_runs=len(results), missing_runs=missing, invalid_runs=errors,
        primary_model=PRIMARY, reference_model=REFERENCE, promotion_eligible=False, deployment_eligible=False,
        evaluation_unit=EVALUATION_UNIT,
        refit=False, recalibration=False, new_data_used_for_fitting=False, statistical_superiority_assessed=False,
        criteria_status="PASSED" if all(checks[PRIMARY].values()) else "NOT_PASSED",
        checks=checks[PRIMARY], checks_by_model=checks, acceptance_criteria=CRITERIA, models=summaries,
        paired_changes=paired, cases=results, source_sha256=dict(sorted(new_sources.items())),
        limitations=LIMITATIONS), "report_sha256")


def report_exit_code(report: Dict[str, Any]) -> int:
    return 2 if report["status"] != "COMPLETED" else (0 if report["criteria_status"] == "PASSED" else 3)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze = sub.add_parser("freeze")
    freeze.add_argument("--source-protocol", required=True, type=Path)
    freeze.add_argument("--source-campaign", required=True, type=Path)
    freeze.add_argument("--development-root", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    evaluate = sub.add_parser("evaluate")
    evaluate.add_argument("--protocol", required=True, type=Path)
    evaluate.add_argument("--campaign-root", required=True, type=Path)
    evaluate.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            p = freeze_protocol(args.source_protocol, args.source_campaign, args.development_root, args.output)
            params = p["development"]["selected_parameters"]
            print(f"protocol={args.output.resolve() / 'protocol.json'}")
            print(f"runs=12 traffic_minutes={sum(c['duration_s'] for c in p['cases']) / 60:.1f} models=2 shadow_only=true")
            print(f"selected: alpha={params['alpha']:g} beta={params['beta']:g} phi={params['phi']:g}")
            print("refit=false recalibration=false promotion_eligible=false deployment_eligible=false")
            print(f"protocol_sha256={p['protocol_sha256']}")
            return 0
        target = args.output.absolute()
        output = target.resolve()
        if (target.is_symlink() or output.exists() or output.parent != args.protocol.resolve().parent
                or output.suffix != ".json" or not output.name.startswith("campaign-review")):
            raise ValueError("use novo campaign-review*.json diretamente no diretório v3")
        report = evaluate_campaign(args.protocol, args.campaign_root)
        v1.write_new_json(output, report)
        print(f"status={report['status']} runs={report['evaluated_runs']}/12 criteria={report['criteria_status']}")
        return report_exit_code(report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
