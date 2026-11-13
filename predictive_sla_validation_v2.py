#!/usr/bin/env python3
"""Prospectively confirm a post-hoc selected policy, preserving protocol v1.

Only activation persistence changes from two windows to one. No model fitting,
online risk publication, LLM call, or actuation occurs in this experiment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence

import predictive_sla_validation as v1
from backtest_sla_risk import _classification_block, backtest_model
from qos_holt import QosHoltModel
from sla_episode_evaluation import summarize_episode_reports


ROOT = Path(__file__).resolve().parent
PROTOCOL_SCHEMA = "comas-predictive-sla-prospective/2"
SUMMARY_SCHEMA = "comas-predictive-sla-validation-summary/2"
POLICY = {**v1.POLICY, "activation_windows": 1}
CODE_FILES = (*v1.CODE_FILES, "predictive_sla_validation_v2.py",
              "scripts/collect_qos_validation_campaign_v2.py")
CRITERIA = {
    "all_twelve_runs_valid": "All 12 planned runs must pass the frozen data checks.",
    "no_control_activations": "No persistent activation in stable-low or short-pulses.",
    "ramp_subjects_have_eligible_episodes": "Each ramp run and port must have an eligible observed episode.",
    "all_eligible_ramp_episodes_anticipated": "Every eligible ramp episode must have a positive, pre-onset warning within 12 s.",
    "no_unmatched_activations": "No unmatched activation, including late or duplicate warnings, in any run.",
    "no_censored_activations": "No activation with incomplete future follow-up in any run.",
}
LIMITATIONS = [
    "One-window confirmation was selected after inspecting the v1 campaign; its selection evidence is post-hoc.",
    "Only new traces collected after the v2 freeze are confirmatory for this selected policy.",
    "Repeated workloads share a testbed and both monitored ports are correlated; independence is not guaranteed.",
    "Two-second pulses may be diluted or split by two-second counter sampling.",
    "The frozen artifacts retain pilot_single_run_temporal_split training; there is no refit or automatic promotion.",
    "Criteria concern shadow warning behavior, not application SLA protection, actuator timing, LLM decisions or scalability.",
]


def _snapshot_sources(protocol: Dict[str, Any], campaign: Path) -> List[Dict[str, str]]:
    sources = []
    for case in protocol["cases"]:
        case_root = campaign / case["case_id"]
        record_path = case_root / "run.json"
        record = json.loads(record_path.read_text(encoding="utf-8"))
        if (record != v1.seal(record, "run_sha256")
                or record["protocol_sha256"] != protocol["protocol_sha256"]
                or record["case_id"] != case["case_id"] or record["status"] != "COMPLETED"):
            raise ValueError("registro da campanha v1 mudou ou está incompleto")
        sources.append(dict(path=str(record_path.resolve()), sha256=v1.digest_file(record_path)))
        for source in record["sources"]:
            path = (case_root / source["csv"]).resolve()
            if not path.is_relative_to(case_root.resolve()) or v1.digest_file(path) != source["sha256"]:
                raise ValueError("CSV da campanha v1 mudou")
            sources.append(dict(path=str(path), sha256=source["sha256"]))
    return sources


def _compact_episodes(blocks: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    episodes = summarize_episode_reports(blocks)
    reasons = Counter(row["reason"] for row in episodes["activations"] if row["status"] == "UNMATCHED")
    return {key: episodes[key] for key in (
        "eligible_episodes", "detected", "missed", "total_activations",
        "unmatched_activations", "censored_activations", "warning_lead_time_s", "timing_basis",
    )} | {"unmatched_reasons": dict(reasons)}


def freeze_protocol(source_protocol: Path, source_campaign: Path, output: Path) -> Dict[str, Any]:
    source_protocol, source_campaign, output = (path.resolve() for path in (
        source_protocol, source_campaign, output))
    if output.exists():
        raise ValueError("saída já existe; use um novo diretório v2")
    for protected in (source_protocol.parent, source_campaign):
        if output.is_relative_to(protected) or protected.is_relative_to(output):
            raise ValueError("diretório v2 não pode sobrepor os artefatos v1")
    parent = v1.load_protocol(source_protocol)
    if parent["repetitions"] != 3 or len(parent["cases"]) != 12:
        raise ValueError("a confirmação v2 requer a campanha v1 de 12 casos")
    baseline = v1.evaluate_campaign(source_protocol, source_campaign)
    if baseline["status"] != "COMPLETED":
        raise ValueError("campanha v1 incompleta/inválida; não congele v2")
    summary_path = source_campaign / "campaign-summary.json"
    if json.loads(summary_path.read_text(encoding="utf-8")) != baseline:
        raise ValueError("relatório v1 diverge da reavaliação congelada")
    summary_sha256 = v1.digest_file(summary_path)
    sources = _snapshot_sources(parent, source_campaign)
    latest_source_end = max(json.loads((source_campaign / case["case_id"] / "run.json").read_text())["ended_ns"]
                            for case in parent["cases"])
    created_ns = time.time_ns()
    if created_ns <= latest_source_end:
        raise ValueError("a campanha v1 deve estar encerrada antes do congelamento v2")
    csv_hashes = sorted({sha for case in baseline["cases"] for sha in case["source_sha256"]})
    model_contents = {name: (source_protocol.parent / entry["path"]).read_bytes()
                      for name, entry in parent["models"].items()}
    model = QosHoltModel.load(source_protocol.parent / parent["models"]["coverage90"]["path"])
    selected_blocks = []
    for case in parent["cases"]:
        series, _, _ = v1._read_case(parent, case, source_campaign / case["case_id"])
        selected, _, _ = backtest_model(model=model, series=series, **POLICY)
        selected_blocks.append(selected["aggregate"]["episode_events"])
    selection = v1.seal(dict(
        schema_version="comas-predictive-sla-policy-selection/1",
        scope="post_hoc_selection_evidence_not_confirmatory_validation",
        source_protocol_sha256=parent["protocol_sha256"], source_summary_sha256=summary_sha256,
        primary_model="coverage90", refit=False, promotion_eligible=False,
        two_windows=_compact_episodes([baseline["models"]["coverage90"]["episode_events"]]),
        one_window=_compact_episodes(selected_blocks)), "selection_sha256")
    payload = dict(
        schema_version=PROTOCOL_SCHEMA, created_ns=created_ns,
        scope="prospective_confirmation_of_posthoc_selected_policy",
        promotion_eligible=False, git_commit=subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        code_sha256={name: v1.digest_file(ROOT / name) for name in CODE_FILES},
        models={name: {**entry, "path": f"models/{name}.json"}
                for name, entry in parent["models"].items()},
        primary_model="coverage90", secondary_model="coverage95",
        policy=dict(POLICY), reference_policy=dict(v1.POLICY),
        subjects=parent["subjects"], quality=parent["quality"], collection=parent["collection"],
        sample_interval_s=2, horizons_steps=[2, 4, 6], repetitions=3,
        cases=v1.planned_cases(3), acceptance_criteria=dict(CRITERIA),
        evaluation_unit="separate_workload_run; both ports are correlated",
        source_v1=dict(protocol_path=str(source_protocol), protocol_sha256=parent["protocol_sha256"],
                       campaign_root=str(source_campaign), summary_sha256=summary_sha256,
                       protected_sources=sources, excluded_csv_sha256=csv_hashes),
        selection_sha256=selection["selection_sha256"], limitations=list(LIMITATIONS))
    # Recheck the read-only source snapshot before creating anything.
    v1.load_protocol(source_protocol)
    if (_snapshot_sources(parent, source_campaign) != sources
            or v1.digest_file(summary_path) != summary_sha256):
        raise ValueError("artefatos v1 mudaram durante o congelamento")
    output.mkdir(parents=True, exist_ok=False)
    (output / "models").mkdir()
    for name, content in model_contents.items():
        with (output / payload["models"][name]["path"]).open("xb") as handle:
            handle.write(content)
    v1.write_new_json(output / "selection-analysis.json", selection)
    payload = v1.seal(payload, "protocol_sha256")
    v1.write_new_json(output / "protocol.json", payload)
    load_protocol(output / "protocol.json")
    return payload


def load_protocol(path: Path) -> Dict[str, Any]:
    path = path.resolve()
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != PROTOCOL_SCHEMA or payload != v1.seal(payload, "protocol_sha256"):
        raise ValueError("schema/checksum do protocolo v2 inválido")
    if (payload["policy"] != POLICY or payload["reference_policy"] != v1.POLICY
            or payload["acceptance_criteria"] != CRITERIA or payload["subjects"] != v1.SUBJECTS
            or payload["quality"] != v1.QUALITY or payload["collection"] != v1.COLLECTION
            or payload["sample_interval_s"] != 2 or payload["horizons_steps"] != [2, 4, 6]
            or payload["repetitions"] != 3 or payload["cases"] != v1.planned_cases(3)
            or payload["primary_model"] != "coverage90" or payload["secondary_model"] != "coverage95"
            or payload["promotion_eligible"] is not False or payload["limitations"] != LIMITATIONS
            or payload["scope"] != "prospective_confirmation_of_posthoc_selected_policy"):
        raise ValueError("configuração diverge do protocolo v2 congelado")
    if payload["code_sha256"] != {name: v1.digest_file(ROOT / name) for name in CODE_FILES}:
        raise ValueError("código mudou desde o congelamento v2")
    source = payload["source_v1"]
    parent_path = Path(source["protocol_path"])
    campaign = Path(source["campaign_root"])
    parent = v1.load_protocol(parent_path)
    if (parent["protocol_sha256"] != source["protocol_sha256"] or parent["repetitions"] != 3
            or payload["created_ns"] <= parent["created_ns"]
            or v1.digest_file(campaign / "campaign-summary.json") != source["summary_sha256"]
            or _snapshot_sources(parent, campaign) != source["protected_sources"]):
        raise ValueError("proveniência/artefatos v1 mudaram")
    if any(payload["created_ns"] <= json.loads((campaign / case["case_id"] / "run.json").read_text())["ended_ns"]
           for case in parent["cases"]):
        raise ValueError("congelamento v2 deve ser posterior ao encerramento v1")
    original_report = json.loads((campaign / "campaign-summary.json").read_text(encoding="utf-8"))
    hashes = sorted({sha for case in original_report["cases"] for sha in case["source_sha256"]})
    if source["excluded_csv_sha256"] != hashes:
        raise ValueError("lista de exclusão dos CSVs v1 mudou")
    selection = json.loads((path.parent / "selection-analysis.json").read_text(encoding="utf-8"))
    if (selection != v1.seal(selection, "selection_sha256")
            or selection["selection_sha256"] != payload["selection_sha256"]
            or selection["source_protocol_sha256"] != source["protocol_sha256"]
            or selection["source_summary_sha256"] != source["summary_sha256"]):
        raise ValueError("evidência de seleção pós-hoc mudou")
    expected_models = {name: {**entry, "path": f"models/{name}.json"}
                       for name, entry in parent["models"].items()}
    if payload["models"] != expected_models:
        raise ValueError("v2 deve preservar exatamente os modelos congelados v1")
    for name, entry in payload["models"].items():
        model_path = (path.parent / entry["path"]).resolve()
        if (not model_path.is_relative_to(path.parent)
                or v1.digest_file(model_path) != entry["sha256"]
                or QosHoltModel.load(model_path).resolved_model_id() != entry["model_id"]):
            raise ValueError(f"modelo v2 mudou: {name}")
    return payload


def campaign_output(protocol_path: Path, output: Path) -> Path:
    output = output.resolve()
    if output.parent != protocol_path.resolve().parent or not (
        output.name == "campaign" or output.name.startswith("campaign-")):
        raise ValueError("a coleta v2 exige um novo campaign ou campaign-* dentro do diretório v2")
    if output.exists():
        raise ValueError("saída já existe; não sobrescreva ou retome uma campanha")
    return output


def _summarize(results: Sequence[Dict[str, Any]], name: str) -> Dict[str, Any]:
    confusion = Counter()
    blocks, per_run = [], []
    windows = watch = 0
    for case in results:
        aggregate = case["models"][name]["aggregate"]
        episodes = aggregate["episode_events"]
        confusion.update(aggregate["candidate"]["confusion"])
        blocks.append(episodes)
        windows += aggregate["evaluated_windows"]
        watch += aggregate["watch_only"]["windows"]
        per_run.append(dict(case_id=case["case_id"], profile=case["profile"],
                            eligible=episodes["eligible_episodes"], detected=episodes["detected"],
                            unmatched_activations=episodes["unmatched_activations"],
                            lead_mean_s=episodes["warning_lead_time_s"]["mean"]))
    return dict(evaluated_windows=windows, watch_windows=watch,
                pooled_window_candidate=_classification_block(confusion),
                episode_events=summarize_episode_reports(blocks), per_run=per_run)


def assess_criteria(results: Sequence[Dict[str, Any]], complete: bool) -> Dict[str, bool]:
    controls = [case for case in results if case["profile"] in ("stable-low", "short-pulses")]
    ramps = [case for case in results if case["profile"] in ("fast-ramp", "slow-ramp")]
    all_blocks = [case["models"]["coverage90"]["aggregate"]["episode_events"] for case in results]
    return dict(
        all_twelve_runs_valid=complete,
        no_control_activations=bool(controls) and all(
            case["models"]["coverage90"]["aggregate"]["episode_events"]["total_activations"] == 0
            for case in controls),
        ramp_subjects_have_eligible_episodes=bool(ramps) and all(
            len(case["models"]["coverage90"]["series"]) == 2 and all(
                series["episode_events"]["eligible_episodes"] > 0
                for series in case["models"]["coverage90"]["series"])
            for case in ramps),
        all_eligible_ramp_episodes_anticipated=bool(ramps) and all(
            case["models"]["coverage90"]["aggregate"]["episode_events"]["detected"]
            == case["models"]["coverage90"]["aggregate"]["episode_events"]["eligible_episodes"]
            for case in ramps),
        no_unmatched_activations=bool(all_blocks) and all(block["unmatched_activations"] == 0 for block in all_blocks),
        no_censored_activations=bool(all_blocks) and all(block["censored_activations"] == 0 for block in all_blocks))


def evaluate_campaign(protocol_path: Path, campaign_root: Path) -> Dict[str, Any]:
    protocol_path, campaign_root = protocol_path.resolve(), campaign_root.resolve()
    protocol = load_protocol(protocol_path)
    if campaign_root.parent != protocol_path.parent or not (
        campaign_root.name == "campaign" or campaign_root.name.startswith("campaign-")):
        raise ValueError("avalie somente uma campanha nova dentro do diretório v2")
    artifacts = {name: QosHoltModel.load(protocol_path.parent / entry["path"])
                 for name, entry in protocol["models"].items()}
    results, errors, missing, intervals = [], [], [], []
    excluded = set(protocol["source_v1"]["excluded_csv_sha256"])
    for artifact in artifacts.values():
        excluded.update(row["csv_sha256"] for row in artifact.training.get("source_series", []))
    seen_hashes = set()
    for case in protocol["cases"]:
        case_root = campaign_root / case["case_id"]
        if not (case_root / "run.json").exists():
            missing.append(case["case_id"])
            continue
        try:
            series, record, hashes = v1._read_case(protocol, case, case_root)
            if excluded.intersection(hashes) or seen_hashes.intersection(hashes):
                raise ValueError("CSV do piloto/v1/outra execução reutilizado; v2 exige novas coletas")
            interval = record["started_ns"], record["ended_ns"]
            if any(max(interval[0], old[0]) < min(interval[1], old[1]) for old in intervals):
                raise ValueError("execuções sobrepostas não são repetições separadas")
            models, signatures = {}, []
            for name, artifact in artifacts.items():
                result, points, candidates = backtest_model(model=artifact, series=series, **protocol["policy"])
                result["activation_windows"] = 1
                models[name] = result
                signatures.append((points, candidates))
            reference, points, candidates = backtest_model(
                model=artifacts["coverage90"], series=series, **protocol["reference_policy"])
            reference["activation_windows"] = 2
            models["coverage90-confirmation2"] = reference
            signatures.append((points, candidates))
            if any(item != signatures[0] for item in signatures[1:]):
                raise ValueError("previsões/candidatos diferem; comparação pareada inválida")
            results.append(dict(case_id=case["case_id"], profile=case["profile"],
                                repetition=case["repetition"], models=models, source_sha256=hashes,
                                point_forecasts_identical=True, candidate_decisions_identical=True))
            seen_hashes.update(hashes)
            intervals.append(interval)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(case_id=case["case_id"], error=str(exc)))
    complete = not errors and not missing and len(results) == 12
    checks = assess_criteria(results, complete)
    return dict(schema_version=SUMMARY_SCHEMA, protocol_sha256=protocol["protocol_sha256"],
                scope=protocol["scope"], promotion_eligible=False,
                status="COMPLETED" if complete else "INCOMPLETE_OR_INVALID",
                planned_runs=12, evaluated_runs=len(results), missing_runs=missing, invalid_runs=errors,
                criteria_status="PASSED" if all(checks.values()) else "NOT_PASSED",
                checks=checks, acceptance_criteria=protocol["acceptance_criteria"],
                models={name: _summarize(results, name) for name in (
                    "coverage90", "coverage95", "coverage90-confirmation2")},
                cases=results, limitations=protocol["limitations"])


def report_exit_code(report: Dict[str, Any]) -> int:
    return 2 if report["status"] != "COMPLETED" else (0 if report["criteria_status"] == "PASSED" else 3)


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze", help="preserva v1 e congela a confirmação v2")
    freeze.add_argument("--source-protocol", required=True, type=Path)
    freeze.add_argument("--source-campaign", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    evaluate = commands.add_parser("evaluate", help="reavalia somente dados novos, sem rede")
    evaluate.add_argument("--protocol", required=True, type=Path)
    evaluate.add_argument("--campaign-root", required=True, type=Path)
    evaluate.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            protocol = freeze_protocol(args.source_protocol, args.source_campaign, args.output)
            print(f"protocol={args.output / 'protocol.json'}")
            print(f"runs=12 activation_windows=1 traffic_minutes={sum(row['duration_s'] for row in protocol['cases']) / 60:.1f}")
            print(f"protocol_sha256={protocol['protocol_sha256']}")
            return 0
        output = args.output.resolve()
        if (output.exists() or output.parent != args.protocol.resolve().parent
                or output.suffix != ".json" or not output.name.startswith("campaign-review")):
            raise ValueError("use um novo campaign-review*.json dentro do diretório v2")
        report = evaluate_campaign(args.protocol.resolve(), args.campaign_root.resolve())
        v1.write_new_json(output, report)
        print(f"status={report['status']} runs={report['evaluated_runs']}/12 criteria={report['criteria_status']}")
        return report_exit_code(report)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
