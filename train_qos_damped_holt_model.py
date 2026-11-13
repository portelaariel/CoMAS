#!/usr/bin/env python3
"""Offline damped-Holt development on sealed v1 runs; no holdout or runtime change."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Sequence

import predictive_sla_validation as v1
from qos_damped_holt import QosDampedHoltModel, train_damped_model
from qos_holt import QosHoltModel


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-qos-damped-development/1"
ALPHAS = (0.1, 0.2, 0.35, 0.5, 0.7, 0.9)
BETAS = (0.0, 0.05, 0.1, 0.2, 0.35, 0.5)
PHIS = (0.8, 0.9, 0.95, 0.98, 1.0)
CODE_FILES = (*v1.CODE_FILES, "qos_damped_holt.py", "train_qos_damped_holt_model.py")
LIMITATIONS = [
    "The damping family and search grid were chosen after inspecting v2 failures.",
    "V1 runs have already been inspected and are reused only as development data, not an independent test.",
    "Repetitions 1/2 select parameters; repetition 3 calibrates intervals only. V2 data are not read or fitted.",
    "Both ports share a workload; successive samples and repeated runs share a testbed and are correlated.",
    "Calibration coverage is in-sample descriptive coverage, not held-out coverage or a guaranteed operational level.",
    "Sample-step horizons nominally represent 4/8/12 s; acquisition jitter remains in provenance and is not resampled away.",
    "Forecast MSE selection does not optimize or establish early SLA warnings, control-alarm safety or preventive effectiveness.",
    "No risk threshold/persistence tuning, prospective test, LLM decision, runtime deployment or preventive action occurs.",
    "New artifacts need a separately frozen evaluation on newly collected traces before any promotion claim.",
]


def source_snapshot(protocol: Dict[str, Any], protocol_path: Path, campaign: Path) -> Dict[str, str]:
    protocol_path, campaign = protocol_path.resolve(), campaign.resolve()
    files = [protocol_path, campaign / "campaign-summary.json"]
    files.extend(protocol_path.parent / row["path"] for row in protocol["models"].values())
    for case in protocol["cases"]:
        case_root = (campaign / case["case_id"]).resolve()
        if not case_root.is_relative_to(campaign):
            raise ValueError("execução fora do diretório da campanha")
        record_path = case_root / "run.json"
        files.append(record_path)
        record = json.loads(record_path.read_text(encoding="utf-8"))
        for row in record["sources"]:
            path = (case_root / row["csv"]).resolve()
            if not path.is_relative_to(case_root):
                raise ValueError("fonte fora da execução")
            files.append(path)
    return {str(path.resolve()): v1.digest_file(path) for path in files}


def _code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def _partition_summary(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    runs = {item["run_id"]: item["profile"] for item in items}
    return dict(workload_runs=len(runs), correlated_port_sequences=len(items),
                samples=sum(len(row["values"]) for row in items),
                profile_run_counts=dict(Counter(runs.values())), run_ids=sorted(runs))


def _series_provenance(item: Dict[str, Any], case: Dict[str, Any], source: Dict[str, Any],
                       case_root: Path, record: Dict[str, Any], split: str) -> Dict[str, Any]:
    timestamps = item["timestamps_ns"]
    intervals = [(b - a) / 1e9 for a, b in zip(timestamps, timestamps[1:])]
    return dict(series_id=item["series_id"], run_id=case["case_id"], profile=case["profile"],
                repetition=case["repetition"], split=split, cid=item["cid"], port_id=item["port_id"],
                csv=str((case_root / source["csv"]).resolve()), csv_sha256=source["sha256"],
                run_sha256=record["run_sha256"], samples=len(item["values"]),
                started_ns=record["started_ns"], ended_ns=record["ended_ns"],
                first_sample_ns=timestamps[0], last_sample_ns=timestamps[-1],
                observed_sample_interval_s=dict(minimum=min(intervals), maximum=max(intervals),
                                               mean=sum(intervals) / len(intervals)))


def fit_campaign(protocol_path: Path, campaign: Path, output: Path) -> Dict[str, Any]:
    protocol_path, campaign = protocol_path.resolve(), campaign.resolve()
    # A new sibling directory only: never inside frozen protocols, pilot, or campaign.
    requested_output = output.absolute()
    output = output.resolve()
    if (output.parent != protocol_path.parent.parent
            or not output.name.startswith("qos-damped-development")
            or requested_output.is_symlink()):
        raise ValueError("saída deve ser um novo diretório qos-damped-development* irmão do protocolo")
    if output.exists():
        raise FileExistsError(f"saída já existe: {output}; use outro nome")
    protocol = v1.load_protocol(protocol_path)  # V2 schema is explicitly rejected.
    if protocol["repetitions"] != 3 or campaign != protocol_path.parent / "campaign":
        raise ValueError("treino requer a campanha v1 completa, com três repetições, dentro do protocolo")
    sources_before, code_before = source_snapshot(protocol, protocol_path, campaign), _code_snapshot()
    original_summary = json.loads((campaign / "campaign-summary.json").read_text(encoding="utf-8"))
    verified = v1.evaluate_campaign(protocol_path, campaign)
    if verified["status"] != "COMPLETED" or verified["evaluated_runs"] != 12:
        raise ValueError("treino requer 12 execuções v1 válidas e encerradas")
    if original_summary != verified:
        raise ValueError("relatório v1 diverge da reavaliação congelada")
    native = QosHoltModel.load(protocol_path.parent / protocol["models"]["coverage90"]["path"])
    partitions, provenance = {"train": [], "calibration": []}, []
    for case in protocol["cases"]:
        case_root = campaign / case["case_id"]
        subjects, record, _ = v1._read_case(protocol, case, case_root)
        split = "train" if case["repetition"] in (1, 2) else "calibration"
        for item, source in zip(subjects, record["sources"]):
            partitions[split].append({**item, "run_id": case["case_id"], "profile": case["profile"]})
            provenance.append(_series_provenance(item, case, source, case_root, record, split))
    partition_summary = {name: _partition_summary(items) for name, items in partitions.items()}
    if (partition_summary["train"]["workload_runs"] != 8
            or partition_summary["calibration"]["workload_runs"] != 4):
        raise ValueError("partições de desenvolvimento incompletas")
    created_at = datetime.now(timezone.utc).isoformat()
    git_commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    spec = v1.seal(dict(
        schema_version=SCHEMA, created_at=created_at, git_commit=git_commit,
        source_protocol=str(protocol_path), source_protocol_sha256=protocol["protocol_sha256"],
        source_campaign=str(campaign), input_sha256=sources_before, code_sha256=code_before,
        partition_rule="whole_workload_runs: repetitions_1_2_train; repetition_3_calibration; reset_each_port_run",
        partitions=partition_summary, source_series=provenance,
        sample_interval_s=protocol["sample_interval_s"], horizons_steps=protocol["horizons_steps"],
        coverage=0.9, priming_samples=native.priming_samples,
        search_grid=dict(alpha=list(ALPHAS), beta=list(BETAS), phi=list(PHIS)),
        v2_used_for_fitting=False, independent_test_used=False, promotion_eligible=False,
        deployment_eligible=False, limitations=LIMITATIONS), "development_spec_sha256")
    model, selection = train_damped_model(
        train_series=partitions["train"], calibration_series=partitions["calibration"],
        horizons_steps=spec["horizons_steps"], sample_interval_s=spec["sample_interval_s"],
        priming_samples=spec["priming_samples"], coverage=spec["coverage"],
        alphas=ALPHAS, betas=BETAS, phis=PHIS, created_at=created_at,
        training_metadata=dict(development_spec_sha256=spec["development_spec_sha256"],
                               git_commit=git_commit, code_sha256=code_before,
                               source_protocol_sha256=protocol["protocol_sha256"],
                               input_sha256=sources_before, source_series=provenance,
                               partitions=partition_summary, limitations=LIMITATIONS))
    if source_snapshot(protocol, protocol_path, campaign) != sources_before or _code_snapshot() != code_before:
        raise ValueError("fontes/código mudaram durante o treino; nenhum artefato será publicado")
    # Independent loader/identity check before publishing; test metrics must remain empty.
    model = QosDampedHoltModel.from_dict(model.to_dict())
    report = dict(schema_version=SCHEMA, status="DEVELOPMENT_FITTED", created_at=created_at,
                  model_id=model.resolved_model_id(), model_type=model.model_type,
                  development_spec_sha256=spec["development_spec_sha256"],
                  validation_scope=model.training["validation_scope"], promotion_eligible=False,
                  deployment_eligible=False, test_evaluated=False, v2_used_for_fitting=False,
                  original_v1_unchanged=True, source_integrity_verified=True,
                  partitions=partition_summary, selection=selection,
                  horizons=[dict(horizon_s=h.horizon_steps * model.sample_interval_s,
                                 horizon_steps=h.horizon_steps, alpha=h.alpha, beta=h.beta, phi=h.phi,
                                 interval_radius=h.interval_radius, calibration_samples=h.calibration_samples,
                                 training=h.training_metrics, calibration_descriptive=h.calibration_metrics,
                                 test=None) for h in model.horizons], limitations=LIMITATIONS)
    output.mkdir(exist_ok=False)
    for name, payload in (("development-spec.json", spec), ("qos-damped-holt-model.json", model.to_dict()),
                          ("qos-damped-holt-evaluation.json", report)):
        v1.write_new_json(output / name, payload)
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--campaign-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = fit_campaign(args.protocol, args.campaign_root, args.output)
        p = report["partitions"]
        print("status=DEVELOPMENT_FITTED source=v1 v2_used_for_fitting=false independent_test=false")
        print(f"train_runs={p['train']['workload_runs']} calibration_runs={p['calibration']['workload_runs']} "
              "correlated_ports_per_run=2 originals_unchanged=true")
        for h in report["horizons"]:
            print(f"h={h['horizon_s']:g}s alpha={h['alpha']:g} beta={h['beta']:g} phi={h['phi']:g} "
                  f"radius90={h['interval_radius']:.6f} train_rmse={h['training']['rmse']:.6f} "
                  f"calibration_rmse={h['calibration_descriptive']['rmse']:.6f}")
        print("promotion_eligible=false deployment_eligible=false test_evaluated=false")
        print(f"model={args.output.resolve() / 'qos-damped-holt-model.json'}")
        print(f"report={args.output.resolve() / 'qos-damped-holt-evaluation.json'}")
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.CalledProcessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
