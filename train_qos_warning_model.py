#!/usr/bin/env python3
"""Offline train-only warning-objective development; not independent validation."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Sequence

import predictive_sla_validation as v1
import predictive_sla_damped_replay as replay
import train_qos_damped_holt_model as previous
import qos_warning_selection as selection
from qos_holt import QosHoltModel


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-qos-warning-development/1"
ALPHAS, BETAS, PHIS = previous.ALPHAS, previous.BETAS, previous.PHIS
CODE_FILES = (*replay.CODE_FILES, "qos_warning_selection.py", "train_qos_warning_model.py")
LIMITATIONS = [
    "The warning objective and shared-parameter family were designed after inspecting v2 failures; no independent test is present.",
    "Only v1 repetitions 1/2 choose parameters; v1 repetition 3 sets interval radii after selection and cannot rank candidates.",
    "One alpha/beta/phi tuple is shared by all horizons, a restricted family rather than the complete horizon-specific Cartesian grid.",
    "Zero control/censored activations and at least one anticipated episode are training feasibility conditions, not safety guarantees.",
    "The lexicographic priorities are an explicit design choice, not empirically established optimal costs or learned weights.",
    "Threshold 0.80, two consecutive horizons, activation 1, clearing 2 and the sustained-episode matcher remain fixed.",
    "Original v1 official activation-2 results are verified and preserved, not replaced by the development activation-1 replay.",
    "Correlated ports are pooled within workload runs; repeated runs, windows and episodes are not independent statistical units.",
    "Lead time is conditional on anticipated episodes and is not optimized; misses, late, unmatched and censored alarms remain explicit.",
    "Calibration empirical coverage is descriptive and is not held-out coverage or an operational guarantee.",
    "Previously inspected v2 traces are not read, selected on, recalibrated on or called an independent holdout by this command.",
    "No runtime, LLM, network, new traffic, preventive action or promotion is performed; new prospective validation remains necessary.",
]


def code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def fit_campaign(protocol_path: Path, campaign: Path, output: Path) -> Dict[str, Any]:
    protocol_path, campaign = protocol_path.resolve(), campaign.resolve()
    requested = output.absolute()
    output = output.resolve()
    if (requested.is_symlink() or output.parent != protocol_path.parent.parent
            or not output.name.startswith("qos-warning-development")):
        raise ValueError("saída deve ser novo diretório qos-warning-development* irmão do protocolo v1")
    if output.exists():
        raise FileExistsError(f"saída já existe: {output}; use outro nome")
    protocol = v1.load_protocol(protocol_path)
    if protocol["repetitions"] != 3 or campaign != protocol_path.parent / "campaign":
        raise ValueError("treino requer campanha v1 completa com três repetições")
    sources, code = previous.source_snapshot(protocol, protocol_path, campaign), code_snapshot()
    official = v1.evaluate_campaign(protocol_path, campaign)
    if (official["status"] != "COMPLETED" or official["evaluated_runs"] != 12
            or json.loads((campaign / "campaign-summary.json").read_text(encoding="utf-8")) != official):
        raise ValueError("relatório v1 incompleto/divergente; não altere as fontes")
    native = QosHoltModel.load(protocol_path.parent / protocol["models"]["coverage90"]["path"])
    if protocol["horizons_steps"] != [2, 4, 6] or protocol["sample_interval_s"] != 2:
        raise ValueError("desenvolvimento requer horizontes nominais de 4/8/12 s e amostragem de 2 s")
    partitions, provenance = {"train": [], "calibration": []}, []
    for case in protocol["cases"]:
        case_root = campaign / case["case_id"]
        subjects, record, _ = v1._read_case(protocol, case, case_root)
        split = "train" if case["repetition"] in (1, 2) else "calibration"
        for item, source in zip(subjects, record["sources"]):
            partitions[split].append({**item, "run_id": case["case_id"], "profile": case["profile"]})
            provenance.append(previous._series_provenance(item, case, source, case_root, record, split))
    counts = {name: previous._partition_summary(items) for name, items in partitions.items()}
    if counts["train"]["workload_runs"] != 8 or counts["calibration"]["workload_runs"] != 4:
        raise ValueError("partições incompletas")
    created_at = datetime.now(timezone.utc).isoformat()
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    spec = v1.seal(dict(
        schema_version=SCHEMA, created_at=created_at, git_commit=commit,
        source_protocol=str(protocol_path), source_campaign=str(campaign),
        source_protocol_sha256=protocol["protocol_sha256"], input_sha256=sources, code_sha256=code,
        partitions=counts, source_series=provenance,
        partition_rule="whole_runs: repetitions_1_2_train; repetition_3_radius_calibration_only",
        objective=selection.OBJECTIVE, warning_policy=selection.WARNING_POLICY,
        horizons_steps=[2, 4, 6], sample_interval_s=2, priming_samples=native.priming_samples, coverage=.9,
        search_grid=dict(alpha=list(ALPHAS), beta=list(BETAS), phi=list(PHIS)),
        v2_used_for_fitting=False, independent_test_used=False, promotion_eligible=False,
        deployment_eligible=False, limitations=LIMITATIONS), "development_spec_sha256")
    train = partitions["train"]
    search = selection.choose_parameters(train_series=train, priming=native.priming_samples, sample_interval_s=2,
                                         alphas=ALPHAS, betas=BETAS, phis=PHIS)
    # Reference is descriptive, never an extra source of selected parameters.
    baseline = selection.run_blocks(native, train)
    for item, block in zip(train, baseline):
        replay._check_native_reference(native, item, selection.WARNING_POLICY, block)
    baseline_score = selection.score_blocks(baseline)
    model, selected_blocks, paired = None, None, None
    if search["selected"] is not None:
        parameters = search["selected"]["parameters"]
        model = selection.calibrate_selected(
            parameters=parameters, train_series=train, calibration_series=partitions["calibration"],
            priming=native.priming_samples, sample_interval_s=2, created_at=created_at,
            metadata={key: spec[key] for key in ("development_spec_sha256", "partitions", "source_series",
                                               "input_sha256", "code_sha256", "source_protocol_sha256",
                                               "search_grid", "git_commit", "limitations")})
        selected_blocks = selection.run_blocks(model, train)
        placeholder = selection.run_blocks(selection.candidate_model(parameters, priming=native.priming_samples,
                                                                     sample_interval_s=2), train)
        if (selection.warning_signature(placeholder) != selection.warning_signature(selected_blocks)
                or selection.score_blocks(selected_blocks) != search["selected"]["score"]):
            raise ValueError("calibração mudou previsões/alertas/objetivo selecionados")
        paired = replay.paired_changes(baseline, selected_blocks)
    if previous.source_snapshot(protocol, protocol_path, campaign) != sources or code_snapshot() != code:
        raise ValueError("fontes/código mudaram durante o treino; não publique artefatos")
    report = v1.seal(dict(
        schema_version=SCHEMA, status="WARNING_DEVELOPMENT_FITTED" if model else "NO_FEASIBLE_CANDIDATE",
        created_at=created_at, development_spec_sha256=spec["development_spec_sha256"],
        model_id=model.resolved_model_id() if model else None, model_artifact_written=model is not None,
        selection=search, partitions=counts, warning_policy=selection.WARNING_POLICY,
        original_v1_unchanged=True, baseline_exact=True, source_integrity_verified=True,
        calibration_used_for_selection=False, v2_used_for_fitting=False, test_evaluated=False,
        promotion_eligible=False, deployment_eligible=False,
        original_training_reference=dict(score=baseline_score, summary=replay.aggregate(baseline), series=baseline),
        selected_training=(dict(summary=replay.aggregate(selected_blocks), series=selected_blocks)
                           if selected_blocks is not None else None), paired_changes=paired,
        horizons=([dict(horizon_s=h.horizon_steps * 2, alpha=h.alpha, beta=h.beta, phi=h.phi,
                       interval_radius=h.interval_radius, calibration_samples=h.calibration_samples,
                       training=h.training_metrics, calibration_descriptive=h.calibration_metrics, test=None)
                   for h in model.horizons] if model else []), limitations=LIMITATIONS), "report_sha256")
    output.mkdir(exist_ok=False)
    v1.write_new_json(output / "development-spec.json", spec)
    v1.write_new_json(output / "qos-warning-evaluation.json", report)
    if model:
        v1.write_new_json(output / "qos-warning-model.json", model.to_dict())
    return report


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--campaign-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        report = fit_campaign(args.protocol, args.campaign_root, args.output)
        search = report["selection"]
        print(f"status={report['status']} source=v1 train_runs=8 calibration_runs=4 v2_used_for_fitting=false")
        print(f"candidates={search['candidate_count']} feasible={search['feasible_candidates']} family=shared_alpha_beta_phi")
        for name, block in (("original_train", report["original_training_reference"]),
                            ("selected_train", report["selected_training"])):
            if block is None:
                print(f"{name}: NONE")
                continue
            s = block["summary"]
            print(f"{name}: anticipated={s['anticipated']}/{s['eligible_episodes']} late={s['late_activations']} "
                  f"control={s['control_activations']} unmatched={s['unmatched_activations']} "
                  f"FP={s['candidate']['confusion']['FP']}")
        p = search["selected"]["parameters"] if search["selected"] else None
        print(f"selected: alpha={p['alpha']:g} beta={p['beta']:g} phi={p['phi']:g}" if p else "selected: NONE")
        print("calibration_used_for_selection=false independent_test=false promotion_eligible=false deployment_eligible=false")
        print(f"report={args.output.resolve() / 'qos-warning-evaluation.json'}")
        return 0  # A completed search, including NONE, is not a validation pass.
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
