#!/usr/bin/env python3
"""Freeze and evaluate prospective QoS traces without fitting or actuating."""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence

from backtest_sla_risk import _classification_block, _validate_model, backtest_model
from qos_holt import QosHoltModel
from sla_episode_evaluation import summarize_episode_reports, validate_timestamps
from train_qos_holt_model import load_manifest


ROOT = Path(__file__).resolve().parent
PROTOCOL_SCHEMA = "comas-predictive-sla-prospective/1"
RUN_SCHEMA = "comas-predictive-sla-validation-run/1"
CODE_FILES = (
    "predictive_sla_validation.py", "scripts/collect_qos_validation_campaign.py",
    "backtest_sla_risk.py", "sla_episode_evaluation.py", "sla_risk.py",
    "qos_holt.py", "qos_telemetry.py", "train_qos_holt_model.py",
)
POLICY = dict(threshold=0.8, required_consecutive_horizons=2,
              activation_windows=2, clear_windows=2,
              episode_min_breach_samples=2, episode_clear_samples=2)
SUBJECTS = [
    dict(cid="192.168.10.10", port_id="2:4", url="http://127.0.0.1:6060",
         capacity_bps=100_000_000),
    dict(cid="192.168.11.10", port_id="3:3", url="http://127.0.0.1:6061",
         capacity_bps=100_000_000),
]
QUALITY = dict(minimum_samples=40, maximum_gap_s=5, boundary_tolerance_s=6,
               steady_stage_min_s=10, stage_settle_s=4,
               minimum_rate_fraction=0.5, maximum_rate_fraction=2.0)
COLLECTION = dict(offered_rate_mbit=140, udp_port=5009, api_poll_s=0.5,
                  safety_poll_s=2, qdisc_handle="7a51:", warmup_s=4)


def digest_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def seal(payload: Dict[str, Any], field: str) -> Dict[str, Any]:
    content = {key: value for key, value in payload.items() if key != field}
    encoded = json.dumps(content, sort_keys=True, separators=(",", ":"),
                         allow_nan=False).encode("utf-8")
    return {**content, field: hashlib.sha256(encoded).hexdigest()}


def write_new_json(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, sort_keys=True, allow_nan=False)
        handle.write("\n")


def profiles() -> Dict[str, List[Dict[str, int]]]:
    def stage(rate: int, seconds: int) -> Dict[str, int]:
        return dict(rate_mbit=rate, duration_s=seconds)
    return {
        "stable-low": [stage(20, 40), stage(50, 80), stage(20, 30)],
        "short-pulses": [stage(20, 40)] +
            [stage(rate, seconds) for _ in range(4)
             for rate, seconds in ((110, 2), (20, 18))] + [stage(20, 30)],
        "slow-ramp": [stage(20, 40)] +
            [stage(rate, 10) for rate in range(30, 101, 10)] +
            [stage(100, 20), stage(20, 30)],
        "fast-ramp": [stage(20, 40)] +
            [stage(rate, 4) for rate in (40, 60, 80, 100)] +
            [stage(100, 40), stage(20, 30)],
    }


def planned_cases(repetitions: int) -> List[Dict[str, Any]]:
    if isinstance(repetitions, bool) or not isinstance(repetitions, int) or not 1 <= repetitions <= 10:
        raise ValueError("repetições devem estar entre 1 e 10")
    names = list(profiles())
    cases = []
    for repeat in range(1, repetitions + 1):
        offset = (repeat - 1) % len(names)
        for name in names[offset:] + names[:offset]:
            stages = profiles()[name]
            cases.append(dict(case_id=f"r{repeat:02d}-{name}", profile=name,
                              repetition=repeat, stages=stages,
                              duration_s=sum(row["duration_s"] for row in stages)))
    return cases


def freeze_protocol(pilot_root: Path, output: Path, repetitions: int = 3) -> Dict[str, Any]:
    cases = planned_cases(repetitions)
    manifest_path = pilot_root / "qos-holt-manifest-v1.json"
    manifest, _, metadata = load_manifest(manifest_path)
    if manifest["sample_interval_s"] != 2 or manifest["horizons_steps"] != [2, 4, 6]:
        raise ValueError("esta campanha requer amostragem de 2 s e horizontes [2,4,6]")
    specifications = {
        "coverage90": pilot_root / "model-v1-coverage90/qos-holt-model.json",
        "coverage95": pilot_root / "model-v1/qos-holt-model.json",
    }
    models = {}
    contents = {}
    for name, path in specifications.items():
        artifact = QosHoltModel.load(path)
        _validate_model(artifact, manifest, metadata)
        if not math.isclose(artifact.coverage, 0.90 if name == "coverage90" else 0.95):
            raise ValueError(f"coverage inesperada em {name}")
        contents[name] = path.read_bytes()
        models[name] = dict(path=f"models/{name}.json", sha256=digest_file(path),
                            model_id=artifact.resolved_model_id(),
                            training_scope=artifact.training.get("validation_scope"),
                            training_promotion_eligible=artifact.training.get("promotion_eligible", False))
    code_hashes = {name: digest_file(ROOT / name) for name in CODE_FILES}
    commit = subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip()
    payload = seal({
        "schema_version": PROTOCOL_SCHEMA, "created_ns": time.time_ns(),
        "scope": "prospective_validation_of_frozen_pilot_models",
        "promotion_eligible": False, "git_commit": commit,
        "code_sha256": code_hashes, "pilot_manifest_sha256": digest_file(manifest_path),
        "models": models, "primary_model": "coverage90", "secondary_model": "coverage95",
        "policy": dict(POLICY), "subjects": SUBJECTS, "quality": QUALITY,
        "sample_interval_s": 2, "horizons_steps": [2, 4, 6],
        "repetitions": repetitions, "cases": cases,
        "collection": dict(COLLECTION),
        "evaluation_unit": "separate_workload_run; both ports are correlated",
        "traffic_expectations": "profile names are not ground-truth labels; use observed QoS",
        "limitations": [
            "The artifacts were selected on a previously inspected pilot; no refit or promotion occurs.",
            "Repeated workloads share a testbed; statistical independence is not guaranteed.",
            "Two-second pulses can be diluted or split by two-second counter sampling.",
            "No application-level SLA, LLM decision or preventive actuation is evaluated.",
        ],
    }, "protocol_sha256")
    output.mkdir(parents=True, exist_ok=False)
    (output / "models").mkdir()
    for name, content in contents.items():
        (output / models[name]["path"]).write_bytes(content)
    write_new_json(output / "protocol.json", payload)
    return payload


def load_protocol(path: Path) -> Dict[str, Any]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    if payload.get("schema_version") != PROTOCOL_SCHEMA:
        raise ValueError("schema de protocolo inválido")
    if payload != seal(payload, "protocol_sha256"):
        raise ValueError("checksum do protocolo mudou")
    if (payload["policy"] != POLICY or payload["subjects"] != SUBJECTS
            or payload["quality"] != QUALITY
            or payload["collection"] != COLLECTION
            or payload["sample_interval_s"] != 2
            or payload["horizons_steps"] != [2, 4, 6]
            or set(payload["models"]) != {"coverage90", "coverage95"}
            or payload["primary_model"] != "coverage90"
            or payload["secondary_model"] != "coverage95"
            or payload["promotion_eligible"] is not False
            or payload["cases"] != planned_cases(payload["repetitions"])):
        raise ValueError("configuração diverge do protocolo congelado desta versão")
    if payload["code_sha256"] != {name: digest_file(ROOT / name) for name in CODE_FILES}:
        raise ValueError("código mudou desde o congelamento; não misture versões")
    for name, specification in payload["models"].items():
        model_path = (path.parent / specification["path"]).resolve()
        if not model_path.is_relative_to(path.parent.resolve()):
            raise ValueError("modelo congelado está fora do diretório do protocolo")
        if digest_file(model_path) != specification["sha256"]:
            raise ValueError(f"hash do modelo congelado mudou: {name}")
        model = QosHoltModel.load(model_path)
        if model.resolved_model_id() != specification["model_id"]:
            raise ValueError("identidade do modelo congelado mudou")
        if (model.metric != "utilization_ratio" or model.sample_interval_s != 2
                or [h.horizon_steps for h in model.horizons] != [2, 4, 6]
                or not math.isclose(model.coverage, 0.90 if name == "coverage90" else 0.95)):
            raise ValueError("contrato do modelo incompatível com a campanha")
    return payload


def _read_case(protocol: Dict[str, Any], case: Dict[str, Any], case_root: Path) -> tuple:
    record = json.loads((case_root / "run.json").read_text(encoding="utf-8"))
    if record != seal(record, "run_sha256"):
        raise ValueError("checksum do registro de execução mudou")
    if (record.get("schema_version") != RUN_SCHEMA or record.get("case_id") != case["case_id"]
            or record.get("protocol_sha256") != protocol["protocol_sha256"]
            or record.get("status") != "COMPLETED"):
        raise ValueError("execução incompleta ou de outro protocolo/caso")
    start, end = record["started_ns"], record["ended_ns"]
    if start < protocol["created_ns"] or end <= start:
        raise ValueError("a coleta deve ser posterior ao congelamento")
    if end - start < case["duration_s"] * 1_000_000_000:
        raise ValueError("execução menor que o perfil planejado")
    workload = record["workload"]
    for ordinal, (actual, expected) in enumerate(zip(workload, case["stages"])):
        if (actual["rate_mbit"] != expected["rate_mbit"]
                or actual["duration_s"] != expected["duration_s"]
                or actual["end_ns"] - actual["start_ns"] < expected["duration_s"] * 1_000_000_000
                or actual["start_ns"] < start or actual["end_ns"] > end):
            raise ValueError(f"patamar {ordinal} difere do planejado")
        if ordinal and actual["start_ns"] < workload[ordinal - 1]["end_ns"]:
            raise ValueError("patamares temporais sobrepostos")
    if len(workload) != len(case["stages"]):
        raise ValueError("patamares incompletos")
    if len(record["sources"]) != len(protocol["subjects"]):
        raise ValueError("fontes incompletas")
    series, hashes = [], []
    for specification, subject in zip(record["sources"], protocol["subjects"]):
        if specification["cid"] != subject["cid"] or specification["port_id"] != subject["port_id"]:
            raise ValueError("identidade da fonte diverge do protocolo")
        csv_path = (case_root / specification["csv"]).resolve()
        if not csv_path.is_relative_to(case_root.resolve()):
            raise ValueError("CSV deve estar dentro da execução")
        checksum = digest_file(csv_path)
        if checksum != specification["sha256"]:
            raise ValueError("CSV mudou após o encerramento da coleta")
        values, timestamps = [], []
        with csv_path.open(encoding="utf-8", newline="") as handle:
            for row in csv.DictReader(handle):
                timestamp = int(row["ts_ns"])
                value = float(row["utilization_ratio"])
                if (row["cid"] != subject["cid"] or row["port_id"] != subject["port_id"]
                        or not start <= timestamp <= end or row["quality"] != "VALID"
                        or float(row["capacity_bps"]) != subject["capacity_bps"]
                        or not math.isfinite(value) or value < 0):
                    raise ValueError("amostra inválida ou fora do escopo congelado")
                values.append(value)
                timestamps.append(timestamp)
        validate_timestamps(timestamps, len(values))
        if len(values) < QUALITY["minimum_samples"]:
            raise ValueError("amostras insuficientes")
        if any(right - left > QUALITY["maximum_gap_s"] * 1e9
               for left, right in zip(timestamps, timestamps[1:])):
            raise ValueError("lacuna na coleta; não será ocultada pela segmentação")
        if (timestamps[0] - start > QUALITY["boundary_tolerance_s"] * 1e9
                or end - timestamps[-1] > QUALITY["boundary_tolerance_s"] * 1e9):
            raise ValueError("coleta não cobre os limites da execução")
        delivery = []
        for ordinal, stage in enumerate(workload, 1):
            if stage["duration_s"] < QUALITY["steady_stage_min_s"]:
                continue  # A two-second pulse is not a steady-state delivery test.
            steady_values = [value for timestamp, value in zip(timestamps, values)
                             if stage["start_ns"] + QUALITY["stage_settle_s"] * 1e9
                             <= timestamp < stage["end_ns"]]
            if len(steady_values) < 2:
                raise ValueError(f"patamar {ordinal}: telemetria estável insuficiente")
            observed = sum(steady_values) / len(steady_values)
            expected = stage["rate_mbit"] * 1_000_000 / subject["capacity_bps"]
            if not (expected * QUALITY["minimum_rate_fraction"] <= observed
                    <= expected * QUALITY["maximum_rate_fraction"]):
                raise ValueError(f"patamar {ordinal}: tráfego observado incompatível com o planejado")
            delivery.append(dict(stage=ordinal, samples=len(steady_values),
                                 mean_utilization=observed, expected_nominal_utilization=expected))
        hashes.append(checksum)
        series.append(dict(series_id=f"{case['case_id']}/{subject['cid']}/{subject['port_id']}",
                           cid=subject["cid"], port_id=subject["port_id"], values=values,
                           timestamps_ns=timestamps, delivery_checks=delivery))
    return series, record, hashes


def evaluate_campaign(protocol_path: Path, campaign_root: Path) -> Dict[str, Any]:
    protocol = load_protocol(protocol_path)
    artifacts = {name: QosHoltModel.load(protocol_path.parent / entry["path"])
                 for name, entry in protocol["models"].items()}
    results, errors, missing, seen_hashes, intervals = [], [], [], set(), []
    for case in protocol["cases"]:
        case_root = campaign_root / case["case_id"]
        if not (case_root / "run.json").exists():
            missing.append(case["case_id"])
            continue
        try:
            series, record, hashes = _read_case(protocol, case, case_root)
            if seen_hashes.intersection(hashes):
                raise ValueError("CSV reutilizado em outra execução")
            interval = (record["started_ns"], record["ended_ns"])
            if any(max(interval[0], old[0]) < min(interval[1], old[1]) for old in intervals):
                raise ValueError("execuções sobrepostas não são repetições separadas")
            for artifact in artifacts.values():
                original_hashes = {row["csv_sha256"] for row in artifact.training.get("source_series", [])}
                if original_hashes.intersection(hashes):
                    raise ValueError("CSV do piloto reutilizado como validação")
            models, points, candidates = {}, [], []
            for name, artifact in artifacts.items():
                result, point_signature, candidate_signature = backtest_model(
                    model=artifact, series=series, **protocol["policy"])
                models[name] = result
                points.append(point_signature)
                candidates.append(candidate_signature)
            results.append(dict(case_id=case["case_id"], profile=case["profile"],
                                repetition=case["repetition"], models=models,
                                source_sha256=hashes,
                                delivery_checks=[dict(cid=row["cid"], port_id=row["port_id"],
                                                      stages=row["delivery_checks"]) for row in series],
                                point_forecasts_identical=all(row == points[0] for row in points),
                                candidate_decisions_identical=all(row == candidates[0] for row in candidates)))
            seen_hashes.update(hashes)
            intervals.append(interval)
        except (OSError, ValueError, KeyError, TypeError) as exc:
            errors.append(dict(case_id=case["case_id"], error=str(exc)))
    summaries = {}
    for name in artifacts:
        candidate_counts = Counter()
        episode_blocks = []
        windows = watch = 0
        per_run = []
        for case in results:
            aggregate = case["models"][name]["aggregate"]
            episodes = aggregate["episode_events"]
            candidate_counts.update(aggregate["candidate"]["confusion"])
            episode_blocks.append(episodes)
            windows += aggregate["evaluated_windows"]
            watch += aggregate["watch_only"]["windows"]
            per_run.append(dict(case_id=case["case_id"], profile=case["profile"],
                                candidate=aggregate["candidate"], episodes=episodes["actual_episodes"],
                                detected=episodes["detected"], eligible=episodes["eligible_episodes"],
                                unmatched_activations=episodes["unmatched_activations"],
                                censored_activations=episodes["censored_activations"],
                                lead_mean_s=episodes["warning_lead_time_s"]["mean"]))
        summaries[name] = dict(evaluated_windows=windows, watch_windows=watch,
                               pooled_window_candidate=_classification_block(candidate_counts),
                               episode_events=summarize_episode_reports(episode_blocks), per_run=per_run)
    return dict(schema_version="comas-predictive-sla-validation-summary/1",
                protocol_sha256=protocol["protocol_sha256"],
                status="COMPLETED" if not errors and not missing else "INCOMPLETE_OR_INVALID",
                promotion_eligible=False, planned_runs=len(protocol["cases"]),
                evaluated_runs=len(results), missing_runs=missing, invalid_runs=errors,
                models=summaries, cases=results, limitations=protocol["limitations"])


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    freeze = commands.add_parser("freeze", help="congela protocolo e cópias dos modelos, sem rede")
    freeze.add_argument("--pilot-root", required=True, type=Path)
    freeze.add_argument("--output", required=True, type=Path)
    freeze.add_argument("--repetitions", type=int, default=3)
    evaluate = commands.add_parser("evaluate", help="avalia somente os novos CSVs, sem rede")
    evaluate.add_argument("--protocol", required=True, type=Path)
    evaluate.add_argument("--campaign-root", required=True, type=Path)
    evaluate.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            protocol = freeze_protocol(args.pilot_root.resolve(), args.output.resolve(), args.repetitions)
            print(f"protocol: {args.output / 'protocol.json'}")
            print(f"runs={len(protocol['cases'])} traffic_minutes={sum(row['duration_s'] for row in protocol['cases']) / 60:.1f}")
            print(f"protocol_sha256={protocol['protocol_sha256']}")
            return 0
        if args.output.exists():
            raise ValueError("saída já existe; use outro nome")
        if args.output.resolve().is_relative_to(args.protocol.parent.resolve() / "models"):
            raise ValueError("saída não pode modificar os modelos congelados")
        if args.output.resolve().name in ("protocol.json", "run.json") or args.output.suffix != ".json":
            raise ValueError("use um novo nome de relatório .json")
        report = evaluate_campaign(args.protocol.resolve(), args.campaign_root.resolve())
        write_new_json(args.output, report)
        print(f"status={report['status']} runs={report['evaluated_runs']}/{report['planned_runs']}")
        for name, result in report["models"].items():
            episodes = result["episode_events"]
            print(f"{name}: episodes={episodes['detected']}/{episodes['eligible_episodes']} "
                  f"unmatched={episodes['unmatched_activations']} censored={episodes['censored_activations']} "
                  f"lead_mean_s={episodes['warning_lead_time_s']['mean']}")
        return 0 if report["status"] == "COMPLETED" else 2
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
