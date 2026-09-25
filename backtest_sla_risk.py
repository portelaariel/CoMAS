#!/usr/bin/env python3
"""Backtest offline do contrato determinístico de risco preditivo de SLA.

O comando reproduz, sobre a partição de teste, o mesmo caminho
``MultiHorizonHoltForecaster -> evaluate_sla_forecast ->
SlaRiskPersistence`` usado pelo futuro runtime shadow. Ele não publica no
ETCD, não consulta LLM e não executa ações de rede.
"""

from __future__ import annotations

import argparse
import json
import math
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from qos_holt import MultiHorizonHoltForecaster, QosHoltModel
from sla_risk import (
    SLA_RISK_EVENT_TYPE,
    SlaRiskPersistence,
    SlaRiskPolicy,
    evaluate_sla_forecast,
)
from train_qos_holt_model import load_manifest


BACKTEST_SCHEMA_VERSION = "comas-sla-risk-backtest/1"


def _ratio(numerator: int, denominator: int) -> Optional[float]:
    if denominator == 0:
        return None
    return round(numerator / denominator, 12)


def _latency_summary(values: Iterable[float]) -> Dict[str, Any]:
    parsed = [round(float(value), 12) for value in values]
    if not parsed:
        return {
            "count": 0,
            "values": [],
            "minimum": None,
            "mean": None,
            "maximum": None,
        }
    return {
        "count": len(parsed),
        "values": parsed,
        "minimum": min(parsed),
        "mean": round(sum(parsed) / len(parsed), 12),
        "maximum": max(parsed),
    }


def _confusion_metrics(confusion: Dict[str, int]) -> Dict[str, Optional[float]]:
    tp = confusion["TP"]
    tn = confusion["TN"]
    fp = confusion["FP"]
    fn = confusion["FN"]
    precision = _ratio(tp, tp + fp)
    recall = _ratio(tp, tp + fn)
    specificity = _ratio(tn, tn + fp)
    f1 = None
    if precision is not None and recall is not None and precision + recall:
        f1 = round(2.0 * precision * recall / (precision + recall), 12)
    return {
        "accuracy": _ratio(tp + tn, tp + tn + fp + fn),
        "precision": precision,
        "recall": recall,
        "specificity": specificity,
        "false_positive_rate": _ratio(fp, fp + tn),
        "f1": f1,
    }


def _classification_block(confusion: Counter) -> Dict[str, Any]:
    normalized = {
        name: int(confusion.get(name, 0))
        for name in ("TP", "TN", "FP", "FN")
    }
    return {
        "confusion": normalized,
        "metrics": _confusion_metrics(normalized),
    }


def _update_confusion(counter: Counter, predicted: bool, actual: bool) -> None:
    if predicted and actual:
        counter["TP"] += 1
    elif predicted:
        counter["FP"] += 1
    elif actual:
        counter["FN"] += 1
    else:
        counter["TN"] += 1


def _first_consecutive(flags: Sequence[bool], required: int) -> Optional[int]:
    streak = 0
    for index, flag in enumerate(flags):
        streak = streak + 1 if flag else 0
        if streak >= required:
            return index - required + 1
    return None


def _breached(value: float, *, comparator: str, threshold: float) -> bool:
    return value >= threshold if comparator == "MAX" else value <= threshold


def _actual_future_outcome(
    sequence: Sequence[float], index: int, policy: SlaRiskPolicy,
) -> Dict[str, Any]:
    values = [float(sequence[index + step]) for step in policy.horizons_steps]
    flags = [
        _breached(value, comparator=policy.comparator,
                  threshold=policy.threshold)
        for value in values
    ]
    run_start = _first_consecutive(
        flags, policy.required_consecutive_horizons
    )
    return {
        "positive": run_start is not None,
        "values": values,
        "breaches": flags,
        "confirming_horizon_steps": (
            [] if run_start is None else list(policy.horizons_steps[
                run_start:run_start + policy.required_consecutive_horizons
            ])
        ),
    }


def _crossing_indexes(
    sequence: Sequence[float], *, comparator: str, threshold: float,
) -> List[int]:
    breached = [
        _breached(value, comparator=comparator, threshold=threshold)
        for value in sequence
    ]
    return [
        index for index, value in enumerate(breached)
        if value and (index == 0 or not breached[index - 1])
    ]


def _warning_summary(
    *, sequence: Sequence[float], observations: Sequence[Dict[str, Any]],
    comparator: str, threshold: float, max_horizon_steps: int,
    sample_interval_s: float, signal: str,
) -> Dict[str, Any]:
    crossings = _crossing_indexes(
        sequence, comparator=comparator, threshold=threshold
    )
    detected = 0
    ineligible = 0
    latencies: List[float] = []
    for crossing in crossings:
        eligible = [
            row for row in observations
            if 0 < crossing - row["index"] <= max_horizon_steps
        ]
        if not eligible:
            ineligible += 1
            continue
        alerts = [row for row in eligible if row[signal]]
        if alerts:
            detected += 1
            earliest = min(alerts, key=lambda row: row["index"])
            latencies.append(
                (crossing - earliest["index"]) * sample_interval_s
            )
    eligible_count = len(crossings) - ineligible
    return {
        "actual_crossings": len(crossings),
        "eligible_crossings": eligible_count,
        "ineligible_crossings": ineligible,
        "detected": detected,
        "missed": eligible_count - detected,
        "detection_rate": _ratio(detected, eligible_count),
        "warning_lead_time_s": _latency_summary(latencies),
    }


def _source_fingerprint(sources: Iterable[Dict[str, Any]]) -> List[Tuple[Any, ...]]:
    values = [(
        item.get("series_id"), item.get("split"), item.get("cid"),
        item.get("port_id"), item.get("start_ns"), item.get("end_ns"),
        item.get("csv_sha256"),
    ) for item in sources]
    return sorted(values, key=repr)


def _bind_test_sequences(
    test_sequences: Sequence[Sequence[float]], metadata: Dict[str, Any],
) -> List[Dict[str, Any]]:
    bound: List[Dict[str, Any]] = []
    cursor = 0
    for source in metadata.get("source_series", []):
        if source.get("split") != "test":
            continue
        count = int(source.get("usable_sequences", 0))
        for segment in range(count):
            if cursor >= len(test_sequences):
                raise ValueError("metadados excedem as sequências de teste")
            suffix = "" if count == 1 else f"#{segment + 1}"
            bound.append({
                "series_id": f"{source['series_id']}{suffix}",
                "cid": source["cid"],
                "port_id": source["port_id"],
                "values": list(test_sequences[cursor]),
            })
            cursor += 1
    if cursor != len(test_sequences):
        raise ValueError("sequências de teste não possuem metadados correspondentes")
    return bound


def _validate_model(
    model: QosHoltModel, manifest: Dict[str, Any], metadata: Dict[str, Any],
) -> None:
    expected_steps = tuple(int(value) for value in manifest["horizons_steps"])
    actual_steps = tuple(item.horizon_steps for item in model.horizons)
    if actual_steps != expected_steps:
        raise ValueError(
            f"horizontes do modelo {actual_steps!r} diferem do manifesto "
            f"{expected_steps!r}"
        )
    if not math.isclose(
        model.sample_interval_s, float(manifest["sample_interval_s"]),
        rel_tol=0.0, abs_tol=1e-12,
    ):
        raise ValueError("sample_interval_s do modelo difere do manifesto")
    model_sources = model.training.get("source_series")
    if not isinstance(model_sources, list):
        raise ValueError("modelo não registra source_series")
    if _source_fingerprint(model_sources) != _source_fingerprint(
        metadata.get("source_series", [])
    ):
        raise ValueError("fontes ou hashes do modelo diferem do manifesto")


def _empty_accumulator() -> Dict[str, Any]:
    return {
        "evaluated_windows": 0,
        "unscored_tail_windows": 0,
        "actual_positive_windows": 0,
        "actual_negative_windows": 0,
        "decision_counts": Counter(),
        "risk_level_counts": Counter(),
        "candidate": Counter(),
        "any_signal": Counter(),
        "persistent_active": Counter(),
        "watch_positive": 0,
        "watch_negative": 0,
        "activation_transitions": 0,
        "clear_transitions": 0,
        "crossing": {
            "watch_or_candidate": [],
            "candidate": [],
            "persistent_active": [],
        },
    }


def _merge_accumulator(target: Dict[str, Any], source: Dict[str, Any]) -> None:
    for name in (
        "evaluated_windows", "unscored_tail_windows",
        "actual_positive_windows", "actual_negative_windows",
        "watch_positive", "watch_negative", "activation_transitions",
        "clear_transitions",
    ):
        target[name] += source[name]
    for name in (
        "decision_counts", "risk_level_counts", "candidate", "any_signal",
        "persistent_active",
    ):
        target[name].update(source[name])
    for name in target["crossing"]:
        target["crossing"][name].extend(source["crossing"][name])


def _aggregate_crossing(blocks: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    values: List[float] = []
    result = {
        "actual_crossings": 0,
        "eligible_crossings": 0,
        "ineligible_crossings": 0,
        "detected": 0,
        "missed": 0,
    }
    for block in blocks:
        for name in result:
            result[name] += int(block[name])
        values.extend(block["warning_lead_time_s"]["values"])
    result["detection_rate"] = _ratio(
        result["detected"], result["eligible_crossings"]
    )
    result["warning_lead_time_s"] = _latency_summary(values)
    return result


def _render_accumulator(accumulator: Dict[str, Any]) -> Dict[str, Any]:
    evaluated = accumulator["evaluated_windows"]
    watch_windows = accumulator["decision_counts"].get("WATCH", 0)
    watch_total = accumulator["watch_positive"] + accumulator["watch_negative"]
    return {
        "evaluated_windows": evaluated,
        "unscored_tail_windows": accumulator["unscored_tail_windows"],
        "ground_truth": {
            "positive_windows": accumulator["actual_positive_windows"],
            "negative_windows": accumulator["actual_negative_windows"],
        },
        "decision_counts": dict(sorted(accumulator["decision_counts"].items())),
        "risk_level_counts": dict(sorted(accumulator["risk_level_counts"].items())),
        "candidate": _classification_block(accumulator["candidate"]),
        "watch_only": {
            "windows": watch_windows,
            "rate": _ratio(watch_windows, evaluated),
            "future_positive_windows": accumulator["watch_positive"],
            "future_negative_windows": accumulator["watch_negative"],
            "precision": _ratio(accumulator["watch_positive"], watch_total),
        },
        "watch_or_candidate": _classification_block(
            accumulator["any_signal"]
        ),
        "persistent_active": {
            **_classification_block(accumulator["persistent_active"]),
            "activation_transitions": accumulator["activation_transitions"],
            "clear_transitions": accumulator["clear_transitions"],
        },
        "crossing_events": {
            name: _aggregate_crossing(blocks)
            for name, blocks in accumulator["crossing"].items()
        },
    }


def _raw_from_rendered(report: Dict[str, Any]) -> Dict[str, Any]:
    raw = _empty_accumulator()
    raw["evaluated_windows"] = report["evaluated_windows"]
    raw["unscored_tail_windows"] = report["unscored_tail_windows"]
    raw["actual_positive_windows"] = report["ground_truth"]["positive_windows"]
    raw["actual_negative_windows"] = report["ground_truth"]["negative_windows"]
    raw["decision_counts"].update(report["decision_counts"])
    raw["risk_level_counts"].update(report["risk_level_counts"])
    for name in ("candidate", "watch_or_candidate", "persistent_active"):
        target = "any_signal" if name == "watch_or_candidate" else name
        raw[target].update(report[name]["confusion"])
    raw["watch_positive"] = report["watch_only"]["future_positive_windows"]
    raw["watch_negative"] = report["watch_only"]["future_negative_windows"]
    raw["activation_transitions"] = report["persistent_active"]["activation_transitions"]
    raw["clear_transitions"] = report["persistent_active"]["clear_transitions"]
    for name, block in report["crossing_events"].items():
        raw["crossing"][name].append(block)
    return raw


def _backtest_series(
    *, model: QosHoltModel, series: Dict[str, Any], policy: SlaRiskPolicy,
    activation_windows: int, clear_windows: int,
) -> Tuple[Dict[str, Any], Dict[Tuple[str, int], Tuple[float, ...]],
           Dict[Tuple[str, int], bool]]:
    values = series["values"]
    forecaster = MultiHorizonHoltForecaster(model)
    persistence = SlaRiskPersistence(
        activation_windows=activation_windows,
        clear_windows=clear_windows,
    )
    maximum_horizon = max(policy.horizons_steps)
    accumulator = _empty_accumulator()
    observations: List[Dict[str, Any]] = []
    point_signature: Dict[Tuple[str, int], Tuple[float, ...]] = {}
    candidate_signature: Dict[Tuple[str, int], bool] = {}

    for index, observed in enumerate(values):
        forecasts = forecaster.update(observed)
        if not forecasts:
            continue
        if index + maximum_horizon >= len(values):
            accumulator["unscored_tail_windows"] += 1
            continue
        observation_ns = int(
            round((index + 1) * model.sample_interval_s * 1_000_000_000)
        )
        evaluation = evaluate_sla_forecast(
            policy=policy,
            cid=series["cid"],
            subject_type="port",
            subject_id=series["port_id"],
            observed_value=observed,
            window_id=index + 1,
            observation_ns=observation_ns,
            sample_interval_s=model.sample_interval_s,
            forecasts=forecasts,
            model_id=model.resolved_model_id(),
            model_type=model.model_type,
            created_ns=observation_ns,
            ttl_s=maximum_horizon * model.sample_interval_s,
        )
        actual = _actual_future_outcome(values, index, policy)
        persistence_result = persistence.update(evaluation)
        decision = evaluation["decision"]
        candidate = decision == SLA_RISK_EVENT_TYPE
        any_signal = decision != "NORMAL"
        persistent_active = bool(persistence_result["active"])

        accumulator["evaluated_windows"] += 1
        accumulator[
            "actual_positive_windows" if actual["positive"]
            else "actual_negative_windows"
        ] += 1
        accumulator["decision_counts"][decision] += 1
        accumulator["risk_level_counts"][evaluation["risk"]["level"]] += 1
        _update_confusion(accumulator["candidate"], candidate, actual["positive"])
        _update_confusion(accumulator["any_signal"], any_signal, actual["positive"])
        _update_confusion(
            accumulator["persistent_active"], persistent_active,
            actual["positive"],
        )
        if decision == "WATCH":
            accumulator[
                "watch_positive" if actual["positive"] else "watch_negative"
            ] += 1
        if persistence_result["transitioned"]:
            if persistence_result["active"]:
                accumulator["activation_transitions"] += 1
            else:
                accumulator["clear_transitions"] += 1

        observations.append({
            "index": index,
            "watch_or_candidate": any_signal,
            "candidate": candidate,
            "persistent_active": persistent_active,
        })
        key = (series["series_id"], index)
        point_signature[key] = tuple(
            float(item["predicted_value"]) for item in forecasts
        )
        candidate_signature[key] = candidate

    for signal in accumulator["crossing"]:
        accumulator["crossing"][signal].append(_warning_summary(
            sequence=values,
            observations=observations,
            comparator=policy.comparator,
            threshold=policy.threshold,
            max_horizon_steps=maximum_horizon,
            sample_interval_s=model.sample_interval_s,
            signal=signal,
        ))

    report = {
        "series_id": series["series_id"],
        "cid": series["cid"],
        "port_id": series["port_id"],
        "samples": len(values),
        **_render_accumulator(accumulator),
    }
    return report, point_signature, candidate_signature


def backtest_model(
    *, model: QosHoltModel, series: Sequence[Dict[str, Any]],
    threshold: float, required_consecutive_horizons: int,
    activation_windows: int, clear_windows: int,
) -> Tuple[Dict[str, Any], Dict[Tuple[str, int], Tuple[float, ...]],
           Dict[Tuple[str, int], bool]]:
    policy = SlaRiskPolicy(
        metric="utilization_ratio",
        comparator="MAX",
        threshold=threshold,
        horizons_steps=tuple(item.horizon_steps for item in model.horizons),
        required_consecutive_horizons=required_consecutive_horizons,
    )
    aggregate = _empty_accumulator()
    per_series: List[Dict[str, Any]] = []
    point_signature: Dict[Tuple[str, int], Tuple[float, ...]] = {}
    candidate_signature: Dict[Tuple[str, int], bool] = {}
    for item in series:
        report, points, candidates = _backtest_series(
            model=model,
            series=item,
            policy=policy,
            activation_windows=activation_windows,
            clear_windows=clear_windows,
        )
        per_series.append(report)
        point_signature.update(points)
        candidate_signature.update(candidates)
        _merge_accumulator(aggregate, _raw_from_rendered(report))

    return ({
        "model_id": model.resolved_model_id(),
        "model_type": model.model_type,
        "coverage": model.coverage,
        "validation_scope": model.training.get("validation_scope"),
        "promotion_eligible": bool(model.training.get("promotion_eligible", False)),
        "horizons": [
            {
                "horizon_steps": item.horizon_steps,
                "horizon_s": item.horizon_steps * model.sample_interval_s,
                "alpha": item.alpha,
                "beta": item.beta,
                "interval_radius": item.interval_radius,
            }
            for item in model.horizons
        ],
        "aggregate": _render_accumulator(aggregate),
        "series": per_series,
    }, point_signature, candidate_signature)


def build_report(
    *, manifest_path: Path, model_specs: Sequence[Tuple[str, Path]],
    threshold: float, required_consecutive_horizons: int,
    activation_windows: int, clear_windows: int,
) -> Dict[str, Any]:
    manifest, partitions, metadata = load_manifest(manifest_path)
    series = _bind_test_sequences(partitions["test"], metadata)
    models: Dict[str, Any] = {}
    point_signatures = []
    candidate_signatures = []
    for name, path in model_specs:
        model = QosHoltModel.load(path)
        _validate_model(model, manifest, metadata)
        result, points, candidates = backtest_model(
            model=model,
            series=series,
            threshold=threshold,
            required_consecutive_horizons=required_consecutive_horizons,
            activation_windows=activation_windows,
            clear_windows=clear_windows,
        )
        result["path"] = str(path.resolve())
        models[name] = result
        point_signatures.append(points)
        candidate_signatures.append(candidates)

    return {
        "schema_version": BACKTEST_SCHEMA_VERSION,
        "created_at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
        "manifest": str(manifest_path.resolve()),
        "validation_scope": metadata["validation_scope"],
        "promotion_eligible": metadata["promotion_eligible"],
        "split": "test",
        "policy": {
            "metric": "utilization_ratio",
            "comparator": "MAX",
            "threshold": threshold,
            "horizons_steps": list(manifest["horizons_steps"]),
            "required_consecutive_horizons": required_consecutive_horizons,
            "activation_windows": activation_windows,
            "clear_windows": clear_windows,
            "ground_truth": (
                "actual observations breach the SLA at the same required number "
                "of consecutive forecast horizons"
            ),
        },
        "comparison": {
            "point_forecasts_identical_across_models": (
                all(item == point_signatures[0] for item in point_signatures[1:])
            ),
            "candidate_decisions_identical_across_models": (
                all(item == candidate_signatures[0]
                    for item in candidate_signatures[1:])
            ),
        },
        "models": models,
        "limitations": [
            "Window-level observations are temporally dependent and are not "
            "independent experimental repetitions.",
            "Warning lead times describe only threshold crossings present in "
            "the held-out trace.",
            "The pilot_single_run_temporal_split scope is mechanical evidence "
            "and is not eligible for model promotion.",
            "Ground truth is derived from observed port utilization, not from "
            "an independent application-level SLA measurement.",
        ],
    }


def _model_spec(raw: str) -> Tuple[str, Path]:
    name, separator, path = raw.partition("=")
    name = name.strip()
    path = path.strip()
    if not separator or not name or not path:
        raise argparse.ArgumentTypeError("modelo deve usar NOME=CAMINHO")
    return name, Path(path).expanduser()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Backtest offline de PREDICTED_SLA_RISK"
    )
    parser.add_argument("manifest", type=Path)
    parser.add_argument(
        "--model", action="append", type=_model_spec, required=True,
        metavar="NOME=CAMINHO",
    )
    parser.add_argument("--threshold", type=float, default=0.8)
    parser.add_argument("--required-consecutive-horizons", type=int, default=2)
    parser.add_argument("--activation-windows", type=int, default=2)
    parser.add_argument("--clear-windows", type=int, default=2)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--force", action="store_true")
    return parser


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        names = [name for name, _ in args.model]
        if len(names) != len(set(names)):
            raise ValueError("nomes de modelos devem ser únicos")
        protected = {args.manifest.resolve(), *(path.resolve() for _, path in args.model)}
        if args.output.resolve() in protected:
            raise ValueError("--output não pode sobrescrever manifesto ou modelo")
        if not math.isfinite(args.threshold) or args.threshold < 0.0:
            raise ValueError("--threshold deve ser finito e não negativo")
        if args.output.exists() and not args.force:
            raise ValueError(
                f"saída já existe: {args.output}; use --force para substituir"
            )
        report = build_report(
            manifest_path=args.manifest,
            model_specs=args.model,
            threshold=args.threshold,
            required_consecutive_horizons=args.required_consecutive_horizons,
            activation_windows=args.activation_windows,
            clear_windows=args.clear_windows,
        )
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(
            json.dumps(report, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2

    print(f"backtest: {args.output}")
    print(
        "point_forecasts_identical="
        f"{str(report['comparison']['point_forecasts_identical_across_models']).lower()}"
    )
    print(
        "candidate_decisions_identical="
        f"{str(report['comparison']['candidate_decisions_identical_across_models']).lower()}"
    )
    for name, result in report["models"].items():
        aggregate = result["aggregate"]
        metrics = aggregate["candidate"]["metrics"]
        print(
            f"{name}: coverage={result['coverage']} "
            f"windows={aggregate['evaluated_windows']} "
            f"watch={aggregate['watch_only']['windows']} "
            f"precision={metrics['precision']} recall={metrics['recall']} "
            f"f1={metrics['f1']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
