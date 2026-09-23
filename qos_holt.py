#!/usr/bin/env python3
"""Holt multi-horizon forecasting for predictive SLA risk.

This module is independent from the DDoS detector.  It fits one Holt model per
forecast horizon, calibrates a finite-sample conformal interval per horizon and
reports metrics on a separate held-out test partition.  It has no ETCD, LLM or
actuation dependency.
"""

from __future__ import annotations

import hashlib
import json
import math
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple


QOS_HOLT_SCHEMA_VERSION = 1
QOS_HOLT_MODEL_TYPE = "holt_qos_multihorizon"


def _finite(value: Any, name: str) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} deve ser numérico") from exc
    if not math.isfinite(parsed):
        raise ValueError(f"{name} deve ser finito")
    return parsed


def _positive_int(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} deve ser inteiro positivo")
    try:
        parsed = int(value)
    except (TypeError, ValueError) as exc:
        raise ValueError(f"{name} deve ser inteiro positivo") from exc
    if parsed != value or parsed <= 0:
        raise ValueError(f"{name} deve ser inteiro positivo")
    return parsed


def _canonical_digest(payload: Dict[str, Any]) -> str:
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


@dataclass(frozen=True)
class HorizonModel:
    horizon_steps: int
    alpha: float
    beta: float
    interval_radius: float
    calibration_samples: int
    training_metrics: Dict[str, float] = field(default_factory=dict)
    calibration_metrics: Dict[str, float] = field(default_factory=dict)
    test_metrics: Dict[str, float] = field(default_factory=dict)

    def __post_init__(self) -> None:
        _positive_int(self.horizon_steps, "horizon_steps")
        alpha = _finite(self.alpha, "alpha")
        beta = _finite(self.beta, "beta")
        radius = _finite(self.interval_radius, "interval_radius")
        _positive_int(self.calibration_samples, "calibration_samples")
        if not 0.0 < alpha <= 1.0:
            raise ValueError("alpha deve estar no intervalo (0, 1]")
        if not 0.0 <= beta <= 1.0:
            raise ValueError("beta deve estar no intervalo [0, 1]")
        if radius < 0.0:
            raise ValueError("interval_radius não pode ser negativo")

    def to_dict(self) -> Dict[str, Any]:
        return {
            "horizon_steps": self.horizon_steps,
            "alpha": self.alpha,
            "beta": self.beta,
            "interval": {
                "method": "absolute_residual_split_conformal",
                "radius": self.interval_radius,
                "calibration_samples": self.calibration_samples,
            },
            "metrics": {
                "training": dict(self.training_metrics),
                "calibration": dict(self.calibration_metrics),
                "test": dict(self.test_metrics),
            },
        }


@dataclass(frozen=True)
class QosHoltModel:
    metric: str
    sample_interval_s: float
    coverage: float
    priming_samples: int
    horizons: Tuple[HorizonModel, ...]
    created_at: str
    training: Dict[str, Any] = field(default_factory=dict)
    model_id: str = ""
    schema_version: int = QOS_HOLT_SCHEMA_VERSION
    model_type: str = QOS_HOLT_MODEL_TYPE

    def __post_init__(self) -> None:
        if self.metric != "utilization_ratio":
            raise ValueError("metric deve ser utilization_ratio")
        interval = _finite(self.sample_interval_s, "sample_interval_s")
        coverage = _finite(self.coverage, "coverage")
        _positive_int(self.priming_samples, "priming_samples")
        if interval <= 0.0:
            raise ValueError("sample_interval_s deve ser positivo")
        if not 0.5 < coverage < 1.0:
            raise ValueError("coverage deve estar no intervalo (0.5, 1)")
        if not self.horizons:
            raise ValueError("ao menos um horizonte é obrigatório")
        steps = tuple(item.horizon_steps for item in self.horizons)
        if steps != tuple(sorted(set(steps))):
            raise ValueError("horizontes devem ser crescentes e únicos")
        if not str(self.created_at).strip():
            raise ValueError("created_at é obrigatório")

    def _payload_without_id(self) -> Dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "model_type": self.model_type,
            "metric": self.metric,
            "sample_interval_s": self.sample_interval_s,
            "coverage": self.coverage,
            "runtime": {"priming_samples": self.priming_samples},
            "horizons": [item.to_dict() for item in self.horizons],
            "training": dict(self.training),
            "created_at": self.created_at,
        }

    def resolved_model_id(self) -> str:
        if self.model_id:
            return self.model_id
        return f"{QOS_HOLT_MODEL_TYPE}:{_canonical_digest(self._payload_without_id())[:24]}"

    def to_dict(self) -> Dict[str, Any]:
        payload = self._payload_without_id()
        payload["model_id"] = self.resolved_model_id()
        return payload

    def save(self, path: Path) -> None:
        Path(path).write_text(
            json.dumps(self.to_dict(), indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "QosHoltModel":
        if not isinstance(payload, dict):
            raise ValueError("artefato deve conter um objeto JSON")
        if payload.get("schema_version") != QOS_HOLT_SCHEMA_VERSION:
            raise ValueError("schema_version incompatível")
        if payload.get("model_type") != QOS_HOLT_MODEL_TYPE:
            raise ValueError("model_type incompatível")
        raw_horizons = payload.get("horizons")
        if not isinstance(raw_horizons, list) or not raw_horizons:
            raise ValueError("horizons deve ser uma lista não vazia")
        horizons: List[HorizonModel] = []
        for raw in raw_horizons:
            if not isinstance(raw, dict):
                raise ValueError("cada horizonte deve ser um objeto")
            interval = raw.get("interval")
            metrics = raw.get("metrics", {})
            if not isinstance(interval, dict) or not isinstance(metrics, dict):
                raise ValueError("interval e metrics devem ser objetos")
            if interval.get("method") != "absolute_residual_split_conformal":
                raise ValueError("método de intervalo incompatível")
            horizons.append(HorizonModel(
                horizon_steps=raw.get("horizon_steps"),
                alpha=raw.get("alpha"),
                beta=raw.get("beta"),
                interval_radius=interval.get("radius"),
                calibration_samples=interval.get("calibration_samples"),
                training_metrics=dict(metrics.get("training", {})),
                calibration_metrics=dict(metrics.get("calibration", {})),
                test_metrics=dict(metrics.get("test", {})),
            ))
        runtime = payload.get("runtime")
        training = payload.get("training", {})
        if not isinstance(runtime, dict) or not isinstance(training, dict):
            raise ValueError("runtime e training devem ser objetos")
        model = cls(
            metric=str(payload.get("metric", "")),
            sample_interval_s=payload.get("sample_interval_s"),
            coverage=payload.get("coverage"),
            priming_samples=runtime.get("priming_samples"),
            horizons=tuple(horizons),
            created_at=str(payload.get("created_at", "")),
            training=dict(training),
            model_id=str(payload.get("model_id", "")),
        )
        expected_id = QosHoltModel(
            metric=model.metric,
            sample_interval_s=model.sample_interval_s,
            coverage=model.coverage,
            priming_samples=model.priming_samples,
            horizons=model.horizons,
            created_at=model.created_at,
            training=model.training,
        ).resolved_model_id()
        if model.model_id != expected_id:
            raise ValueError("model_id não corresponde ao conteúdo do artefato")
        return model

    @classmethod
    def load(cls, path: Path) -> "QosHoltModel":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def _updated_state(
    level: Optional[float], trend: float, value: float, alpha: float, beta: float,
) -> Tuple[float, float]:
    observation = _finite(value, "observation")
    if observation < 0.0:
        raise ValueError("observações de utilização não podem ser negativas")
    if level is None:
        return observation, 0.0
    previous_level = level
    level = alpha * observation + (1.0 - alpha) * (level + trend)
    trend = beta * (level - previous_level) + (1.0 - beta) * trend
    return level, trend


def forecast_records(
    sequences: Iterable[Sequence[float]], *, alpha: float, beta: float,
    horizon_steps: int, priming_samples: int,
) -> List[Tuple[float, float, float]]:
    """Return ``(observed, predicted, residual)`` without crossing sequences."""
    horizon = _positive_int(horizon_steps, "horizon_steps")
    priming = _positive_int(priming_samples, "priming_samples")
    records: List[Tuple[float, float, float]] = []
    for raw_sequence in sequences:
        values = [_finite(value, "observation") for value in raw_sequence]
        level: Optional[float] = None
        trend = 0.0
        for index, value in enumerate(values):
            level, trend = _updated_state(level, trend, value, alpha, beta)
            target_index = index + horizon
            if index + 1 < priming or target_index >= len(values):
                continue
            predicted = max(0.0, level + horizon * trend)
            observed = values[target_index]
            records.append((observed, predicted, observed - predicted))
    return records


def _metrics(
    records: Sequence[Tuple[float, float, float]],
    interval_radius: Optional[float] = None,
) -> Dict[str, float]:
    if not records:
        raise ValueError("não há previsões suficientes para calcular métricas")
    residuals = [item[2] for item in records]
    result: Dict[str, float] = {
        "samples": len(records),
        "mae": sum(abs(value) for value in residuals) / len(residuals),
        "rmse": math.sqrt(
            sum(value * value for value in residuals) / len(residuals)
        ),
        "bias": sum(residuals) / len(residuals),
    }
    if interval_radius is not None:
        radius = _finite(interval_radius, "interval_radius")
        result["interval_coverage"] = (
            sum(abs(value) <= radius for value in residuals) / len(residuals)
        )
        result["mean_interval_width"] = 2.0 * radius
    return {key: round(value, 12) for key, value in result.items()}


def fit_horizon(
    sequences: Iterable[Sequence[float]], *, horizon_steps: int,
    priming_samples: int, alphas: Sequence[float], betas: Sequence[float],
) -> Tuple[float, float, Dict[str, float]]:
    cached = [list(sequence) for sequence in sequences]
    best: Optional[Tuple[float, float, float, List[Tuple[float, float, float]]]] = None
    for alpha in alphas:
        parsed_alpha = _finite(alpha, "alpha")
        if not 0.0 < parsed_alpha <= 1.0:
            raise ValueError("alpha deve estar no intervalo (0, 1]")
        for beta in betas:
            parsed_beta = _finite(beta, "beta")
            if not 0.0 <= parsed_beta <= 1.0:
                raise ValueError("beta deve estar no intervalo [0, 1]")
            records = forecast_records(
                cached,
                alpha=parsed_alpha,
                beta=parsed_beta,
                horizon_steps=horizon_steps,
                priming_samples=priming_samples,
            )
            if not records:
                continue
            mse = sum(item[2] * item[2] for item in records) / len(records)
            candidate = (mse, parsed_alpha, parsed_beta, records)
            if best is None or candidate[:3] < best[:3]:
                best = candidate
    if best is None:
        raise ValueError("partição de treino não contém previsões suficientes")
    return best[1], best[2], _metrics(best[3])


def conformal_radius(residuals: Sequence[float], coverage: float) -> float:
    """Finite-sample split-conformal quantile of absolute residuals."""
    parsed_coverage = _finite(coverage, "coverage")
    if not 0.5 < parsed_coverage < 1.0:
        raise ValueError("coverage deve estar no intervalo (0.5, 1)")
    absolute = sorted(abs(_finite(value, "residual")) for value in residuals)
    if not absolute:
        raise ValueError("não há resíduos de calibração")
    rank = min(len(absolute), math.ceil((len(absolute) + 1) * parsed_coverage))
    return absolute[rank - 1]


def train_qos_holt_model(
    *, train_sequences: Iterable[Sequence[float]],
    calibration_sequences: Iterable[Sequence[float]],
    test_sequences: Iterable[Sequence[float]], horizons_steps: Sequence[int],
    sample_interval_s: float, coverage: float, priming_samples: int,
    alphas: Sequence[float], betas: Sequence[float], created_at: str,
    training_metadata: Optional[Dict[str, Any]] = None,
) -> QosHoltModel:
    train = [list(sequence) for sequence in train_sequences]
    calibration = [list(sequence) for sequence in calibration_sequences]
    test = [list(sequence) for sequence in test_sequences]
    if not train or not calibration or not test:
        raise ValueError("treino, calibração e teste devem conter sequências")
    steps = tuple(_positive_int(value, "horizons_steps") for value in horizons_steps)
    if steps != tuple(sorted(set(steps))):
        raise ValueError("horizons_steps deve ser crescente e sem repetições")

    horizons: List[HorizonModel] = []
    for horizon in steps:
        alpha, beta, training_metrics = fit_horizon(
            train,
            horizon_steps=horizon,
            priming_samples=priming_samples,
            alphas=alphas,
            betas=betas,
        )
        calibration_records = forecast_records(
            calibration,
            alpha=alpha,
            beta=beta,
            horizon_steps=horizon,
            priming_samples=priming_samples,
        )
        radius = conformal_radius(
            [item[2] for item in calibration_records], coverage
        )
        test_records = forecast_records(
            test,
            alpha=alpha,
            beta=beta,
            horizon_steps=horizon,
            priming_samples=priming_samples,
        )
        horizons.append(HorizonModel(
            horizon_steps=horizon,
            alpha=alpha,
            beta=beta,
            interval_radius=radius,
            calibration_samples=len(calibration_records),
            training_metrics=training_metrics,
            calibration_metrics=_metrics(calibration_records, radius),
            test_metrics=_metrics(test_records, radius),
        ))

    return QosHoltModel(
        metric="utilization_ratio",
        sample_interval_s=sample_interval_s,
        coverage=coverage,
        priming_samples=priming_samples,
        horizons=tuple(horizons),
        created_at=created_at,
        training=dict(training_metadata or {}),
    )


class MultiHorizonHoltForecaster:
    """Online read-only inference using one calibrated state per horizon."""

    def __init__(self, model: QosHoltModel):
        self.model = model
        self._states: Dict[int, Dict[str, Any]] = {
            item.horizon_steps: {"level": None, "trend": 0.0, "count": 0}
            for item in model.horizons
        }

    def update(self, observed_value: float) -> List[Dict[str, float]]:
        result: List[Dict[str, float]] = []
        for horizon in self.model.horizons:
            state = self._states[horizon.horizon_steps]
            level, trend = _updated_state(
                state["level"], state["trend"], observed_value,
                horizon.alpha, horizon.beta,
            )
            state.update(level=level, trend=trend, count=state["count"] + 1)
            if state["count"] < self.model.priming_samples:
                continue
            predicted = max(0.0, level + horizon.horizon_steps * trend)
            result.append({
                "horizon_steps": horizon.horizon_steps,
                "predicted_value": round(predicted, 12),
                "lower_bound": round(
                    max(0.0, predicted - horizon.interval_radius), 12
                ),
                "upper_bound": round(
                    predicted + horizon.interval_radius, 12
                ),
            })
        return result
