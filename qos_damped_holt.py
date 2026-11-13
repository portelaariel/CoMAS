"""Experimental additive damped Holt: separate artifact, train-only selection.

The frozen qos_holt.py model and runtime are not modified. These artifacts
require separate prospective evaluation and cannot be loaded as native Holt.
"""

from __future__ import annotations

import json
import math
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Tuple

from qos_holt import (
    HorizonModel, QosHoltModel, _canonical_digest, _finite, _metrics,
    _positive_int, _updated_state, conformal_radius,
)


MODEL_TYPE = "damped_holt_qos_multihorizon"
SELECTION_OBJECTIVE = "mean_profile_mean_run_mse; ports/windows pooled within each run"
METHOD_REFERENCE = "https://www.statsmodels.org/stable/_modules/statsmodels/tsa/holtwinters/model.html"


@dataclass(frozen=True)
class DampedHorizonModel(HorizonModel):
    phi: float = 1.0

    def __post_init__(self) -> None:
        super().__post_init__()
        if (any(isinstance(v, bool) for v in (self.alpha, self.beta, self.phi))
                or not 0 < _finite(self.phi, "phi") <= 1):
            raise ValueError("phi deve estar em (0, 1]")

    def to_dict(self) -> Dict[str, Any]:
        return {**super().to_dict(), "phi": self.phi}


@dataclass(frozen=True)
class QosDampedHoltModel(QosHoltModel):
    model_type: str = MODEL_TYPE

    def __post_init__(self) -> None:
        super().__post_init__()
        if (self.model_type != MODEL_TYPE or self.schema_version != 1
                or any(not isinstance(h, DampedHorizonModel) for h in self.horizons)):
            raise ValueError("contrato do modelo amortecido inválido")
        if any(h.test_metrics for h in self.horizons):
            raise ValueError("artefato de desenvolvimento não pode conter métricas de teste")
        if self.training.get("promotion_eligible", False) is not False or self.training.get("deployment_eligible", False) is not False:
            raise ValueError("artefato experimental não pode declarar promoção/deployment")
        if self.training.get("test_evaluated", False) is not False:
            raise ValueError("artefato de desenvolvimento não contém teste independente")

    def resolved_model_id(self) -> str:
        return self.model_id or f"{MODEL_TYPE}:{_canonical_digest(self._payload_without_id())[:24]}"

    @classmethod
    def from_dict(cls, payload: Dict[str, Any]) -> "QosDampedHoltModel":
        if not isinstance(payload, dict) or payload.get("schema_version") != 1 or payload.get("model_type") != MODEL_TYPE:
            raise ValueError("schema/tipo do artefato amortecido inválido")
        raw_horizons = payload.get("horizons")
        runtime, training = payload.get("runtime"), payload.get("training")
        if not isinstance(raw_horizons, list) or not raw_horizons or not isinstance(runtime, dict) or not isinstance(training, dict):
            raise ValueError("horizons/runtime/training inválidos")
        horizons = []
        for raw in raw_horizons:
            if not isinstance(raw, dict) or "phi" not in raw:
                raise ValueError("phi é obrigatório em cada horizonte")
            interval, metrics = raw.get("interval"), raw.get("metrics", {})
            if not isinstance(interval, dict) or interval.get("method") != "absolute_residual_split_conformal" or not isinstance(metrics, dict):
                raise ValueError("interval/metrics inválidos")
            if metrics.get("test", {}):
                raise ValueError("artefato de desenvolvimento não pode conter métricas de teste")
            horizons.append(DampedHorizonModel(
                horizon_steps=raw.get("horizon_steps"), alpha=raw.get("alpha"), beta=raw.get("beta"), phi=raw["phi"],
                interval_radius=interval.get("radius"), calibration_samples=interval.get("calibration_samples"),
                training_metrics=dict(metrics.get("training", {})), calibration_metrics=dict(metrics.get("calibration", {}))))
        model = cls(metric=payload.get("metric"), sample_interval_s=payload.get("sample_interval_s"),
                    coverage=payload.get("coverage"), priming_samples=runtime.get("priming_samples"),
                    horizons=tuple(horizons), created_at=payload.get("created_at", ""), training=dict(training))
        if payload.get("model_id") != model.resolved_model_id():
            raise ValueError("model_id não corresponde ao conteúdo do artefato")
        return model

    @classmethod
    def load(cls, path: Path) -> "QosDampedHoltModel":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))


def updated_state(level: Optional[float], trend: float, observed: float,
                  alpha: float, beta: float, phi: float) -> Tuple[float, float]:
    value = _finite(observed, "observation")
    if value < 0:
        raise ValueError("observação negativa")
    if phi == 1:
        result = _updated_state(level, trend, value, alpha, beta)
    elif level is None:
        result = value, 0.0
    else:
        damped = phi * trend
        new_level = alpha * value + (1 - alpha) * (level + damped)
        result = new_level, beta * (new_level - level) + (1 - beta) * damped
    if not all(math.isfinite(v) for v in result):
        raise ValueError("estado Holt não finito")
    return result


def projected_value(level: float, trend: float, phi: float, steps: int) -> float:
    multiplier = steps if phi == 1 else sum(phi ** i for i in range(1, steps + 1))
    value = level + multiplier * trend
    if not math.isfinite(value):
        raise ValueError("previsão Holt não finita")
    return max(0.0, value)


class MultiHorizonDampedHoltForecaster:
    """Read-only past-only forecasting with separately recalibrated intervals."""

    def __init__(self, model: QosDampedHoltModel):
        self.model = model
        self.states = {h.horizon_steps: dict(level=None, trend=0.0, count=0) for h in model.horizons}

    def update(self, observed_value: float) -> List[Dict[str, float]]:
        observed = _finite(observed_value, "observation")
        if observed < 0:
            raise ValueError("observação negativa")
        forecasts = []
        for h in self.model.horizons:
            state = self.states[h.horizon_steps]
            level, trend = updated_state(state["level"], state["trend"], observed, h.alpha, h.beta, h.phi)
            state.update(level=level, trend=trend, count=state["count"] + 1)
            if state["count"] < self.model.priming_samples:
                continue
            predicted = projected_value(level, trend, h.phi, h.horizon_steps)
            forecasts.append(dict(horizon_steps=h.horizon_steps, predicted_value=round(predicted, 12),
                                  lower_bound=round(max(0.0, predicted - h.interval_radius), 12),
                                  upper_bound=round(predicted + h.interval_radius, 12)))
        return forecasts


def forecast_records(values: Sequence[float], *, alpha: float, beta: float, phi: float,
                     horizon_steps: int, priming_samples: int) -> List[Tuple[float, float, float]]:
    """One sequence, one state reset; future targets are only scoring labels."""
    horizon_steps = _positive_int(horizon_steps, "horizon_steps")
    priming_samples = _positive_int(priming_samples, "priming_samples")
    alpha, beta, phi = (_validated_grid([v], name, zero)[0] for v, name, zero in (
        (alpha, "alpha", False), (beta, "beta", True), (phi, "phi", False)))
    values = [_finite(value, "observation") for value in values]
    level, trend = None, 0.0
    result = []
    for index, value in enumerate(values):
        level, trend = updated_state(level, trend, value, alpha, beta, phi)
        if index + 1 < priming_samples or index + horizon_steps >= len(values):
            continue
        prediction = round(projected_value(level, trend, phi, horizon_steps), 12)
        actual = values[index + horizon_steps]
        result.append((actual, prediction, actual - prediction))
    return result


def balanced_loss(series: Sequence[Dict[str, Any]], records: Sequence[List[Tuple[float, float, float]]]) -> float:
    """Equal profile/run weights; never treat correlated ports as independent runs."""
    if not series or len(series) != len(records):
        raise ValueError("sequências e previsões incompatíveis")
    by_run = defaultdict(list)
    profiles = {}
    for item, scores in zip(series, records):
        by_run[item["run_id"]].extend(row[2] ** 2 for row in scores)
        profiles[item["run_id"]] = item["profile"]
    by_profile = defaultdict(list)
    for run, squared in by_run.items():
        if not squared:
            raise ValueError("execução de treino sem previsões suficientes")
        by_profile[profiles[run]].append(sum(squared) / len(squared))
    return sum(sum(losses) / len(losses) for losses in by_profile.values()) / len(by_profile)


def _validated_grid(values: Sequence[float], name: str, allow_zero: bool) -> List[float]:
    if not values or any(isinstance(v, bool) for v in values):
        raise ValueError(f"grid {name} vazio/inválido")
    result = sorted({_finite(v, name) for v in values})
    if any(v < 0 or v > 1 or (v == 0 and not allow_zero) for v in result):
        raise ValueError(f"grid {name} fora do intervalo")
    return result


def train_damped_model(*, train_series: Sequence[Dict[str, Any]], calibration_series: Sequence[Dict[str, Any]],
                       horizons_steps: Sequence[int], sample_interval_s: float, priming_samples: int,
                       coverage: float, alphas: Sequence[float], betas: Sequence[float], phis: Sequence[float],
                       created_at: str, training_metadata: Dict[str, Any]) -> Tuple[QosDampedHoltModel, Dict[str, Any]]:
    """Choose alpha/beta/phi jointly using TRAIN only; CALIBRATION sets radii only."""
    alpha_grid, beta_grid, phi_grid = (_validated_grid(grid, name, zero) for grid, name, zero in (
        (alphas, "alpha", False), (betas, "beta", True), (phis, "phi", False)))
    sample_interval_s, coverage = _finite(sample_interval_s, "sample_interval_s"), _finite(coverage, "coverage")
    if sample_interval_s <= 0 or not 0.5 < coverage < 1:
        raise ValueError("sample_interval_s/coverage inválidos")
    steps = tuple(_positive_int(h, "horizon_steps") for h in horizons_steps)
    priming = _positive_int(priming_samples, "priming_samples")
    if not steps or steps != tuple(sorted(set(steps))):
        raise ValueError("horizontes devem ser crescentes e únicos")
    if not train_series or not calibration_series:
        raise ValueError("treino e calibração são obrigatórios")
    if {s["run_id"] for s in train_series} & {s["run_id"] for s in calibration_series}:
        raise ValueError("execução não pode aparecer em treino e calibração")
    for partition in (train_series, calibration_series):
        run_profiles = defaultdict(set)
        for item in partition:
            run_profiles[item["run_id"]].add(item["profile"])
            if len(item["values"]) < priming + max(steps):
                raise ValueError("sequência curta para treino/calibração")
            if any(not math.isfinite(v) or v < 0 for v in item["values"]):
                raise ValueError("observações inválidas")
        if any(len(names) != 1 for names in run_profiles.values()):
            raise ValueError("execução não pode conter perfis contraditórios")
    horizons, selections = [], []
    for horizon in steps:
        best = None
        candidates = []
        for alpha in alpha_grid:
            for beta in beta_grid:
                for phi in phi_grid:
                    records = [forecast_records(s["values"], alpha=alpha, beta=beta, phi=phi,
                                                horizon_steps=horizon, priming_samples=priming) for s in train_series]
                    loss = balanced_loss(train_series, records)
                    candidates.append(dict(alpha=alpha, beta=beta, phi=phi, balanced_train_mse=loss))
                    key = loss, -phi, alpha, beta  # Exact ties prefer less damping, then smaller alpha/beta.
                    if best is None or key < best[0]:
                        best = key, alpha, beta, phi, records
        _, alpha, beta, phi, records = best
        calibration = [row for item in calibration_series
                       for row in forecast_records(item["values"], alpha=alpha, beta=beta, phi=phi,
                                                   horizon_steps=horizon, priming_samples=priming)]
        radius = conformal_radius([row[2] for row in calibration], coverage)
        horizons.append(DampedHorizonModel(
            horizon_steps=horizon, alpha=alpha, beta=beta, phi=phi, interval_radius=radius,
            calibration_samples=len(calibration), training_metrics=_metrics([r for group in records for r in group]),
            calibration_metrics=_metrics(calibration, radius)))
        selections.append(dict(horizon_steps=horizon, selected=dict(alpha=alpha, beta=beta, phi=phi),
                               balanced_train_mse=best[0][0], candidates=candidates))
        if 1.0 in phi_grid:
            reference = min((c for c in candidates if c["phi"] == 1),
                            key=lambda c: (c["balanced_train_mse"], c["alpha"], c["beta"]))
            ref_records = [r for s in calibration_series for r in forecast_records(
                s["values"], alpha=reference["alpha"], beta=reference["beta"], phi=1,
                horizon_steps=horizon, priming_samples=priming)]
            ref_radius = conformal_radius([row[2] for row in ref_records], coverage)
            selections[-1]["train_selected_undamped_reference"] = {
                **reference, "recalibrated_interval_radius": ref_radius,
                "calibration_descriptive_metrics": _metrics(ref_records, ref_radius)}
    metadata = {**training_metadata, "validation_scope": "posthoc_run_grouped_development_no_holdout",
                "promotion_eligible": False, "deployment_eligible": False, "test_evaluated": False,
                "selection_objective": SELECTION_OBJECTIVE, "method_reference": METHOD_REFERENCE,
                "search_grid": dict(alpha=alpha_grid, beta=beta_grid, phi=phi_grid),
                "tie_break": "minimum_loss_then_largest_phi_then_smallest_alpha_beta"}
    model = QosDampedHoltModel(metric="utilization_ratio", sample_interval_s=sample_interval_s, coverage=coverage,
                              priming_samples=priming, horizons=tuple(horizons), created_at=created_at, training=metadata)
    return model, dict(objective=SELECTION_OBJECTIVE, horizons=selections,
                       calibration_used_for_selection=False, independent_test_used=False)
