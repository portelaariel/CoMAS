#!/usr/bin/env python3
"""Detecção determinística de risco futuro de violação de SLA.

O módulo é deliberadamente independente do caminho de mitigação DDoS. Ele
recebe previsões multihorizonte já calculadas e intervalos calibrados, classifica
o risco e aplica persistência temporal. Não publica no ETCD, não consulta LLM e
não executa ações de rede.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any, Dict, Iterable, List, Optional, Tuple


SLA_RISK_SCHEMA_VERSION = 1
SLA_RISK_EVENT_TYPE = "PREDICTED_SLA_RISK"
SLA_EVALUATION_EVENT_TYPE = "SLA_RISK_EVALUATION"

SUPPORTED_METRICS = {
    "throughput_bps",
    "utilization_ratio",
    "rtt_ms",
    "jitter_ms",
    "loss_ratio",
    "queue_occupancy_ratio",
}
SUPPORTED_COMPARATORS = {"MAX", "MIN"}
SUPPORTED_SUBJECT_TYPES = {"flow", "port", "path", "service"}


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


@dataclass(frozen=True)
class SlaRiskPolicy:
    """Política imutável usada para avaliar uma série de QoS."""

    metric: str
    comparator: str
    threshold: float
    horizons_steps: Tuple[int, ...] = (2, 4, 6)
    required_consecutive_horizons: int = 2

    def __post_init__(self) -> None:
        if self.metric not in SUPPORTED_METRICS:
            raise ValueError(f"métrica de SLA não suportada: {self.metric!r}")
        if self.comparator not in SUPPORTED_COMPARATORS:
            raise ValueError("comparator deve ser MAX ou MIN")
        threshold = _finite(self.threshold, "threshold")
        if threshold < 0.0:
            raise ValueError("threshold não pode ser negativo")
        horizons = tuple(
            _positive_int(value, "horizons_steps")
            for value in self.horizons_steps
        )
        if not horizons or tuple(sorted(set(horizons))) != horizons:
            raise ValueError("horizons_steps deve ser crescente e sem repetições")
        required = _positive_int(
            self.required_consecutive_horizons,
            "required_consecutive_horizons",
        )
        if required > len(horizons):
            raise ValueError(
                "required_consecutive_horizons excede os horizontes disponíveis"
            )
        object.__setattr__(self, "threshold", threshold)
        object.__setattr__(self, "horizons_steps", horizons)
        object.__setattr__(self, "required_consecutive_horizons", required)


def _breach_flags(*, comparator: str, threshold: float, predicted: float,
                  lower: float, upper: float) -> Tuple[bool, bool, bool]:
    """Retorna (possível, provável, intervalo inteiro em violação)."""
    if comparator == "MAX":
        return upper >= threshold, predicted >= threshold, lower >= threshold
    return lower <= threshold, predicted <= threshold, upper <= threshold


def _first_consecutive_run(flags: List[bool], required: int) -> Optional[int]:
    streak = 0
    for index, flag in enumerate(flags):
        streak = streak + 1 if flag else 0
        if streak >= required:
            return index - required + 1
    return None


def evaluate_sla_forecast(
    *,
    policy: SlaRiskPolicy,
    cid: str,
    subject_type: str,
    subject_id: str,
    observed_value: float,
    window_id: int,
    observation_ns: int,
    sample_interval_s: float,
    forecasts: Iterable[Dict[str, Any]],
    model_id: str,
    model_type: str,
    created_ns: int,
    ttl_s: float,
) -> Dict[str, Any]:
    """Avalia cruzamentos futuros sem realizar qualquer efeito externo.

    Cada previsão precisa trazer ``horizon_steps``, ``predicted_value``,
    ``lower_bound`` e ``upper_bound``. Os intervalos devem ter sido calibrados
    previamente para cada horizonte; este módulo não inventa incerteza.
    """
    cid = str(cid).strip()
    subject_type = str(subject_type).strip()
    subject_id = str(subject_id).strip()
    model_id = str(model_id).strip()
    model_type = str(model_type).strip()
    if not all((cid, subject_id, model_id, model_type)):
        raise ValueError("cid, subject_id, model_id e model_type são obrigatórios")
    if subject_type not in SUPPORTED_SUBJECT_TYPES:
        raise ValueError(f"subject_type não suportado: {subject_type!r}")

    observed = _finite(observed_value, "observed_value")
    interval_s = _finite(sample_interval_s, "sample_interval_s")
    ttl = _finite(ttl_s, "ttl_s")
    if interval_s <= 0.0 or ttl <= 0.0:
        raise ValueError("sample_interval_s e ttl_s devem ser positivos")
    window = _positive_int(window_id, "window_id")
    observed_ns = _positive_int(observation_ns, "observation_ns")
    created = _positive_int(created_ns, "created_ns")
    if created < observed_ns:
        raise ValueError("created_ns não pode preceder observation_ns")

    rows: List[Dict[str, Any]] = []
    for raw in forecasts:
        if not isinstance(raw, dict):
            raise ValueError("cada previsão deve ser um objeto")
        steps = _positive_int(raw.get("horizon_steps"), "horizon_steps")
        predicted = _finite(raw.get("predicted_value"), "predicted_value")
        lower = _finite(raw.get("lower_bound"), "lower_bound")
        upper = _finite(raw.get("upper_bound"), "upper_bound")
        if lower > predicted or predicted > upper:
            raise ValueError("o intervalo deve conter predicted_value")
        possible, likely, high_confidence = _breach_flags(
            comparator=policy.comparator,
            threshold=policy.threshold,
            predicted=predicted,
            lower=lower,
            upper=upper,
        )
        level = (
            "HIGH_CONFIDENCE" if high_confidence else
            "LIKELY" if likely else
            "POSSIBLE" if possible else
            "CLEAR"
        )
        rows.append({
            "horizon_steps": steps,
            "horizon_s": round(steps * interval_s, 6),
            "predicted_value": predicted,
            "lower_bound": lower,
            "upper_bound": upper,
            "risk_level": level,
            "possible_breach": possible,
            "likely_breach": likely,
            "high_confidence_breach": high_confidence,
        })

    rows.sort(key=lambda item: item["horizon_steps"])
    received_horizons = tuple(item["horizon_steps"] for item in rows)
    if received_horizons != policy.horizons_steps:
        raise ValueError(
            f"horizontes recebidos {received_horizons!r} diferem da política "
            f"{policy.horizons_steps!r}"
        )

    likely_flags = [item["likely_breach"] for item in rows]
    run_start = _first_consecutive_run(
        likely_flags, policy.required_consecutive_horizons
    )
    first_possible = next(
        (item for item in rows if item["possible_breach"]), None
    )
    first_likely = next(
        (item for item in rows if item["likely_breach"]), None
    )
    candidate = run_start is not None
    if candidate:
        decision = SLA_RISK_EVENT_TYPE
    elif first_possible is not None:
        decision = "WATCH"
    else:
        decision = "NORMAL"

    if any(item["high_confidence_breach"] for item in rows):
        aggregate_level = "HIGH_CONFIDENCE"
    elif first_likely is not None:
        aggregate_level = "LIKELY"
    elif first_possible is not None:
        aggregate_level = "POSSIBLE"
    else:
        aggregate_level = "CLEAR"

    expires_ns = created + int(ttl * 1e9)
    return {
        "schema_version": SLA_RISK_SCHEMA_VERSION,
        "event_type": (
            SLA_RISK_EVENT_TYPE if candidate else SLA_EVALUATION_EVENT_TYPE
        ),
        "decision": decision,
        "cid": cid,
        "subject": {"type": subject_type, "id": subject_id},
        "metric": policy.metric,
        "sla": {
            "comparator": policy.comparator,
            "threshold": policy.threshold,
        },
        "observation": {
            "window_id": window,
            "value": observed,
            "observed_ns": observed_ns,
        },
        "forecast": {
            "sample_interval_s": interval_s,
            "required_consecutive_horizons": (
                policy.required_consecutive_horizons
            ),
            "horizons": rows,
        },
        "risk": {
            "level": aggregate_level,
            "candidate": candidate,
            "earliest_possible_crossing_s": (
                None if first_possible is None else first_possible["horizon_s"]
            ),
            "earliest_likely_crossing_s": (
                None if first_likely is None else first_likely["horizon_s"]
            ),
            "confirming_horizon_steps": (
                [] if run_start is None else [
                    item["horizon_steps"]
                    for item in rows[
                        run_start:run_start + policy.required_consecutive_horizons
                    ]
                ]
            ),
        },
        "model": {"id": model_id, "type": model_type},
        "created_ns": created,
        "expires_ns": expires_ns,
    }


class SlaRiskPersistence:
    """Confirma candidatos e limpa após ciclos sem um novo candidato.

    ``WATCH`` representa incerteza do intervalo, não uma renovação do risco
    pontual. Por isso ele interrompe a sequência de ativação e, assim como
    ``NORMAL``, conta para a limpeza de um risco anteriormente ativo.
    """

    def __init__(self, activation_windows: int = 2, clear_windows: int = 2):
        self.activation_windows = _positive_int(
            activation_windows, "activation_windows"
        )
        self.clear_windows = _positive_int(clear_windows, "clear_windows")
        self._states: Dict[Tuple[str, str, str], Dict[str, Any]] = {}

    def update(self, evaluation: Dict[str, Any]) -> Dict[str, Any]:
        subject = evaluation.get("subject") or {}
        key = (
            str(evaluation.get("cid", "")),
            str(subject.get("id", "")),
            str(evaluation.get("metric", "")),
        )
        if not all(key):
            raise ValueError("avaliação não identifica cid, subject e metric")
        decision = evaluation.get("decision")
        if decision not in {SLA_RISK_EVENT_TYPE, "WATCH", "NORMAL"}:
            raise ValueError("decision de risco inválida")

        state = self._states.setdefault(key, {
            "active": False,
            "risk_streak": 0,
            "clear_streak": 0,
        })
        transitioned = False
        if decision == SLA_RISK_EVENT_TYPE:
            state["risk_streak"] += 1
            state["clear_streak"] = 0
            if (not state["active"]
                    and state["risk_streak"] >= self.activation_windows):
                state["active"] = True
                transitioned = True
            status = "ACTIVE_RISK" if state["active"] else "PENDING_RISK"
        else:
            state["risk_streak"] = 0
            if state["active"]:
                state["clear_streak"] += 1
                if state["clear_streak"] >= self.clear_windows:
                    state["active"] = False
                    state["clear_streak"] = 0
                    transitioned = True
                    status = "CLEARED" if decision == "NORMAL" else "WATCH"
                else:
                    status = "ACTIVE_RISK"
            else:
                state["clear_streak"] = 0
                status = decision

        return {
            "status": status,
            "active": state["active"],
            "transitioned": transitioned,
            "risk_streak": state["risk_streak"],
            "clear_streak": state["clear_streak"],
            "activation_windows": self.activation_windows,
            "clear_windows": self.clear_windows,
        }
