#!/usr/bin/env python3
"""Funções puras para fusão multicritério de evidências multi-domínio."""

import json
import math
from typing import Any, Dict, List, Optional


DEFAULT_COLLAB_WEIGHTS = {
    "severity": 0.25,
    "corroboration": 0.25,
    "rate_ratio": 0.13,
    "persistence": 0.12,
    "model_reliability": 0.08,
    "freshness": 0.05,
    "topology": 0.05,
    "agreement": 0.07,
}


def load_collaboration_weights(raw: str) -> Dict[str, float]:
    """Carrega pesos parciais, valida-os e normaliza a soma para um."""
    weights = dict(DEFAULT_COLLAB_WEIGHTS)
    if raw.strip():
        try:
            overrides = json.loads(raw)
        except json.JSONDecodeError as exc:
            raise ValueError("COLLAB_WEIGHTS_JSON deve ser JSON válido") from exc
        if not isinstance(overrides, dict):
            raise ValueError("COLLAB_WEIGHTS_JSON deve ser um objeto")
        unknown = set(overrides) - set(weights)
        if unknown:
            raise ValueError(f"critérios MCDA desconhecidos: {sorted(unknown)}")
        weights.update(overrides)
    try:
        parsed = {name: float(value) for name, value in weights.items()}
    except (TypeError, ValueError) as exc:
        raise ValueError("pesos MCDA devem ser numéricos") from exc
    if any(not math.isfinite(value) or value < 0.0 for value in parsed.values()):
        raise ValueError("pesos MCDA devem ser não negativos e finitos")
    total = sum(parsed.values())
    if total <= 0.0:
        raise ValueError("ao menos um peso MCDA deve ser positivo")
    return {name: value / total for name, value in parsed.items()}


def canonical_flow_key(anomaly: Dict[str, Any]) -> Optional[str]:
    """Retorna a identidade de fluxo comum a switches e domínios."""
    meta = anomaly.get("meta", {})
    src = meta.get("nw_src")
    dst = meta.get("nw_dst")
    if anomaly.get("kind") != "THROUGHPUT_SPIKE" or meta.get("type") != "flow":
        return None
    if not src or not dst:
        return None
    return f"{src}->{dst}"


def clip01(value: float) -> float:
    return max(0.0, min(1.0, float(value)))


def score_collaborative_evidence(
        evidences: List[Dict[str, Any]], *, now_ns_value: int,
        expected_domains: int, min_domains: int, weights: Dict[str, float],
        freshness_s: float, persistence_windows: int, rate_ratio_max: float,
        suspect_threshold: float, alert_threshold: float,
        decision_threshold: float) -> Dict[str, Any]:
    """Funde evidências de domínios independentes em uma decisão explicável.

    Cada critério é normalizado para ``[0, 1]``. A função não acessa rede nem
    estado global, o que permite reproduzir uma decisão experimentalmente.
    """
    latest_by_cid: Dict[str, Dict[str, Any]] = {}
    for evidence in evidences:
        cid = str(evidence.get("cid", ""))
        try:
            ts_ns = int(evidence.get("ts_ns", 0))
        except (TypeError, ValueError):
            continue
        age_ns = now_ns_value - ts_ns
        if not cid or age_ns < 0 or age_ns > freshness_s * 1e9:
            continue
        previous = latest_by_cid.get(cid)
        if previous is None or ts_ns > int(previous.get("ts_ns", 0)):
            latest_by_cid[cid] = evidence

    current = list(latest_by_cid.values())
    model_ids = sorted({str(item.get("model_id", "unknown")) for item in current})
    window_ids = set()
    for item in current:
        try:
            window_id = int(item.get("window_id", -1))
        except (TypeError, ValueError):
            continue
        if window_id >= 0:
            window_ids.add(window_id)
    empty_criteria = {name: 0.0 for name in weights}
    base = {
        "score": 0.0,
        "criteria": empty_criteria,
        "contributions": empty_criteria.copy(),
        "participating_domains": sorted(latest_by_cid),
        "confirming_domains": [],
        "expected_domains": expected_domains,
        "min_domains": min_domains,
        "model_ids": model_ids,
        "window_ids": sorted(window_ids),
        "observation_start_ns": (
            min(int(item["ts_ns"]) for item in current) if current else None
        ),
        "observation_end_ns": (
            max(int(item["ts_ns"]) for item in current) if current else None
        ),
    }
    if not current:
        return {**base, "decision": "NO_EVIDENCE", "reason": "sem evidência recente"}
    if len(model_ids) != 1:
        return {
            **base,
            "decision": "MODEL_MISMATCH",
            "reason": "domínios usam modelos incompatíveis",
        }

    confirming = []
    for item in current:
        try:
            if float(item.get("z_score", 0.0)) >= float(item.get("threshold", math.inf)):
                confirming.append(item)
        except (TypeError, ValueError):
            continue
    confirming_domains = sorted(str(item["cid"]) for item in confirming)
    if not confirming:
        return {
            **base,
            "decision": "NORMAL",
            "reason": "nenhum domínio confirmou o limiar estatístico",
        }

    severities = []
    rate_ratios = []
    persistences = []
    reliabilities = []
    freshness_values = []
    topology_values = []
    z_values = []
    for item in confirming:
        z_score = max(0.0, float(item.get("z_score", 0.0)))
        threshold = max(float(item.get("threshold", 1.0)), 1e-9)
        observed = max(0.0, float(item.get("observed_bps", 0.0)))
        predicted = max(1.0, float(item.get("predicted_bps", 0.0)))
        ratio = max(1.0, observed / predicted)
        age_s = max(0.0, (now_ns_value - int(item["ts_ns"])) / 1e9)

        # 3x o limiar (ou mais) representa severidade máxima.
        severities.append(clip01((z_score / threshold - 1.0) / 2.0))
        rate_ratios.append(clip01(math.log(ratio) / math.log(rate_ratio_max)))
        persistences.append(clip01(
            float(item.get("persistence_windows", 1)) / persistence_windows
        ))
        reliabilities.append(clip01(float(item.get("model_reliability", 0.5))))
        freshness_values.append(clip01(1.0 - age_s / freshness_s))
        topology_values.append(clip01(float(item.get("flow_specificity", 1.0))))
        z_values.append(z_score)

    def mean(values: List[float]) -> float:
        return sum(values) / len(values) if values else 0.0

    if len(z_values) >= 2 and max(z_values) > 0.0:
        agreement = clip01(1.0 - (max(z_values) - min(z_values)) / max(z_values))
    else:
        agreement = 0.0

    criteria = {
        "severity": mean(severities),
        "corroboration": clip01(len(confirming_domains) / expected_domains),
        "rate_ratio": mean(rate_ratios),
        "persistence": mean(persistences),
        "model_reliability": mean(reliabilities),
        "freshness": mean(freshness_values),
        "topology": mean(topology_values),
        "agreement": agreement,
    }
    contributions = {
        name: criteria[name] * weights[name] for name in weights
    }
    # Use the same canonical value for both the protocol decision and its
    # persisted evidence.  Classifying with the full-precision value and only
    # then rounding it for the timeline can otherwise produce an apparently
    # contradictory event at a threshold (for example, CORROBORATED with a
    # recorded score of 0.800000 when the decision threshold is 0.8).
    score = round(clip01(sum(contributions.values())), 6)
    if score < suspect_threshold:
        decision = "NORMAL"
    elif score < alert_threshold:
        decision = "SUSPECT"
    elif score < decision_threshold:
        decision = "CORROBORATED"
    elif len(confirming_domains) < min_domains:
        decision = "WAITING_QUORUM"
    else:
        decision = "MITIGATE"

    return {
        **base,
        "score": score,
        "criteria": {name: round(value, 6) for name, value in criteria.items()},
        "contributions": {
            name: round(value, 6) for name, value in contributions.items()
        },
        "confirming_domains": confirming_domains,
        "decision": decision,
        "reason": ("quórum e pontuação suficientes" if decision == "MITIGATE"
                   else "pontuação/quórum ainda insuficientes"),
    }
