"""Offline, one-to-one evaluation of warnings for sustained SLA episodes.

This supplementary ground truth does not replace instantaneous violations or
window-level forecast metrics. No runtime decision or network action is made.
"""

from __future__ import annotations

import math
from typing import Any, Dict, List, Optional, Sequence


EPISODE_POLICY_VERSION = "observed-sla-episodes/1"


def _positive_integer(value: int, name: str) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError(f"{name} deve ser inteiro positivo")


def validate_timestamps(timestamps: Sequence[int], samples: int) -> None:
    if len(timestamps) != samples:
        raise ValueError("timestamps e valores devem ter o mesmo tamanho")
    if any(isinstance(value, bool) or not isinstance(value, int) or value <= 0
           for value in timestamps):
        raise ValueError("timestamps devem ser inteiros positivos")
    if any(right <= left for left, right in zip(timestamps, timestamps[1:])):
        raise ValueError("timestamps devem ser estritamente crescentes")


def episode_policy(min_breach_samples: int, clear_samples: int) -> Dict[str, Any]:
    _positive_integer(min_breach_samples, "episode_min_breach_samples")
    _positive_integer(clear_samples, "episode_clear_samples")
    return {
        "version": EPISODE_POLICY_VERSION,
        "min_consecutive_breach_samples": min_breach_samples,
        "consecutive_clear_samples": clear_samples,
        "onset": "first_breach_in_confirming_streak; retrospective",
        "end": "last_breach_before_confirmed_clear",
        "matching": "chronological_episode_then_earliest_unused_activation",
        "warning_signal": "persistent_activation",
        "warning_horizon": "0 < onset_time - activation_time <= max_horizon_s",
        "observation_scope": "evaluated_windows_only; unscored_tail_has_no_alerts",
        "followup": "onset_horizon_must_leave_min_breach_samples_for_confirmation",
        "independence": "series episodes are not independent experimental runs",
    }


def _observed_episodes(
    values: Sequence[float], *, comparator: str, threshold: float,
    min_breach_samples: int, clear_samples: int,
) -> Dict[str, Any]:
    episodes: List[Dict[str, Any]] = []
    active: Optional[Dict[str, Any]] = None
    breach_streak = clear_streak = 0
    unconfirmed_runs = unconfirmed_samples = 0
    for index, value in enumerate(values):
        breach = value >= threshold if comparator == "MAX" else value <= threshold
        if active is None:
            if breach:
                breach_streak += 1
                if breach_streak >= min_breach_samples:
                    active = {
                        "onset_index": index - min_breach_samples + 1,
                        "confirmation_index": index,
                        "last_breach_index": index,
                        "clear_confirmation_index": None,
                        "breach_samples": breach_streak,
                    }
                    breach_streak = clear_streak = 0
            else:
                if breach_streak:
                    unconfirmed_runs += 1
                    unconfirmed_samples += breach_streak
                breach_streak = 0
        elif breach:
            active["last_breach_index"] = index
            active["breach_samples"] += 1
            clear_streak = 0
        else:
            clear_streak += 1
            if clear_streak >= clear_samples:
                active["clear_confirmation_index"] = index
                episodes.append(active)
                active = None
                clear_streak = 0
    if active is not None:
        episodes.append(active)
    if breach_streak:
        unconfirmed_runs += 1
        unconfirmed_samples += breach_streak
    return {
        "episodes": episodes,
        "unconfirmed_breach_runs": unconfirmed_runs,
        "unconfirmed_breach_samples": unconfirmed_samples,
    }


def evaluate_episodes(
    *, values: Sequence[float], observations: Sequence[Dict[str, Any]],
    timestamps_ns: Optional[Sequence[int]], series_id: str, cid: str,
    port_id: str, comparator: str, threshold: float,
    sample_interval_s: float, max_horizon_steps: int,
    min_breach_samples: int = 2, clear_samples: int = 2,
) -> Dict[str, Any]:
    policy = episode_policy(min_breach_samples, clear_samples)
    _positive_integer(max_horizon_steps, "max_horizon_steps")
    if comparator not in ("MAX", "MIN"):
        raise ValueError("comparador de episódio inválido")
    if not math.isfinite(threshold):
        raise ValueError("limiar de episódio deve ser finito")
    if not math.isfinite(sample_interval_s) or sample_interval_s <= 0:
        raise ValueError("sample_interval_s deve ser finito e positivo")
    policy.update({
        "comparator": comparator,
        "threshold": threshold,
        "max_warning_horizon_s": max_horizon_steps * sample_interval_s,
    })
    if any(not math.isfinite(value) for value in values):
        raise ValueError("valores de episódio devem ser finitos")
    actual_timestamps = timestamps_ns is not None
    timestamps = (list(timestamps_ns) if actual_timestamps else [
        round((index + 1) * sample_interval_s * 1_000_000_000)
        for index in range(len(values))
    ])
    validate_timestamps(timestamps, len(values))
    indexes = [row["index"] for row in observations]
    if any(isinstance(index, bool) or not isinstance(index, int)
           or index < 0 or index >= len(values) for index in indexes):
        raise ValueError("índice de observação fora da série")
    if len(set(indexes)) != len(indexes):
        raise ValueError("índices de observação duplicados")
    indexes.sort()
    activation_indexes = sorted(
        row["index"] for row in observations if row["persistent_activation"]
    )
    horizon_ns = round(max_horizon_steps * sample_interval_s * 1_000_000_000)
    observed = _observed_episodes(
        values, comparator=comparator, threshold=threshold,
        min_breach_samples=min_breach_samples, clear_samples=clear_samples,
    )
    identity = {"series_id": series_id, "cid": cid, "port_id": port_id}
    episodes = []
    used: Dict[int, str] = {}
    for ordinal, raw in enumerate(observed["episodes"], 1):
        onset = raw["onset_index"]
        episode_id = f"{series_id}:episode:{ordinal}"
        eligible_indexes = [
            index for index in indexes
            if 0 < timestamps[onset] - timestamps[index] <= horizon_ns
        ]
        available = [index for index in activation_indexes
                     if index in eligible_indexes and index not in used]
        alert = available[0] if available else None
        if alert is not None:
            used[alert] = episode_id
        clearance = raw["clear_confirmation_index"]
        episodes.append({
            **identity, **raw, "episode_id": episode_id,
            "onset_ts_ns": timestamps[onset],
            "confirmation_ts_ns": timestamps[raw["confirmation_index"]],
            "last_breach_ts_ns": timestamps[raw["last_breach_index"]],
            "clear_confirmation_ts_ns": (
                None if clearance is None else timestamps[clearance]
            ),
            "left_censored": onset == 0,
            "right_censored": clearance is None,
            "eligible": bool(eligible_indexes),
            "detected": alert is not None,
            "activation_index": alert,
            "activation_ts_ns": None if alert is None else timestamps[alert],
            "warning_lead_time_s": (
                None if alert is None else (timestamps[onset] - timestamps[alert]) / 1e9
            ),
            "nominal_warning_lead_time_s": (
                None if alert is None else (onset - alert) * sample_interval_s
            ),
        })
    activations = []
    last_confirmable_onset_ns = (
        timestamps[-min_breach_samples] if len(values) >= min_breach_samples else 0
    )
    for index in activation_indexes:
        if index in used:
            status, reason = "MATCHED", "pre_onset_warning_within_horizon"
        elif any(0 < row["onset_ts_ns"] - timestamps[index] <= horizon_ns
                 for row in episodes):
            status, reason = "UNMATCHED", "additional_warning_for_matched_episode"
        elif any(row["onset_index"] <= index <= (
            row["clear_confirmation_index"]
            if row["clear_confirmation_index"] is not None else len(values) - 1
        ) for row in episodes):
            status, reason = "UNMATCHED", "at_or_after_episode_onset"
        elif timestamps[index] + horizon_ns > last_confirmable_onset_ns:
            status, reason = "CENSORED", "incomplete_future_followup"
        else:
            status, reason = "UNMATCHED", "no_sustained_episode_within_horizon"
        activations.append({
            **identity, "activation_index": index,
            "activation_ts_ns": timestamps[index], "status": status,
            "reason": reason, "matched_episode_id": used.get(index),
        })
    return summarize_episode_reports([{
        "policy": policy,
        "timing_basis": "csv_timestamps" if actual_timestamps else "nominal_samples",
        "episodes": episodes, "activations": activations,
        "unconfirmed_breach_runs": observed["unconfirmed_breach_runs"],
        "unconfirmed_breach_samples": observed["unconfirmed_breach_samples"],
    }])


def _latencies(values: Sequence[float]) -> Dict[str, Any]:
    return {
        "count": len(values), "values": [round(value, 12) for value in values],
        "minimum": min(values) if values else None,
        "mean": round(sum(values) / len(values), 12) if values else None,
        "maximum": max(values) if values else None,
    }


def summarize_episode_reports(reports: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    if reports and any(report["policy"] != reports[0]["policy"] for report in reports):
        raise ValueError("não é possível agregar políticas de episódio diferentes")
    episodes = [row for report in reports for row in report["episodes"]]
    activations = [row for report in reports for row in report["activations"]]
    eligible = sum(row["eligible"] for row in episodes)
    matched = sum(row["detected"] for row in episodes)
    censored = sum(row["status"] == "CENSORED" for row in activations)
    unmatched = sum(row["status"] == "UNMATCHED" for row in activations)
    bases = {report["timing_basis"] for report in reports}
    return {
        "policy": reports[0]["policy"] if reports else None,
        "timing_basis": next(iter(bases)) if len(bases) == 1 else "mixed_or_empty",
        "actual_episodes": len(episodes), "eligible_episodes": eligible,
        "ineligible_episodes": len(episodes) - eligible,
        "detected": matched, "missed": eligible - matched,
        "detection_rate": round(matched / eligible, 12) if eligible else None,
        "total_activations": len(activations), "matched_activations": matched,
        "unmatched_activations": unmatched, "censored_activations": censored,
        "activation_match_rate": (
            round(matched / (matched + unmatched), 12) if matched + unmatched else None
        ),
        "unconfirmed_breach_runs": sum(report["unconfirmed_breach_runs"] for report in reports),
        "unconfirmed_breach_samples": sum(report["unconfirmed_breach_samples"] for report in reports),
        "warning_lead_time_s": _latencies([
            row["warning_lead_time_s"] for row in episodes if row["detected"]
        ]),
        "nominal_warning_lead_time_s": _latencies([
            row["nominal_warning_lead_time_s"] for row in episodes if row["detected"]
        ]),
        "episodes": episodes, "activations": activations,
    }
