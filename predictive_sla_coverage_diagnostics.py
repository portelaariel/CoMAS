#!/usr/bin/env python3
"""Describe fresh existing-alert coverage without changing frozen v4 results."""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, Sequence

import predictive_sla_diagnostics as coverage
import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import predictive_sla_validation_v4 as v4


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-predictive-sla-alert-coverage-diagnostics/1"
CODE_FILES = (*v4.CODE_FILES, "predictive_sla_diagnostics.py", "predictive_sla_coverage_diagnostics.py")
NEW = "NEW_ACTIVATION_ANTICIPATED"
EXISTING = "EXISTING_ALERT_FRESH_COVERAGE"
ABSENT = "NO_FRESH_PRE_ONSET_ALERT"
UNKNOWN = "UNASSESSABLE"
INELIGIBLE = "INELIGIBLE"
COVERAGE_POLICY = {
    **coverage.COVERAGE_POLICY,
    "version": "v4-existing-alert-coverage/1",
    "categories": [NEW, EXISTING, ABSENT, UNKNOWN, INELIGIBLE],
    "priority": "preserve_strict_matching_first; existing_coverage_only_for_unmatched_episodes",
    "existing_alert": "continuous_active_state_with_recorded_activation_and_fresh_candidate_at_onset_minus_one",
    "acceptance": "none; frozen_v4_criteria_and_one_to_one_matching_unchanged",
}
LIMITATIONS = [
    "This descriptive definition was requested after inspecting v4 misses; it is post-hoc, not a new prospective acceptance criterion.",
    "A fresh existing alert is not a new activation, independently anticipated episode or a successful preventive action.",
    "Strict matches remain credited even if the latest forecast cleared; strict anticipation and current fresh coverage are different measures.",
    "Missing or stale pre-onset evaluations remain unassessable, never zero or evidence of coverage from an old alert.",
    "Freshness uses the frozen acquisition-quality maximum gap, not an operational deadline or measured publication time.",
    "Latest-renewal age and existing-alert age are not new warning lead times or actuator time budgets.",
    "The observed threshold, two-sample clearing, episode boundaries, raw forecast FP and control/unmatched activations remain unchanged.",
    "Onsets and diagnostic contexts are retrospective; only pre-onset rows determine supplementary coverage.",
    "Both models use the same rule on correlated ports and workloads; no superiority, generalization or scalability claim is made.",
    "No refit, recalibration, runtime change, traffic, risk publication, LLM, consensus, authority request or actuation occurs.",
]


def code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def _compact_row(row: Dict[str, Any] | None) -> Dict[str, Any] | None:
    if row is None:
        return None
    # Deliberately exclude future truth/residuals from coverage evidence.
    fields = ("index", "ts_ns", "observed_value", "candidate", "active", "activation",
              "entry_inhibited", "clear_transition", "predictions",
              "active_alert_started_index", "active_alert_started_ns")
    return {key: row[key] for key in fields if key in row}


def classify_episodes(block: Dict[str, Any], timestamps_ns: Sequence[int], *,
                      maximum_age_s: float, maximum_horizon_s: float) -> list:
    """Classify frozen episodes using only contiguous past alert state."""
    rows, started, previous_active, previous_index = [], None, None, None
    for raw in block["rows"]:
        adjacent = previous_index is not None and raw["index"] == previous_index + 1
        if (any(not isinstance(raw[key], bool) for key in ("active", "activation", "candidate"))
                or (previous_index is not None and raw["index"] <= previous_index)
                or (raw["activation"] and (not raw["active"] or (adjacent and previous_active)))
                or (adjacent and raw["active"] and previous_active is False and not raw["activation"])):
            raise ValueError("ciclo/ordem dos registros de alerta inválido")
        if not adjacent:
            started = None  # A missing row cannot prove continuity of an old alert.
        if raw["activation"]:
            started = raw["index"], raw["ts_ns"]
        elif not raw["active"]:
            started = None
        rows.append({**raw, "active_alert_started_index": None if started is None else started[0],
                     "active_alert_started_ns": None if started is None else started[1]})
        previous_active, previous_index = raw["active"], raw["index"]
    diagnoses = coverage.evaluate_fresh_coverage(
        rows=rows, episodes=block["episode_events"]["episodes"], timestamps_ns=timestamps_ns,
        maximum_age_s=maximum_age_s, maximum_horizon_s=maximum_horizon_s)
    result = []
    for frozen, diagnosis in zip(block["episode_events"]["episodes"], diagnoses):
        latest = diagnosis["latest_pre_onset_evaluation"]
        if (diagnosis["fresh_active_coverage"] is True
                and latest["active_alert_started_ns"] is None):
            diagnosis = {**diagnosis, "coverage_assessable": False, "fresh_active_coverage": None,
                         "covered_without_new_activation": False,
                         "coverage_reason": "alert_activation_or_continuity_unavailable"}
        if not diagnosis["eligible"]:
            category = INELIGIBLE
        elif diagnosis["strict_anticipated"]:
            category = NEW
        elif diagnosis["fresh_active_coverage"] is True:
            category = EXISTING
        elif not diagnosis["coverage_assessable"]:
            category = UNKNOWN
        else:
            category = ABSENT
        start_ns = None if latest is None else latest["active_alert_started_ns"]
        result.append({**diagnosis, "category": category, "frozen_episode": frozen,
                       "latest_pre_onset_evaluation": _compact_row(latest),
                       "existing_alert_age_at_onset_s": (
                           None if start_ns is None else (frozen["onset_ts_ns"] - start_ns) / 1e9),
                       "diagnostic_context": [_compact_row(r) for r in rows
                                              if frozen["onset_index"] - 3 <= r["index"] <= frozen["onset_index"]]})
    return result


def summarize(series: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    episodes = [e for item in series for e in item["episodes"] if e["eligible"]]
    counts = Counter(e["category"] for e in episodes)
    total = len(episodes)
    return dict(
        eligible_episodes=total, strict_anticipated=counts[NEW],
        existing_alert_fresh_coverage=counts[EXISTING], no_fresh_pre_onset_alert=counts[ABSENT],
        unassessable_without_strict_match=counts[UNKNOWN],
        documented_warning_or_fresh_existing_alert=counts[NEW] + counts[EXISTING],
        descriptive_coverage_rate=(counts[NEW] + counts[EXISTING]) / total if total else None,
        fresh_active_pre_onset=sum(e["fresh_active_coverage"] is True for e in episodes),
        latest_evaluation_unassessable=sum(not e["coverage_assessable"] for e in episodes),
        strict_matches_without_latest_fresh_coverage=sum(
            e["strict_anticipated"] and e["fresh_active_coverage"] is not True for e in episodes),
        partition_counts={key: counts[key] for key in (NEW, EXISTING, ABSENT, UNKNOWN)},
        partition_complete=sum(counts.values()) == total,
        ineligible_episodes=sum(not e["eligible"] for item in series for e in item["episodes"]))


def _sources(protocol: Dict[str, Any], path: Path, campaign: Path, official: Dict[str, Any]) -> Dict[str, str]:
    traces = {s["path"]: s["sha256"] for s in v2._snapshot_sources(protocol, campaign)}
    plan = campaign / "campaign-plan.json"
    if plan.exists():
        if plan.is_symlink() or json.loads(plan.read_text()) != protocol:
            raise ValueError("plano da campanha v4 mudou")
        traces[str(plan.resolve())] = v1.digest_file(plan)
    if traces != official["source_sha256"]:
        raise ValueError("fontes do relatório oficial v4 divergem da campanha")
    expected = {**protocol["protected_source_sha256"], **traces,
                **{str((path.parent / model["path"]).resolve()): model["sha256"]
                   for model in protocol["models"].values()}}
    if any(v1.digest_file(Path(p)) != sha for p, sha in expected.items()):
        raise ValueError("fontes protegidas v4 mudaram")
    return {**expected, str(path): v1.digest_file(path),
            str(campaign / "campaign-summary.json"): v1.digest_file(campaign / "campaign-summary.json")}


def build_report(protocol_path: Path, campaign: Path) -> Dict[str, Any]:
    if protocol_path.absolute().is_symlink():
        raise ValueError("protocolo não pode ser link simbólico")
    path = protocol_path.resolve()
    campaign = v4.campaign_path(path, campaign)
    summary_path = campaign / "campaign-summary.json"
    if summary_path.is_symlink():
        raise ValueError("relatório oficial não pode ser link simbólico")
    code = code_snapshot()
    p = v4.load_protocol(path)
    official = v4._sealed(summary_path, v4.SUMMARY_SCHEMA, "report_sha256")
    if official["status"] != "COMPLETED" or official["evaluated_runs"] != 12:
        raise ValueError("diagnóstico requer 12 execuções v4 válidas e encerradas")
    before = _sources(p, path, campaign, official)
    verified = v4.evaluate_campaign(path, campaign)
    if verified != official:
        raise ValueError("relatório v4 diverge da reavaliação congelada; não será corrigido")
    models = {name: [] for name in p["models"]}
    for case, evaluated in zip(p["cases"], verified["cases"]):
        subjects, _, hashes = v1._read_case(p, case, campaign / case["case_id"])
        if evaluated["case_id"] != case["case_id"] or hashes != evaluated["source_sha256"]:
            raise ValueError("identidade/fontes da campanha v4 mudaram")
        for name, items in models.items():
            for subject, block in zip(subjects, evaluated["models"][name]["series"]):
                if subject["series_id"] != block["series_id"]:
                    raise ValueError("identidade da série diverge do replay v4")
                episodes = classify_episodes(
                    block, subject["timestamps_ns"], maximum_age_s=p["quality"]["maximum_gap_s"],
                    maximum_horizon_s=max(p["horizons_steps"]) * p["sample_interval_s"])
                items.append(dict(case_id=case["case_id"], profile=case["profile"],
                                  series_id=block["series_id"], cid=block["cid"], port_id=block["port_id"],
                                  source_sha256=block["source_sha256"], episodes=episodes))
    results = {}
    frozen_fields = ("anticipated", "eligible_episodes", "missed", "late_activations", "control_activations",
                     "unmatched_activations", "censored_activations", "candidate", "lead_time_s", "watch_windows")
    for name, items in models.items():
        total = summarize(items)
        frozen = verified["models"][name]
        if (total["strict_anticipated"] != frozen["anticipated"]
                or total["eligible_episodes"] != frozen["eligible_episodes"] or not total["partition_complete"]):
            raise ValueError("diagnóstico mudou a contagem oficial de episódios")
        results[name] = dict(summary=total, series=items,
                             per_profile={profile: summarize([s for s in items if s["profile"] == profile])
                                          for profile in v1.profiles()},
                             frozen_metrics={key: frozen[key] for key in frozen_fields})
    v4.load_protocol(path)
    if code_snapshot() != code or _sources(p, path, campaign, official) != before:
        raise ValueError("fontes/código mudaram durante o diagnóstico; nenhuma saída será publicada")
    return v1.seal(dict(
        schema_version=SCHEMA, created_ns=time.time_ns(), status="DIAGNOSTIC_COMPLETED",
        scope="posthoc_descriptive_not_replacement_acceptance", official_v4_unchanged=True,
        primary_model=p["primary_model"], refit=False, recalibration=False,
        promotion_eligible=False, deployment_eligible=False, sla_protection_established=False,
        execution_boundary=dict(v4.BOUNDARY), operational_timing=verified["operational_timing"],
        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        source_sha256=before, code_sha256=code, frozen_code_sha256=p["code_sha256"],
        baseline=dict(status=verified["status"], criteria_status=verified["criteria_status"],
                      checks=verified["checks"], checks_by_model=verified["checks_by_model"],
                      protocol_sha256=p["protocol_sha256"], report_sha256=official["report_sha256"],
                      summary_file_sha256=before[str(summary_path)]),
        coverage_policy={**COVERAGE_POLICY, "maximum_age_s": p["quality"]["maximum_gap_s"]},
        models=results, limitations=LIMITATIONS), "report_sha256")


def output_path(protocol_path: Path, requested: Path) -> Path:
    resolved = requested.resolve()
    if (requested.absolute().is_symlink() or resolved.exists()
            or resolved.parent != protocol_path.resolve().parent or resolved.suffix != ".json"
            or not resolved.name.startswith("coverage-diagnostics")):
        raise ValueError("use novo coverage-diagnostics*.json diretamente no diretório v4")
    return resolved


def console_lines(report: Dict[str, Any]) -> list:
    baseline = report["baseline"]
    lines = [f"official_v4={baseline['status']} criteria={baseline['criteria_status']} unchanged=true"]
    for name, model in report["models"].items():
        s = model["summary"]
        lines.append(f"{name}: new_activations={s['strict_anticipated']}/{s['eligible_episodes']} "
                     f"existing_fresh_alert={s['existing_alert_fresh_coverage']} "
                     f"no_fresh_alert={s['no_fresh_pre_onset_alert']} "
                     f"unassessable={s['unassessable_without_strict_match']}")
    unmatched = [(s, e) for s in report["models"][report["primary_model"]]["series"] for e in s["episodes"]
                 if e["eligible"] and not e["strict_anticipated"]]
    for series, episode in unmatched[:3]:
        lines.append(f"MISS {episode['episode_id']} onset={episode['onset_index']} "
                     f"category={episode['category']} reason={episode['coverage_reason']}")
    if len(unmatched) > 3:
        lines.append(f"additional_misses_in_json={len(unmatched) - 3}")
    lines.append("status=DIAGNOSTIC_COMPLETED promotion_eligible=false")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        target = output_path(args.protocol, args.output)
        report = build_report(args.protocol, args.campaign_root)
        v1.write_new_json(target, report)
        print("\n".join(console_lines(report)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
