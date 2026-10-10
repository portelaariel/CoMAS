#!/usr/bin/env python3
"""Post-hoc preventive-entry sensitivity; never a runtime or promotion gate.

Only NEW one-horizon warning activation is inhibited at/above the observed
threshold. Existing forecast alerts retain the original renewal/clearing rule.
All observed crossings, including priming/tail samples, remain separately
recorded. No future observation is consulted by either state machine.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any, Dict

import predictive_sla_horizon_sensitivity as sensitivity
import predictive_sla_damped_replay as replay
import predictive_sla_validation as v1
import predictive_sla_validation_v3 as v3
from backtest_sla_risk import _classification_block, _update_confusion
from sla_episode_evaluation import evaluate_episodes, validate_timestamps
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPersistence


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-predictive-sla-preventive-entry-study/1"
CODE_FILES = (*sensitivity.CODE_FILES, "predictive_sla_preventive_entry_study.py")
ENTRY_RULE = {
    "version": "diagnostic-preventive-entry/1",
    "forecast_gate": "one_horizon; frozen_points_and_intervals",
    "new_activation": "raw_candidate AND observed_value < frozen_threshold",
    "at_or_above_threshold_while_inactive": "inhibit_new_forecast_alert_entry; retain_observed_crossing",
    "already_active": "original_raw_forecast_renewal_and_two_window_clearing",
    "observed_channel": "all_samples; threshold_crossings_and_past_only_sustained_confirmation",
    "matching": "unchanged_strict_sustained_episode_timestamp_matcher",
}
LIMITATIONS = [
    "This rule was motivated by inspected v3 pulses; this is a post-hoc diagnostic, not independent validation.",
    "Only new forecast-alert entry changes; point forecasts, intervals, raw candidates, labels and observed episodes do not change.",
    "Below-threshold entry is a local instantaneous condition, not proof of anticipation of a sustained episode.",
    "A crossing is not discarded or labeled harmless: instantaneous and sustained observed states remain separately recorded.",
    "Suppressed new entry can reappear on a later below-threshold sample; the stateful replay measures that rather than masking old activations.",
    "Already-active alerts retain raw renewal/clearing, including when the current observation breaches the threshold.",
    "Raw window forecast FP counts remain unchanged; fewer preventive activations do not establish better forecast accuracy.",
    "Removing a late forecast activation does not resolve the missed episode or prove reactive protection.",
    "Lead times are conditional; paired losses/gains and late/unmatched/control alarms remain explicit.",
    "Correlated ports and repeated workloads do not establish statistical superiority or generalization.",
    "No variant is selected, deployed or promoted; any proposed rule requires newly frozen prospective validation.",
    "No fitting, recalibration, new traffic, LLM consultation, ETCD publication or actuator request occurs.",
]


def code_snapshot() -> Dict[str, str]:
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def output_path(protocol_path: Path, requested: Path) -> Path:
    absolute, resolved = requested.absolute(), requested.resolve()
    if absolute.is_symlink() or resolved.exists():
        raise ValueError("saída já existe ou é link simbólico; use outro nome")
    if (resolved.parent != protocol_path.resolve().parent or not resolved.name.startswith("preventive-entry")
            or resolved.suffix != ".json"):
        raise ValueError("use novo preventive-entry*.json diretamente no diretório do protocolo v3")
    return resolved


def observed_channel(series: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    """Classify ALL samples using current/past values, including priming/tails."""
    if settings != v3.POLICY:
        raise ValueError("política observada deve permanecer igual à v3")
    values, timestamps = series["values"], series["timestamps_ns"]
    validate_timestamps(timestamps, len(values))
    active = False
    breach_streak = clear_streak = 0
    rows = []
    for index, value in enumerate(values):
        if not math.isfinite(value) or value < 0:
            raise ValueError("observação inválida")
        breached = value >= settings["threshold"]
        confirmation = cleared = False
        if breached:
            breach_streak += 1
            clear_streak = 0
            if not active and breach_streak >= settings["episode_min_breach_samples"]:
                active = confirmation = True
        else:
            breach_streak = 0
            if active:
                clear_streak += 1
                if clear_streak >= settings["episode_clear_samples"]:
                    active = False
                    cleared = True
                    clear_streak = 0
        rows.append(dict(index=index, ts_ns=timestamps[index], observed_value=value,
                         threshold_breach=breached, breach_streak=breach_streak,
                         sustained_episode_active=active, confirmation_transition=confirmation,
                         clear_transition=cleared))
    return dict(series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"],
                scope="all_observed_samples_including_priming_and_unscored_tail", rows=rows,
                threshold_crossing_samples=sum(r["threshold_breach"] for r in rows),
                sustained_confirmations=sum(r["confirmation_transition"] for r in rows))


def replay_entry(series: Dict[str, Any], baseline: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    """Replay entry inhibition, not a retrospective deletion of old activations."""
    observed = observed_channel(series, settings)
    confirmations = [r["index"] for r in observed["rows"] if r["confirmation_transition"]]
    if confirmations != [e["confirmation_index"] for e in baseline["episode_events"]["episodes"]]:
        raise ValueError("canal observado diverge das confirmações de episódios congelados")
    state = SlaRiskPersistence(activation_windows=settings["activation_windows"], clear_windows=settings["clear_windows"])
    active = False
    rows, observations, classifications, inhibited = [], [], [], []
    active_counts = Counter()
    activations = clears = 0
    for raw in baseline["rows"]:
        index = raw["index"]
        current = observed["rows"][index]
        if raw["ts_ns"] != current["ts_ns"] or raw["observed_value"] != current["observed_value"]:
            raise ValueError("janela verificada não corresponde à observação")
        candidate = raw["decision"] == SLA_RISK_EVENT_TYPE
        if candidate != raw["candidate"]:
            raise ValueError("candidato bruto inconsistente")
        previous_active = active
        inhibit = candidate and current["threshold_breach"] and not previous_active
        # An inhibited entry resets its pending streak. Never filter an active
        # alert's renewal by current value or clear it solely on an actual breach.
        effective = "WATCH" if inhibit else raw["decision"]
        result = state.update(dict(cid=series["cid"], subject={"id": series["port_id"]},
                                   metric="utilization_ratio", decision=effective))
        active = bool(result["active"])
        activation = bool(result["transitioned"] and active)
        cleared = bool(result["transitioned"] and not active)
        if activation and current["threshold_breach"]:
            raise ValueError("nova ativação preventiva em janela já acima do limiar")
        if previous_active and candidate and (not active or inhibit):
            raise ValueError("regra de entrada não pode suprimir renovação de alerta ativo")
        _update_confusion(active_counts, active, raw["actual_positive"])
        activations += activation
        clears += cleared
        observations.append(dict(index=index, persistent_activation=activation))
        rows.append({**raw, "active": active, "activation": activation, "clear_transition": cleared,
                     "raw_active": raw["active"], "raw_activation": raw["activation"],
                     "entry_inhibited": inhibit, "entry_eligible": not current["threshold_breach"],
                     "persistence_input_decision": effective, "observed_state": current})
        evidence = dict(index=index, ts_ns=raw["ts_ns"], observed_value=raw["observed_value"],
                        observed_threshold_breach=current["threshold_breach"],
                        observed_sustained_episode_active=current["sustained_episode_active"],
                        phase="AT_OR_ABOVE_THRESHOLD" if current["threshold_breach"] else "BELOW_THRESHOLD")
        if raw["activation"]:
            classifications.append({**evidence, "kind": "raw_forecast_activation"})
        if activation:
            classifications.append({**evidence, "kind": "preventive_entry_activation"})
        if inhibit:
            inhibited.append(evidence)
    horizon_s = baseline["episode_events"]["policy"]["max_warning_horizon_s"]
    episodes = evaluate_episodes(
        values=series["values"], observations=observations, timestamps_ns=series["timestamps_ns"],
        series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"], comparator="MAX",
        threshold=settings["threshold"], sample_interval_s=2, max_horizon_steps=int(horizon_s / 2),
        min_breach_samples=settings["episode_min_breach_samples"], clear_samples=settings["episode_clear_samples"])
    block = {**baseline, "rows": rows,
             "persistent_active": {**_classification_block(active_counts), "activation_transitions": activations,
                                   "clear_transitions": clears},
             "episode_events": episodes, "late_activations": replay._late_activations(episodes),
             "entry_diagnostic": dict(rule=ENTRY_RULE, inhibited_entry_windows=inhibited,
                                     classified_activations=classifications, observed_channel=observed)}
    # Raw decisions, forecasts, WINDOW labels/scope and episode truth stay fixed.
    if (block["candidate"] != baseline["candidate"] or block["watch_only"] != baseline["watch_only"]
            or len(rows) != len(baseline["rows"])):
        raise ValueError("o diagnóstico não pode alterar candidatos brutos ou escopo")
    replay.paired_changes([baseline], [block])
    return block


def _pair(raw: list, gated: list) -> Dict[str, Any]:
    paired = replay.paired_changes(raw, gated)
    paired["paired_episodes"] = [dict(
        episode_id=e["episode_id"], eligible=e["eligible"], onset_ts_ns=e["onset_ts_ns"],
        ungated_anticipated=e["original_anticipated"], preventive_entry_anticipated=e["trained_anticipated"],
        ungated_lead_s=e["original_lead_s"], preventive_entry_lead_s=e["trained_lead_s"])
        for e in paired["paired_episodes"]]
    changes = []
    for before, after in zip(raw, gated):
        if before["series_id"] != after["series_id"]:
            raise ValueError("pareamento de séries divergente")
        a = {r["index"]: r for r in before["rows"] if r["activation"]}
        b = {r["index"]: r for r in after["rows"] if r["activation"]}
        for kind, indexes in (("REMOVED", a.keys() - b.keys()), ("ADDED", b.keys() - a.keys())):
            for index in sorted(indexes):
                row = (a if kind == "REMOVED" else b)[index]
                changes.append(dict(case_id=before["case_id"], profile=before["profile"], cid=before["cid"],
                                    port_id=before["port_id"], index=index, ts_ns=row["ts_ns"], change=kind,
                                    observed_value=row["observed_value"]))
    paired["activation_changes"] = changes
    return paired


def study(protocol_path: Path, campaign: Path, source_study: Path) -> Dict[str, Any]:
    path = protocol_path.resolve()
    requested, source = source_study.absolute(), source_study.resolve()
    if (requested.is_symlink() or source.parent != path.parent or source.suffix != ".json"
            or not source.name.startswith("horizon-sensitivity")):
        raise ValueError("use o horizon-sensitivity*.json original junto ao protocolo v3")
    source_hash, code = v1.digest_file(source), code_snapshot()
    saved = json.loads(source.read_text(encoding="utf-8"))
    if saved.get("schema_version") != sensitivity.SCHEMA or saved != v1.seal(saved, "report_sha256"):
        raise ValueError("schema/checksum do estudo de horizontes inválido")
    verified = sensitivity.study(path, campaign)
    # A new implementation commit is expected; no other lineage/result change
    # is allowed. Preserve both historical and current commit IDs in this report.
    def comparable(payload):
        return {k: v for k, v in payload.items() if k not in ("git_commit", "report_sha256")}
    if comparable(saved) != comparable(verified):
        raise ValueError("estudo de horizontes não reproduz integralmente os dados e resultados verificados")
    protected = {**saved["protected_source_sha256"], str(source): source_hash}
    if any(v1.digest_file(Path(p)) != sha for p, sha in protected.items()):
        raise ValueError("fontes protegidas mudaram")
    p = v3.load_protocol(path)
    campaign = v3.campaign_path(path, campaign)
    subjects = {}
    for case in p["cases"]:
        series, _, _ = v1._read_case(p, case, campaign / case["case_id"])
        for item in series:
            subjects[item["series_id"]] = item
    models = {}
    for name in (v3.REFERENCE, v3.PRIMARY):
        baseline = verified["models"][name]["variants"]["consecutive1"]
        raw = baseline["series"]
        gated = [replay_entry(subjects[b["series_id"]], b, p["policy"]) for b in raw]
        # Summaries remain compatible with the old raw-forecast metrics. In
        # particular raw_FP is NOT re-scored or reduced by the entry condition.
        cases = p["cases"]
        raw_summary, gated_summary = v3._summarize(raw, cases), v3._summarize(gated, cases)
        if raw_summary != baseline["summary"] or raw_summary["forecast_errors"] != gated_summary["forecast_errors"]:
            raise ValueError("baseline bruto ou erros das previsões mudaram")
        if raw_summary["candidate"] != gated_summary["candidate"]:
            raise ValueError("o filtro de entrada não pode melhorar artificialmente a precisão do modelo")
        models[name] = dict(model_id=verified["models"][name]["model_id"],
                           model_sha256=verified["models"][name]["model_sha256"],
                           variants=dict(ungated_one_horizon=dict(summary=raw_summary, series=raw),
                                         preventive_entry_one_horizon=dict(summary=gated_summary, series=gated)),
                           paired_changes=_pair(raw, gated),
                           inhibited_entry_windows=sum(len(b["entry_diagnostic"]["inhibited_entry_windows"]) for b in gated))
    if (code_snapshot() != code or any(v1.digest_file(Path(p)) != sha for p, sha in protected.items())):
        raise ValueError("fontes/código mudaram durante a análise; nenhum diagnóstico será publicado")
    return v1.seal(dict(
        schema_version=SCHEMA, status="ENTRY_STUDY_COMPLETED", scope="post_hoc_v3_preventive_entry",
        independent_test=False, promotion_eligible=False, deployment_eligible=False, selected_variant="NONE",
        refit=False, recalibration=False, new_traffic=False, llm_consulted=False, runtime_changed=False,
        statistical_superiority_assessed=False, entry_rule=ENTRY_RULE,
        protocol_path=str(path), protocol_sha256=p["protocol_sha256"], campaign_root=str(campaign),
        source_study=dict(path=str(source), sha256=source_hash, report_sha256=saved["report_sha256"], git_commit=saved["git_commit"]),
        official_v3=saved["official_v3"], official_v3_unchanged=True, source_study_unchanged=True, baseline_exact=True,
        forecasts_intervals_raw_candidates_and_window_labels_identical=True, observed_episode_ground_truth_identical=True,
        observed_crossings_retained=True, existing_alert_renewal_retained=True, scoring_target=saved["scoring_target"],
        evaluation_unit=v3.EVALUATION_UNIT, models=models, code_sha256=code, protected_source_sha256=protected,
        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
        limitations=LIMITATIONS), "report_sha256")


def print_summary(report: Dict[str, Any]) -> None:
    print(f"official_v3={report['official_v3']['status']} criteria={report['official_v3']['criteria_status']} "
          "unchanged=true baseline_exact=true observed_crossings_retained=true")
    for name in (v3.REFERENCE, v3.PRIMARY):
        model = report["models"][name]
        for variant, item in model["variants"].items():
            s = item["summary"]
            lead = "N/A" if s["lead_time_s"]["mean"] is None else f"{s['lead_time_s']['mean']:.3f}s"
            print(f"{name} {variant}: anticipated={s['anticipated']}/{s['eligible_episodes']} "
                  f"late={s['late_activations']} control={s['control_activations']} unmatched={s['unmatched_activations']} "
                  f"censored={s['censored_activations']} raw_FP={s['candidate']['confusion']['FP']} lead={lead}")
        pair = model["paired_changes"]
        print(f"{name} paired: lost={len(pair['lost_anticipated_episodes'])} gained={len(pair['gained_anticipated_episodes'])} "
              f"removed={sum(e['change'] == 'REMOVED' for e in pair['activation_changes'])} "
              f"added={sum(e['change'] == 'ADDED' for e in pair['activation_changes'])}")
    print("status=ENTRY_STUDY_COMPLETED selected_variant=NONE promotion_eligible=false independent_test=false")


def main(argv: list | None = None) -> int:
    parser = argparse.ArgumentParser(description="Estudo offline de novas ativações preventivas antes do limiar observado")
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--campaign-root", type=Path, required=True)
    parser.add_argument("--source-study", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        target = output_path(args.protocol, args.output)
        report = study(args.protocol, args.campaign_root, args.source_study)
        v1.write_new_json(target, report)
        print_summary(report)
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
