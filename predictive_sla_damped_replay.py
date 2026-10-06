#!/usr/bin/env python3
"""Read-only replay of a v1-trained damped model on inspected v2 development data.

This is not a new prospective validation. Frozen v2 rules/results and trained
artifacts remain unchanged; no fitting, LLM, network or actuation occurs.
"""

from __future__ import annotations

import argparse
import json
import math
import subprocess
import sys
import time
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import train_qos_damped_holt_model as training
from backtest_sla_risk import _actual_future_outcome, _classification_block, _ratio, _update_confusion, backtest_model
from qos_damped_holt import MODEL_TYPE, MultiHorizonDampedHoltForecaster, QosDampedHoltModel
from qos_holt import MultiHorizonHoltForecaster, QosHoltModel
from sla_episode_evaluation import evaluate_episodes, summarize_episode_reports, validate_timestamps
from sla_risk import SLA_RISK_EVENT_TYPE, SlaRiskPersistence, SlaRiskPolicy, evaluate_sla_forecast


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-qos-damped-development-replay/1"
CODE_FILES = (*v2.CODE_FILES, "qos_damped_holt.py", "train_qos_damped_holt_model.py",
              "predictive_sla_damped_replay.py")
CONTROLS = ("stable-low", "short-pulses")
LIMITATIONS = [
    "V2 failures informed the damping family; these already inspected traces are development data, not an independent holdout.",
    "The model was selected on v1 training runs and recalibrated on v1 calibration runs; no parameters are changed in this replay.",
    "The frozen v2 threshold, consecutive horizons, activation/clearing rules and episode matcher remain unchanged.",
    "Late activations are not anticipation; absence of new activation is not proof that an already active alert provided no coverage.",
    "Conditional warning lead times concern anticipated episodes only; misses, late, unmatched and censored activations remain explicit.",
    "Control activations count designated control profiles, not independently proven malicious/benign labels or actual preventive actions.",
    "Both ports share a workload; windows/episodes and repeated runs share a testbed and are correlated.",
    "Forecast errors/interval coverage use the common scored windows and are descriptive, not fitting metrics or independent guarantees.",
    "No new traffic, prospective test, runtime deployment, LLM decision, SLA protection or preventive action is evaluated.",
]


def _latencies(values: Sequence[float]) -> Dict[str, Any]:
    return dict(count=len(values), values=list(values), minimum=min(values) if values else None,
                maximum=max(values) if values else None,
                mean=sum(values) / len(values) if values else None)


def _late_activations(episodes: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Describe only the frozen matcher's late category; never change its match."""
    result = []
    for activation in episodes["activations"]:
        if activation["reason"] != "at_or_after_episode_onset":
            continue
        containing = [e for e in episodes["episodes"] if e["onset_index"] <= activation["activation_index"]
                      and (e["clear_confirmation_index"] is None
                           or activation["activation_index"] <= e["clear_confirmation_index"])]
        if len(containing) != 1:
            raise ValueError("ativação tardia sem episódio observado inequívoco")
        episode = containing[0]
        result.append({**activation, "episode_id": episode["episode_id"],
                       "onset_index": episode["onset_index"], "onset_ts_ns": episode["onset_ts_ns"],
                       "delay_after_onset_s": (activation["activation_ts_ns"] - episode["onset_ts_ns"]) / 1e9})
    return result


def structural_property(model: QosHoltModel, policy: Dict[str, Any]) -> bool:
    """With first-observation/zero-trend initialization, the two short points coincide."""
    return (tuple(h.horizon_steps for h in model.horizons) == (2, 4, 6)
            and policy["required_consecutive_horizons"] == 2
            and model.horizons[0].beta == model.horizons[1].beta == 0
            and model.horizons[0].alpha == model.horizons[1].alpha)


def replay_series(model: QosHoltModel, series: Dict[str, Any], settings: Dict[str, Any]) -> Dict[str, Any]:
    """Past-only forecast -> unchanged SLA contract -> unchanged persistence/matcher."""
    if isinstance(model, QosDampedHoltModel) and model.model_type == MODEL_TYPE:
        predictor = MultiHorizonDampedHoltForecaster(model)
    elif type(model) is QosHoltModel:
        predictor = MultiHorizonHoltForecaster(model)
    else:
        raise ValueError("tipo de modelo não suportado no replay")
    values, timestamps = series["values"], series["timestamps_ns"]
    validate_timestamps(timestamps, len(values))
    if any(not math.isfinite(v) or v < 0 for v in values):
        raise ValueError("observações inválidas")
    policy = SlaRiskPolicy(metric=model.metric, comparator="MAX", threshold=settings["threshold"],
                           horizons_steps=tuple(h.horizon_steps for h in model.horizons),
                           required_consecutive_horizons=settings["required_consecutive_horizons"])
    maximum = max(policy.horizons_steps)
    persistence = SlaRiskPersistence(activation_windows=settings["activation_windows"],
                                     clear_windows=settings["clear_windows"])
    rows, observations = [], []
    candidate_counts, active_counts = Counter(), Counter()
    decisions, risks = Counter(), Counter()
    watch_positive = watch_negative = activations = clears = tail = 0
    flat = structural_property(model, settings)
    first_breach = next((i for i, v in enumerate(values) if v >= policy.threshold), None)
    for index, observed in enumerate(values):
        forecasts = predictor.update(observed)
        if not forecasts:
            continue
        if index + maximum >= len(values):
            tail += 1
            continue  # Same scored scope as the frozen official backtest.
        evaluation = evaluate_sla_forecast(
            policy=policy, cid=series["cid"], subject_type="port", subject_id=series["port_id"],
            observed_value=observed, window_id=index + 1, observation_ns=timestamps[index],
            sample_interval_s=model.sample_interval_s, forecasts=forecasts,
            model_id=model.resolved_model_id(), model_type=model.model_type,
            created_ns=timestamps[index], ttl_s=maximum * model.sample_interval_s)
        state = persistence.update(evaluation)
        actual = _actual_future_outcome(values, index, policy)
        decision = evaluation["decision"]
        candidate, active = decision == SLA_RISK_EVENT_TYPE, bool(state["active"])
        activation, clear = bool(state["transitioned"] and active), bool(state["transitioned"] and not active)
        if flat and (forecasts[0]["predicted_value"] != forecasts[1]["predicted_value"]
                     or candidate != (forecasts[1]["predicted_value"] >= policy.threshold)):
            raise ValueError("identidade estrutural das previsões de 4/8 s não foi reproduzida")
        _update_confusion(candidate_counts, candidate, actual["positive"])
        _update_confusion(active_counts, active, actual["positive"])
        decisions[decision] += 1
        risks[evaluation["risk"]["level"]] += 1
        if decision == "WATCH":
            if actual["positive"]:
                watch_positive += 1
            else:
                watch_negative += 1
        activations += activation
        clears += clear
        observations.append(dict(index=index, persistent_activation=activation))
        rows.append(dict(index=index, ts_ns=timestamps[index], observed_value=observed,
                         decision=decision, candidate=candidate, active=active,
                         activation=activation, clear_transition=clear, actual_positive=actual["positive"],
                         before_first_observed_breach=first_breach is None or index < first_breach,
                         predictions=evaluation["forecast"]["horizons"], actual_horizons=actual["values"]))
    episodes = evaluate_episodes(
        values=values, observations=observations, timestamps_ns=timestamps,
        series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"],
        comparator=policy.comparator, threshold=policy.threshold,
        sample_interval_s=model.sample_interval_s, max_horizon_steps=maximum,
        min_breach_samples=settings["episode_min_breach_samples"], clear_samples=settings["episode_clear_samples"])
    return dict(series_id=series["series_id"], cid=series["cid"], port_id=series["port_id"], samples=len(values),
                evaluated_windows=len(rows), unscored_tail_windows=tail, candidate=_classification_block(candidate_counts),
                persistent_active={**_classification_block(active_counts), "activation_transitions": activations,
                                   "clear_transitions": clears},
                decision_counts=dict(sorted(decisions.items())), risk_level_counts=dict(sorted(risks.items())),
                watch_only=dict(windows=decisions["WATCH"], rate=_ratio(decisions["WATCH"], len(rows)),
                                future_positive_windows=watch_positive, future_negative_windows=watch_negative,
                                precision=_ratio(watch_positive, watch_positive + watch_negative)),
                episode_events=episodes, late_activations=_late_activations(episodes), rows=rows,
                structural_diagnostics=dict(short_horizons_flat_identical=flat, checked_windows=len(rows) if flat else 0,
                                            first_observed_breach_index=first_breach,
                                            candidates_before_first_observed_breach=sum(
                                                r["candidate"] and r["before_first_observed_breach"] for r in rows)))


def _check_native_reference(model: QosHoltModel, series: Dict[str, Any], settings: Dict[str, Any], block: Dict[str, Any]) -> None:
    reference, points, candidates = backtest_model(model=model, series=[series], **settings)
    expected = reference["series"][0]
    fields = ("evaluated_windows", "unscored_tail_windows", "candidate", "persistent_active", "episode_events",
              "decision_counts", "risk_level_counts", "watch_only")
    measured_points = {(series["series_id"], row["index"]): tuple(p["predicted_value"] for p in row["predictions"])
                       for row in block["rows"]}
    measured_candidates = {(series["series_id"], row["index"]): row["candidate"] for row in block["rows"]}
    if (any(block[field] != expected[field] for field in fields)
            or measured_points != points or measured_candidates != candidates):
        raise ValueError("replay original diverge do baseline nativo; não publique a comparação")


def aggregate(items: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    candidate, active = Counter(), Counter()
    for item in items:
        candidate.update(item["candidate"]["confusion"])
        active.update(item["persistent_active"]["confusion"])
    episodes = summarize_episode_reports([item["episode_events"] for item in items])
    late = [event for item in items for event in item["late_activations"]]
    forecast_errors = {}
    rows = [row for item in items for row in item["rows"]]
    for step in sorted({p["horizon_steps"] for row in rows for p in row["predictions"]}):
        errors, covered, widths = [], 0, []
        for row in rows:
            for p, actual in zip(row["predictions"], row["actual_horizons"]):
                if p["horizon_steps"] == step:
                    errors.append(actual - p["predicted_value"])
                    covered += p["lower_bound"] <= actual <= p["upper_bound"]
                    widths.append(p["upper_bound"] - p["lower_bound"])
        forecast_errors[str(step)] = dict(samples=len(errors), mae=sum(abs(e) for e in errors) / len(errors),
                                         rmse=math.sqrt(sum(e * e for e in errors) / len(errors)),
                                         bias=sum(errors) / len(errors), interval_coverage=covered / len(errors),
                                         mean_emitted_interval_width=sum(widths) / len(widths))
    return dict(workload_runs=len({s["case_id"] for s in items}), correlated_port_sequences=len(items),
                evaluated_windows=len(rows), unscored_tail_windows=sum(s["unscored_tail_windows"] for s in items),
                candidate=_classification_block(candidate), persistent_active=_classification_block(active),
                watch_windows=sum(s["watch_only"]["windows"] for s in items),
                eligible_episodes=episodes["eligible_episodes"], anticipated=episodes["detected"],
                missed=episodes["missed"], total_activations=episodes["total_activations"],
                unmatched_activations=episodes["unmatched_activations"], censored_activations=episodes["censored_activations"],
                unmatched_reasons=dict(Counter(a["reason"] for a in episodes["activations"] if a["status"] == "UNMATCHED")),
                late_activations=len(late), episodes_with_late_activation=len({a["episode_id"] for a in late}),
                late_delay_s=_latencies([a["delay_after_onset_s"] for a in late]),
                lead_time_s=episodes["warning_lead_time_s"],
                control_activations=sum(s["episode_events"]["total_activations"] for s in items if s["profile"] in CONTROLS),
                control_eligible_episodes=sum(s["episode_events"]["eligible_episodes"] for s in items if s["profile"] in CONTROLS),
                forecast_errors=forecast_errors,
                structural_diagnostics=dict(short_horizons_flat_identical=bool(items) and all(
                    s["structural_diagnostics"]["short_horizons_flat_identical"] for s in items),
                    checked_windows=sum(s["structural_diagnostics"]["checked_windows"] for s in items),
                    candidates_before_first_observed_breach=sum(
                        s["structural_diagnostics"]["candidates_before_first_observed_breach"] for s in items)))


def paired_changes(original: Sequence[Dict[str, Any]], trained: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    a = {e["episode_id"]: e for s in original for e in s["episode_events"]["episodes"]}
    b = {e["episode_id"]: e for s in trained for e in s["episode_events"]["episodes"]}
    ground_truth = ("onset_index", "onset_ts_ns", "confirmation_index", "last_breach_index",
                    "clear_confirmation_index", "eligible", "left_censored", "right_censored")
    if set(a) != set(b) or any(any(a[key][field] != b[key][field] for field in ground_truth) for key in a):
        raise ValueError("modelos não podem alterar episódios observados ou sua elegibilidade")
    return dict(ground_truth_matches=True,
                lost_anticipated_episodes=[key for key in a if a[key]["eligible"] and a[key]["detected"] and not b[key]["detected"]],
                gained_anticipated_episodes=[key for key in a if a[key]["eligible"] and not a[key]["detected"] and b[key]["detected"]],
                paired_episodes=[dict(episode_id=key, eligible=a[key]["eligible"], onset_ts_ns=a[key]["onset_ts_ns"],
                                     original_anticipated=a[key]["detected"], trained_anticipated=b[key]["detected"],
                                     original_lead_s=a[key]["warning_lead_time_s"], trained_lead_s=b[key]["warning_lead_time_s"])
                                 for key in a])


def load_development(development: Path, protocol: Dict[str, Any]) -> tuple:
    spec_path = development / "development-spec.json"
    spec = json.loads(spec_path.read_text(encoding="utf-8"))
    report = json.loads((development / "qos-damped-holt-evaluation.json").read_text(encoding="utf-8"))
    model = QosDampedHoltModel.load(development / "qos-damped-holt-model.json")
    if (spec.get("schema_version") != training.SCHEMA or spec != v1.seal(spec, "development_spec_sha256")
            or report.get("schema_version") != training.SCHEMA or report.get("status") != "DEVELOPMENT_FITTED"
            or report.get("model_id") != model.resolved_model_id()
            or report.get("created_at") != spec["created_at"] or model.created_at != spec["created_at"]):
        raise ValueError("especificação/relatório/modelo de desenvolvimento incompatíveis")
    for flag in ("promotion_eligible", "deployment_eligible"):
        if spec.get(flag) is not False or report.get(flag) is not False or model.training.get(flag) is not False:
            raise ValueError("artefato de desenvolvimento não pode declarar promoção/deployment")
    if (spec.get("independent_test_used") is not False or report.get("test_evaluated") is not False
            or spec.get("v2_used_for_fitting") is not False or report.get("v2_used_for_fitting") is not False):
        raise ValueError("artefato não é um treino v1 sem teste independente")
    source = protocol["source_v1"]
    parent_path, parent_campaign = Path(source["protocol_path"]).resolve(), Path(source["campaign_root"]).resolve()
    if (development.parent != parent_path.parent.parent
            or not development.name.startswith("qos-damped-development")):
        raise ValueError("modelo deve estar no diretório de desenvolvimento irmão do protocolo v1")
    if (Path(spec["source_protocol"]).resolve() != parent_path
            or Path(spec["source_campaign"]).resolve() != parent_campaign
            or spec["source_protocol_sha256"] != source["protocol_sha256"]):
        raise ValueError("modelo não foi treinado na campanha v1 de origem deste protocolo v2")
    for field in ("development_spec_sha256", "partitions", "source_series", "input_sha256", "code_sha256", "source_protocol_sha256"):
        if model.training.get(field) != spec[field]:
            raise ValueError(f"proveniência de desenvolvimento diverge: {field}")
    if (report.get("development_spec_sha256") != spec["development_spec_sha256"]
            or report.get("partitions") != spec["partitions"] or model.training.get("search_grid") != spec["search_grid"]
            or spec["code_sha256"] != training._code_snapshot()):
        raise ValueError("código/proveniência do treino mudou")
    parent = v1.load_protocol(parent_path)
    if training.source_snapshot(parent, parent_path, parent_campaign) != spec["input_sha256"]:
        raise ValueError("fontes originais do treino mudaram")
    expected_horizons = [dict(horizon_s=h.horizon_steps * model.sample_interval_s, horizon_steps=h.horizon_steps,
                             alpha=h.alpha, beta=h.beta, phi=h.phi, interval_radius=h.interval_radius,
                             calibration_samples=h.calibration_samples, training=h.training_metrics,
                             calibration_descriptive=h.calibration_metrics, test=None) for h in model.horizons]
    if report.get("horizons") != expected_horizons or report.get("validation_scope") != model.training.get("validation_scope"):
        raise ValueError("relatório diverge dos parâmetros/métricas do modelo treinado")
    baseline = QosHoltModel.load(parent_path.parent / parent["models"]["coverage90"]["path"])
    if (model.metric != baseline.metric or model.sample_interval_s != baseline.sample_interval_s
            or model.priming_samples != baseline.priming_samples or model.coverage != .9
            or tuple(h.horizon_steps for h in model.horizons) != tuple(protocol["horizons_steps"])):
        raise ValueError("modelo treinado não compartilha o escopo amostral do baseline")
    return spec, model


def source_snapshot(protocol: Dict[str, Any], protocol_path: Path, campaign: Path, development: Path) -> Dict[str, str]:
    sources = training.source_snapshot(protocol, protocol_path, campaign)
    for name in ("development-spec.json", "qos-damped-holt-model.json", "qos-damped-holt-evaluation.json"):
        path = development / name
        sources[str(path)] = v1.digest_file(path)
    sources[str(protocol_path.parent / "selection-analysis.json")] = v1.digest_file(protocol_path.parent / "selection-analysis.json")
    parent_path, parent_campaign = Path(protocol["source_v1"]["protocol_path"]), Path(protocol["source_v1"]["campaign_root"])
    sources.update(training.source_snapshot(v1.load_protocol(parent_path), parent_path, parent_campaign))
    return sources


def build_report(protocol_path: Path, campaign: Path, development: Path) -> Dict[str, Any]:
    protocol_path, campaign, development = (p.resolve() for p in (protocol_path, campaign, development))
    protocol = v2.load_protocol(protocol_path)
    before = source_snapshot(protocol, protocol_path, campaign, development)
    code = {name: v1.digest_file(ROOT / name) for name in CODE_FILES}
    spec, model = load_development(development, protocol)
    verified = v2.evaluate_campaign(protocol_path, campaign)
    summary_path = campaign / "campaign-summary.json"
    if verified["status"] != "COMPLETED" or verified["evaluated_runs"] != 12:
        raise ValueError("replay requer 12 execuções v2 válidas e encerradas")
    if json.loads(summary_path.read_text(encoding="utf-8")) != verified:
        raise ValueError("relatório v2 diverge da reavaliação congelada")
    baseline = QosHoltModel.load(protocol_path.parent / protocol["models"]["coverage90"]["path"])
    variants = {"original_holt90": dict(model_id=baseline.resolved_model_id(), series=[]),
                "trained_damped90": dict(model_id=model.resolved_model_id(), series=[])}
    for case, expected in zip(protocol["cases"], verified["cases"]):
        subjects, record, hashes = v1._read_case(protocol, case, campaign / case["case_id"])
        if hashes != expected["source_sha256"]:
            raise ValueError("fontes v2 mudaram após a reavaliação")
        for series, source in zip(subjects, record["sources"]):
            for name, artifact in (("original_holt90", baseline), ("trained_damped90", model)):
                block = replay_series(artifact, series, protocol["policy"])
                if name == "original_holt90":
                    _check_native_reference(baseline, series, protocol["policy"], block)
                block.update(case_id=case["case_id"], profile=case["profile"], repetition=case["repetition"],
                             source_sha256=source["sha256"])
                variants[name]["series"].append(block)
    for variant in variants.values():
        variant["summary"] = aggregate(variant["series"])
        variant["per_profile"] = {p: aggregate([s for s in variant["series"] if s["profile"] == p]) for p in v1.profiles()}
        variant["per_run"] = {c["case_id"]: aggregate([s for s in variant["series"] if s["case_id"] == c["case_id"]])
                              for c in protocol["cases"]}
    measured = variants["original_holt90"]["summary"]
    official = verified["models"]["coverage90"]
    if (measured["candidate"] != official["pooled_window_candidate"]
            or measured["watch_windows"] != official["watch_windows"]
            or measured["anticipated"] != official["episode_events"]["detected"]
            or measured["eligible_episodes"] != official["episode_events"]["eligible_episodes"]):
        raise ValueError("baseline agregado diverge dos resultados oficiais")
    paired = paired_changes(variants["original_holt90"]["series"], variants["trained_damped90"]["series"])
    v2.load_protocol(protocol_path)
    if (source_snapshot(protocol, protocol_path, campaign, development) != before
            or {name: v1.digest_file(ROOT / name) for name in CODE_FILES} != code):
        raise ValueError("fontes/código mudaram durante o replay; nenhum relatório será publicado")
    return v1.seal(dict(schema_version=SCHEMA, created_ns=time.time_ns(), status="REPLAY_COMPLETED",
                        scope="posthoc_v2_development_replay_not_independent_validation",
                        promotion_eligible=False, deployment_eligible=False, independent_test=False,
                        refit=False, recalibration=False, baseline_exact=True, original_artifacts_unchanged=True,
                        development_spec_sha256=spec["development_spec_sha256"],
                        git_commit=subprocess.check_output(["git", "rev-parse", "HEAD"], cwd=ROOT, text=True).strip(),
                        source_sha256=before, analysis_code_sha256=code, risk_policy=protocol["policy"],
                        official_v2=dict(status=verified["status"], criteria_status=verified["criteria_status"],
                                         checks=verified["checks"], models=verified["models"],
                                         protocol_sha256=protocol["protocol_sha256"], summary_sha256=before[str(summary_path)]),
                        variants=variants, paired_changes=paired, limitations=list(LIMITATIONS)), "report_sha256")


def output_path(development: Path, output: Path) -> Path:
    if output.absolute().is_symlink():
        raise ValueError("saída não pode ser um link simbólico")
    output = output.resolve()
    if (output.exists() or output.parent != development.resolve() or output.suffix != ".json"
            or not output.name.startswith("replay-v2")):
        raise ValueError("use um novo replay-v2*.json diretamente no diretório do modelo de desenvolvimento")
    return output


def console_lines(report: Dict[str, Any], output: Path) -> List[str]:
    official = report["official_v2"]
    lines = [f"official_v2={official['status']} criteria={official['criteria_status']} unchanged=true baseline_exact=true"]
    for name, short in (("original_holt90", "original"), ("trained_damped90", "trained")):
        s = report["variants"][name]["summary"]
        lead = "N/A" if s["lead_time_s"]["mean"] is None else f"{s['lead_time_s']['mean']:.3f}s"
        lines.append(f"{short}: anticipated={s['anticipated']}/{s['eligible_episodes']} late={s['late_activations']} "
                     f"control={s['control_activations']} unmatched={s['unmatched_activations']} "
                     f"FP={s['candidate']['confusion']['FP']} WATCH={s['watch_windows']} lead={lead}")
    paired = report["paired_changes"]
    lines.append(f"paired: lost={len(paired['lost_anticipated_episodes'])} gained={len(paired['gained_anticipated_episodes'])} "
                 "ground_truth_unchanged=true")
    structural = report["variants"]["trained_damped90"]["summary"]["structural_diagnostics"]
    lines.append(f"structural: flat_identical_4_8={str(structural['short_horizons_flat_identical']).lower()} "
                 f"checked_windows={structural['checked_windows']} pre_first_breach_candidates={structural['candidates_before_first_observed_breach']}")
    lines.append("status=REPLAY_COMPLETED promotion_eligible=false independent_test=false")
    lines.append(f"report={output}")
    return lines


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", required=True, type=Path)
    parser.add_argument("--campaign-root", required=True, type=Path)
    parser.add_argument("--development-root", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        destination = output_path(args.development_root, args.output)
        report = build_report(args.protocol, args.campaign_root, args.development_root)
        v1.write_new_json(destination, report)
        print("\n".join(console_lines(report, destination)))
        return 0
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
