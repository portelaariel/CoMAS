#!/usr/bin/env python3
"""Offline, explicit-cohort consolidation of frozen shadow pilots.

No traffic, API/ETCD calls, fitting, authority or actuation. Re-evaluate existing
artifacts without overwriting them; retain the known failed control attempt.
"""

from __future__ import annotations

import argparse
import json
import math
import re
import sys
import time
from pathlib import Path

import predictive_sla_shadow_controls as controls
import predictive_sla_shadow_fast_ramp as fast
import predictive_sla_shadow_ramp as slow
import predictive_sla_shadow_ramp_analysis as paired
import predictive_sla_validation as provenance


ROOT = Path(__file__).resolve().parent
MANIFEST_SCHEMA = "comas-shadow-characterization-manifest/2"
SUMMARY_SCHEMA = "comas-shadow-characterization-summary/2"
OUTPUT_PREFIX = "qos-shadow-characterization-"
MODULES = {"slow-ramp": slow, "fast-ramp": fast,
           "stable-low": controls, "short-pulses": controls}
PREFIXES = ("qos-online-shadow-v2-diagnostics-ramp-",
            "qos-online-shadow-v2-diagnostics-fast-ramp-",
            "qos-online-shadow-v2-diagnostics-control-stable-low-",
            "qos-online-shadow-v2-diagnostics-control-short-pulses-")
# Explicit console-reported cohort. Labels are not performance verdicts; the
# original receipts and replayed reports must actually satisfy their contracts.
COHORT = (
    ("slow-ramp", 1, "COLLECTED", "qos-online-shadow-v2-diagnostics-ramp-20261012T153426Z"),
    ("slow-ramp", 2, "COLLECTED", "qos-online-shadow-v2-diagnostics-ramp-rep2-20261012T160150Z"),
    ("slow-ramp", 3, "COLLECTED", "qos-online-shadow-v2-diagnostics-ramp-rep3-20261012T160729Z"),
    ("fast-ramp", 1, "COLLECTED", "qos-online-shadow-v2-diagnostics-fast-ramp-20261012T165515Z"),
    ("fast-ramp", 2, "COLLECTED", "qos-online-shadow-v2-diagnostics-fast-ramp-rep2-20261012T203328Z"),
    ("fast-ramp", 3, "COLLECTED", "qos-online-shadow-v2-diagnostics-fast-ramp-rep3-20261012T210738Z"),
    ("stable-low", None, "STOPPED_ERROR", "qos-online-shadow-v2-diagnostics-control-stable-low-20261014T194859Z"),
    ("stable-low", 1, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-stable-low-20261014T202304Z"),
    ("stable-low", 2, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-stable-low-rep2-20261016T121557Z"),
    ("stable-low", 3, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-stable-low-rep3-20261016T122552Z"),
    ("short-pulses", 1, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-short-pulses-20261014T202921Z"),
    ("short-pulses", 2, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-short-pulses-rep2-20261016T122100Z"),
    ("short-pulses", 3, "COLLECTED", "qos-online-shadow-v2-diagnostics-control-short-pulses-rep3-20261016T123042Z"),
)
CODE_FILES = tuple(dict.fromkeys((*controls.CODE_FILES, "predictive_sla_shadow_report.py")))
POLICY = dict(
    cohort="explicit_required_12_completed_pilots_and_known_failed_control; no_latest_success_selection",
    extra_directories="must_be_registered_explicitly_with_extra_attempt; never_silently_discarded",
    source_validation="receipted_attempts_use_frozen_loaders_and_exact_replay; unfinalized_sources_inventory_only",
    repetitions="receipted_attempts_only: distinct_paths_UUIDs_CSV_hashes_and_nonoverlapping_intervals",
    statistics="descriptive_physical_pilot_counts; correlated_ports_not_independent_trials",
    failure="excluded_from_performance_only; retained_in_attempt_counts_and_provenance",
    missing_receipt="explicit_extra_registration_only; UNKNOWN_not_success_failure_or_preparation; no_performance_metrics",
    pulses="actual_native_timestamp_value_binding; measured_interval_overlap; descriptive_not_delivery_pass",
    action="offline_report_only; no_acceptance_or_promotion",
)
LIMITATIONS = [
    "This is a small, explicitly selected laboratory characterization, not a new independent acceptance test.",
    "Two ports observe the same shared link; port episodes and pair renewals are not independent trials.",
    "Positive margins refer to retrospective sampled utilization onsets, not exact physical SLA crossing times.",
    "Minimum observed margin is descriptive, not a guaranteed deadline budget.",
    "No authority, actuator, LLM or real SLA-protection latency was measured in these pilots.",
    "Quiet controls do not establish 100% specificity or a general false-alarm rate.",
    "Pulse maxima are averages over measured counter intervals; no clipping at utilization 1 or instantaneous-peak claim.",
    "The known stopped attempt remains an operational failure; subsequent success does not explain its root cause.",
    "Explicit extra directories without a final receipt are inventory-only UNKNOWN sources, not proved preparations, failures or completed trials; their execution, lineage and timing are unassessed.",
    "The original v4 remains NOT_PASSED; no source result, model, threshold or policy is changed.",
]


def read_json(path):
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"arquivo ausente ou link simbólico: {path}")
    return json.loads(path.read_text(encoding="utf-8"))


def sealed(path, schema, field):
    payload = read_json(path)
    if (not isinstance(payload, dict) or payload.get("schema_version") != schema
            or payload != provenance.seal(payload, field)):
        raise ValueError(f"schema/checksum inválido: {path}")
    return payload


def code_snapshot():
    return {name: provenance.digest_file(ROOT / name) for name in CODE_FILES}


def entries_for(results, extra=()):
    entries = [dict(profile=profile, repetition=rep, expected_receipt_status=status,
                    directory=name, root=str(results / name)) for profile, rep, status, name in COHORT]
    names = {row["directory"] for row in entries}
    for name in extra:
        if Path(name).name != name or name in names or not name.startswith(PREFIXES):
            raise ValueError("extra-attempt deve ser novo nome de diretório de piloto, sem caminho")
        root = results / name
        receipt_path = root / "pilot" / "pilot-run.json"
        if receipt_path.is_symlink():
            raise ValueError("recibo não pode ser link simbólico")
        if not receipt_path.exists():
            entries.append(dict(profile=None, repetition=None, expected_receipt_status="MISSING_FINAL_RECEIPT",
                                directory=name, root=str(root)))
            names.add(name)
            continue
        p = read_json(root / "protocol.json")
        profile = p["case"]["profile"]
        if profile not in MODULES:
            raise ValueError("perfil adicional desconhecido")
        receipt = sealed(receipt_path, MODULES[profile].RECEIPT_SCHEMA, "run_sha256")
        if receipt["status"] not in {"COLLECTED", "STOPPED_ERROR"}:
            raise ValueError("tentativa adicional sem recibo final reconhecido")
        entries.append(dict(profile=profile, repetition=None, expected_receipt_status=receipt["status"],
                            directory=name, root=str(root)))
        names.add(name)
    return entries


def check_directory_set(results, entries):
    expected = {row["directory"] for row in entries}
    found = {path.name for path in results.iterdir() if path.name.startswith(PREFIXES)}
    if found != expected:
        raise ValueError(f"coorte difere dos diretórios: ausentes={sorted(expected-found)}; "
                         f"adicionais={sorted(found-expected)}; registre adicionais com --extra-attempt NOME")


def inventory(entries):
    files = {}
    for entry in entries:
        root = Path(entry["root"])
        if root.is_symlink() or not root.is_dir():
            raise ValueError(f"piloto ausente ou link simbólico: {root}")
        for path in sorted(root.rglob("*")):
            if path.is_symlink():
                raise ValueError(f"link simbólico não permitido no piloto: {path}")
            if path.is_file():
                files[str(path)] = provenance.digest_file(path)
    return files


def load_attempt(entry):
    root = Path(entry["root"])
    if entry["expected_receipt_status"] == "MISSING_FINAL_RECEIPT":
        receipt_path = root / "pilot" / "pilot-run.json"
        if (entry["profile"] is not None or root.is_symlink() or not root.is_dir()
                or receipt_path.exists() or receipt_path.is_symlink()):
            raise ValueError("fonte sem recibo mudou; não a reclassifique silenciosamente")
        return None, None, None
    module = MODULES[entry["profile"]]
    p = module.load_protocol(root / "protocol.json")
    receipt = sealed(root / "pilot" / "pilot-run.json", module.RECEIPT_SCHEMA, "run_sha256")
    if (p["case"]["profile"] != entry["profile"] or receipt["protocol_sha256"] != p["protocol_sha256"]
            or receipt["boundary"] != p["boundary"] or p["source_criteria_status"] != "NOT_PASSED"
            or receipt["status"] != entry["expected_receipt_status"]):
        raise ValueError(f"perfil/protocolo/recibo divergem da tentativa declarada: {root.name}")
    for key in ("started_ns", "ended_ns"):
        if type(receipt.get(key)) is not int or receipt[key] <= 0:
            raise ValueError("recibo sem intervalo temporal positivo")
    if receipt["ended_ns"] <= receipt["started_ns"]:
        raise ValueError("intervalo temporal inválido no recibo")
    return module, p, receipt


def freeze(results, output, extra=()):
    if results.absolute().is_symlink() or output.absolute().is_symlink():
        raise ValueError("diretórios não podem ser links simbólicos")
    results, output = results.resolve(), output.resolve()
    if (not results.is_dir() or output.exists() or output.parent != results
            or not output.name.startswith(OUTPUT_PREFIX)):
        raise ValueError("use novo diretório qos-shadow-characterization-* dentro de results")
    entries = entries_for(results, extra)
    check_directory_set(results, entries)
    files, code = inventory(entries), code_snapshot()
    for entry in entries:
        load_attempt(entry)
    if inventory(entries) != files or code_snapshot() != code:
        raise ValueError("fontes/código mudaram durante o congelamento; não consolide dados em execução")
    manifest = provenance.seal(dict(schema_version=MANIFEST_SCHEMA, created_ns=time.time_ns(),
        results_root=str(results), entries=entries, policy=POLICY, source_files_sha256=files,
        code_sha256=code, limitations=LIMITATIONS), "manifest_sha256")
    output.mkdir()
    provenance.write_new_json(output / "manifest.json", manifest)
    return manifest


def load_manifest(path):
    if path.absolute().is_symlink():
        raise ValueError("manifesto não pode ser link simbólico")
    path = path.resolve()
    manifest = sealed(path, MANIFEST_SCHEMA, "manifest_sha256")
    results = Path(manifest["results_root"])
    if (results != results.resolve() or results.is_symlink() or path.name != "manifest.json"
            or path.parent.parent != results or not path.parent.name.startswith(OUTPUT_PREFIX)):
        raise ValueError("manifesto fora do diretório de relatório")
    declared = manifest["entries"]
    extras = [row["directory"] for row in declared[len(COHORT):]]
    if (declared != entries_for(results, extras) or manifest["policy"] != POLICY
            or manifest["code_sha256"] != code_snapshot() or manifest["limitations"] != LIMITATIONS):
        raise ValueError("coorte/política/código do relatório mudou")
    check_directory_set(results, declared)
    if inventory(declared) != manifest["source_files_sha256"]:
        raise ValueError("arquivos de origem mudaram após congelar o manifesto")
    return manifest


def shadow_root(root, receipt):
    if receipt.get("shadow_run") is None:
        return None
    path = Path(receipt["shadow_run"])
    if (path.is_symlink() or path != path.resolve() or path.parent != root / "runs"
            or not re.fullmatch(r"[0-9a-f]{32}", path.name)):
        raise ValueError("run shadow fora da tentativa")
    return path


def failure_details(root, receipt):
    shadow = shadow_root(root, receipt)
    summary_path = None if shadow is None else shadow / "shadow-summary.json"
    summary = read_json(summary_path) if summary_path is not None and summary_path.exists() else None
    if summary is not None and (summary.get("schema_version") != controls.diagnostic.SUMMARY_SCHEMA
                                or summary.get("boundary") != receipt["boundary"]):
        raise ValueError("resumo diagnóstico da falha incompatível")
    native_path = root / "pilot" / "workload" / "run.json"
    native = sealed(native_path, provenance.RUN_SCHEMA, "run_sha256") if native_path.exists() else None
    return dict(error=receipt.get("error"), collector_exit_code=receipt.get("collector_exit_code"),
        shadow_exit_code=receipt.get("shadow_exit_code"), cleanup_errors=receipt.get("cleanup_errors"),
        originals_unchanged=receipt.get("originals_unchanged"), source_errors=receipt.get("source_errors"),
        collection_status=None if native is None else native.get("status"),
        diagnostic_status=None if summary is None else summary.get("status"),
        failed_stage=None if summary is None else summary.get("failed_stage"),
        domain_reports=None if summary is None else summary.get("domain_reports"),
        transport_summary=None if summary is None else summary.get("transport_summary"),
        root_cause="NOT_ESTABLISHED", performance_metrics=None)


def pulse_evidence(p, series, record, journals):
    pulses = [stage for stage in record["workload"] if stage["rate_mbit"] == 110]
    if len(pulses) != 4:
        raise ValueError("perfil de pulsos não contém os quatro patamares originais")
    result = []
    for block in series:
        cid = block["cid"]
        native = dict(zip(block["timestamps_ns"], block["values"]))
        samples = [row["record"]["sample"] for row in journals[cid]
                   if row["kind"] == "LOCAL_EVALUATION" and row["record"]["sample"]["ts_ns"] in native]
        rows = []
        for ordinal, pulse in enumerate(pulses, 1):
            windows = []
            for sample in samples:
                interval = sample.get("interval_s")
                if type(interval) not in (float, int) or not math.isfinite(interval) or interval <= 0:
                    raise ValueError("intervalo medido indisponível; não invente janela de dois segundos")
                ts = sample["ts_ns"]
                if sample["cid"] != cid or sample["utilization_ratio"] != native[ts]:
                    raise ValueError("amostra do pulso difere da referência nativa")
                if ts > pulse["start_ns"] and ts - round(interval * 1e9) < pulse["end_ns"]:
                    windows.append(dict(ts_ns=ts, interval_s=interval, utilization_ratio=native[ts]))
            rows.append(dict(pulse=ordinal, start_ns=pulse["start_ns"], end_ns=pulse["end_ns"],
                windows=windows, windows_count=len(windows),
                peak_mean_utilization=max(row["utilization_ratio"] for row in windows) if windows else None,
                threshold_crossing_windows=sum(row["utilization_ratio"] >= p["policy"]["threshold"] for row in windows),
                review_status="WINDOWS_AVAILABLE" if windows else "INSUFFICIENT_EVIDENCE"))
        result.append(dict(cid=cid, port_id=block["port_id"], pulses=rows))
    return result


def compact_domain(domain):
    keys = ("cid", "port_id", "samples", "native_samples_seen_by_sidecar", "native_samples_not_seen_by_sidecar",
            "local_activations_missing_from_reference", "strict_activation_episodes", "episode_timings",
            "joint_pre_sampled_onset", "joint_at_or_after_sampled_onset", "joint_without_recorded_agreement",
            "agreement_available_margin_s", "control_observation", "full_sidecar_reference_coverage",
            "forecast_ready_reference_samples", "local_activations_outside_reference", "observed_joint_pair_witnesses",
            "unsupported_joint_pair_witnesses", "censored_joint_pair_witnesses", "outside_reference_joint_pair_witnesses")
    return {key: domain[key] for key in keys if key in domain}


def consolidate(manifest):
    attempts, common, csv_hashes, uuids, intervals = [], None, set(), set(), []
    lineage_files, unfinalized_sources = {}, []
    for entry in manifest["entries"]:
        root = Path(entry["root"])
        module, p, receipt = load_attempt(entry)
        if receipt is None:
            unfinalized_sources.append(dict(**entry, status="UNKNOWN", reason="missing_final_receipt",
                execution_started=None, execution_completed=None, authority=None, actuation=None,
                protocol_validation="NOT_ASSESSED", timing_validation="UNASSESSABLE",
                performance_metrics=None, domains=None,
                source_files_sha256={name: checksum for name, checksum in manifest["source_files_sha256"].items()
                                     if Path(name).is_relative_to(root)}))
            continue
        identity = {key: p[key] for key in ("source_diagnostic_config", "source_idle_run", "source_criteria_status",
                    "model", "policy", "subjects", "collection", "runtime", "matching_policy", "boundary")}
        if common is None:
            common = identity
        elif common != identity:
            raise ValueError("modelo/política/sujeitos/linhagem diferem entre pilotos")
        lineage_files.update(p["source_artifacts_sha256"])
        start, end = receipt["started_ns"], receipt["ended_ns"]
        if any(max(start, a) < min(end, b) for a, b in intervals):
            raise ValueError("tentativas temporais sobrepostas; não conte como pilotos separados")
        intervals.append((start, end))
        shadow = shadow_root(root, receipt)
        if shadow is not None:
            if shadow.name in uuids:
                raise ValueError("UUID shadow reutilizado em outra tentativa")
            uuids.add(shadow.name)
        result = dict(**entry, protocol_sha256=p["protocol_sha256"], receipt_sha256=receipt["run_sha256"],
            started_ns=start, ended_ns=end, shadow_run=None if shadow is None else str(shadow))
        if receipt["status"] == "STOPPED_ERROR":
            attempts.append(dict(result, status="STOPPED_ERROR", failure=failure_details(root, receipt),
                                 measurement_status=None, domains=None))
            continue
        name = "control-observation.json" if module is controls else "paired-timing.json"
        stored = sealed(root / "pilot" / name, module.REPORT_SCHEMA, "report_sha256")
        replayed = module.evaluate(root / "protocol.json", receipt)
        expected = "CONTROL_OBSERVED" if module is controls else "PAIRED"
        if stored != replayed or stored.get("measurement_status") != expected:
            raise ValueError(f"relatório não reproduzível/incompleto: {root.name}")
        series, record, hashes = provenance._read_case(p, p["case"], root / "pilot" / "workload")
        if csv_hashes.intersection(hashes) or len(set(hashes)) != len(hashes):
            raise ValueError("CSV reutilizado entre séries/pilotos")
        csv_hashes.update(hashes)
        journals = {s["cid"]: paired.read_journal(shadow / f"{s['cid']}.ndjson") for s in p["subjects"]}
        pulses = pulse_evidence(p, series, record, journals) if entry["profile"] == "short-pulses" else None
        attempts.append(dict(result, status="COMPLETED", measurement_status=expected,
            report_sha256=stored["report_sha256"], source_csv_sha256=hashes,
            control_observation=stored.get("control_observation"),
            distinct_joint_agreement_witnesses=stored["distinct_joint_agreement_witnesses"],
            domains=[compact_domain(d) for d in stored["domains"]], pulse_evidence=pulses))
    for name, checksum in lineage_files.items():
        path = Path(name)
        if path.is_symlink() or provenance.digest_file(path) != checksum:
            raise ValueError(f"artefato da linhagem mudou: {name}")
    profiles = {}
    for profile in MODULES:
        rows = [row for row in attempts if row["profile"] == profile]
        complete = [row for row in rows if row["status"] == "COMPLETED"]
        domains = [d for row in complete for d in row["domains"]]
        timings = [e for d in domains for e in d["episode_timings"]]
        margins = [e["joint_agreement"]["agreement_available_margin_s"] for e in timings if e["joint_agreement"] is not None]
        profiles[profile] = dict(attempts=len(rows), completed_pilots=len(complete),
            stopped_attempts=len(rows)-len(complete), correlated_port_series=len(domains),
            sampled_episodes=len(timings),
            joint_pre_sampled_onset=sum(d["joint_pre_sampled_onset"] for d in domains),
            joint_at_or_after_sampled_onset=sum(d["joint_at_or_after_sampled_onset"] for d in domains),
            joint_without_recorded_agreement=sum(d["joint_without_recorded_agreement"] for d in domains),
            agreement_margin_s=paired.summary_stats(margins),
            local_activations=sum(d["strict_activation_episodes"]["total_activations"] for d in domains),
            unmatched_activations=sum(d["strict_activation_episodes"]["unmatched_activations"] for d in domains),
            censored_activations=sum(d["strict_activation_episodes"]["censored_activations"] for d in domains),
            native_samples_not_seen_by_sidecar=sum(d["native_samples_not_seen_by_sidecar"] for d in domains),
            control_observations=[row["control_observation"] for row in complete] if profile in controls.PROFILES else None,
            distinct_joint_pair_witnesses=sum(row["distinct_joint_agreement_witnesses"] for row in complete))
    status = "CONSOLIDATED_WITH_UNFINALIZED_SOURCES" if unfinalized_sources else "CONSOLIDATED"
    return dict(schema_version=SUMMARY_SCHEMA, status=status, manifest_sha256=manifest["manifest_sha256"],
        policy=POLICY, lineage=common, original_v4_status=common["source_criteria_status"],
        registered_directories=len(manifest["entries"]),
        unfinalized_directories=len(unfinalized_sources), unfinalized_sources=unfinalized_sources,
        attempts_total=len(attempts), completed_pilots=sum(row["status"] == "COMPLETED" for row in attempts),
        stopped_attempts=sum(row["status"] == "STOPPED_ERROR" for row in attempts), profiles=profiles, attempts=attempts,
        source_files_sha256=manifest["source_files_sha256"], protected_lineage_sha256=lineage_files,
        originals_unchanged=True, original_reports_reproduced=True, statistical_independence_established=False,
        specificity=None, false_alarm_rate=None, deadline_feasibility="UNKNOWN",
        sla_protection_established=False, promotion_eligible=False, deployment_eligible=False,
        report_execution=dict(offline=True, new_traffic=False, api_calls=False, etcd_writes=False,
                              source_writes=False, fitting=False, authority=False, actuation=False, llm=False),
        limitations=LIMITATIONS)


def render_markdown(report):
    lines = ["# CoMAS — caracterização shadow online", "",
        f"Status de consolidação: `{report['status']}` — não é aprovação ou promoção.", "",
        f"Diretórios registrados: {report['registered_directories']}; sem recibo final: {report['unfinalized_directories']}.",
        f"Tentativas com recibo: {report['attempts_total']}; pilotos concluídos: {report['completed_pilots']}; "
        f"interrompidos: {report['stopped_attempts']}.",
        "Duas portas correlacionadas por piloto; independência estatística não estabelecida.", "",
        "| Perfil | Tentativas | Concluídos | Falhas | Episódios amostrados | Acordos antecipados | Margem mínima (s) | Ativações locais |",
        "|---|---:|---:|---:|---:|---:|---:|---:|"]
    for profile, row in report["profiles"].items():
        margin = row["agreement_margin_s"]["minimum"]
        text = "N/A" if margin is None else f"{margin:.6f}"
        lines.append(f"| {profile} | {row['attempts']} | {row['completed_pilots']} | {row['stopped_attempts']} | "
                     f"{row['sampled_episodes']} | {row['joint_pre_sampled_onset']} | {text} | {row['local_activations']} |")
    lines.extend(["", "A margem é relativa ao início amostrado retrospectivo, não ao instante físico exato.",
                  "Controles quietos não estabelecem especificidade de 100%. Contagens de pares não são ações independentes.",
                  "", "## Tentativas e evidências", ""])
    for row in report["attempts"]:
        lines.extend([f"### {row['directory']}", "", f"- Perfil: `{row['profile']}`; estado: `{row['status']}`.",
                      f"- Protocolo SHA256: `{row['protocol_sha256']}`.", f"- Recibo SHA256: `{row['receipt_sha256']}`."])
        if row["status"] == "STOPPED_ERROR":
            failure = row["failure"]
            lines.extend([f"- Erro registrado: `{failure['error']}`.",
                          f"- Causa fundamental: `{failure['root_cause']}`; métricas de desempenho não atribuídas."])
        else:
            lines.append(f"- Relatório original SHA256: `{row['report_sha256']}`; replay offline idêntico.")
            if row["control_observation"] is not None:
                lines.append(f"- Observação do controle: `{row['control_observation']}`.")
            if row["pulse_evidence"] is not None:
                for domain in row["pulse_evidence"]:
                    peaks = [p["peak_mean_utilization"] for p in domain["pulses"]]
                    counts = [p["windows_count"] for p in domain["pulses"]]
                    lines.append(f"- Pulsos {domain['cid']}: máximos médios por janela `{peaks}`; janelas `{counts}`.")
        lines.append("")
    if report["unfinalized_sources"]:
        lines.extend(["## Fontes sem recibo final — resultado desconhecido", "",
            "Não entram nas métricas nem nas contagens de tentativas com recibo. Ausência de recibo não prova ausência de execução.",
            "Perfil, linhagem, intervalo temporal, authority e atuação não foram validados; não são classificados como falhas ou preparações.", ""])
        for row in report["unfinalized_sources"]:
            lines.extend([f"### {row['directory']}", "", "- Estado: `UNKNOWN`; motivo: `missing_final_receipt`.",
                          f"- Arquivos inventariados: {len(row['source_files_sha256'])}; hashes preservados no JSON e inventário.",
                          "- Métricas de desempenho: desconhecidas (`null`), não zero.", ""])
    lines.extend(["## Proveniência e limites", "",
                  f"Manifesto SHA256: `{report['manifest_sha256']}`.",
                  "`source-inventory.json` contém os caminhos absolutos e hashes dos artefatos, incluindo a falha.",
                  "O JSON completo conserva resultados por domínio, episódios, censura e evidências dos pulsos.",
                  "v4 original: `NOT_PASSED`. Authority, atuação e LLM não foram medidos; prazo real permanece desconhecido.", ""])
    lines.extend(f"- {item}" for item in report["limitations"])
    return "\n".join(lines) + "\n"


def build(path):
    manifest = load_manifest(path)
    output = path.resolve().parent
    names = ("validation-summary.json", "validation-summary.md", "source-inventory.json")
    if any((output / name).exists() or (output / name).is_symlink() for name in names):
        raise ValueError("saída já existe; preserve-a e congele outro diretório de relatório")
    report = consolidate(manifest)
    if load_manifest(path) != manifest:
        raise ValueError("fontes/manifesto mudaram durante a consolidação")
    report = provenance.seal(report, "report_sha256")
    provenance.write_new_json(output / names[0], report)
    with (output / names[1]).open("x", encoding="utf-8") as handle:
        handle.write(render_markdown(report))
    provenance.write_new_json(output / names[2], provenance.seal(dict(
        manifest_sha256=manifest["manifest_sha256"], report_sha256=report["report_sha256"],
        source_files_sha256=report["source_files_sha256"], protected_lineage_sha256=report["protected_lineage_sha256"]), "inventory_sha256"))
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    frozen = commands.add_parser("freeze")
    frozen.add_argument("--results-root", type=Path, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    frozen.add_argument("--extra-attempt", action="append", default=[])
    report = commands.add_parser("build")
    report.add_argument("--manifest", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            m = freeze(args.results_root, args.output, args.extra_attempt)
            print(f"manifest={args.output / 'manifest.json'} registered={len(m['entries'])} offline=true")
        else:
            result = build(args.manifest)
            print(f"status={result['status']} registered={result['registered_directories']} attempts_with_receipt={result['attempts_total']} completed={result['completed_pilots']} stopped={result['stopped_attempts']} unfinalized={result['unfinalized_directories']} originals_unchanged=true offline=true")
            for profile, row in result["profiles"].items():
                print(f"{profile}: completed={row['completed_pilots']} stopped={row['stopped_attempts']} episodes={row['sampled_episodes']} pre_onset={row['joint_pre_sampled_onset']} late={row['joint_at_or_after_sampled_onset']} missing={row['joint_without_recorded_agreement']} activations={row['local_activations']} min_margin_s={row['agreement_margin_s']['minimum']}")
            print(f"json={args.manifest.parent / 'validation-summary.json'}")
            print(f"markdown={args.manifest.parent / 'validation-summary.md'}")
        return 0
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
