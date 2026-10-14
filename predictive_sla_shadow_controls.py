#!/usr/bin/env python3
"""One opt-in stable or short-pulse control with frozen shadow agents and paired timing analysis.

Uses the existing guarded lab collector/cleanup. Never changes an earlier
protocol, model, collector, switch rule, authority gate, actuator or LLM path.
"""

from __future__ import annotations

import argparse
import copy
import fcntl
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_shadow_ramp as slow
import predictive_sla_shadow_control_analysis as analysis
import predictive_sla_shadow_fast_ramp as fast
import predictive_sla_validation as provenance
from scripts import collect_qos_validation_campaign as collector


ROOT = Path(__file__).resolve().parent
SCHEMA = "comas-predictive-sla-shadow-control-protocol/1"
RECEIPT_SCHEMA = "comas-predictive-sla-shadow-control-run/1"
REPORT_SCHEMA = "comas-predictive-sla-shadow-control-observation/1"
PROFILES = ("stable-low", "short-pulses")
CODE_FILES = (*fast.CODE_FILES, "predictive_sla_shadow_controls.py", "predictive_sla_shadow_control_analysis.py")
RUNTIME = dict(slow.RUNTIME)


read_json = slow.read_json
source_state = slow.source_state
await_ready = slow.await_ready
stop_shadow = slow.stop_shadow
stop_collection = slow.stop_collection


def code_snapshot():
    return {name: provenance.digest_file(ROOT / name) for name in CODE_FILES}


def case_from(original, profile):
    if profile not in PROFILES:
        raise ValueError("perfil de controle inválido")
    cases = [case for case in original["cases"] if case["profile"] == profile]
    if not cases:
        raise ValueError("perfil de controle ausente no protocolo de origem")
    case = copy.deepcopy(cases[0])
    case["case_id"] = "online-" + profile
    return case


def freeze(source, idle_run, output, profile):
    if profile not in PROFILES:
        raise ValueError("perfil de controle inválido")
    if any(path.absolute().is_symlink() for path in (source, idle_run, output)):
        raise ValueError("fontes/saídas não podem ser links simbólicos")
    source, idle_run, output = source.resolve(), idle_run.resolve(), output.resolve()
    if (output.exists() or output.parent != source.parent.parent
            or not output.name.startswith("qos-online-shadow-v2-diagnostics-control-" + profile + "-")):
        raise ValueError("use novo diretório irmão qos-online-shadow-v2-diagnostics-control-PERFIL-*")
    config, original, artifacts = source_state(source, idle_run)
    case, code = case_from(original, profile), code_snapshot()
    # Reuse the immutable atomic/HTTP implementation in another sealed config.
    new_config = diagnostic.freeze(Path(config["source_shadow_config"]), output)
    duration = case["duration_s"] + original["collection"]["warmup_s"] + sum(
        RUNTIME[key] for key in ("startup_timeout_s", "setup_reserve_s", "after_workload_reserve_s"))
    payload = provenance.seal(dict(schema_version=SCHEMA, created_ns=time.time_ns(),
        source_diagnostic_config=str(source), source_idle_run=str(idle_run),
        source_artifacts_sha256=artifacts, source_criteria_status=config["source_criteria_status"],
        diagnostic_config_sha256=new_config["config_sha256"], model=config["model"], policy=config["policy"],
        subjects=config["subjects"], collection=original["collection"], case=case,
        runtime=RUNTIME, shadow_duration_s=duration, code_sha256=code,
        control_characterization_policy=analysis.POLICY,
        matching_policy=analysis.MATCHING, boundary=diagnostic.protocol.BOUNDARY,
        promotion_eligible=False, deployment_eligible=False,
        limitations=[*diagnostic.LIMITATIONS, *analysis.LIMITATIONS]), "protocol_sha256")
    if source_state(source, idle_run) != (config, original, artifacts) or code_snapshot() != code:
        raise ValueError("fontes/código mudaram durante o congelamento do controle; preserve a saída parcial")
    provenance.write_new_json(output / "protocol.json", payload)
    load_protocol(output / "protocol.json")
    return payload


def load_protocol(path):
    if path.absolute().is_symlink():
        raise ValueError("protocolo não pode ser link simbólico")
    path = path.resolve()
    p = read_json(path)
    if p.get("schema_version") != SCHEMA or p != provenance.seal(p, "protocol_sha256"):
        raise ValueError("schema/checksum do protocolo de controle inválido")
    source = Path(p["source_diagnostic_config"])
    if (path.name != "protocol.json" or not path.parent.name.startswith("qos-online-shadow-v2-diagnostics-control-" + p["case"]["profile"] + "-")
            or path.parent.parent != source.resolve().parent.parent or path.parent == source.resolve().parent):
        raise ValueError("protocolo fora do novo diretório de controle")
    config, original, artifacts = source_state(source, Path(p["source_idle_run"]))
    new_config = diagnostic.load_config(path.parent / "shadow-config.json")
    case = case_from(original, p["case"]["profile"])
    duration = case["duration_s"] + original["collection"]["warmup_s"] + sum(
        RUNTIME[key] for key in ("startup_timeout_s", "setup_reserve_s", "after_workload_reserve_s"))
    expected = dict(source_artifacts_sha256=artifacts, source_criteria_status=config["source_criteria_status"],
        diagnostic_config_sha256=new_config["config_sha256"], model=config["model"], policy=config["policy"],
        subjects=config["subjects"], collection=original["collection"], case=case,
        runtime=RUNTIME, shadow_duration_s=duration, code_sha256=code_snapshot(),
        control_characterization_policy=analysis.POLICY,
        matching_policy=analysis.MATCHING, boundary=diagnostic.protocol.BOUNDARY,
        promotion_eligible=False, deployment_eligible=False,
        limitations=[*diagnostic.LIMITATIONS, *analysis.LIMITATIONS])
    if any(p.get(key) != value for key, value in expected.items()):
        raise ValueError("modelo/política/fontes/código diferem do protocolo de controle")
    return p


def preflight(path):
    p = load_protocol(path)
    snapshot = collector.preflight(p)
    diagnostic.preflight(diagnostic.load_config(path.resolve().parent / "shadow-config.json"))
    return snapshot


def collect(path, allow_traffic):
    if allow_traffic is not True:
        raise ValueError("coleta exige --allow-lab-traffic")
    p = load_protocol(path)
    if sys.platform != "linux":
        raise ValueError("coleta somente no servidor Linux")
    previous = signal.signal(signal.SIGTERM, collector.interrupt_collection)
    try:
        with Path(f"/tmp/comas-qos-validation-{os.getuid()}.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collector.collect_case(p, p["case"], path.resolve().parent / "pilot" / "workload")
    finally:
        signal.signal(signal.SIGTERM, previous)


def evaluate(path, receipt):
    p = load_protocol(path)
    root = path.resolve().parent
    if (receipt.get("schema_version") != RECEIPT_SCHEMA or receipt != provenance.seal(receipt, "run_sha256")
            or receipt["status"] != "COLLECTED" or receipt["protocol_sha256"] != p["protocol_sha256"]
            or receipt.get("boundary") != p["boundary"] or receipt.get("originals_unchanged") is not True
            or receipt.get("cleanup_errors") or receipt.get("source_errors")
            or receipt.get("shadow_exit_code") != 0 or receipt.get("collector_exit_code") != 0):
        raise ValueError("não avalie coleta/runtime incompletos como sucesso")
    shadow_root = Path(receipt["shadow_run"])
    if (shadow_root.parent != root / "runs" or not re.fullmatch(r"[0-9a-f]{32}", shadow_root.name)
            or shadow_root.is_symlink()):
        raise ValueError("run shadow fora do piloto")
    summary = read_json(shadow_root / "shadow-summary.json")
    manifest = read_json(shadow_root / "manifest.json")
    if (summary.get("schema_version") != diagnostic.SUMMARY_SCHEMA or summary.get("status") != "COMPLETED"
            or summary.get("originals_unchanged") is not True or summary.get("diagnostic_traces_complete") is not True
            or summary.get("boundary") != p["boundary"]
            or manifest["config_sha256"] != p["diagnostic_config_sha256"]
            or manifest["duration_s"] != p["shadow_duration_s"]):
        raise ValueError("diagnóstico shadow não completou validamente")
    analysis.check_artifacts(shadow_root, summary, p["subjects"])
    series, record, hashes = provenance._read_case(p, p["case"], root / "pilot" / "workload")
    if not receipt["started_ns"] <= manifest["started_ns"] <= record["started_ns"]:
        raise ValueError("janela shadow não começou dentro deste piloto antes da coleta")
    launcher = analysis.read_journal(shadow_root / "launcher-transport.ndjson")
    if not launcher or any(row.get("pid") != receipt.get("shadow_launcher_pid") for row in launcher):
        raise ValueError("run shadow não pertence ao processo lançado por este piloto")
    if record.get("cleanup_errors") or any(code is None for code in record.get("process_return_codes_after_cleanup", [None])):
        raise ValueError("limpeza da coleta não está confirmada")
    config = diagnostic.load_config(root / "shadow-config.json")
    journals = {subject["cid"]: analysis.read_journal(shadow_root / f"{subject['cid']}.ndjson") for subject in p["subjects"]}
    for block in series:
        times = [row["record"]["sample"]["ts_ns"] for row in journals[block["cid"]] if row["kind"] == "LOCAL_EVALUATION"]
        if not times or min(times) > block["timestamps_ns"][0] or max(times) < block["timestamps_ns"][-1]:
            raise ValueError("journal shadow não cobre toda a janela CSV do controle")
    report = analysis.analyze(config, shadow_root.name, series, journals)
    if load_protocol(path) != p:
        raise ValueError("fontes/protocolo mudaram durante a análise")
    return provenance.seal(dict(**report, schema_version=REPORT_SCHEMA,
        profile=p["case"]["profile"], workload=p["case"],
        protocol_sha256=p["protocol_sha256"], source_criteria_status=p["source_criteria_status"],
        originals_unchanged=True, collection_status=record["status"], shadow_status=summary["status"],
        shadow_run=str(shadow_root), source_csv_sha256=hashes,
        input_sha256={str(root / "pilot" / "workload" / "run.json"): provenance.digest_file(root / "pilot" / "workload" / "run.json"),
                      str(shadow_root / "shadow-summary.json"): provenance.digest_file(shadow_root / "shadow-summary.json")}), "report_sha256")


def run(path, allow_traffic, allow_publication):
    if allow_traffic is not True or allow_publication is not True:
        raise ValueError("run exige --allow-lab-traffic e --allow-shadow-publication")
    p = load_protocol(path)
    path = path.resolve()
    preflight(path)
    root, output = path.parent, path.parent / "pilot"
    if output.is_symlink():
        raise ValueError("saída não pode ser link simbólico")
    if (root / "runs").is_symlink():
        raise ValueError("diretório runs não pode ser link simbólico")
    output.mkdir(exist_ok=False)
    print(f"pilot={output}", flush=True)
    shadow = traffic = shadow_root = None
    error, cleanup_errors = None, []
    start_ns = time.time_ns()
    start_monotonic = time.monotonic()
    existing = {directory.name for directory in (root / "runs").iterdir()} if (root / "runs").exists() else set()
    try:
        with (output / "shadow.log").open("x") as shadow_log, (output / "collection.log").open("x") as traffic_log:
            shadow = subprocess.Popen([sys.executable, str(ROOT / "predictive_sla_shadow_diagnostics.py"), "run",
                "--config", str(root / "shadow-config.json"), "--duration-s", str(p["shadow_duration_s"]),
                "--allow-shadow-publication"], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                stdout=shadow_log, stderr=subprocess.STDOUT, start_new_session=True)
            shadow_root = await_ready(diagnostic.load_config(root / "shadow-config.json"), root, shadow,
                                      existing, p["runtime"]["startup_timeout_s"])
            print("shadow_ready=true baseline=OBSERVE traffic_not_started=true", flush=True)
            traffic = subprocess.Popen([sys.executable, str(ROOT / "predictive_sla_shadow_controls.py"), "_collect",
                "--protocol", str(path), "--allow-lab-traffic"], cwd=str(ROOT), stdin=subprocess.DEVNULL,
                stdout=traffic_log, stderr=subprocess.STDOUT, start_new_session=True)
            progress_at = time.monotonic() + 30
            while traffic.poll() is None:
                if shadow.poll() is not None:
                    raise ValueError("shadow terminou durante a coleta; interrompa a controle e preserve os artefatos")
                if time.monotonic() >= progress_at:
                    print("collection=RUNNING shadow_active=true authority=false actuation=false", flush=True)
                    progress_at = time.monotonic() + 30
                time.sleep(.25)
            if traffic.returncode != 0:
                raise ValueError("coleta falhou; consulte collection.log e workload/run.json")
            print("collection=COMPLETED waiting_for_shadow=true", flush=True)
            remaining = max(1, p["shadow_duration_s"] + p["runtime"]["shadow_finish_reserve_s"] - (time.monotonic() - start_monotonic))
            shadow.wait(timeout=remaining)
            if shadow.returncode != 0:
                raise ValueError("diagnóstico shadow falhou; consulte shadow.log")
    except (Exception, KeyboardInterrupt) as exc:
        error = str(exc) or type(exc).__name__
    finally:
        for callback, process in ((lambda proc: stop_collection(proc, p["runtime"]["collector_cleanup_timeout_s"]), traffic),
                                  (stop_shadow, shadow)):
            try:
                callback(process)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                cleanup_errors.append(str(exc))
    changed = []
    try:
        load_protocol(path)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        changed.append(str(exc))
    complete = (error is None and not cleanup_errors and not changed and shadow_root is not None
                and shadow is not None and shadow.poll() == 0 and traffic is not None and traffic.poll() == 0)
    receipt = provenance.seal(dict(schema_version=RECEIPT_SCHEMA, protocol_sha256=p["protocol_sha256"],
        status="COLLECTED" if complete else "STOPPED_ERROR", started_ns=start_ns, ended_ns=time.time_ns(),
        shadow_run=None if shadow_root is None else str(shadow_root), error=error,
        shadow_launcher_pid=None if shadow is None else shadow.pid,
        shadow_exit_code=None if shadow is None else shadow.poll(), collector_exit_code=None if traffic is None else traffic.poll(),
        originals_unchanged=not changed, source_errors=changed, cleanup_errors=cleanup_errors,
        boundary=p["boundary"]), "run_sha256")
    provenance.write_new_json(output / "pilot-run.json", receipt)
    if not complete:
        print(f"status=STOPPED_ERROR error={error} cleanup_errors={len(cleanup_errors)} originals_unchanged={not changed}")
        return False
    try:
        report = evaluate(path, receipt)
    except (OSError, ValueError, KeyError, TypeError) as exc:
        provenance.write_new_json(output / "timing-error.json", dict(error=str(exc), measurement_status="INSUFFICIENT_EVIDENCE"))
        print(f"measurement=INSUFFICIENT_EVIDENCE error={exc}")
        return False
    provenance.write_new_json(output / "control-observation.json", report)
    print(f"status=COMPLETED measurement={report['measurement_status']} authority=false actuation=false deadline=UNKNOWN")
    print_compact(report)
    return report["measurement_status"] == "CONTROL_OBSERVED"


def print_compact(report):
    print(f"control_observation={report['control_observation']} distinct_joint_pairs={report['distinct_joint_agreement_witnesses']} promotion=false")
    for domain in report["domains"]:
        local = domain["strict_activation_episodes"]
        print(f"{domain['cid']}: coverage={domain['full_sidecar_reference_coverage']} episodes={local['actual_episodes']} activations={local['total_activations']} unmatched={local['unmatched_activations']} censored={local['censored_activations']} joint_pairs={domain['observed_joint_pair_witnesses']} unsupported_pairs={domain['unsupported_joint_pair_witnesses']} censored_pairs={domain['censored_joint_pair_witnesses']} outside_pairs={domain['outside_reference_joint_pair_witnesses']}")
        print(f"  observation={domain['control_observation']} unseen_samples={domain['native_samples_not_seen_by_sidecar']} outside_activations={len(domain['local_activations_outside_reference'])}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    frozen = sub.add_parser("freeze")
    frozen.add_argument("--source-config", type=Path, required=True)
    frozen.add_argument("--idle-run", type=Path, required=True)
    frozen.add_argument("--profile", choices=PROFILES, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    for name in ("preflight", "run", "_collect", "evaluate"):
        command = sub.add_parser(name)
        command.add_argument("--protocol", type=Path, required=True)
        if name in ("run", "_collect"):
            command.add_argument("--allow-lab-traffic", action="store_true")
        if name == "run":
            command.add_argument("--allow-shadow-publication", action="store_true")
        if name == "evaluate":
            command.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            p = freeze(args.source_config, args.idle_run, args.output, args.profile)
            print(f"protocol={args.output / 'protocol.json'} profile={p['case']['profile']} traffic_s={p['case']['duration_s']} shadow_s={p['shadow_duration_s']} source_v4={p['source_criteria_status']}")
        elif args.command == "preflight":
            preflight(args.protocol)
            print(f"preflight=READY domains=2 hosts=2 switches=4 profile={load_protocol(args.protocol)['case']['profile']} authority=false actuation=false")
        elif args.command == "_collect":
            collect(args.protocol, args.allow_lab_traffic)
        elif args.command == "evaluate":
            root = args.protocol.resolve().parent
            receipt = read_json(root / "pilot" / "pilot-run.json")
            if receipt != provenance.seal(receipt, "run_sha256"):
                raise ValueError("checksum do recibo do piloto inválido")
            destination = args.output.absolute()
            if (destination.is_symlink() or destination.parent.resolve() != root / "pilot"
                    or destination.suffix != ".json" or destination.name in {"pilot-run.json", "timing-error.json"}
                    or destination.exists()):
                raise ValueError("use novo JSON dentro de pilot; não sobrescreva fontes/resultados")
            report = evaluate(args.protocol, receipt)
            provenance.write_new_json(destination, report)
            print_compact(report)
            return 0 if report["measurement_status"] == "CONTROL_OBSERVED" else 3
        else:
            return 0 if run(args.protocol, args.allow_lab_traffic, args.allow_shadow_publication) else 2
    except (KeyboardInterrupt, OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
