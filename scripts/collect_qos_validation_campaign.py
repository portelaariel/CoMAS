#!/usr/bin/env python3
"""Collect a frozen, laboratory-only QoS campaign on an existing Mininet.

Preflight is read-only. Collection requires --allow-lab-traffic, never calls
an actuator, and cleans up only its own process groups and tagged qdisc.
"""

from __future__ import annotations

import argparse
import csv
import fcntl
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any, Dict, List


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from predictive_sla_validation import (
    RUN_SCHEMA, digest_file, evaluate_campaign, load_protocol, seal, write_new_json,
)
from qos_telemetry import QosDatasetExporter


def command(arguments: List[str], *, allow_absent: bool = False) -> str:
    result = subprocess.run(arguments, capture_output=True, text=True, timeout=15)
    if result.returncode and not (allow_absent and result.returncode == 1):
        raise ValueError(f"comando falhou: {' '.join(arguments)}: {result.stderr.strip()}")
    return result.stdout.strip()


def host_command(pid: int, arguments: List[str]) -> str:
    return command(["sudo", "-n", "mnexec", "-a", str(pid), *arguments])


def get_json(url: str) -> Dict[str, Any]:
    request = urllib.request.Request(url, headers={"Accept": "application/json"}, method="GET")
    with urllib.request.urlopen(request, timeout=3) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("resposta REST excedeu o limite")
    payload = json.loads(raw)
    if not isinstance(payload, dict):
        raise ValueError("resposta REST não é um objeto")
    return payload


def guard_status(payload: Dict[str, Any], subject: Dict[str, Any]) -> Dict[str, Any]:
    config, agent = payload.get("config", {}), payload.get("agentic", {})
    expected = dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                    agentic_live_actuation_opt_in=False, poll_interval_s=2,
                    qos_telemetry_enabled=True)
    if payload.get("cid") != subject["cid"]:
        raise ValueError("CoMAS respondeu com outro controlador")
    for name, value in expected.items():
        if name not in config or config[name] != value or (
            isinstance(value, bool) and config[name] is not value
        ):
            raise ValueError(f"configuração insegura/incompatível: {subject['cid']} {name}")
    if agent.get("actuation_enabled") is not False or agent.get("live_executions") != 0:
        raise ValueError("agente pode atuar ou já registrou execução live")
    return dict(cid=subject["cid"], checked_ns=time.time_ns(), config=expected,
                actuation_enabled=False, live_executions=0)


def latest_sample(payload: Dict[str, Any], subject: Dict[str, Any]) -> Dict[str, Any]:
    if payload.get("enabled") is not True:
        raise ValueError("telemetria QoS desativada")
    candidates = [row for row in payload.get("latest", []) if row.get("port_id") == subject["port_id"]]
    if len(candidates) != 1:
        raise ValueError(f"porta QoS ausente/duplicada: {subject['port_id']}")
    sample = candidates[0]
    if (set(sample) != set(QosDatasetExporter.HEADER)
            or sample.get("cid") != subject["cid"]
            or sample.get("capacity_bps") != subject["capacity_bps"]):
        raise ValueError("identidade, capacidade ou schema QoS incompatível")
    timestamp = sample["ts_ns"]
    if isinstance(timestamp, bool) or not isinstance(timestamp, int):
        raise ValueError("timestamp QoS inválido")
    age = time.time_ns() - timestamp
    if not -1_000_000_000 <= age <= 6_000_000_000:
        raise ValueError("telemetria QoS antiga ou relógio incompatível")
    return sample


def check_flows(text: str, switch: str, incoming: int, outgoing: int) -> None:
    flows = []
    for line in text.splitlines():
        if "actions=" not in line:
            continue
        action = line.split("actions=", 1)[1].strip()
        if action in ("", "drop"):
            raise ValueError(f"{switch}: regra DROP presente; não será removida automaticamente")
        fields = dict(re.findall(r"(\w+)=([^,\s]+)", line))
        flows.append((fields, action))
    for source, destination, in_port, out_port in (
        ("10.0.0.1", "10.0.0.8", incoming, outgoing),
        ("10.0.0.8", "10.0.0.1", outgoing, incoming),
    ):
        matches = [row for row, action in flows
                   if row.get("cookie") == "0x51534c41" and row.get("priority") == "3100"
                   and row.get("nw_src") == source and row.get("nw_dst") == destination
                   and row.get("in_port") == str(in_port) and action == f"output:{out_port}"
                   and int(row.get("idle_timeout", "0")) == 0
                   and int(row.get("hard_timeout", "0")) == 0]
        if not matches:
            raise ValueError(f"{switch}: regra persistente de calibração ausente/incorreta")


def root_qdisc(pid: int) -> Dict[str, Any]:
    rows = json.loads(host_command(pid, ["tc", "-j", "qdisc", "show", "dev", "h1-eth0"]))
    roots = [row for row in rows if row.get("root") is True]
    if len(roots) != 1:
        raise ValueError("qdisc root ausente/ambíguo")
    return roots[0]


def namespace(pid: int) -> str:
    return command(["sudo", "-n", "readlink", f"/proc/{pid}/ns/net"])


def preflight(protocol: Dict[str, Any]) -> Dict[str, Any]:
    if sys.platform != "linux":
        raise ValueError("a coleta/preflight deve ser executada no servidor Linux")
    for binary in ("sudo", "mnexec", "ovs-ofctl", "tc", "iperf", "timeout", "pgrep", "ip", "ss", "readlink"):
        if shutil.which(binary) is None:
            raise ValueError(f"comando necessário não encontrado: {binary}")
    command(["sudo", "-n", "true"])
    hosts = {}
    for host, expected_ip in (("h1", "10.0.0.1"), ("h8", "10.0.0.8")):
        pids = command(["pgrep", "-f", f"[m]ininet:{host}$"], allow_absent=True).splitlines()
        if len(pids) != 1:
            raise ValueError(f"namespace {host} ausente ou ambíguo")
        pid = int(pids[0])
        addresses = json.loads(host_command(pid, ["ip", "-j", "address", "show", "dev", f"{host}-eth0"]))
        if not any(row.get("local") == expected_ip for entry in addresses for row in entry.get("addr_info", [])):
            raise ValueError(f"endereço/interface inesperado em {host}")
        hosts[host] = dict(pid=pid, namespace=namespace(pid))
    if hosts["h1"]["namespace"] == hosts["h8"]["namespace"]:
        raise ValueError("h1/h8 não possuem namespaces distintos")
    if root_qdisc(hosts["h1"]["pid"]).get("kind") != "noqueue":
        raise ValueError("h1 já possui shaping; a campanha não substituirá esse qdisc")
    for pid in command(["sudo", "-n", "pgrep", "-x", "iperf"], allow_absent=True).splitlines():
        identity = command(["sudo", "-n", "readlink", f"/proc/{int(pid)}/ns/net"], allow_absent=True)
        if identity in {row["namespace"] for row in hosts.values()}:
            raise ValueError(f"iperf já está ativo em h1/h8 (PID {pid}); não será encerrado")
    port = str(protocol["collection"]["udp_port"])
    if host_command(hosts["h8"]["pid"], ["ss", "-H", "-lun", f"sport = :{port}"]):
        raise ValueError("porta UDP reservada já está em uso")
    for switch, incoming, outgoing in (("s1", 1, 3), ("s2", 3, 4), ("s3", 3, 4), ("s4", 3, 2)):
        text = command(["sudo", "-n", "ovs-ofctl", "-O", "OpenFlow10", "dump-flows", switch])
        check_flows(text, switch, incoming, outgoing)
    safety = []
    for subject in protocol["subjects"]:
        safety.append(guard_status(get_json(subject["url"] + "/predictor/status"), subject))
        sample = latest_sample(get_json(subject["url"] + "/predictor/qos"), subject)
        if sample["quality"] != "VALID":
            raise ValueError("aguarde a telemetria QoS ficar VALID")
    return dict(status="READY", checked_ns=time.time_ns(), hosts=hosts, safety=safety)


def stop_owned_process(process: subprocess.Popen) -> None:
    for name in ("INT", "TERM", "KILL"):
        if process.poll() is not None:
            return
        # Each group is created with start_new_session=True by this collector.
        command(["sudo", "-n", "kill", f"-{name}", "--", f"-{process.pid}"], allow_absent=True)
        try:
            process.wait(timeout=3)
            return
        except subprocess.TimeoutExpired:
            continue
    raise ValueError("não foi possível encerrar o grupo de processos da coleta")


def collect_case(protocol: Dict[str, Any], case: Dict[str, Any], output: Path) -> Dict[str, Any]:
    output.mkdir(parents=True, exist_ok=False)
    record = dict(schema_version=RUN_SCHEMA, protocol_sha256=protocol["protocol_sha256"],
                  case_id=case["case_id"], status="FAILED", started_ns=time.time_ns(),
                  workload=[], sources=[], safety_observations=[], cleanup_errors=[])
    processes, handles, files, snapshot = [], [], [], None
    csv_handles = []
    owns_qdisc = False
    settings = protocol["collection"]
    primary_error = None
    try:
        snapshot = preflight(protocol)
        record["preflight"] = snapshot
        h1, h8 = snapshot["hosts"]["h1"]["pid"], snapshot["hosts"]["h8"]["pid"]
        handle = settings["qdisc_handle"]
        host_command(h1, ["tc", "qdisc", "add", "dev", "h1-eth0", "root",
                          "handle", handle, "htb", "default", "10"])
        owns_qdisc = True
        host_command(h1, ["tc", "class", "replace", "dev", "h1-eth0", "parent", handle,
                          "classid", handle + "10", "htb", "rate", "20mbit", "ceil", "20mbit",
                          "burst", "256k", "cburst", "256k"])
        for host_pid, name, arguments in (
            (h8, "server", ["timeout", "--signal=INT", str(case["duration_s"] + 90),
                            "iperf", "-s", "-u", "-p", str(settings["udp_port"]), "-i", "2"]),
            (h1, "client", ["iperf", "-c", "10.0.0.8", "-u", "-p", str(settings["udp_port"]),
                            "-b", f"{settings['offered_rate_mbit']}M", "-t", str(case["duration_s"] + 30), "-i", "2"]),
        ):
            if name == "client":
                time.sleep(1)
            log = (output / f"iperf-{name}.log").open("x", encoding="utf-8")
            handles.append(log)
            processes.append(subprocess.Popen(
                ["sudo", "-n", "mnexec", "-a", str(host_pid), *arguments],
                stdin=subprocess.DEVNULL, stdout=log, stderr=subprocess.STDOUT,
                start_new_session=True))
        record["owned_process_groups"] = [process.pid for process in processes]
        time.sleep(settings["warmup_s"])
        record["started_ns"] = time.time_ns()
        writers = []
        last_timestamps = [0] * len(protocol["subjects"])
        for index, _ in enumerate(protocol["subjects"]):
            path = output / f"port_utilization_domain{index}.csv"
            csv_handle = path.open("x", encoding="utf-8", newline="")
            handles.append(csv_handle)
            csv_handles.append(csv_handle)
            files.append(path)
            writer = csv.DictWriter(csv_handle, fieldnames=QosDatasetExporter.HEADER)
            writer.writeheader()
            writers.append(writer)
        next_poll = next_safety = time.monotonic()
        for ordinal, stage in enumerate(case["stages"], 1):
            host_command(h1, ["tc", "class", "change", "dev", "h1-eth0", "parent", handle,
                              "classid", handle + "10", "htb", "rate", f"{stage['rate_mbit']}mbit",
                              "ceil", f"{stage['rate_mbit']}mbit", "burst", "256k", "cburst", "256k"])
            started = time.time_ns()
            deadline = time.monotonic() + stage["duration_s"]
            print(f"{case['case_id']}: stage={ordinal}/{len(case['stages'])} rate={stage['rate_mbit']}M", flush=True)
            while time.monotonic() < deadline:
                now = time.monotonic()
                if any(process.poll() is not None for process in processes):
                    raise ValueError("iperf terminou antes do perfil; consulte os logs")
                if now >= next_safety:
                    for host in snapshot["hosts"].values():
                        if namespace(host["pid"]) != host["namespace"]:
                            raise ValueError("namespace mudou durante a coleta")
                    if root_qdisc(h1).get("handle") != handle:
                        raise ValueError("qdisc mudou durante a coleta")
                    for subject in protocol["subjects"]:
                        record["safety_observations"].append(
                            guard_status(get_json(subject["url"] + "/predictor/status"), subject))
                    next_safety = time.monotonic() + settings["safety_poll_s"]
                if now >= next_poll:
                    for index, subject in enumerate(protocol["subjects"]):
                        sample = latest_sample(get_json(subject["url"] + "/predictor/qos"), subject)
                        timestamp = sample["ts_ns"]
                        if timestamp < record["started_ns"]:
                            continue
                        if timestamp < last_timestamps[index]:
                            raise ValueError("timestamp QoS regrediu durante a coleta")
                        if timestamp > last_timestamps[index]:
                            writers[index].writerow(sample)
                            csv_handles[index].flush()
                            last_timestamps[index] = timestamp
                            if sample["quality"] != "VALID":
                                raise ValueError("falha de qualidade QoS registrada; caso interrompido")
                    next_poll = time.monotonic() + settings["api_poll_s"]
                time.sleep(min(0.1, max(0, deadline - time.monotonic())))
            record["workload"].append({**stage, "start_ns": started, "end_ns": time.time_ns()})
        record["status"] = "COMPLETED"
    except BaseException as exc:
        primary_error = exc
        record["error"] = str(exc) or type(exc).__name__
    finally:
        record["ended_ns"] = time.time_ns()
        for process in reversed(processes):
            try:
                stop_owned_process(process)
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                record["cleanup_errors"].append(str(exc))
        record["process_return_codes_after_cleanup"] = [process.poll() for process in processes]
        for file_handle in handles:
            file_handle.close()
        if owns_qdisc:
            try:
                pid = snapshot["hosts"]["h1"]["pid"]
                if namespace(pid) != snapshot["hosts"]["h1"]["namespace"]:
                    raise ValueError("namespace mudou; qdisc não será removido em outro host")
                if root_qdisc(pid).get("handle") != settings["qdisc_handle"]:
                    raise ValueError("qdisc mudou; não será removido automaticamente")
                host_command(pid, ["tc", "qdisc", "del", "dev", "h1-eth0", "root", "handle", settings["qdisc_handle"]])
            except (OSError, ValueError, subprocess.SubprocessError) as exc:
                record["cleanup_errors"].append(str(exc))
        record["sources"] = [{"cid": subject["cid"], "port_id": subject["port_id"],
                              "csv": path.name, "sha256": digest_file(path)}
                             for subject, path in zip(protocol["subjects"], files)]
        if record["cleanup_errors"]:
            record["status"] = "FAILED"
            primary_error = primary_error or ValueError("cleanup incompleto; não prossiga com outra execução")
        record = seal(record, "run_sha256")
        write_new_json(output / "run.json", record)
    if primary_error:
        raise primary_error
    return record


def interrupt_collection(*_: Any) -> None:
    raise KeyboardInterrupt("SIGTERM recebido")


def main(argv: List[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-lab-traffic", action="store_true")
    args = parser.parse_args(argv)
    try:
        protocol = load_protocol(args.protocol.resolve())
        if args.preflight_only:
            snapshot = preflight(protocol)
            print(f"preflight={snapshot['status']} domains={len(snapshot['safety'])} hosts=2 switches=4")
            return 0
        if not args.allow_lab_traffic or args.output is None:
            raise ValueError("a coleta exige --allow-lab-traffic e um novo --output")
        if sys.platform != "linux":
            raise ValueError("a coleta deve ocorrer no servidor Linux")
        with Path(f"/tmp/comas-qos-validation-{os.getuid()}.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            args.output.mkdir(parents=True, exist_ok=False)
            write_new_json(args.output / "campaign-plan.json", protocol)
            previous_term = signal.signal(signal.SIGTERM, interrupt_collection)
            try:
                for case in protocol["cases"]:
                    collect_case(protocol, case, args.output / case["case_id"])
                    print(f"{case['case_id']}: collected", flush=True)
                report = evaluate_campaign(args.protocol.resolve(), args.output.resolve())
                write_new_json(args.output / "campaign-summary.json", report)
                print(f"status={report['status']} runs={report['evaluated_runs']}/{report['planned_runs']}")
                return 0 if report["status"] == "COMPLETED" else 2
            finally:
                signal.signal(signal.SIGTERM, previous_term)
    except KeyboardInterrupt:
        print("coleta interrompida; artefatos parciais preservados", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
