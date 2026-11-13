#!/usr/bin/env python3
"""One unchanged slow-ramp pilot with separate, read-only Linux/ETCD monitoring.

Does not repair/restart containers or retry a failed pilot. The existing ramp
owns traffic, shadow publication and cleanup; this wrapper only launches it
with explicit permission. Monitoring failures remain missing data, never zeros.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import math
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import threading
import time
import urllib.request

import predictive_sla_shadow_ramp as ramp


CHECK_SHA = "0ef4c0ecb988c6858cd360d58e5e2d9e85a84577bb53fbc6f411d7fb0cd0391a"
RECOVERY_SHA = "e2d091826cc1decad011665ef8b7580941021b1edb3cf7c6faebdfbb556e558d"
HOST_INTERVAL_S = 1
METRICS_INTERVAL_S = 5
METRICS_SOCKET_TIMEOUT_S = 1
BASELINE_S = 10
POST_S = 5
MAX_BODY = 8 * 1024 * 1024
DISK_FAMILIES = ("etcd_disk_wal_fsync_duration_seconds", "etcd_disk_backend_commit_duration_seconds")
METRIC_PREFIXES = ("etcd_disk_", "etcd_server_", "etcd_network_peer_", "grpc_server_started_total",
                   "grpc_server_handled_total", "process_cpu_seconds_total", "process_resident_memory_bytes",
                   "process_start_time_seconds", "go_goroutines")
LIMITATIONS = [
    "Instrumented single attempt, not an acceptance test or a causal experiment.",
    "GET /metrics adds observation overhead; it does not write ETCD keys or use endpoint health.",
    "Host/cgroup samples are nominally 1 s; three sequential member scrapes nominally every 5 s.",
    "All observation gaps, failed scrapes and counter resets are retained, not imputed as zero.",
    "ETCD metrics include normal CoMAS traffic, not only the isolated shadow namespace.",
    "Disk histograms are cumulative. Interval means use adjacent successful scrape deltas, not lifetime P95.",
    "Host diskstats include multiple device layers; do not sum mapper/partition/physical counters.",
    "Host CPU includes steal/iowait; Linux iowait alone does not establish a disk bottleneck.",
    "Cgroup CPU throttling is not proof of host CPU starvation; PSI/host metrics are separate.",
    "The unchanged shadow 1 s socket timeout is not a total end-to-end deadline.",
    "No LLM, authority, actuation, promotion or guaranteed SLA protection is enabled.",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def pinned_module(name, path, expected):
    require(path.is_file() and not path.is_symlink() and digest(path) == expected,
            f"helper ausente ou SHA256 divergente: {path}")
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def read_json(path):
    require(path.is_file() and not path.is_symlink(), f"fonte ausente/symlink: {path}")
    return json.loads(path.read_text())


def number_pairs(text):
    return {line.split()[0]: int(line.split()[1]) for line in text.splitlines() if line.strip()}


def cgroup_path(pid, proc=Path("/proc"), root=Path("/sys/fs/cgroup")):
    require(type(pid) is int and pid > 0, "PID do container inválido")
    require((root / "cgroup.controllers").is_file(), "este observador exige cgroup v2; nenhuma migração será feita")
    lines = (proc / str(pid) / "cgroup").read_text().splitlines()
    paths = [line[3:] for line in lines if line.startswith("0::")]
    require(len(paths) == 1 and paths[0].startswith("/") and ".." not in Path(paths[0]).parts,
            "cgroup v2 ausente/ambíguo ou caminho inseguro")
    found = (root / paths[0].lstrip("/")).resolve()
    require(found != root.resolve() and root.resolve() in found.parents, "cgroup do container fora da árvore esperada")
    for filename in ("cgroup.procs", "cpu.stat", "cpu.max", "memory.current", "memory.events", "io.stat"):
        require((found / filename).is_file(), f"cgroup inacessível: {found / filename}")
    require(str(pid) in (found / "cgroup.procs").read_text().split(), "PID não pertence ao cgroup encontrado")
    return found


def host_sample(groups, proc=Path("/proc")):
    start = time.monotonic_ns()
    stat = (proc / "stat").read_text().splitlines()
    cpu = [int(value) for value in next(line for line in stat if line.startswith("cpu ")).split()[1:]]
    # guest and guest_nice are already included in user/nice; never double count them.
    require(len(cpu) >= 8, "campos CPU Linux incompletos")
    row = dict(time_ns=time.time_ns(), monotonic_ns=start, cpu_ticks=cpu[:8],
               loadavg=(proc / "loadavg").read_text().strip(),
               meminfo=(proc / "meminfo").read_text(), vmstat=number_pairs((proc / "vmstat").read_text()),
               diskstats=(proc / "diskstats").read_text(),
               pressure={kind: (proc / "pressure" / kind).read_text() for kind in ("cpu", "io", "memory")},
               containers={})
    for name, group in groups.items():
        row["containers"][name] = dict(cpu=number_pairs((group / "cpu.stat").read_text()),
            cpu_max=(group / "cpu.max").read_text().strip(),
            memory_bytes=int((group / "memory.current").read_text()),
            memory_events=number_pairs((group / "memory.events").read_text()),
            io_stat=(group / "io.stat").read_text())
    row["sampling_ms"] = (time.monotonic_ns() - start) / 1e6
    return row


def parse_metrics(body):
    found = {}
    for line in body.splitlines():
        if not line or line.startswith("#"):
            continue
        match = re.fullmatch(r'([a-zA-Z_:][a-zA-Z0-9_:]*)(\{.*\})?\s+([^\s]+)(?:\s+[0-9.]+)?', line)
        require(match is not None, "linha /metrics inválida")
        name, labels, value = match.groups()
        if not name.startswith(METRIC_PREFIXES):
            continue
        number = float(value)
        require(math.isfinite(number), f"métrica não finita: {name}")
        key = name + (labels or "")
        require(key not in found, f"série métrica duplicada: {key}")
        found[key] = number
    for family in DISK_FAMILIES:
        for suffix in ("_count", "_sum"):
            require(family + suffix in found, f"métrica ETCD obrigatória ausente: {family + suffix}")
    require("etcd_server_has_leader" in found, "métrica de liderança ETCD ausente")
    return found


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def scrape(url):
    require(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", url), "metrics deve usar endpoint loopback")
    require(0 < int(url.rsplit(":", 1)[1]) <= 65535, "porta inválida")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url + "/metrics", method="GET")
    with opener.open(request, timeout=METRICS_SOCKET_TIMEOUT_S) as response:
        require(response.status == 200, "HTTP /metrics diferente de 200")
        body = response.read(MAX_BODY + 1)
    require(len(body) <= MAX_BODY, "resposta /metrics excedeu limite")
    return parse_metrics(body.decode("utf-8"))


def metric_sample(name, url):
    start = time.monotonic_ns()
    row = dict(member=name, time_ns=time.time_ns(), monotonic_ns=start, status="SUCCESS")
    try:
        row["metrics"] = scrape(url)
    except Exception as exc:
        row.update(status="MISSING", error=f"{type(exc).__name__}: {exc}")
    row.update(ended_ns=time.time_ns(), elapsed_ms=(time.monotonic_ns() - start) / 1e6)
    return row


def metric_delta(before, after):
    if before is None or before["status"] != "SUCCESS" or after["status"] != "SUCCESS":
        return None
    a, b = before["metrics"], after["metrics"]
    elapsed = (after["monotonic_ns"] - before["monotonic_ns"]) / 1e9
    require(elapsed > 0, "intervalo de scrape não positivo")
    if a.get("process_start_time_seconds") != b.get("process_start_time_seconds"):
        return dict(status="PROCESS_RESTART_OR_IDENTITY_CHANGE", elapsed_s=elapsed)
    disk = {}
    for family in DISK_FAMILIES:
        count = b[family + "_count"] - a[family + "_count"]
        total = b[family + "_sum"] - a[family + "_sum"]
        if count < 0 or total < 0:
            return dict(status="COUNTER_RESET", elapsed_s=elapsed)
        disk[family] = dict(operations=count, total_seconds=total,
                           mean_ms=1000 * total / count if count else None)
    return dict(status="DELTA_OBSERVED", elapsed_s=elapsed, disk=disk)


class Monitor:
    def __init__(self, output, groups, urls):
        self.output, self.groups, self.urls = output, groups, urls
        self.stop = threading.Event()
        self.counts = {name: dict(success=0, missing=0) for name in ("host", *urls)}
        self.errors, self.threads = [], []

    def host_loop(self):
        try:
            with (self.output / "host.ndjson").open("x") as stream:
                while not self.stop.is_set():
                    start = time.monotonic()
                    try:
                        row = dict(status="SUCCESS", **host_sample(self.groups))
                        self.counts["host"]["success"] += 1
                    except Exception as exc:
                        row = dict(time_ns=time.time_ns(), status="MISSING", error=str(exc))
                        self.counts["host"]["missing"] += 1
                    stream.write(json.dumps(row, sort_keys=True) + "\n")
                    stream.flush()
                    self.stop.wait(max(0, HOST_INTERVAL_S - (time.monotonic() - start)))
        except Exception as exc:
            self.errors.append(f"host sampler: {exc}")

    def metrics_loop(self):
        previous = {}
        try:
            with (self.output / "etcd-metrics.ndjson").open("x") as stream:
                while not self.stop.is_set():
                    start = time.monotonic()
                    for name, url in self.urls.items():
                        if self.stop.is_set():
                            break
                        row = metric_sample(name, url)
                        row["interval_delta"] = metric_delta(previous.get(name), row)
                        previous[name] = row if row["status"] == "SUCCESS" else None
                        self.counts[name]["success" if row["status"] == "SUCCESS" else "missing"] += 1
                        stream.write(json.dumps(row, sort_keys=True) + "\n")
                        stream.flush()
                    self.stop.wait(max(0, METRICS_INTERVAL_S - (time.monotonic() - start)))
        except Exception as exc:
            self.errors.append(f"metrics sampler: {exc}")

    def start(self):
        for target in (self.host_loop, self.metrics_loop):
            thread = threading.Thread(target=target, daemon=True)
            self.threads.append(thread)
            thread.start()

    def finish(self):
        self.stop.set()
        for thread in self.threads:
            thread.join(timeout=10)
            if thread.is_alive():
                self.errors.append("sampler ainda ativo; instrumentação incompleta")


def runtime_state(check, helper, docker, receipt_path):
    receipt, plan = read_json(receipt_path), read_json(receipt_path.parent / "plan.json")
    require(receipt.get("status") == "RECOVERED" and not receipt.get("cleanup_errors")
            and receipt.get("original_containers_unchanged") is True
            and receipt.get("tool_sha256") == RECOVERY_SHA, "recuperação não confirmada")
    require(re.fullmatch(r"[0-9a-f]{32}", receipt["run_id"])
            and receipt["runtime"] == "comas-etcd2-recovered-" + receipt["run_id"][:12], "runtime inválido")
    identity, urls = check.containers(helper, docker, plan, receipt)
    rows = helper.inspect(docker, "etcd1", "etcd3", receipt["runtime"])
    groups = {}
    for name, row in rows.items():
        require(row["State"]["Running"] is True and row["State"].get("OOMKilled") is False,
                f"container indisponível/OOM: {name}")
        groups[name] = cgroup_path(row["State"]["Pid"])
    states = check.cluster_state(helper, docker, plan["state"]["cluster_id"],
                                 receipt["recovered_status"]["raftAppliedIndex"])
    return dict(identity=identity, urls=urls, cgroups={k: str(v) for k, v in groups.items()},
                status=states, runtime=receipt["runtime"]), groups


def validate_before(protocol_path, receipt, check, helper, docker):
    require(sys.platform == "linux", "observador disponível somente no servidor Linux")
    p = ramp.load_protocol(protocol_path)
    require(p["case"]["profile"] == "slow-ramp"
            and ramp.diagnostic.protocol.TIMING["request_timeout_s"] == 1
            and p["boundary"] == ramp.diagnostic.protocol.BOUNDARY, "perfil/timeout/fronteira mudou")
    require(not (protocol_path.parent / "pilot").exists() and not (protocol_path.parent / "runs").exists(),
            "protocolo já usado; preserve-o e congele novo diretório")
    ramp.preflight(protocol_path)
    state, groups = runtime_state(check, helper, docker, receipt)
    host_sample(groups)
    for name, url in state["urls"].items():
        metrics = scrape(url)
        require(metrics["etcd_server_has_leader"] == 1, f"{name}: sem líder")
    return p, state, groups


def stop_owned(process, timeout_s=240):
    if process is None or process.poll() is not None:
        return
    # Only the supervisor receives SIGINT. It must clean its own native collector
    # and independently-sessioned shadow workers; never kill their process tree.
    try:
        process.send_signal(signal.SIGINT)
    except ProcessLookupError:
        if process.poll() is not None:
            return
        raise
    process.wait(timeout=timeout_s)


def capture_logs(names, output, start_ns, end_ns):
    results = {}
    since, until = str(max(0, start_ns // 10**9 - 2)), str(end_ns // 10**9 + 2)
    for name in names:
        path = output / f"{name}.log"
        try:
            with path.open("x") as stream:
                command = (["sudo", "-n"] if os.geteuid() else []) + ["docker", "logs", "--timestamps",
                    "--since", since, "--until", until, name]
                result = subprocess.run(command, stdout=stream, stderr=subprocess.STDOUT, timeout=20)
            require(result.returncode == 0, f"docker logs exit={result.returncode}")
            results[name] = dict(status="CAPTURED", sha256=digest(path))
        except Exception as exc:
            results[name] = dict(status="MISSING", error=str(exc))
    return results


def interrupted(signum, frame):
    raise KeyboardInterrupt(f"sinal {signum}; solicitar limpeza ao próprio supervisor")


def run(args, check, helper):
    require(args.allow_lab_traffic is True and args.allow_shadow_publication is True,
            "run exige --allow-lab-traffic e --allow-shadow-publication")
    protocol_path = args.protocol.resolve()
    docker = helper.Docker()
    p, before, groups = validate_before(protocol_path, args.recovery_receipt, check, helper, docker)
    print("preflight=READY host=cgroup2 etcd_metrics=3 shadow_timeout_s=1 "
          "authority=false actuation=false llm=false", flush=True)
    output = protocol_path.parent / "instrumentation"
    require(not output.is_symlink(), "instrumentação não pode ser symlink")
    output.mkdir(mode=0o700, exist_ok=False)
    sources = (protocol_path, protocol_path.parent / "shadow-config.json", args.recovery_receipt,
               args.recovery_receipt.parent / "plan.json", args.recovery_tool, args.read_check_tool, Path(__file__))
    hashes = {str(path): digest(path) for path in sources}
    report = dict(schema_version="comas-shadow-instrumented-ramp/1", status="STOPPED_ERROR", error=None,
        started_ns=time.time_ns(), source_sha256=hashes, before=before,
        host=dict(uname=list(os.uname()), logical_cpus=os.cpu_count(),
                  clock_ticks_per_second=os.sysconf("SC_CLK_TCK"), page_bytes=os.sysconf("SC_PAGE_SIZE")),
        host_interval_s=HOST_INTERVAL_S, metrics_interval_s=METRICS_INTERVAL_S,
        metrics_socket_timeout_s=METRICS_SOCKET_TIMEOUT_S, baseline_s=BASELINE_S, post_s=POST_S,
        source_criteria_status=p["source_criteria_status"], boundary=p["boundary"],
        promotion_eligible=False, deadline="UNKNOWN", monitoring_etcd_writes_requested=0,
        container_changes_requested=0, limitations=LIMITATIONS, cleanup_errors=[])
    ramp.provenance.write_new_json(output / "observation-plan.json", report)
    monitor, process = Monitor(output, groups, before["urls"]), None
    old_handlers = {sig: signal.signal(sig, interrupted) for sig in (signal.SIGTERM, signal.SIGINT)}
    try:
        monitor.start()
        print(f"instrumentation={output} baseline_s={BASELINE_S} shadow_timeout_s=1", flush=True)
        time.sleep(BASELINE_S)
        require(not monitor.errors and all(count["success"] > 0 and not count["missing"]
                for count in monitor.counts.values()), "baseline de instrumentação incompleta; tráfego não iniciado")
        with (output / "launcher.log").open("x") as log:
            command = [sys.executable, str(ramp.ROOT / "predictive_sla_shadow_ramp.py"), "run",
                       "--protocol", str(protocol_path), "--allow-lab-traffic", "--allow-shadow-publication"]
            report["pilot_launched_ns"] = time.time_ns()
            process = subprocess.Popen(command, cwd=str(ramp.ROOT), stdin=subprocess.DEVNULL,
                                       stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            report["owned_supervisor_pid"] = process.pid
            deadline = time.monotonic() + p["shadow_duration_s"] + 270
            progress = time.monotonic() + 30
            while process.poll() is None:
                require(time.monotonic() < deadline, "supervisor ultrapassou janela limitada; solicitar limpeza")
                if time.monotonic() >= progress:
                    print("observation=RUNNING authority=false actuation=false llm=false", flush=True)
                    progress = time.monotonic() + 30
                time.sleep(.25)
            report["pilot_exit_code"] = process.returncode
            report["pilot_finished_ns"] = time.time_ns()
        time.sleep(POST_S)
    except (Exception, KeyboardInterrupt) as exc:
        report["error"] = str(exc) or type(exc).__name__
    finally:
        # Repeated Ctrl-C must not cut short native qdisc/process cleanup.
        for sig in old_handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            stop_owned(process)
        except Exception as exc:
            report["cleanup_errors"].append(str(exc))
        monitor.finish()
        report["ended_ns"] = time.time_ns()
        report["samples"], report["monitor_errors"] = monitor.counts, monitor.errors
        report["logs"] = capture_logs(groups, output, report["started_ns"], report["ended_ns"])
        try:
            after, _ = runtime_state(check, helper, docker, args.recovery_receipt)
            report["after"] = after
            require(after["identity"] == before["identity"] and after["cgroups"] == before["cgroups"],
                    "runtime/cgroup reiniciou ou mudou")
            require(all(digest(Path(path)) == sha for path, sha in hashes.items()), "fonte/código mudou")
            ramp.load_protocol(protocol_path)
            report["sources_and_runtimes_unchanged"] = True
        except Exception as exc:
            report["verification_error"] = str(exc)
        pilot_path = protocol_path.parent / "pilot" / "pilot-run.json"
        if pilot_path.is_file():
            pilot = read_json(pilot_path)
            report["pilot"] = {k: pilot.get(k) for k in ("status", "error", "shadow_run", "collector_exit_code",
                "shadow_exit_code", "cleanup_errors", "originals_unchanged")}
            report["pilot_receipt_sha256"] = digest(pilot_path)
        complete = (not report["error"] and not report["cleanup_errors"] and not monitor.errors
            and report.get("pilot_exit_code") == 0 and report.get("sources_and_runtimes_unchanged") is True
            and report.get("pilot", {}).get("status") == "COLLECTED"
            and not any(row["missing"] or row["success"] < 2 for row in monitor.counts.values())
            and all(row["status"] == "CAPTURED" for row in report["logs"].values()))
        report["status"] = "OBSERVED_COMPLETED" if complete else "REVIEW_REQUIRED"
        report["artifact_sha256"] = {path.name: digest(path) for path in output.iterdir() if path.is_file()}
        ramp.provenance.write_new_json(output / "instrumentation-summary.json",
                                     ramp.provenance.seal(report, "report_sha256"))
        for sig, handler in old_handlers.items():
            signal.signal(sig, handler)
    print(f"status={report['status']} pilot_exit={report.get('pilot_exit_code', 'UNKNOWN')} "
          "authority=false actuation=false llm=false deadline=UNKNOWN")
    for name, counts in monitor.counts.items():
        print(f"{name}: samples={counts['success']} missing={counts['missing']}")
    log = output / "launcher.log"
    if log.is_file():
        print("\n".join(log.read_text().splitlines()[-9:]))
    print(f"report={output / 'instrumentation-summary.json'}")
    if report["error"] or report.get("verification_error"):
        print(f"erro={report.get('verification_error') or report['error']}", file=sys.stderr)
    return 0 if complete else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("preflight", "run"))
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--recovery-receipt", type=Path, required=True)
    parser.add_argument("--recovery-tool", type=Path, required=True)
    parser.add_argument("--read-check-tool", type=Path, required=True)
    parser.add_argument("--allow-lab-traffic", action="store_true")
    parser.add_argument("--allow-shadow-publication", action="store_true")
    args = parser.parse_args(argv)
    try:
        check = pinned_module("pinned_read_check", args.read_check_tool, CHECK_SHA)
        helper = pinned_module("pinned_recovery", args.recovery_tool, RECOVERY_SHA)
        if args.command == "preflight":
            validate_before(args.protocol.resolve(), args.recovery_receipt, check, helper, helper.Docker())
            print("preflight=READY host=cgroup2 etcd_metrics=3 shadow_timeout_s=1 authority=false actuation=false llm=false")
            return 0
        return run(args, check, helper)
    except (Exception, KeyboardInterrupt) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
