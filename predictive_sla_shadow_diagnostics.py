#!/usr/bin/env python3
"""Instrument frozen atomic shadow v2 in a new, opt-in diagnostic pilot.

No earlier source/config/result is edited. Calls use the unchanged v1 HTTP
client and timeout; tracing cannot turn an unacknowledged write into success.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import io
import json
import multiprocessing
import os
import re
import sys
import time
import urllib.error
import uuid
from pathlib import Path

import predictive_sla_shadow as legacy
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_shadow_v2 as atomic
import predictive_sla_validation as provenance
from qos_damped_holt import QosDampedHoltModel


CONFIG_SCHEMA = "comas-predictive-sla-shadow-diagnostics-config/1"
SUMMARY_SCHEMA = "comas-predictive-sla-shadow-diagnostics/1"
TRACE_SCHEMA = "comas-shadow-request-trace/1"
ROOT = Path(__file__).resolve().parent
CODE_FILES = (*atomic.CODE_FILES, "predictive_sla_shadow_diagnostics.py")
DIAGNOSTICS = dict(
    version=1, request_timeout_s=protocol.TIMING["request_timeout_s"],
    timeout_scope="unchanged_urllib_socket_io_timeout_not_total_deadline",
    request_policy="one_forwarded_call_no_retry",
    write_error_policy="commit_unknown_unless_rejected_locally_before_request",
    recorded_stages=["request_start", "http_json_received_or_error", "store_validation"],
    duration_clock="process_local_monotonic_ns",
    payload_logging="sha256_and_byte_count_only",
    incomplete_request_policy="interrupted_elapsed_unknown",
)
LIMITATIONS = [*atomic.LIMITATIONS,
    "Instrumentation adds client-side journal overhead; durations are not isolated ETCD server timings.",
    "Socket timeout is unchanged and is not an end-to-end deadline guarantee.",
    "A received JSON response is not a validated transaction acknowledgement.",
    "HTTP durations and whole store-operation durations overlap and must not be added.",
    "Traces locate the failing operation, not the root cause in CPU, disk, network or ETCD consensus.",
    "A stopped peer may have committed writes; a missing summary is not a zero-publication result.",
]
# Preserve the frozen implementations; rebinding below is process-local and
# restored before spawning workers or returning to a caller.
BASE_STORE, BASE_WORKER, BASE_PREFLIGHT = atomic.AtomicShadowStore, atomic.worker, atomic.preflight
_BINDING_ACTIVE = False


def code_snapshot():
    return {name: provenance.digest_file(ROOT / name) for name in CODE_FILES}


def freeze(source, output):
    if source.absolute().is_symlink() or output.absolute().is_symlink():
        raise ValueError("fontes/saídas não podem ser links simbólicos")
    source, output = source.resolve(), output.resolve()
    if (output.exists() or output.parent != source.parent.parent
            or not output.name.startswith("qos-online-shadow-v2-diagnostics")):
        raise ValueError("use novo diretório irmão qos-online-shadow-v2-diagnostics*; preserve a v2")
    original = atomic.load_config(source)
    artifacts, code = atomic.previous_artifacts(source), code_snapshot()
    fields = ("source_protocol", "source_criteria_status", "model", "policy", "subjects", "shared_subject",
              "timing", "boundary", "publication", "etcd_url", "protected_source_sha256")
    config = provenance.seal(dict(
        **{key: original[key] for key in fields}, schema_version=CONFIG_SCHEMA, created_ns=time.time_ns(),
        source_shadow_config=str(source), source_v2_artifacts_sha256=artifacts,
        code_sha256=code, diagnostics=DIAGNOSTICS, limitations=LIMITATIONS), "config_sha256")
    model_bytes = (source.parent / "model.json").read_bytes()
    if (atomic.load_config(source) != original or atomic.previous_artifacts(source) != artifacts
            or code_snapshot() != code):
        raise ValueError("fontes/código mudaram durante o congelamento diagnóstico")
    output.mkdir()
    with (output / "model.json").open("xb") as handle:
        handle.write(model_bytes)
    provenance.write_new_json(output / "shadow-config.json", config)
    load_config(output / "shadow-config.json")
    return config


def load_config(path):
    if path.absolute().is_symlink():
        raise ValueError("config não pode ser link simbólico")
    path = path.resolve()
    config = legacy.read_sealed(path, CONFIG_SCHEMA, "config_sha256")
    source = Path(config["source_shadow_config"])
    if (path.name != "shadow-config.json" or path.parent == source.resolve().parent
            or path.parent.parent != source.resolve().parent.parent
            or not path.parent.name.startswith("qos-online-shadow-v2-diagnostics")):
        raise ValueError("config fora do novo diretório diagnóstico")
    original = atomic.load_config(source)
    fields = ("source_protocol", "source_criteria_status", "model", "policy", "subjects", "shared_subject",
              "timing", "boundary", "publication", "etcd_url", "protected_source_sha256")
    expected = dict(**{key: original[key] for key in fields}, diagnostics=DIAGNOSTICS,
                    code_sha256=code_snapshot(), limitations=LIMITATIONS)
    if any(config.get(key) != value for key, value in expected.items()):
        raise ValueError("config/fontes/código diferem do congelamento diagnóstico")
    artifacts = config["source_v2_artifacts_sha256"]
    required = {str(source.resolve()), str(source.resolve().parent / "model.json")}
    if not isinstance(artifacts, dict) or not required <= artifacts.keys():
        raise ValueError("proveniência dos artefatos v2 ausente")
    for name, expected_hash in artifacts.items():
        artifact = Path(name)
        if (artifact.is_symlink() or source.resolve().parent not in artifact.resolve().parents
                or provenance.digest_file(artifact) != expected_hash):
            raise ValueError(f"artefato v2 protegido mudou: {name}")
    model = path.parent / "model.json"
    if (model.is_symlink() or provenance.digest_file(model) != config["model"]["sha256"]
            or QosDampedHoltModel.load(model).resolved_model_id() != config["model"]["model_id"]):
        raise ValueError("modelo diagnóstico mudou")
    return config


def is_timeout(exc):
    return isinstance(exc, TimeoutError) or (
        isinstance(exc, urllib.error.URLError) and isinstance(exc.reason, TimeoutError))


class RequestTrace:
    """Record one unchanged HTTP invocation; never retry or log body contents."""

    def __init__(self, config, role, handle, allow_writes=False, request=None):
        self.config, self.role, self.handle = config, role, handle
        self.allow_writes = allow_writes
        self.request = legacy.http_json if request is None else request
        self.sequence, self.last_request = 0, None

    def describe(self, url, payload):
        for subject in self.config["subjects"]:
            for suffix, operation in (("/predictor/status", "telemetry_status_read"),
                                      ("/predictor/qos", "telemetry_qos_read")):
                if url == subject["url"] + suffix and payload is None:
                    return operation, False
        if url == self.config["etcd_url"] + "/v3/kv/range" and isinstance(payload, dict):
            prefix = base64.b64decode(payload["key"], validate=True).decode("ascii")
            limit = base64.b64decode(payload["range_end"], validate=True).decode("ascii")
            if (set(payload) != {"key", "range_end", "serializable"} or payload["serializable"] is not False
                    or not re.fullmatch(r"/comas/experimental/predictive-sla-shadow-v2/[0-9a-f]{32}/", prefix)
                    or limit != prefix[:-1] + "0"):
                raise ValueError("leitura fora do snapshot shadow v2")
            return "etcd_snapshot_read", False
        if url == self.config["etcd_url"] + "/v3/kv/txn" and isinstance(payload, dict):
            if not self.allow_writes:
                raise ValueError("fase de diagnóstico somente leitura não permite transação")
            puts = payload.get("success", [])
            if (payload.get("failure", []) or set(payload) - {"compare", "success", "failure"}
                    or not isinstance(puts, list)
                    or any(set(item) != {"request_put"} or set(item["request_put"]) != {"key", "value"}
                           for item in puts)):
                raise ValueError("operações inesperadas na transação diagnóstica")
            keys = [base64.b64decode(item["request_put"]["key"], validate=True).decode("ascii")
                    for item in puts]
            pattern = r"/comas/experimental/predictive-sla-shadow-v2/([0-9a-f]{32})/(.+)"
            matches = [re.fullmatch(pattern, key) for key in keys]
            if not matches or not all(matches) or len({m[1] for m in matches}) != 1:
                raise ValueError("transação fora do namespace shadow v2")
            suffixes = [match[2] for match in matches]
            expected = [dict(target="VERSION", result="EQUAL", key=puts[0]["request_put"]["key"], version="0")]
            if len(puts) == 1 and suffixes == ["manifest"] and payload.get("compare") == expected:
                return "etcd_namespace_reserve", True
            for subject in self.config["subjects"]:
                if (payload.get("compare") == []
                        and suffixes == ["risks/" + subject["cid"], "proposals/" + subject["cid"]]):
                    return "etcd_pair_transaction", True
        raise ValueError("endpoint/operação fora do piloto diagnóstico")

    def emit(self, row):
        legacy.journal(self.handle, dict(schema_version=TRACE_SCHEMA, role=self.role, pid=os.getpid(), **row))

    def __call__(self, url, payload=None):
        self.sequence += 1
        self.last_request = None
        request_id = f"{self.role}:{self.sequence}"
        method = "GET" if payload is None else "POST"
        try:
            operation, writing = self.describe(url, payload)
            body = b"" if payload is None else protocol.encoded(payload)
        except Exception as exc:
            self.emit(dict(kind="REQUEST_REJECTED_LOCALLY", request_id=request_id, endpoint=url,
                           method=method, error=str(exc), error_type=type(exc).__name__,
                           request_sent=False, commit_outcome="NOT_SENT", elapsed_ms=None))
            raise
        info = dict(request_id=request_id, operation=operation, endpoint=url, method=method,
                    configured_timeout_s=DIAGNOSTICS["request_timeout_s"],
                    request_bytes=len(body), payload_sha256=None if payload is None else protocol.digest(payload),
                    started_ns=time.time_ns(), writing=writing)
        self.last_request = info
        self.emit(dict(kind="REQUEST_STARTED", **info,
                       commit_outcome="UNKNOWN" if writing else "NOT_APPLICABLE"))
        started = time.monotonic_ns()
        try:
            result = self.request(url, payload)
        except Exception as exc:
            elapsed = (time.monotonic_ns() - started) / 1e6
            status = "TIMEOUT" if is_timeout(exc) else "REQUEST_ERROR"
            if isinstance(exc, urllib.error.HTTPError):
                status = "HTTP_ERROR"
            elif isinstance(exc, (ValueError, json.JSONDecodeError)):
                status = "RESPONSE_ERROR"
            end = dict(kind="REQUEST_FINISHED", **info, finished_ns=time.time_ns(), elapsed_ms=elapsed,
                       status=status, error=str(exc), error_type=type(exc).__name__,
                       http_status=exc.code if isinstance(exc, urllib.error.HTTPError) else None,
                       commit_outcome="UNKNOWN" if writing else "NOT_APPLICABLE", retry_attempted=False)
            self.last_request = end
            self.emit(end)
            raise
        elapsed = (time.monotonic_ns() - started) / 1e6
        end = dict(kind="REQUEST_FINISHED", **info, finished_ns=time.time_ns(), elapsed_ms=elapsed,
                   status="HTTP_JSON_RECEIVED", error=None, error_type=None,
                   commit_outcome="UNKNOWN" if writing else "NOT_APPLICABLE", retry_attempted=False)
        self.last_request = end
        self.emit(end)
        return result


class DiagnosticStore(BASE_STORE):
    """Keep v2 metadata/ack checks; report validation separately from HTTP."""

    def __init__(self, url, run_id, trace):
        if not isinstance(trace, RequestTrace):
            raise ValueError("store diagnóstico exige o registrador de requisições")
        super().__init__(url, run_id, trace)

    def _validated(self, operation, callback):
        sequence = self.request.sequence
        started = time.monotonic_ns()
        try:
            result = callback()
        except Exception as exc:
            elapsed = (time.monotonic_ns() - started) / 1e6
            forwarded = self.request.sequence > sequence and self.request.last_request is not None
            info = self.request.last_request if forwarded else {}
            received = info.get("status") == "HTTP_JSON_RECEIVED"
            writing = operation != "etcd_snapshot_read"
            self.request.emit(dict(kind="STORE_OPERATION_FINISHED", operation=operation,
                request_id=info.get("request_id"), endpoint=self.url + ("/v3/kv/txn" if writing else "/v3/kv/range"),
                finished_ns=time.time_ns(), elapsed_ms=elapsed,
                status="VALIDATION_REJECTED" if received else "REQUEST_FAILED" if forwarded else "REJECTED_LOCALLY",
                error=str(exc), error_type=type(exc).__name__,
                commit_outcome=("UNKNOWN" if forwarded else "NOT_SENT") if writing else "NOT_APPLICABLE"))
            raise
        elapsed = (time.monotonic_ns() - started) / 1e6
        info = self.request.last_request
        writing = operation != "etcd_snapshot_read"
        row = dict(kind="STORE_OPERATION_FINISHED", operation=operation, request_id=info["request_id"],
                   endpoint=info["endpoint"], finished_ns=time.time_ns(), elapsed_ms=elapsed,
                   status="ACK_VALIDATED" if writing else "SNAPSHOT_VALIDATED", error=None,
                   commit_outcome="CONFIRMED" if writing else "NOT_APPLICABLE")
        if operation == "etcd_pair_transaction":
            row.update(pair_mod_revision=result["revision"], pair_publication_ack_ns=result["pair_publication_ack_ns"])
        elif operation == "etcd_namespace_reserve":
            row["namespace_revision"] = result
        self.request.emit(row)
        return result

    def read(self):
        return self._validated("etcd_snapshot_read", super().read)

    def reserve(self, manifest):
        return self._validated("etcd_namespace_reserve", lambda: super(DiagnosticStore, self).reserve(manifest))

    def put_pair(self, cid, risk, item):
        return self._validated("etcd_pair_transaction", lambda: super(DiagnosticStore, self).put_pair(cid, risk, item))


@contextlib.contextmanager
def transport_bindings(trace):
    """Adapt only HTTP/store construction in this CLI/child process, then restore."""
    global _BINDING_ACTIVE
    if _BINDING_ACTIVE:
        raise ValueError("instrumentação de transporte não pode ser aninhada")
    before = atomic.http_json, atomic.AtomicShadowStore
    _BINDING_ACTIVE = True
    atomic.http_json = trace
    atomic.AtomicShadowStore = lambda url, run_id: DiagnosticStore(url, run_id, trace)
    try:
        yield
    finally:
        atomic.http_json, atomic.AtomicShadowStore = before
        _BINDING_ACTIVE = False


def preflight(config, trace=None):
    trace = RequestTrace(config, "preflight", io.StringIO()) if trace is None else trace
    with transport_bindings(trace):
        return BASE_PREFLIGHT(config)


def worker(config, model_path, run_id, subject, output, duration_s):
    path = Path(output) / f"{subject['cid']}-transport.ndjson"
    with path.open("x", encoding="utf-8") as handle:
        trace = RequestTrace(config, subject["cid"], handle, allow_writes=True)
        with transport_bindings(trace):
            BASE_WORKER(config, model_path, run_id, subject, output, duration_s)


def trace_summary(rows):
    """Use paired start/end IDs; interrupted durations remain null, not zero."""
    started = {row["request_id"]: row for row in rows if row["kind"] == "REQUEST_STARTED"}
    finished = {row["request_id"]: row for row in rows if row["kind"] == "REQUEST_FINISHED"}
    groups, failures, interrupted = {}, [], []
    for request_id, beginning in started.items():
        key = beginning["operation"] + " " + beginning["endpoint"]
        group = groups.setdefault(key, dict(operation=beginning["operation"], endpoint=beginning["endpoint"],
            started=0, http_json_received=0, timeouts=0, errors=0, interrupted=0,
            received_elapsed_ms=[], failed_elapsed_ms=[]))
        group["started"] += 1
        end = finished.get(request_id)
        if end is None:
            group["interrupted"] += 1
            interrupted.append(dict(request_id=request_id, operation=beginning["operation"],
                endpoint=beginning["endpoint"], started_ns=beginning["started_ns"], elapsed_ms=None,
                commit_outcome="UNKNOWN" if beginning["writing"] else "NOT_APPLICABLE"))
        elif end["status"] == "HTTP_JSON_RECEIVED":
            group["http_json_received"] += 1
            group["received_elapsed_ms"].append(end["elapsed_ms"])
        else:
            group["timeouts" if end["status"] == "TIMEOUT" else "errors"] += 1
            group["failed_elapsed_ms"].append(end["elapsed_ms"])
            failures.append(end)
    for group in groups.values():
        for key in ("received_elapsed_ms", "failed_elapsed_ms"):
            values = group[key]
            group[key] = dict(count=len(values), minimum=min(values) if values else None,
                             maximum=max(values) if values else None,
                             mean=sum(values) / len(values) if values else None)
    stores = [row for row in rows if row["kind"] == "STORE_OPERATION_FINISHED"]
    store_failures = [row for row in stores if row["status"] not in ("ACK_VALIDATED", "SNAPSHOT_VALIDATED")]
    validated = {row["request_id"] for row in stores if row["status"] == "ACK_VALIDATED"}
    unconfirmed = [dict(request_id=row["request_id"], operation=row["operation"], endpoint=row["endpoint"],
                        commit_outcome="UNKNOWN", retry_attempted=False)
                   for row in started.values() if row["writing"] and row["request_id"] not in validated]
    return dict(requests_started=len(started), requests_finished=len(finished),
                confirmed_pair_acks=sum(row["operation"] == "etcd_pair_transaction" and row["status"] == "ACK_VALIDATED"
                                        for row in stores),
                groups=list(groups.values()), request_failures=failures,
                store_failures=store_failures, interrupted_requests=interrupted, unconfirmed_writes=unconfirmed,
                locally_rejected=[row for row in rows if row["kind"] == "REQUEST_REJECTED_LOCALLY"])


def read_trace(path):
    if not path.exists():
        return None
    rows, partial = [], False
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            # A killed process can leave the final line incomplete. Keep prior
            # complete evidence, but do not manufacture a finish record.
            if not line.endswith("\n"):
                partial = True
                break
            rows.append(json.loads(line))
    return dict(trace_summary(rows), partial_final_line=partial)


def trace_complete(summary):
    return (summary is not None and summary["requests_started"] > 0
            and summary["requests_started"] == summary["requests_finished"]
            and not summary["request_failures"] and not summary["store_failures"]
            and not summary["locally_rejected"] and not summary["unconfirmed_writes"]
            and not summary["partial_final_line"])


def run(config_path, duration_s, allow_publication):
    if allow_publication is not True:
        raise ValueError("run exige --allow-shadow-publication; não há escrita automática")
    if not 10 <= duration_s <= 3600:
        raise ValueError("duration-s deve estar entre 10 e 3600")
    config = load_config(config_path)
    config_path = config_path.resolve()
    run_id = uuid.uuid4().hex
    output = config_path.parent / "runs" / run_id
    if output.parent.is_symlink():
        raise ValueError("diretório runs não pode ser link simbólico")
    output.mkdir(parents=True, exist_ok=False)
    print(f"shadow_run={output}", flush=True)
    manifest = dict(schema_version=SUMMARY_SCHEMA, run_id=run_id, config_sha256=config["config_sha256"],
        source_shadow_config=config["source_shadow_config"], duration_s=duration_s, started_ns=time.time_ns(),
        host=os.uname().nodename, diagnostics=DIAGNOSTICS, publication=protocol.PUBLICATION,
        boundary=protocol.BOUNDARY, limitations=LIMITATIONS)
    provenance.write_new_json(output / "manifest.json", manifest)
    processes, phase, error = [], "preflight", None
    try:
        with (output / "preflight-transport.ndjson").open("x", encoding="utf-8") as handle:
            preflight(config, RequestTrace(config, "preflight", handle))
        phase = "namespace_reservation"
        with (output / "launcher-transport.ndjson").open("x", encoding="utf-8") as handle:
            store = DiagnosticStore(config["etcd_url"], run_id,
                                    RequestTrace(config, "launcher", handle, allow_writes=True))
            store.reserve(manifest)
        phase = "workers"
        context = multiprocessing.get_context("spawn")
        for subject in config["subjects"]:
            process = context.Process(target=worker, args=(config, str(config_path.parent / "model.json"),
                                     run_id, subject, str(output), duration_s))
            processes.append(process)
            process.start()
        while any(process.is_alive() for process in processes):
            if any(process.exitcode not in (None, 0) for process in processes):
                break
            time.sleep(.25)
        if all(process.exitcode == 0 for process in processes):
            phase = None
    except (Exception, KeyboardInterrupt) as exc:
        error = str(exc) or type(exc).__name__
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()  # Only this launcher's own children.
            if process.pid is not None:
                process.join(timeout=3)
    changed = []
    try:
        load_config(config_path)
    except (ValueError, OSError, KeyError, TypeError) as exc:
        changed.append(str(exc))
    reports, transports = [], {}
    for index, subject in enumerate(config["subjects"]):
        cid = subject["cid"]
        path = output / f"{cid}-summary.json"
        if path.exists():
            report = json.loads(path.read_text())
            report["summary_available"] = True
        else:
            exitcode = processes[index].exitcode if index < len(processes) else None
            report = dict(cid=cid, status="INTERRUPTED" if index < len(processes) else "NOT_STARTED",
                          error=f"worker exit={exitcode}" if index < len(processes) else None,
                          summary_available=False)
        reports.append(report)
        transports[cid] = read_trace(output / f"{cid}-transport.ndjson")
    for role in ("preflight", "launcher"):
        transports[role] = read_trace(output / f"{role}-transport.ndjson")
    traces_complete = all(trace_complete(trace) for trace in transports.values()) and all(
        report.get("counters", {}).get("confirmed_publications") ==
        (transports[report["cid"]]["confirmed_pair_acks"] if transports[report["cid"]] is not None else None)
        for report in reports)
    if phase is None and not traces_complete:
        phase = "diagnostic_trace"
    complete = (phase is None and error is None and not changed and traces_complete
                and all(r["status"] == "COMPLETED" for r in reports))
    summary = dict(schema_version=SUMMARY_SCHEMA, status="COMPLETED" if complete else "STOPPED_ERROR",
        run_id=run_id, failed_stage=phase, error=error, source_criteria_status=config["source_criteria_status"],
        originals_unchanged=not changed, source_errors=changed, domain_reports=reports,
        transport_summary=transports, diagnostic_traces_complete=traces_complete,
        diagnostics=DIAGNOSTICS, publication=protocol.PUBLICATION,
        boundary=protocol.BOUNDARY, deadline_feasibility="UNKNOWN", sla_protection_established=False,
        artifacts_sha256={p.name: provenance.digest_file(p) for p in output.iterdir() if p.is_file()},
        limitations=LIMITATIONS)
    provenance.write_new_json(output / "shadow-summary.json", summary)
    print(f"status={summary['status']} domains=2 diagnostics=true authority=false actuation=false deadline=UNKNOWN")
    for report in reports:
        if report.get("error"):
            print(f"{report['cid']}: {report['status']} error={report['error']}")
    for role, trace in transports.items():
        if trace is not None:
            for failure in trace["request_failures"]:
                print(f"{role}: {failure['operation']} {failure['status']} endpoint={failure['endpoint']} elapsed_ms={failure['elapsed_ms']:.3f} commit={failure['commit_outcome']}")
    return complete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    frozen = sub.add_parser("freeze")
    frozen.add_argument("--source-config", type=Path, required=True)
    frozen.add_argument("--output", type=Path, required=True)
    for name in ("preflight", "run"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "run":
            command.add_argument("--duration-s", type=int, default=60)
            command.add_argument("--allow-shadow-publication", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            config = freeze(args.source_config, args.output)
            print(f"config={args.output / 'shadow-config.json'} diagnostics=1 timeout_s={DIAGNOSTICS['request_timeout_s']} source_v4={config['source_criteria_status']}")
        elif args.command == "preflight":
            trace = RequestTrace(load_config(args.config), "preflight", io.StringIO())
            try:
                preflight(trace.config, trace)
            except Exception:
                failure = trace.last_request
                if failure is not None and failure.get("kind") == "REQUEST_FINISHED":
                    print(f"preflight: {failure['operation']} {failure['status']} endpoint={failure['endpoint']} elapsed_ms={failure['elapsed_ms']:.3f}", file=sys.stderr)
                raise
            print("preflight=READY domains=2 diagnostics=true timeout_s=1 atomic_pairs=true shadow_only=true etcd_writes=0")
        else:
            return 0 if run(args.config, args.duration_s, args.allow_shadow_publication) else 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
