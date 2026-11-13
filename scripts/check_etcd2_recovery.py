#!/usr/bin/env python3
"""Read-only, bounded HTTP observation after the pinned laboratory recovery.

No PUT, transaction, health probe, container start/stop or configuration change.
The existing recovery helper is imported only after its SHA256 is verified.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import importlib.util
import json
import math
from pathlib import Path
import re
import statistics
import sys
import tempfile
import time
import urllib.error
import urllib.request


RECOVERY_SHA256 = "e2d091826cc1decad011665ef8b7580941021b1edb3cf7c6faebdfbb556e558d"
KEY = "/comas/maintenance/etcd2-recovery-read-probe"
TIMEOUT_S = 1
LIMITATIONS = [
    "Short sequential client-side HTTP observation, not server-only latency or a stress test.",
    "Only one exact key is read; this does not reproduce shadow snapshot sizes or publication transactions.",
    "The 1 s urllib socket timeout is not a total end-to-end deadline.",
    "Percentiles describe successful samples only; failed samples are reported separately.",
    "No paired pre-recovery baseline or guarantee that historical timeouts were eliminated.",
    "No SLA promotion, preventive action, LLM call or change to frozen scientific results.",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read_json(path):
    require(path.is_file() and not path.is_symlink(), f"arquivo ausente/symlink: {path}")
    return json.loads(path.read_text())


def load_helper(path):
    require(path.is_file() and not path.is_symlink() and digest(path) == RECOVERY_SHA256,
            "helper de recuperação ausente ou SHA256 diferente da versão aplicada")
    spec = importlib.util.spec_from_file_location("pinned_etcd2_recovery", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def uint64(value):
    # The HTTP gateway encodes uint64 as decimal strings, unlike etcdctl JSON.
    require(type(value) is int or isinstance(value, str) and re.fullmatch(r"[0-9]+", value),
            "ID HTTP ausente/inválido (float/bool não permitido)")
    number = int(value)
    require(0 < number < 2**64, "ID HTTP fora de uint64")
    return number


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, msg, headers, newurl):
        return None


def read_key(url):
    require(re.fullmatch(r"http://127\.0\.0\.1:[0-9]{1,5}", url), "endpoint deve ser loopback HTTP")
    payload = dict(key=base64.b64encode(KEY.encode()).decode(), keys_only=True, serializable=False)
    request = urllib.request.Request(url + "/v3/kv/range", data=json.dumps(payload).encode(),
                                     headers={"Content-Type": "application/json"}, method="POST")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    with opener.open(request, timeout=TIMEOUT_S) as response:
        require(response.status == 200, "status HTTP diferente de 200")
        result = json.load(response)
    require(isinstance(result, dict) and "error" not in result, "resposta ETCD contém erro")
    return result


def validate_read(result, cluster_id, member_id):
    header = result.get("header", {})
    require(uint64(header.get("cluster_id")) == cluster_id, "leitura respondeu por outro cluster")
    require(uint64(header.get("member_id")) == member_id, "leitura respondeu por outro membro")
    require(uint64(header.get("raft_term")) > 0, "termo Raft ausente")
    # Empty ranges are successful reads too. No returned key/value is logged.
    revision = uint64(header.get("revision"))
    require(not any(row.get("value") not in (None, "") for row in result.get("kvs", [])),
            "keys_only retornou valor não vazio")
    return revision


def published_url(row):
    bindings = row["HostConfig"].get("PortBindings", {}).get("2379/tcp") or []
    ports = {item["HostPort"] for item in bindings if item.get("HostIp", "") in ("", "0.0.0.0", "127.0.0.1")}
    require(len(ports) == 1, "publicação IPv4 do endpoint cliente ausente/ambígua")
    port = next(iter(ports))
    require(re.fullmatch(r"[0-9]{1,5}", port) and 0 < int(port) <= 65535, "porta publicada inválida")
    return f"http://127.0.0.1:{port}"


def containers(helper, docker, plan, receipt):
    runtime = receipt["runtime"]
    rows = helper.inspect(docker, *helper.MEMBERS, runtime)
    helper.assert_originals(plan["saved"], rows)
    candidate = rows[runtime]
    require(candidate["State"]["Running"] is True, "runtime recuperado não está ativo")
    require(candidate["Image"] == plan["image"]
            and candidate["Config"].get("Labels", {}).get(helper.LABEL) == receipt["run_id"],
            "imagem/rótulo do runtime recuperado mudou")
    require(candidate["NetworkSettings"]["Networks"][helper.NETWORK]["IPAddress"] == helper.MEMBERS["etcd2"][1],
            "IP do membro recuperado mudou")
    urls = {name: published_url(candidate if name == "etcd2" else rows[name]) for name in helper.MEMBERS}
    require(len(set(urls.values())) == 3, "endpoints publicados não são distintos")
    # Record identifiers only, never environment variables or container secrets.
    identity = {name: {key: row[key] for key in ("Id", "Image", "RestartCount")}
                | dict(started_at=row["State"]["StartedAt"]) for name, row in rows.items()}
    return identity, urls


def cluster_state(helper, docker, cluster_id, floor):
    payload = helper.ctl(docker, "etcd1", "http://192.168.253.11:2379", "member", "list")
    require(helper.validate_members(payload) == cluster_id, "membership/cluster mudou")
    states = {}
    for name, (_, ip) in helper.MEMBERS.items():
        state = helper.endpoint_status(docker, "etcd1", ip)
        helper.validate_status(state, name, cluster_id)
        require(state["raftAppliedIndex"] >= floor, "applied index regrediu desde a recuperação")
        states[name] = state
    require(len({row["leader"] for row in states.values()}) == 1, "líderes observados divergentes")
    require(len({row["raftTerm"] for row in states.values()}) == 1, "termos observados divergentes")
    alarms = helper.ctl(docker, "etcd1", "http://192.168.253.11:2379", "alarm", "list")
    require(not alarms.get("alarms"), "ETCD reporta alarmes; preserve e investigue")
    return states


def latency_summary(rows):
    values = sorted(row["elapsed_ms"] for row in rows if row["status"] == "SUCCESS")
    return dict(samples=len(rows), successful=len(values), failed=len(rows) - len(values),
                timeouts=sum(row["status"] == "TIMEOUT" for row in rows),
                successful_over_1000ms=sum(value > 1000 for value in values),
                mean_ms=statistics.mean(values) if values else None,
                p95_successful_ms=values[math.ceil(0.95 * len(values)) - 1] if values else None,
                maximum_successful_ms=max(values) if values else None)


def measure(urls, members, cluster_id, samples, request=read_key):
    records = {name: [] for name in members}
    for index in range(samples):
        # Rotate order; no concurrency, no retry and at most three reads/round.
        order = list(members)
        order = order[index % len(order):] + order[:index % len(order)]
        for name in order:
            started = time.monotonic_ns()
            row = dict(sample=index + 1, started_ns=time.time_ns(), status="SUCCESS")
            try:
                row["revision"] = validate_read(request(urls[name]), cluster_id, int(members[name][0], 16))
            except Exception as exc:
                timeout = isinstance(exc, TimeoutError) or (isinstance(exc, urllib.error.URLError)
                                                            and isinstance(exc.reason, TimeoutError))
                row.update(status="TIMEOUT" if timeout else "ERROR", error=str(exc)[:400])
            row["elapsed_ms"] = (time.monotonic_ns() - started) / 1e6
            records[name].append(row)
        if index + 1 < samples:
            time.sleep(0.5)
    return records


def run(helper, docker, receipt_path, samples, request=read_key):
    receipt = read_json(receipt_path)
    plan_path = receipt_path.parent / "plan.json"
    plan = read_json(plan_path)
    require(receipt.get("status") == "RECOVERED" and receipt.get("original_containers_unchanged") is True
            and not receipt.get("cleanup_errors") and receipt.get("tool_sha256") == RECOVERY_SHA256,
            "recibo de recuperação não comprova sucesso da versão aplicada")
    require(re.fullmatch(r"[0-9a-f]{32}", receipt["run_id"])
            and receipt["runtime"] == "comas-etcd2-recovered-" + receipt["run_id"][:12], "runtime inesperado")
    source_hashes = {str(path): digest(path) for path in (receipt_path, plan_path)}
    output = Path(tempfile.mkdtemp(prefix="etcd-post-recovery-", dir=receipt_path.parent.parent))
    output.chmod(0o700)
    report = dict(schema_version="comas-etcd-post-recovery/1", status="STOPPED_ERROR", error=None,
                  source_sha256=source_hashes, tool_sha256=digest(Path(__file__)), limitations=LIMITATIONS,
                  request_timeout_s=TIMEOUT_S, timeout_scope="urllib_socket_io_not_total_deadline",
                  etcd_writes_requested=0, container_mutations_requested=0, samples_per_member=samples,
                  promotion_eligible=False, records={}, summary={}, originals_unchanged=None)
    before = None
    try:
        before, urls = containers(helper, docker, plan, receipt)
        report["urls"] = urls
        cluster_id = plan["state"]["cluster_id"]
        floor = receipt["recovered_status"]["raftAppliedIndex"]
        report["before"] = cluster_state(helper, docker, cluster_id, floor)
        report["records"] = measure(urls, helper.MEMBERS, cluster_id, samples, request)
        report["summary"] = {name: latency_summary(rows) for name, rows in report["records"].items()}
        report["after"] = cluster_state(helper, docker, cluster_id, floor)
        first, last = report["before"]["etcd1"], report["after"]["etcd1"]
        require((first["leader"], first["raftTerm"]) == (last["leader"], last["raftTerm"]),
                "líder/termo mudou durante a observação; nenhuma correção automática")
        report["status"] = ("OBSERVED_READS_OK" if all(row["failed"] == 0 for row in report["summary"].values())
                            else "OBSERVED_READ_FAILURES")
    except (Exception, KeyboardInterrupt) as exc:
        report.update(status="STOPPED_ERROR", error=str(exc) or "interrompido")
    finally:
        try:
            after, _ = containers(helper, docker, plan, receipt)
            report["originals_unchanged"] = True
            require(before is not None and before == after, "runtime reiniciou/mudou ou inventário inicial indisponível")
            require(all(digest(Path(path)) == sha for path, sha in source_hashes.items()), "recibo/plano mudou")
            report["runtime_unchanged"] = report["sources_unchanged"] = True
        except Exception as exc:
            report.update(status="STOPPED_ERROR", verification_error=str(exc))
        helper.new_json(output / "read-check.json", report)
    print(f"status={report['status']} etcd_writes_requested=0 container_changes_requested=0")
    for name, row in report["summary"].items():
        mean, p95, maximum = ("N/A" if row[key] is None else f"{row[key]:.3f}"
                              for key in ("mean_ms", "p95_successful_ms", "maximum_successful_ms"))
        print(f"{name}: reads={row['successful']}/{row['samples']} timeouts={row['timeouts']} "
              f"mean_ms={mean} p95_ms={p95} max_ms={maximum}")
    print(f"report={output / 'read-check.json'}")
    if report["error"] or report.get("verification_error"):
        print(f"erro={report.get('verification_error') or report['error']}", file=sys.stderr)
    return 0 if report["status"] == "OBSERVED_READS_OK" else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--recovery-tool", required=True, type=Path)
    parser.add_argument("--samples-per-member", type=int, default=20, choices=range(1, 61))
    args = parser.parse_args(argv)
    try:
        require(args.receipt.name == "recovery.json", "use o recovery.json original")
        require(args.receipt.absolute() == args.receipt.resolve(), "caminho de recibo contém symlink")
        helper = load_helper(args.recovery_tool)
        return run(helper, helper.Docker(), args.receipt.resolve(), args.samples_per_member)
    except (Exception, KeyboardInterrupt) as exc:
        print(f"erro: {str(exc) or 'interrompido'}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
