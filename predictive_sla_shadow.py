#!/usr/bin/env python3
"""Freeze/preflight/run bounded online predictive sidecars, exclusively shadow.

Preflight reads only. Run requires --allow-shadow-publication and starts two
local processes: one per domain. No Mininet traffic, DDoS evidence, claims,
authority, LLM or actuator is invoked. Only an isolated ETCD namespace is used.
"""

from __future__ import annotations

import argparse
import base64
import json
import multiprocessing
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import uuid
from collections import Counter
from pathlib import Path

import predictive_sla_validation as v1
import predictive_sla_validation_v4 as v4
import predictive_sla_shadow_protocol as protocol
from qos_damped_holt import QosDampedHoltModel
from scripts.collect_qos_validation_campaign import guard_status


ROOT = Path(__file__).resolve().parent
CONFIG_SCHEMA = "comas-predictive-sla-online-shadow-config/1"
CODE_FILES = (*v4.CODE_FILES, "predictive_sla_shadow_protocol.py", "predictive_sla_shadow.py",
              "scripts/collect_qos_validation_campaign.py")
LIMITATIONS = [
    "V4 remains NOT_PASSED if originally so; this instrumentation does not promote either model.",
    "Two experimental predictive agents run as separate processes on one host, not in the existing DDoS agents.",
    "Only utilization of the explicitly mapped inter-domain link is considered; this is not a QoS/SLA guarantee.",
    "The ports share traffic: corroboration is not two independent measurements or statistical repetitions.",
    "The read-only latest-sample REST API can skip observations; gaps reset model/persistence, not interpolate.",
    "A bounded timestamp pair is not proof of exact window/episode equivalence; maximum skew is recorded.",
    "ETCD ack is a client-observed upper bound on commit availability; peer read receipt is observed separately.",
    "Elapsed durations use each process's monotonic clock; wall-clock ages assume the same local host clock.",
    "No actual future breach is yet matched to online availability; deadline feasibility remains UNKNOWN.",
    "Authority, actuation and LLM timings are NOT_MEASURED (null), not zero; protection is not established.",
    "Envelope hashes detect inconsistency, not malicious peers; the loopback lab gateway has no added authentication.",
    "Keys expire logically from observation time, not via ETCD leases; a few latest keys remain for each run.",
]


def code_snapshot():
    return {name: v1.digest_file(ROOT / name) for name in CODE_FILES}


def loopback_url(value):
    parsed = urllib.parse.urlsplit(value)
    if (parsed.scheme != "http" or parsed.hostname != "127.0.0.1" or not parsed.port
            or parsed.username or parsed.password or parsed.path or parsed.query or parsed.fragment):
        raise ValueError("use http://127.0.0.1:PORT para o gateway ETCD local")
    return value


def read_sealed(path, schema, field):
    content = json.loads(path.read_text(encoding="utf-8"))
    if content.get("schema_version") != schema or content != v1.seal(content, field):
        raise ValueError(f"schema/checksum inválido: {path.name}")
    return content


def source_state(path):
    p = v4.load_protocol(path)
    summary_path = path.parent / "campaign/campaign-summary.json"
    summary = read_sealed(summary_path, v4.SUMMARY_SCHEMA, "report_sha256")
    if summary.get("protocol_sha256") != p["protocol_sha256"] or summary.get("status") != "COMPLETED":
        raise ValueError("campanha oficial v4 ausente, incompatível ou incompleta")
    protected = {str(path): v1.digest_file(path), str(summary_path): v1.digest_file(summary_path),
                 **p["protected_source_sha256"], **summary["source_sha256"]}
    return p, summary, protected


def freeze(source, output, etcd_url):
    if source.absolute().is_symlink() or output.absolute().is_symlink():
        raise ValueError("fontes/saídas não podem ser links simbólicos")
    source, output = source.resolve(), output.resolve()
    if (output.exists() or output.parent != source.parent.parent
            or not output.name.startswith("qos-online-shadow-")):
        raise ValueError("use novo diretório irmão qos-online-shadow-*; não sobrescreva experimentos")
    p, summary, protected = source_state(source)
    specification = p["models"][v4.PRIMARY]
    model_path = source.parent / specification["path"]
    model_bytes = model_path.read_bytes()
    model = QosDampedHoltModel.load(model_path)
    if (model.sample_interval_s != 2 or tuple(h.horizon_steps for h in model.horizons) != (2, 4, 6)
            or p["subjects"] != v1.SUBJECTS or p["policy"] != v4.POLICY):
        raise ValueError("modelo/bindings/política não correspondem ao laboratório v4")
    protected[str(model_path)] = v1.digest_file(model_path)
    code = code_snapshot()
    config = v1.seal(dict(schema_version=CONFIG_SCHEMA, created_ns=time.time_ns(),
                         source_protocol=str(source), source_criteria_status=summary["criteria_status"],
                         model={**specification, "path": "model.json", "name": v4.PRIMARY},
                         policy=v4.POLICY, subjects=v1.SUBJECTS, shared_subject=protocol.SUBJECT,
                         timing=protocol.TIMING, etcd_url=loopback_url(etcd_url), boundary=protocol.BOUNDARY,
                         protected_source_sha256=protected, code_sha256=code, limitations=LIMITATIONS),
                     "config_sha256")
    if code_snapshot() != code or any(v1.digest_file(Path(k)) != value for k, value in protected.items()):
        raise ValueError("código/fontes mudaram durante o congelamento")
    output.mkdir()
    with (output / "model.json").open("xb") as handle:
        handle.write(model_bytes)
    v1.write_new_json(output / "shadow-config.json", config)
    load_config(output / "shadow-config.json")
    return config


def load_config(path):
    if path.absolute().is_symlink():
        raise ValueError("config não pode ser link simbólico")
    path = path.resolve()
    config = read_sealed(path, CONFIG_SCHEMA, "config_sha256")
    source = Path(config["source_protocol"])
    if (path.name != "shadow-config.json" or not path.parent.name.startswith("qos-online-shadow-")
            or path.parent.parent != source.resolve().parent.parent):
        raise ValueError("config fora do diretório shadow dedicado")
    p, summary, protected = source_state(source)
    original_model = source.parent / p["models"][v4.PRIMARY]["path"]
    protected[str(original_model)] = v1.digest_file(original_model)
    expected = dict(model={**p["models"][v4.PRIMARY], "path": "model.json", "name": v4.PRIMARY},
                    policy=v4.POLICY, subjects=v1.SUBJECTS, shared_subject=protocol.SUBJECT,
                    timing=protocol.TIMING, boundary=protocol.BOUNDARY, code_sha256=code_snapshot(),
                    source_criteria_status=summary["criteria_status"], protected_source_sha256=protected,
                    limitations=LIMITATIONS)
    if any(config.get(k) != value for k, value in expected.items()):
        raise ValueError("config/fontes/código diferem do congelamento shadow")
    loopback_url(config["etcd_url"])
    for name, expected_hash in protected.items():
        if v1.digest_file(Path(name)) != expected_hash:
            raise ValueError(f"fonte protegida mudou: {name}")
    model_path = path.parent / "model.json"
    if model_path.is_symlink() or v1.digest_file(model_path) != config["model"]["sha256"]:
        raise ValueError("modelo shadow mudou")
    if QosDampedHoltModel.load(model_path).resolved_model_id() != config["model"]["model_id"]:
        raise ValueError("identidade do modelo shadow incompatível")
    return config


def http_json(url, payload=None):
    # No redirect or environment HTTP proxy can reroute local evidence/writes.
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect())
    request = urllib.request.Request(url, data=None if payload is None else protocol.encoded(payload),
                                     headers={"Content-Type": "application/json", "Accept": "application/json"},
                                     method="GET" if payload is None else "POST")
    with opener.open(request, timeout=protocol.TIMING["request_timeout_s"]) as response:
        raw = response.read(1_048_577)
    if len(raw) > 1_048_576:
        raise ValueError("resposta excedeu o limite")
    def bad_constant(value):
        raise ValueError(f"JSON não finito: {value}")
    parsed = json.loads(raw, parse_constant=bad_constant)
    if not isinstance(parsed, dict) or parsed.get("error"):
        raise ValueError("resposta HTTP/ETCD inválida")
    return parsed


def b64(value):
    return base64.b64encode(value).decode("ascii")


class ShadowStore:
    """Only two risks, two proposals and one new-run marker; no delete/claim API.

    Uses the official v3 HTTP/JSON gateway, with base64 keys/values. Version-zero
    transaction protects the unique run marker from accidental concurrent reuse.
    """

    def __init__(self, url, run_id, request=None):
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise ValueError("run_id inválido")
        self.url, self.run_id, self.request = loopback_url(url), run_id, http_json if request is None else request
        self.prefix = f"/comas/experimental/predictive-sla-shadow/{run_id}/"
        self.allowed = {f"{kind}/{subject['cid']}" for kind in ("risks", "proposals") for subject in v1.SUBJECTS}

    def read(self):
        prefix = self.prefix.encode("ascii")
        result = self.request(self.url + "/v3/kv/range",
                              {"key": b64(prefix), "range_end": b64(prefix[:-1] + bytes([prefix[-1] + 1]))})
        if not isinstance(result.get("header"), dict) or result.get("more"):
            raise ValueError("snapshot ETCD incompleto")
        values = {}
        for row in result.get("kvs", []):
            key = base64.b64decode(row["key"], validate=True).decode("ascii")
            if not key.startswith(self.prefix):
                raise ValueError("ETCD retornou chave fora do namespace")
            suffix = key[len(self.prefix):]
            if suffix not in self.allowed | {"manifest"} or suffix in values:
                raise ValueError("chave shadow desconhecida/duplicada")
            values[suffix] = json.loads(base64.b64decode(row["value"], validate=True))
            protocol.encoded(values[suffix])  # Reject NaN/Infinity in peer JSON too.
        return values

    def reserve(self, manifest):
        key = b64((self.prefix + "manifest").encode("ascii"))
        response = self.request(self.url + "/v3/kv/txn", {
            "compare": [{"target": "VERSION", "result": "EQUAL", "key": key, "version": "0"}],
            "success": [{"request_put": {"key": key, "value": b64(protocol.encoded(manifest))}}]})
        if response.get("succeeded") is not True or not response.get("header"):
            raise ValueError("namespace já reservado ou confirmação ETCD inválida")

    def put(self, suffix, value):
        if suffix not in self.allowed:
            raise ValueError("escrita fora das chaves shadow permitidas")
        response = self.request(self.url + "/v3/kv/put", {
            "key": b64((self.prefix + suffix).encode("ascii")), "value": b64(protocol.encoded(value))})
        if not response.get("header", {}).get("revision"):
            raise ValueError("publicação sem confirmação de revisão ETCD")
        return response["header"]["revision"]


def latest(payload, subject):
    if payload.get("enabled") is not True:
        raise ValueError("QoS desativado")
    items = [item for item in payload.get("latest", []) if item.get("port_id") == subject["port_id"]]
    if len(items) != 1:
        raise ValueError("porta QoS ausente/ambígua")
    return items[0]


def preflight(config):
    receipts = []
    for subject in config["subjects"]:
        guard_status(http_json(subject["url"] + "/predictor/status"), subject)
        model_age = latest(http_json(subject["url"] + "/predictor/qos"), subject)
        # Validate identity, cadence and freshness without forecasting/publishing.
        if model_age.get("quality") != "VALID" or model_age.get("valid") is not True:
            raise ValueError("aguarde amostra VALID antes do preflight")
        dummy = OnlineRiskValidator(subject)
        dummy.check(model_age)
        receipts.append(dict(cid=subject["cid"], port_id=subject["port_id"], observed_ns=model_age["ts_ns"]))
    # Range is a read, even though the gateway maps it to HTTP POST.
    ShadowStore(config["etcd_url"], uuid.uuid4().hex).read()
    return receipts


class OnlineRiskValidator:
    def __init__(self, subject):
        self.subject = subject

    def check(self, sample):
        if (sample.get("cid") != self.subject["cid"] or sample.get("port_id") != self.subject["port_id"]
                or sample.get("schema_version") != 1 or sample.get("capacity_bps") != self.subject["capacity_bps"]
                or f"{sample.get('dpid')}:{sample.get('port_no')}" != self.subject["port_id"]):
            raise ValueError("amostra QoS incompatível com o binding")
        age = time.time_ns() - protocol.positive_ns(sample.get("ts_ns"))
        if not 0 <= age < protocol.TIMING["max_sample_age_s"] * 1e9:
            raise ValueError("amostra antiga/futura; confira coleta e relógio")
        if (protocol.finite(sample.get("utilization_ratio")) < 0
                or abs(protocol.finite(sample.get("interval_s")) - 2) > protocol.TIMING["sample_interval_tolerance_s"]):
            raise ValueError("utilização/cadência QoS incompatível")


def journal(handle, payload):
    handle.write(protocol.encoded(payload).decode("ascii") + "\n")
    handle.flush()


def publish_record(store, config, run_id, record, completed_ns, handle, durations):
    """Journal each successful ack even if the next publication fails."""
    cid = record["sample"]["cid"]
    risk = protocol.envelope(config, run_id, record, completed_ns)
    before = time.monotonic_ns()
    revision = store.put(f"risks/{cid}", risk)
    ack_ns = time.time_ns()
    elapsed = (time.monotonic_ns() - before) / 1e6
    durations["risk_publication_ms"].append(elapsed)
    journal(handle, dict(kind="RISK_PUBLICATION", cid=cid, risk=risk, risk_revision=revision,
                         risk_publication_ack_ns=ack_ns, risk_publication_ms=elapsed))
    before = time.monotonic_ns()
    item = protocol.proposal(config, risk, ack_ns, time.time_ns())
    durations["proposal_evaluation_ms"].append((time.monotonic_ns() - before) / 1e6)
    before = time.monotonic_ns()
    revision = store.put(f"proposals/{cid}", item)
    ack_ns = time.time_ns()
    elapsed = (time.monotonic_ns() - before) / 1e6
    durations["proposal_publication_ms"].append(elapsed)
    journal(handle, dict(kind="PROPOSAL_PUBLICATION", cid=cid, proposal=item, proposal_revision=revision,
                         proposal_publication_ack_ns=ack_ns, proposal_publication_ms=elapsed))


def worker(config, model_path, run_id, subject, output, duration_s):
    cid = subject["cid"]
    store = ShadowStore(config["etcd_url"], run_id)
    agent = protocol.OnlineRiskAgent(QosDampedHoltModel.load(Path(model_path)), subject, config["policy"])
    started = time.monotonic_ns()
    last_safety = 0
    previous_comparison = None
    counters = Counter()
    durations = {key: [] for key in ("telemetry_read_ms", "processing_ms", "forecast_ms", "observation_to_forecast_ms",
                                    "risk_publication_ms", "proposal_evaluation_ms", "proposal_publication_ms",
                                    "consensus_read_and_evaluation_ms", "observation_to_consensus_ms")}
    status, error = "COMPLETED", None
    with (Path(output) / f"{cid}.ndjson").open("x", encoding="utf-8") as handle:
        try:
            while (time.monotonic_ns() - started) / 1e9 < duration_s:
                cycle = time.monotonic()
                # Unsafe status/transport failure stops this worker. No fallback
                # into DDoS/actuation, no retry of stale proposals with fresh TTL.
                if time.monotonic() - last_safety >= protocol.TIMING["safety_poll_s"]:
                    guard_status(http_json(subject["url"] + "/predictor/status"), subject)
                    last_safety = time.monotonic()
                read_start_ns = time.time_ns()
                read_started = time.monotonic_ns()
                sample = latest(http_json(subject["url"] + "/predictor/qos"), subject)
                received_ns = time.time_ns()
                read_ms = (time.monotonic_ns() - read_started) / 1e6
                forecast_started = time.monotonic_ns()
                record = agent.ingest(sample, received_ns)
                forecast_completed_ns = time.time_ns()
                forecast_ms = (time.monotonic_ns() - forecast_started) / 1e6
                if record is not None:
                    counters[record["status"]] += 1
                    counters["samples"] += 1
                    counters["activations"] += int(record["activation"])
                    durations["telemetry_read_ms"].append(read_ms)
                    durations["processing_ms"].append(forecast_ms)
                    available_ns = forecast_completed_ns if record["status"] == "FORECAST_READY" else None
                    if available_ns is not None:
                        durations["forecast_ms"].append(forecast_ms)
                        durations["observation_to_forecast_ms"].append((available_ns - sample["ts_ns"]) / 1e6)
                    journal(handle, dict(kind="LOCAL_EVALUATION", cid=cid, record=record,
                                         telemetry_read_started_ns=read_start_ns, telemetry_received_ns=received_ns,
                                         processing_completed_ns=forecast_completed_ns, processing_ms=forecast_ms,
                                         forecast_available_ns=available_ns, telemetry_read_ms=read_ms))
                    publish_record(store, config, run_id, record, forecast_completed_ns, handle, durations)
                before = time.monotonic_ns()
                values = store.read()
                peer_received_ns = time.time_ns()
                assessment = protocol.consensus(config, run_id, values, peer_received_ns)
                assessed_ns = time.time_ns()
                if assessed_ns < peer_received_ns:
                    raise ValueError("relógio retrocedeu durante a avaliação")
                # Recheck freshness at completion, not only at peer receipt.
                assessment = protocol.consensus(config, run_id, values, assessed_ns)
                assessed_ns = time.time_ns()
                elapsed = (time.monotonic_ns() - before) / 1e6
                fingerprint = protocol.digest(assessment)
                if fingerprint != previous_comparison:
                    previous_comparison = fingerprint
                    counters[assessment["status"]] += 1
                    ages = []
                    if assessment["status"] in {"SHADOW_PREVENT_AGREED", "OBSERVE", "DISAGREED"}:
                        ages = [(assessed_ns - values[f"proposals/{s['cid']}"]["observed_ns"]) / 1e6
                                for s in config["subjects"]]
                        durations["observation_to_consensus_ms"].append(max(ages))
                    durations["consensus_read_and_evaluation_ms"].append(elapsed)
                    journal(handle, dict(kind="SHADOW_CONSENSUS", cid=cid, assessment=assessment,
                                         peer_snapshot=values,
                                         peer_snapshot_received_ns=peer_received_ns, consensus_completed_ns=assessed_ns,
                                         consensus_read_and_evaluation_ms=elapsed,
                                         oldest_observation_to_consensus_ms=max(ages) if ages else None,
                                         deadline_feasibility="UNKNOWN", sla_protection_established=False))
                time.sleep(max(0, protocol.TIMING["api_poll_s"] - (time.monotonic() - cycle)))
        except Exception as exc:
            status, error = "STOPPED_ERROR", str(exc)
            journal(handle, dict(kind="STOPPED_ERROR", cid=cid, error=error, recorded_ns=time.time_ns()))
    metrics = {key: dict(count=len(items), minimum=min(items) if items else None,
                         maximum=max(items) if items else None, mean=sum(items) / len(items) if items else None)
               for key, items in durations.items()}
    v1.write_new_json(Path(output) / f"{cid}-summary.json", dict(
        status=status, error=error, cid=cid, counters=dict(counters), timings=metrics,
        authority_latency_ms=None, actuation_latency_ms=None, llm_latency_ms=None,
        deadline_feasibility="UNKNOWN", sla_protection_established=False, boundary=protocol.BOUNDARY))
    if status != "COMPLETED":
        raise SystemExit(2)


def run(config_path, duration_s, allow_publication):
    if allow_publication is not True:
        raise ValueError("run exige --allow-shadow-publication; preflight não escreve no ETCD")
    if not 10 <= duration_s <= 3600:
        raise ValueError("duration-s deve estar entre 10 e 3600")
    config = load_config(config_path)
    preflight(config)
    run_id = uuid.uuid4().hex
    store = ShadowStore(config["etcd_url"], run_id)
    output = config_path.resolve().parent / "runs" / run_id
    if output.parent.is_symlink():
        raise ValueError("diretório runs não pode ser link simbólico")
    output.mkdir(parents=True, exist_ok=False)
    manifest = dict(schema_version=protocol.SCHEMA, run_id=run_id, config_sha256=config["config_sha256"],
                    duration_s=duration_s, started_ns=time.time_ns(), namespace=store.prefix,
                    host=os.uname().nodename, clock_scope="same_host_wall_clock; process_local_monotonic_durations",
                    boundary=protocol.BOUNDARY, limitations=LIMITATIONS)
    v1.write_new_json(output / "manifest.json", manifest)
    store.reserve(manifest)
    context = multiprocessing.get_context("spawn")
    processes = [context.Process(target=worker, args=(config, str(config_path.parent / "model.json"),
                                                     run_id, subject, str(output), duration_s))
                 for subject in config["subjects"]]
    print(f"shadow_run={output}", flush=True)
    try:
        for process in processes:
            process.start()
        while any(process.is_alive() for process in processes):
            if any(process.exitcode not in (None, 0) for process in processes):
                break
            time.sleep(0.25)
    finally:
        for process in processes:
            if process.is_alive():
                process.terminate()  # Only this launcher's own children.
            if process.pid is not None:
                process.join(timeout=3)
    changed = []
    try:
        load_config(config_path)
    except (ValueError, OSError) as exc:
        changed.append(str(exc))
    reports = []
    for subject, process in zip(config["subjects"], processes):
        path = output / f"{subject['cid']}-summary.json"
        reports.append(json.loads(path.read_text()) if path.exists() else
                       dict(cid=subject["cid"], status="INTERRUPTED", error=f"worker exit={process.exitcode}"))
    complete = not changed and all(process.exitcode == 0 for process in processes) and all(
        report["status"] == "COMPLETED" for report in reports)
    summary = dict(status="COMPLETED" if complete else "STOPPED_ERROR", run_id=run_id,
                   source_criteria_status=config["source_criteria_status"], originals_unchanged=not changed,
                   source_errors=changed, domain_reports=reports, boundary=protocol.BOUNDARY,
                   deadline_feasibility="UNKNOWN", sla_protection_established=False,
                   artifacts_sha256={path.name: v1.digest_file(path) for path in output.iterdir() if path.is_file()},
                   limitations=LIMITATIONS)
    v1.write_new_json(output / "shadow-summary.json", summary)
    print(f"status={summary['status']} domains={len(reports)} authority=false actuation=false deadline=UNKNOWN")
    return complete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze_cmd = sub.add_parser("freeze")
    freeze_cmd.add_argument("--protocol", type=Path, required=True)
    freeze_cmd.add_argument("--output", type=Path, required=True)
    freeze_cmd.add_argument("--etcd-url", default="http://127.0.0.1:2379")
    for name in ("preflight", "run"):
        command = sub.add_parser(name)
        command.add_argument("--config", type=Path, required=True)
        if name == "run":
            command.add_argument("--duration-s", type=int, default=60)
            command.add_argument("--allow-shadow-publication", action="store_true")
    args = parser.parse_args(argv)
    try:
        if args.command == "freeze":
            config = freeze(args.protocol, args.output, args.etcd_url)
            print(f"config={args.output / 'shadow-config.json'} model={config['model']['name']} source_v4={config['source_criteria_status']}")
        elif args.command == "preflight":
            preflight(load_config(args.config))
            print("preflight=READY domains=2 model=selected_warning90 shadow_only=true etcd_writes=0")
        else:
            return 0 if run(args.config, args.duration_s, args.allow_shadow_publication) else 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
