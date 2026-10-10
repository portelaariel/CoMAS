#!/usr/bin/env python3
"""Opt-in shadow v2: publish each domain's risk and proposal atomically.

V1 code/config/results and the official v4 campaign remain untouched. Freeze
migrates a verified v1 config into a new sibling directory. No traffic,
authority, claim, actuator, LLM, collector restart or ETCD delete is provided.
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
import uuid
from collections import Counter
from pathlib import Path

import predictive_sla_shadow as legacy
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_validation as provenance
from qos_damped_holt import QosDampedHoltModel
from scripts.collect_qos_validation_campaign import guard_status


ROOT = Path(__file__).resolve().parent
CONFIG_SCHEMA = "comas-predictive-sla-online-shadow-config/2"
CODE_FILES = tuple(dict.fromkeys((*legacy.CODE_FILES, "predictive_sla_shadow_protocol_v2.py",
                                 "predictive_sla_shadow_v2.py")))
LIMITATIONS = [*legacy.LIMITATIONS,
    "Atomicity applies to one domain's risk/proposal, not simultaneous publication by both domains.",
    "Same-revision proof comes from ETCD range metadata; it does not authenticate a malicious gateway.",
    "Proposal preparation precedes commit; a client-observed joint ack is journaled after the response only.",
    "A timeout or malformed ack leaves commit outcome UNKNOWN; there is no automatic retry or rollback claim.",
    "V2 publication timing is one joint request, not the sum of v1's separate publication timings.",
]
http_json, b64, latest, journal = legacy.http_json, legacy.b64, legacy.latest, legacy.journal


def code_snapshot():
    return {name: provenance.digest_file(ROOT / name) for name in CODE_FILES}


def previous_artifacts(source):
    """Pin existing v1 artifacts; new runs are not mistaken for overwrites."""
    paths = [source, source.parent / "model.json"]
    runs = source.parent / "runs"
    if runs.is_symlink():
        raise ValueError("diretório de resultados v1 não pode ser link simbólico")
    if runs.exists():
        for directory in runs.iterdir():
            if directory.is_symlink():
                raise ValueError("resultado v1 não pode ser link simbólico")
            if directory.is_dir():
                paths.extend(path for path in directory.iterdir() if path.is_file() or path.is_symlink())
    if any(path.is_symlink() for path in paths):
        raise ValueError("artefato v1 não pode ser link simbólico")
    return {str(path.resolve()): provenance.digest_file(path) for path in paths}


def freeze(source, output):
    if source.absolute().is_symlink() or output.absolute().is_symlink():
        raise ValueError("fontes/saídas não podem ser links simbólicos")
    source, output = source.resolve(), output.resolve()
    if (output.exists() or output.parent != source.parent.parent
            or not output.name.startswith("qos-online-shadow-v2")):
        raise ValueError("use novo diretório irmão qos-online-shadow-v2*; não sobrescreva a v1")
    original = legacy.load_config(source)
    artifacts, code = previous_artifacts(source), code_snapshot()
    config = provenance.seal(dict(
        schema_version=CONFIG_SCHEMA, created_ns=time.time_ns(), source_shadow_config=str(source),
        source_protocol=original["source_protocol"], source_criteria_status=original["source_criteria_status"],
        model=original["model"], policy=original["policy"], subjects=original["subjects"],
        shared_subject=protocol.SUBJECT, timing=protocol.TIMING, boundary=protocol.BOUNDARY,
        publication=protocol.PUBLICATION, etcd_url=original["etcd_url"],
        protected_source_sha256=original["protected_source_sha256"],
        source_v1_artifacts_sha256=artifacts, code_sha256=code, limitations=LIMITATIONS), "config_sha256")
    model_bytes = (source.parent / "model.json").read_bytes()
    if (code_snapshot() != code or previous_artifacts(source) != artifacts
            or legacy.load_config(source) != original):
        raise ValueError("código/fontes mudaram durante o congelamento v2")
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
    if (path.name != "shadow-config.json" or not path.parent.name.startswith("qos-online-shadow-v2")
            or path.parent.parent != source.resolve().parent.parent or path.parent == source.resolve().parent):
        raise ValueError("config fora do novo diretório shadow v2")
    original = legacy.load_config(source)
    expected = dict(source_protocol=original["source_protocol"],
                    source_criteria_status=original["source_criteria_status"], model=original["model"],
                    policy=original["policy"], subjects=original["subjects"], shared_subject=protocol.SUBJECT,
                    timing=protocol.TIMING, boundary=protocol.BOUNDARY, publication=protocol.PUBLICATION,
                    etcd_url=original["etcd_url"], protected_source_sha256=original["protected_source_sha256"],
                    code_sha256=code_snapshot(), limitations=LIMITATIONS)
    if any(config.get(k) != value for k, value in expected.items()):
        raise ValueError("config/fontes/código diferem do congelamento shadow v2")
    artifacts = config["source_v1_artifacts_sha256"]
    if not isinstance(artifacts, dict) or not {str(source.resolve()), str(source.resolve().parent / "model.json")} <= artifacts.keys():
        raise ValueError("proveniência dos artefatos v1 ausente")
    for name, expected_hash in artifacts.items():
        artifact = Path(name)
        if (artifact.is_symlink() or source.resolve().parent not in artifact.resolve().parents
                or provenance.digest_file(artifact) != expected_hash):
            raise ValueError(f"artefato v1 protegido mudou: {name}")
    model_path = path.parent / "model.json"
    if model_path.is_symlink() or provenance.digest_file(model_path) != config["model"]["sha256"]:
        raise ValueError("modelo shadow v2 mudou")
    if QosDampedHoltModel.load(model_path).resolved_model_id() != config["model"]["model_id"]:
        raise ValueError("identidade do modelo shadow v2 incompatível")
    return config


def revision(value):
    """The gateway encodes int64 as strings; reject booleans/floats/default zero."""
    if isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value):
        value = int(value)
    if type(value) is not int or not 0 < value < 2**63:
        raise ValueError("revisão ETCD inválida/ausente")
    return value


class AtomicShadowStore:
    """Two-put transactions only, inside a separate versioned run namespace."""

    def __init__(self, url, run_id, request=None):
        if not re.fullmatch(r"[0-9a-f]{32}", run_id):
            raise ValueError("run_id inválido")
        self.url, self.run_id = legacy.loopback_url(url), run_id
        self.request = http_json if request is None else request
        self.prefix = f"/comas/experimental/predictive-sla-shadow-v2/{run_id}/"
        self.cids = {subject["cid"] for subject in provenance.SUBJECTS}
        self.allowed = {f"{kind}/{cid}" for kind in ("risks", "proposals") for cid in self.cids}

    def read(self):
        prefix = self.prefix.encode("ascii")
        result = self.request(self.url + "/v3/kv/range", {
            "key": b64(prefix), "range_end": b64(prefix[:-1] + bytes([prefix[-1] + 1])),
            "serializable": False})
        if not isinstance(result.get("header"), dict) or result.get("more"):
            raise ValueError("snapshot ETCD incompleto")
        current_revision = revision(result["header"].get("revision"))
        values, revisions = {}, {}
        rows = result.get("kvs", [])
        if not isinstance(rows, list):
            raise ValueError("lista de chaves ETCD inválida")
        for row in rows:
            key = base64.b64decode(row["key"], validate=True).decode("ascii")
            if not key.startswith(self.prefix):
                raise ValueError("ETCD retornou chave fora do namespace v2")
            suffix = key[len(self.prefix):]
            if suffix not in self.allowed | {"manifest"} or suffix in values:
                raise ValueError("chave shadow v2 desconhecida/duplicada")
            modified = revision(row.get("mod_revision"))
            if modified > current_revision or row.get("lease", "0") not in ("0", 0):
                raise ValueError("metadados ETCD incompatíveis com o snapshot shadow")
            values[suffix] = json.loads(base64.b64decode(row["value"], validate=True))
            protocol.encoded(values[suffix])
            revisions[suffix] = modified
        if "count" in result and str(result["count"]) != str(len(values)):
            raise ValueError("contagem ETCD indica snapshot incompleto")
        return dict(values=values, mod_revisions=revisions, snapshot_revision=current_revision)

    def reserve(self, manifest):
        key = b64((self.prefix + "manifest").encode("ascii"))
        response = self.request(self.url + "/v3/kv/txn", {
            "compare": [{"target": "VERSION", "result": "EQUAL", "key": key, "version": "0"}],
            "success": [{"request_put": {"key": key, "value": b64(protocol.encoded(manifest))}}]})
        if response.get("succeeded") is not True:
            raise ValueError("namespace já reservado ou confirmação ETCD inválida")
        return revision(response.get("header", {}).get("revision"))

    def put_pair(self, cid, risk, item):
        if cid not in self.cids:
            raise ValueError("domínio fora das chaves shadow v2 permitidas")
        for value, kind in ((risk, "RISK"), (item, "PROPOSAL")):
            if (not isinstance(value, dict) or value.get("cid") != cid or value.get("run_id") != self.run_id
                    or value.get("kind") != kind or value.get("schema_version") != protocol.SCHEMA
                    or value.get("boundary") != protocol.BOUNDARY):
                raise ValueError("par fora do contrato shadow v2")
        if item.get("risk_sha256") != protocol.digest(risk) or item.get("observed_ns") != risk.get("observed_ns"):
            raise ValueError("proposta não corresponde ao risco da transação")
        operations = [{"request_put": {"key": b64((self.prefix + f"{kind}/{cid}").encode("ascii")),
                                      "value": b64(protocol.encoded(value))}}
                      for kind, value in (("risks", risk), ("proposals", item))]
        # A single commit changes both distinct keys at the same mod_revision.
        response = self.request(self.url + "/v3/kv/txn", {"compare": [], "success": operations, "failure": []})
        ack_ns = time.time_ns()
        if response.get("succeeded") is not True:
            raise ValueError("transação do par não foi confirmada")
        committed = revision(response.get("header", {}).get("revision"))
        replies = response.get("responses")
        if (not isinstance(replies, list) or len(replies) != 2
                or any(not isinstance(row, dict) or set(row) != {"response_put"}
                       or not isinstance(row["response_put"], dict) for row in replies)):
            raise ValueError("confirmação da transação não contém os dois puts")
        for row in replies:
            header = row["response_put"].get("header")
            if header is not None and revision(header.get("revision")) != committed:
                raise ValueError("revisões de confirmação do par diferem")
        return dict(revision=committed, pair_publication_ack_ns=ack_ns)


def preflight(config):
    receipts = []
    for subject in config["subjects"]:
        guard_status(http_json(subject["url"] + "/predictor/status"), subject)
        sample = latest(http_json(subject["url"] + "/predictor/qos"), subject)
        if sample.get("quality") != "VALID" or sample.get("valid") is not True:
            raise ValueError("aguarde amostra VALID antes do preflight")
        legacy.OnlineRiskValidator(subject).check(sample)
        receipts.append(dict(cid=subject["cid"], port_id=subject["port_id"], observed_ns=sample["ts_ns"]))
    AtomicShadowStore(config["etcd_url"], uuid.uuid4().hex).read()
    return receipts


def publish_record(store, config, run_id, record, completed_ns, handle, durations, counters):
    cid = record["sample"]["cid"]
    risk = protocol.envelope(config, run_id, record, completed_ns)
    before = time.monotonic_ns()
    item = protocol.proposal(config, risk, time.time_ns())
    durations["proposal_evaluation_ms"].append((time.monotonic_ns() - before) / 1e6)
    subject = next(s for s in config["subjects"] if s["cid"] == cid)
    protocol.verify_pair(config, run_id, subject, risk, item, time.time_ns())
    attempt = dict(kind="PAIR_PUBLICATION_ATTEMPT", cid=cid, risk=risk, proposal=item,
                   pair_publication_started_ns=time.time_ns(), commit_outcome="UNCONFIRMED")
    journal(handle, attempt)
    counters["publication_attempts"] += 1
    before = time.monotonic_ns()
    try:
        receipt = store.put_pair(cid, risk, item)
    except Exception as exc:
        counters["unconfirmed_publications"] += 1
        journal(handle, dict(kind="PAIR_PUBLICATION_UNCONFIRMED", cid=cid, recorded_ns=time.time_ns(),
                             error=str(exc), commit_outcome="UNKNOWN", retry_attempted=False))
        raise
    elapsed = (time.monotonic_ns() - before) / 1e6
    ack_ns = receipt["pair_publication_ack_ns"]
    counters["confirmed_publications"] += 1
    durations["pair_publication_ms"].append(elapsed)
    journal(handle, dict(kind="PAIR_PUBLICATION", cid=cid, risk=risk, proposal=item,
                         pair_mod_revision=receipt["revision"], pair_publication_ack_ns=ack_ns,
                         pair_publication_ms=elapsed, commit_outcome="CONFIRMED"))
    if ack_ns < attempt["pair_publication_started_ns"]:
        raise ValueError("relógio retrocedeu durante a publicação atômica")
    durations["observation_to_pair_publication_ack_ms"].append((ack_ns - risk["observed_ns"]) / 1e6)


def worker(config, model_path, run_id, subject, output, duration_s):
    cid = subject["cid"]
    store = AtomicShadowStore(config["etcd_url"], run_id)
    last_safety, previous_comparison = None, None
    counters, reasons = Counter(), Counter()
    durations = {key: [] for key in (
        "telemetry_read_ms", "processing_ms", "forecast_ms", "observation_to_forecast_ms",
        "proposal_evaluation_ms", "pair_publication_ms", "observation_to_pair_publication_ack_ms",
        "consensus_read_and_evaluation_ms", "observation_to_consensus_ms")}
    status, error = "COMPLETED", None
    with (Path(output) / f"{cid}.ndjson").open("x", encoding="utf-8") as handle:
        try:
            if provenance.digest_file(Path(model_path)) != config["model"]["sha256"]:
                raise ValueError("modelo shadow v2 mudou antes de iniciar o agente")
            model = QosDampedHoltModel.load(Path(model_path))
            if model.resolved_model_id() != config["model"]["model_id"]:
                raise ValueError("identidade do modelo shadow v2 incompatível")
            agent = protocol.OnlineRiskAgent(model, subject, config["policy"])
            started = time.monotonic_ns()
            while (time.monotonic_ns() - started) / 1e9 < duration_s:
                cycle = time.monotonic()
                if last_safety is None or time.monotonic() - last_safety >= protocol.TIMING["safety_poll_s"]:
                    guard_status(http_json(subject["url"] + "/predictor/status"), subject)
                    last_safety = time.monotonic()
                read_start_ns, read_started = time.time_ns(), time.monotonic_ns()
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
                    publish_record(store, config, run_id, record, forecast_completed_ns, handle, durations, counters)
                before = time.monotonic_ns()
                snapshot = store.read()
                peer_received_ns = time.time_ns()
                # Freshness is assessed at completion rather than just at receipt.
                assessment = protocol.consensus(config, run_id, snapshot, peer_received_ns)
                completed_ns = time.time_ns()
                if completed_ns < peer_received_ns:
                    raise ValueError("relógio retrocedeu durante a avaliação")
                assessment = protocol.consensus(config, run_id, snapshot, completed_ns)
                assessed_ns = time.time_ns()
                elapsed = (time.monotonic_ns() - before) / 1e6
                fingerprint = protocol.digest(assessment)
                if fingerprint != previous_comparison:
                    previous_comparison = fingerprint
                    counters[assessment["status"]] += 1
                    reasons[assessment["status"] + ": " + assessment["reason"]] += 1
                    ages = []
                    if assessment["status"] in {"SHADOW_PREVENT_AGREED", "OBSERVE", "DISAGREED"}:
                        ages = [(assessed_ns - snapshot["values"][f"proposals/{s['cid']}"]["observed_ns"]) / 1e6
                                for s in config["subjects"]]
                        durations["observation_to_consensus_ms"].append(max(ages))
                    durations["consensus_read_and_evaluation_ms"].append(elapsed)
                    journal(handle, dict(kind="SHADOW_CONSENSUS", cid=cid, assessment=assessment,
                                         peer_snapshot=snapshot,
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
    provenance.write_new_json(Path(output) / f"{cid}-summary.json", dict(
        schema_version=protocol.SCHEMA, status=status, error=error, cid=cid,
        counters=dict(counters), consensus_reason_counts=dict(reasons), timings=metrics,
        authority_latency_ms=None, actuation_latency_ms=None, llm_latency_ms=None,
        deadline_feasibility="UNKNOWN", sla_protection_established=False,
        publication=protocol.PUBLICATION, boundary=protocol.BOUNDARY))
    if status != "COMPLETED":
        raise SystemExit(2)


def run(config_path, duration_s, allow_publication):
    if allow_publication is not True:
        raise ValueError("run exige --allow-shadow-publication; preflight não escreve no ETCD")
    if not 10 <= duration_s <= 3600:
        raise ValueError("duration-s deve estar entre 10 e 3600")
    config = load_config(config_path)
    config_path = config_path.resolve()
    preflight(config)
    run_id = uuid.uuid4().hex
    store = AtomicShadowStore(config["etcd_url"], run_id)
    output = config_path.parent / "runs" / run_id
    if output.parent.is_symlink():
        raise ValueError("diretório runs não pode ser link simbólico")
    output.mkdir(parents=True, exist_ok=False)
    manifest = dict(schema_version=protocol.SCHEMA, run_id=run_id, config_sha256=config["config_sha256"],
                    duration_s=duration_s, started_ns=time.time_ns(), namespace=store.prefix,
                    host=os.uname().nodename, clock_scope="same_host_wall_clock; process_local_monotonic_durations",
                    publication=protocol.PUBLICATION, boundary=protocol.BOUNDARY, limitations=LIMITATIONS)
    provenance.write_new_json(output / "manifest.json", manifest)
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
    except (ValueError, OSError, KeyError, TypeError) as exc:
        changed.append(str(exc))
    reports = []
    for subject, process in zip(config["subjects"], processes):
        path = output / f"{subject['cid']}-summary.json"
        reports.append(json.loads(path.read_text()) if path.exists() else
                       dict(cid=subject["cid"], status="INTERRUPTED", error=f"worker exit={process.exitcode}"))
    complete = not changed and all(process.exitcode == 0 for process in processes) and all(
        report["status"] == "COMPLETED" for report in reports)
    summary = dict(schema_version=protocol.SCHEMA, status="COMPLETED" if complete else "STOPPED_ERROR",
                   run_id=run_id, source_criteria_status=config["source_criteria_status"],
                   originals_unchanged=not changed, source_errors=changed, domain_reports=reports,
                   publication=protocol.PUBLICATION, boundary=protocol.BOUNDARY,
                   deadline_feasibility="UNKNOWN", sla_protection_established=False,
                   artifacts_sha256={path.name: provenance.digest_file(path) for path in output.iterdir() if path.is_file()},
                   limitations=LIMITATIONS)
    provenance.write_new_json(output / "shadow-summary.json", summary)
    print(f"status={summary['status']} domains={len(reports)} atomic_pairs=true authority=false actuation=false deadline=UNKNOWN")
    return complete


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    freeze_cmd = sub.add_parser("freeze")
    freeze_cmd.add_argument("--source-config", type=Path, required=True)
    freeze_cmd.add_argument("--output", type=Path, required=True)
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
            print(f"config={args.output / 'shadow-config.json'} model={config['model']['name']} atomic_pairs=true source_v4={config['source_criteria_status']}")
        elif args.command == "preflight":
            preflight(load_config(args.config))
            print("preflight=READY domains=2 model=selected_warning90 atomic_pairs=true shadow_only=true etcd_writes=0")
        else:
            return 0 if run(args.config, args.duration_s, args.allow_shadow_publication) else 2
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
