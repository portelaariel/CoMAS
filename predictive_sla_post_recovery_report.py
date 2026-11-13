#!/usr/bin/env python3
"""Offline inventory and raw-trace audit of the post-recovery shadow cohort.

No preflight/run invocation, HTTP request, Docker command, traffic or ETCD write.
All directories under runs are registered, including sources without receipts.
"""

from __future__ import annotations

import argparse
from collections import Counter
import json
import math
from pathlib import Path
import re
import sys
import time

import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_validation as provenance


KNOWN_RUNS = (
    "195696cb1bb44e6399a0806db3928d6c",
    "385278ca8afe4f88aa44cc3e848d35a2",
    "3d402576d2e346a1a72b31967922e917",
    "e4df5f544587425b88ec54cfe6dd6ca2",
    "f913f9b28308449e9a0d9fa7749975d3",
)
OUTPUT_PREFIX = "qos-shadow-post-recovery-report-"
SCHEMA = "comas-shadow-post-recovery-report/1"
POLICY = dict(
    cohort="all_attempt_directories_in_one_frozen_post_recovery_configuration",
    known_console_results=list(KNOWN_RUNS), intended_total_before_additional_results=3,
    additional_attempts="registered_without_latest_success_selection",
    missing_receipt="UNFINALIZED_UNKNOWN; inventory_only; no_zero_imputation",
    invalid_source="UNVERIFIED; retained_and_excluded_from_verified_transport_totals",
    aggregation="all_verified_finalized_attempts_including_stopped_attempts",
    latency="raw_HTTP_request_durations; pooled_samples_not_mean_of_run_means",
    ack="STORE_OPERATION_FINISHED_ACK_VALIDATED_not_HTTP_JSON_RECEIVED",
    percentiles="nearest_rank_of_received_HTTP_samples_only; failures_reported_separately",
)
LIMITATIONS = [
    "Descriptive post-recovery laboratory characterization, not a preregistered five-run acceptance test.",
    "The console requested three runs in total but supplied five completed run IDs; none is discarded.",
    "Attempts and requests share the same host/cluster and are not independent statistical trials.",
    "HTTP request durations include client/gateway/network work, not isolated ETCD server latency.",
    "HTTP and store-operation durations overlap and must not be added.",
    "A 1 s socket I/O timeout is not a total end-to-end deadline guarantee.",
    "No paired pre-recovery baseline proves that recovery alone eliminated historical timeouts.",
    "Raw trace/receipt consistency is audited; forecasts, SLA protection and authority are not re-evaluated.",
    "Unfinalized or unverified sources have unknown outcomes; their missing measurements are not zero.",
    "The original v4 remains NOT_PASSED; deadline feasibility remains UNKNOWN and promotion is not authorized.",
]


def require(condition, message):
    if not condition:
        raise ValueError(message)


def bad_constant(value):
    raise ValueError(f"JSON não finito: {value}")


def read_json(path):
    require(path.is_file() and not path.is_symlink(), f"arquivo ausente/symlink: {path}")
    return json.loads(path.read_text(encoding="utf-8"), parse_constant=bad_constant)


def positive(value):
    require(type(value) is int and value > 0, "inteiro positivo ausente/inválido")
    return value


def elapsed(value):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            "duração inválida")
    return value


def inventory(root):
    require(root.is_dir() and not root.is_symlink(), "diretório fonte ausente/symlink")
    files, directories = {}, []
    for path in sorted(root.rglob("*")):
        require(not path.is_symlink(), f"symlink na fonte: {path}")
        relative = path.relative_to(root).as_posix()
        if path.is_dir():
            directories.append(relative)
        else:
            require(path.is_file(), f"fonte não regular: {path}")
            files[relative] = provenance.digest_file(path)
    return dict(directories=directories, files_sha256=files)


def records(path):
    rows, partial = [], False
    if not path.exists():
        return None, False
    require(path.is_file() and not path.is_symlink(), "journal não é arquivo regular")
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            if not line.endswith("\n"):
                partial = True
                break
            row = json.loads(line, parse_constant=bad_constant)
            require(isinstance(row, dict), "linha de journal não é objeto JSON")
            rows.append(row)
    return rows, partial


def trace(path, role, config):
    rows, partial = records(path)
    if rows is None:
        return None, []
    starts, finishes, stores = {}, {}, {}
    for row in rows:
        require(row.get("schema_version") == diagnostic.TRACE_SCHEMA and row.get("role") == role,
                "schema/papel de trace incompatível")
        kind, request_id = row.get("kind"), row.get("request_id")
        require(kind in {"REQUEST_STARTED", "REQUEST_FINISHED", "STORE_OPERATION_FINISHED",
                         "REQUEST_REJECTED_LOCALLY"}, "evento de transporte desconhecido")
        if kind == "REQUEST_STARTED":
            require(isinstance(request_id, str) and request_id and request_id not in starts,
                    "request start duplicado/inválido")
            positive(row["started_ns"])
            require(row.get("configured_timeout_s") == 1, "timeout difere do piloto congelado")
            operation, endpoint = row["operation"], row["endpoint"]
            allowed = {"etcd_snapshot_read": config["etcd_url"] + "/v3/kv/range"}
            if role == "launcher":
                allowed = {"etcd_namespace_reserve": config["etcd_url"] + "/v3/kv/txn"}
            else:
                if role != "preflight":
                    allowed["etcd_pair_transaction"] = config["etcd_url"] + "/v3/kv/txn"
                subjects = [s for s in config["subjects"] if role == "preflight" or s["cid"] == role]
                for subject in subjects:
                    for suffix, name in (("/predictor/status", "telemetry_status_read"),
                                         ("/predictor/qos", "telemetry_qos_read")):
                        if operation == name and endpoint == subject["url"] + suffix:
                            allowed[name] = endpoint
            require(operation in allowed and endpoint == allowed[operation], "operação/endpoint fora do piloto")
            require(row.get("writing") is (operation in {"etcd_namespace_reserve", "etcd_pair_transaction"}),
                    "flag writing diverge da operação")
            starts[request_id] = row
        elif kind == "REQUEST_FINISHED":
            require(request_id in starts and request_id not in finishes, "request finish sem start único")
            start = starts[request_id]
            require(all(row.get(key) == start.get(key) for key in ("operation", "endpoint", "writing",
                                                                 "started_ns", "configured_timeout_s")),
                    "request finish não corresponde ao start")
            positive(row["finished_ns"])
            elapsed(row["elapsed_ms"])
            require(row.get("status") in {"HTTP_JSON_RECEIVED", "TIMEOUT", "HTTP_ERROR",
                                           "REQUEST_ERROR", "RESPONSE_ERROR"}, "status HTTP desconhecido")
            require(row.get("commit_outcome") == ("UNKNOWN" if start["writing"] else "NOT_APPLICABLE"),
                    "resposta HTTP não comprova commit validado")
            finishes[request_id] = row
        elif kind == "STORE_OPERATION_FINISHED":
            elapsed(row["elapsed_ms"])
            require(row.get("status") in {"ACK_VALIDATED", "SNAPSHOT_VALIDATED", "VALIDATION_REJECTED",
                                           "REQUEST_FAILED", "REJECTED_LOCALLY"}, "status store desconhecido")
            if request_id is None:
                expected_outcome = "NOT_APPLICABLE" if row.get("operation") == "etcd_snapshot_read" else "NOT_SENT"
                require(row.get("status") == "REJECTED_LOCALLY" and row.get("commit_outcome") == expected_outcome,
                        "operação sem request_id não pode confirmar commit")
                continue
            require(request_id in starts and request_id not in stores, "store sem request único/duplicado")
            require(row.get("operation") == starts[request_id]["operation"]
                    and row.get("endpoint") == starts[request_id]["endpoint"], "store diverge do request")
            if row.get("status") in {"ACK_VALIDATED", "SNAPSHOT_VALIDATED"}:
                require(finishes.get(request_id, {}).get("status") == "HTTP_JSON_RECEIVED",
                        "validação sem resposta HTTP recebida")
                writing = starts[request_id]["writing"]
                require(row["status"] == ("ACK_VALIDATED" if writing else "SNAPSHOT_VALIDATED")
                        and row.get("commit_outcome") == ("CONFIRMED" if writing else "NOT_APPLICABLE"),
                        "ACK incompatível com a operação")
                if row["operation"] == "etcd_pair_transaction":
                    positive(row["pair_mod_revision"])
                    positive(row["pair_publication_ack_ns"])
                elif row["operation"] == "etcd_namespace_reserve":
                    positive(row["namespace_revision"])
            stores[request_id] = row
    result = dict(diagnostic.trace_summary(rows), partial_final_line=partial)
    return result, rows


def samples(rows):
    """Retain raw HTTP samples and failed/unfinished denominators, separately."""
    groups = {}
    for row in rows:
        operation = row.get("operation")
        if not operation:
            continue
        group = groups.setdefault(operation, dict(started=0, received=0, timeouts=0, errors=0,
                                                  ack_validated=0, unconfirmed_writes=0, values_ms=[]))
        if row["kind"] == "REQUEST_STARTED":
            group["started"] += 1
        elif row["kind"] == "REQUEST_FINISHED":
            if row["status"] == "HTTP_JSON_RECEIVED":
                group["received"] += 1
                group["values_ms"].append(row["elapsed_ms"])
            else:
                group["timeouts" if row["status"] == "TIMEOUT" else "errors"] += 1
        elif row["kind"] == "STORE_OPERATION_FINISHED" and row["status"] == "ACK_VALIDATED":
            group["ack_validated"] += 1
    return groups


def merge_groups(destination, source):
    for operation, incoming in source.items():
        target = destination.setdefault(operation, {key: [] if key == "values_ms" else 0 for key in incoming})
        for key, value in incoming.items():
            if key == "values_ms":
                target[key].extend(value)
            else:
                target[key] += value


def finish_groups(groups):
    output = {}
    for operation, source in groups.items():
        values = sorted(source["values_ms"])
        output[operation] = {key: value for key, value in source.items() if key != "values_ms"}
        output[operation].update(
            unfinished=source["started"] - source["received"] - source["timeouts"] - source["errors"],
            received_http_ms=dict(count=len(values), mean=sum(values) / len(values) if values else None,
                                  p95_nearest_rank=values[math.ceil(.95 * len(values)) - 1] if values else None,
                                  maximum=max(values) if values else None))
    return output


def verify_attempt(root, config, source_files):
    run_id = root.name
    require(re.fullmatch(r"[0-9a-f]{32}", run_id), "nome de tentativa não é UUID hexadecimal")
    manifest = read_json(root / "manifest.json")
    summary = read_json(root / "shadow-summary.json")
    expected = dict(schema_version=diagnostic.SUMMARY_SCHEMA, run_id=run_id, diagnostics=diagnostic.DIAGNOSTICS,
                    publication=config["publication"], boundary=config["boundary"])
    require(all(manifest.get(k) == v and summary.get(k) == v for k, v in expected.items()),
            "manifest/summary divergem do run_id/contrato congelado")
    require(manifest.get("source_shadow_config") == config["source_shadow_config"]
            and manifest.get("config_sha256") == config["config_sha256"] and manifest.get("duration_s") == 60,
            "configuração/duração da tentativa mudou")
    positive(manifest["started_ns"])
    require(summary.get("source_criteria_status") == "NOT_PASSED"
            and summary.get("deadline_feasibility") == "UNKNOWN"
            and summary.get("sla_protection_established") is False, "resultado altera os limites científicos")
    require(summary.get("status") in {"COMPLETED", "STOPPED_ERROR"}, "recibo sem status final reconhecido")
    artifacts = summary.get("artifacts_sha256")
    require(isinstance(artifacts, dict) and "manifest.json" in artifacts, "ledger de hashes ausente")
    actual = {p.name for p in root.iterdir() if p.is_file() and p.name != "shadow-summary.json"}
    require(set(artifacts) == actual and all(Path(name).name == name for name in artifacts),
            "ledger não cobre exatamente os arquivos da tentativa")
    for name, sha in artifacts.items():
        require(source_files.get(f"runs/{run_id}/{name}") == sha, f"hash divergente: {name}")
    roles = [s["cid"] for s in config["subjects"]] + ["preflight", "launcher"]
    reports = summary.get("domain_reports")
    require(isinstance(reports, list) and len(reports) == 2
            and {r["cid"] for r in reports} == set(roles[:2]), "recibos dos domínios incompletos")
    transports, raw = {}, {}
    for role in roles:
        transports[role], raw[role] = trace(root / f"{role}-transport.ndjson", role, config)
    require(transports == summary.get("transport_summary"), "resumo de transporte difere dos traces brutos")
    for report in reports:
        cid = report["cid"]
        path = root / f"{cid}-summary.json"
        if path.exists():
            saved = read_json(path)
            require(report == dict(saved, summary_available=True), "recibo de domínio diverge do resumo")
            confirmed = saved.get("counters", {}).get("confirmed_publications", 0)
            require(transports[cid] is not None and confirmed == transports[cid]["confirmed_pair_acks"],
                    "confirmações não correspondem aos ACKs validados")
            journal, partial = records(root / f"{cid}.ndjson")
            require(journal is not None, "journal de publicações ausente")
            publications = [r for r in journal if r.get("kind") == "PAIR_PUBLICATION"]
            require(len(publications) == confirmed, "journal diverge das publicações confirmadas")
            for row in publications:
                require(row.get("commit_outcome") == "CONFIRMED" and row.get("cid") == cid
                        and row["risk"]["run_id"] == row["proposal"]["run_id"] == run_id,
                        "publicação pertence a outro domínio/run")
                positive(row["pair_mod_revision"])
                positive(row["pair_publication_ack_ns"])
            require(not partial or summary["status"] != "COMPLETED", "journal COMPLETED está truncado")
        else:
            require(report.get("summary_available") is False and summary["status"] != "COMPLETED",
                    "recibo de domínio ausente não é sucesso")
    complete = all(diagnostic.trace_complete(t) for t in transports.values()) and all(
        report.get("counters", {}).get("confirmed_publications") ==
        (transports[report["cid"]]["confirmed_pair_acks"] if transports[report["cid"]] is not None else None)
        for report in reports)
    require(summary.get("diagnostic_traces_complete") is complete, "flag de traces completos incorreta")
    if summary["status"] == "COMPLETED":
        require(complete and summary.get("originals_unchanged") is True and not summary.get("source_errors")
                and summary.get("failed_stage") is None and summary.get("error") is None
                and all(r["status"] == "COMPLETED" for r in reports), "COMPLETED sem comprovação completa")
        for rows in raw.values():
            snapshots = {r["request_id"] for r in rows if r["kind"] == "REQUEST_STARTED"
                         and r["operation"] == "etcd_snapshot_read"}
            validated = {r["request_id"] for r in rows if r["kind"] == "STORE_OPERATION_FINISHED"
                         and r["status"] == "SNAPSHOT_VALIDATED"}
            require(snapshots == validated, "COMPLETED sem validação de todos os snapshots")
    workers, supervisor = {}, {}
    for role in roles:
        groups = samples(raw[role])
        if transports[role] is not None:
            for row in transports[role]["unconfirmed_writes"]:
                groups[row["operation"]]["unconfirmed_writes"] += 1
        merge_groups(workers if role in roles[:2] else supervisor, groups)
    timestamps = [r[key] for rows in raw.values() for r in rows
                  for key in ("started_ns", "finished_ns") if type(r.get(key)) is int]
    return dict(run_id=run_id, status=summary["status"], verification="VERIFIED_FINALIZED",
                known_console_result=run_id in KNOWN_RUNS, started_ns=manifest["started_ns"], host=manifest["host"],
                recorded_requests_end_ns=max(timestamps) if timestamps else None,
                originals_unchanged=summary.get("originals_unchanged"),
                diagnostic_traces_complete=complete, domain_reports=reports,
                worker_transport=finish_groups(workers), supervisor_transport=finish_groups(supervisor),
                failed_stage=summary.get("failed_stage"), error=summary.get("error")), workers, supervisor


def markdown(summary):
    counts = summary["attempt_counts"]
    lines = ["# Diagnóstico shadow pós-recuperação — consolidação offline", "",
             f"Status: {summary['status']}. Tentativas registradas: {len(summary['attempts'])}.", "",
             f"Concluídas verificadas: {counts.get('COMPLETED', 0)}; interrompidas verificadas: "
             f"{counts.get('STOPPED_ERROR', 0)}; sem recibo: {counts.get('UNFINALIZED_UNKNOWN', 0)}; "
             f"fontes não verificadas: {counts.get('UNVERIFIED', 0)}.", "",
             "Estatísticas abaixo abrangem somente os traces das tentativas finalizadas verificadas, "
             "incluindo as interrompidas. Fontes sem recibo não são zeros.", ""]
    for operation in ("etcd_pair_transaction", "etcd_snapshot_read"):
        row = summary["verified_finalized_worker_transport"].get(operation)
        if row:
            timing = row["received_http_ms"]
            lines.append(f"- {operation}: iniciadas={row['started']}, respostas={row['received']}, "
                         f"ACKs validados={row['ack_validated']}, timeouts={row['timeouts']}, "
                         f"erros={row['errors']}, sem término={row['unfinished']}; "
                         f"média HTTP={timing['mean']} ms, P95={timing['p95_nearest_rank']} ms, "
                         f"máximo={timing['maximum']} ms.")
    lines.extend(["", "## Inventário", ""])
    for attempt in summary["attempts"]:
        lines.append(f"- `{attempt['run_id']}`: {attempt['status']} ({attempt['verification']}).")
        if attempt.get("verification_error"):
            lines.append(f"  Motivo: {attempt['verification_error']}")
    lines.extend(["", "## Limitações", "", *(f"- {item}" for item in LIMITATIONS), ""])
    return "\n".join(lines)


def build(source, output):
    require(source.absolute() == source.resolve() and output.absolute() == output.resolve(), "caminhos com symlink")
    source, output = source.resolve(), output.resolve()
    require(source.name.startswith("qos-online-shadow-v2-diagnostics-post-recovery-"), "fonte não é o piloto pós-recuperação")
    require(output.parent == source.parent and output.name.startswith(OUTPUT_PREFIX) and not output.exists(),
            "use novo diretório irmão qos-shadow-post-recovery-report-*; não sobrescreva fontes/relatórios")
    config = diagnostic.load_config(source / "shadow-config.json")  # Frozen loaders only; never preflight/run.
    require(config.get("source_criteria_status") == "NOT_PASSED" and config["timing"]["request_timeout_s"] == 1,
            "critério/timeout diverge da configuração congelada")
    require(config["boundary"] == diagnostic.protocol.BOUNDARY and config["publication"] == diagnostic.protocol.PUBLICATION,
            "fronteira shadow/publicação mudou")
    before = inventory(source)
    runs = source / "runs"
    require(runs.is_dir() and not runs.is_symlink(), "inventário runs ausente/symlink")
    directories = sorted(p for p in runs.iterdir() if p.is_dir())
    require(directories, "nenhuma tentativa encontrada")
    attempts, workers, supervisor = [], {}, {}
    for root in directories:
        base = dict(run_id=root.name, known_console_result=root.name in KNOWN_RUNS)
        if not (root / "shadow-summary.json").exists():
            attempts.append(dict(base, status="UNFINALIZED_UNKNOWN", verification="INVENTORY_ONLY",
                                 manifest_present=(root / "manifest.json").is_file()))
            continue
        try:
            attempt, worker_groups, supervisor_groups = verify_attempt(root, config, before["files_sha256"])
            attempts.append(attempt)
            merge_groups(workers, worker_groups)
            merge_groups(supervisor, supervisor_groups)
        except (ValueError, KeyError, TypeError, OSError, AttributeError) as exc:
            attempts.append(dict(base, status="UNVERIFIED", verification="INVENTORY_ONLY",
                                 verification_error=str(exc)))
    found = {root.name for root in directories}
    missing = sorted(set(KNOWN_RUNS) - found)
    counts = dict(Counter(a["status"] for a in attempts))
    status = ("CONSOLIDATED_REQUIRES_REVIEW" if missing or counts.get("UNVERIFIED")
              else "CONSOLIDATED_WITH_UNFINALIZED_SOURCES" if counts.get("UNFINALIZED_UNKNOWN")
              else "CONSOLIDATED_WITH_STOPPED_SOURCES" if counts.get("STOPPED_ERROR") else "CONSOLIDATED")
    tool_hash = provenance.digest_file(Path(__file__))
    manifest = provenance.seal(dict(schema_version=SCHEMA, created_ns=time.time_ns(), source_root=str(source),
        config_sha256=config["config_sha256"], entries=[p.name for p in directories], policy=POLICY,
        source_inventory=before, diagnostic_code_sha256=diagnostic.code_snapshot(), tool_sha256=tool_hash,
        limitations=LIMITATIONS), "manifest_sha256")
    summary = provenance.seal(dict(schema_version=SCHEMA, status=status, manifest_sha256=manifest["manifest_sha256"],
        attempt_counts=counts, attempts=attempts, known_console_runs_missing=missing,
        additional_unreported_directories=sorted(found - set(KNOWN_RUNS)),
        verified_finalized_worker_transport=finish_groups(workers),
        verified_finalized_supervisor_transport=finish_groups(supervisor),
        complete_outcome_coverage=not missing and not counts.get("UNVERIFIED") and not counts.get("UNFINALIZED_UNKNOWN"),
        originals_unchanged=True, offline=True, etcd_writes_requested=0, container_mutations_requested=0,
        source_v4_criteria_status="NOT_PASSED", deadline_feasibility="UNKNOWN", promotion_eligible=False,
        limitations=LIMITATIONS), "report_sha256")
    require(diagnostic.load_config(source / "shadow-config.json") == config and inventory(source) == before
            and diagnostic.code_snapshot() == manifest["diagnostic_code_sha256"]
            and provenance.digest_file(Path(__file__)) == tool_hash,
            "fontes/código mudaram durante a auditoria; não consolide uma execução ativa")
    output.mkdir(mode=0o700)
    provenance.write_new_json(output / "manifest.json", manifest)
    provenance.write_new_json(output / "validation-summary.json", summary)
    with (output / "validation-summary.md").open("x", encoding="utf-8") as handle:
        handle.write(markdown(summary))
    return summary


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source-root", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        summary = build(args.source_root, args.output)
        counts = summary["attempt_counts"]
        print(f"status={summary['status']} registered={len(summary['attempts'])} completed={counts.get('COMPLETED', 0)} "
              f"stopped={counts.get('STOPPED_ERROR', 0)} unfinalized={counts.get('UNFINALIZED_UNKNOWN', 0)} "
              f"unverified={counts.get('UNVERIFIED', 0)} missing_known={len(summary['known_console_runs_missing'])} "
              "originals_unchanged=true offline=true promotion=false deadline=UNKNOWN")
        for operation in ("etcd_pair_transaction", "etcd_snapshot_read"):
            row = summary["verified_finalized_worker_transport"].get(operation)
            if row:
                ms = row["received_http_ms"]
                print(f"{operation}: started={row['started']} received={row['received']} ack_validated={row['ack_validated']} "
                      f"timeouts={row['timeouts']} errors={row['errors']} unfinished={row['unfinished']} "
                      f"unconfirmed={row['unconfirmed_writes']} mean_ms={ms['mean']} "
                      f"p95_ms={ms['p95_nearest_rank']} max_ms={ms['maximum']} scope=verified_finalized_workers")
        for row in summary["attempts"]:
            if row["verification"] == "INVENTORY_ONLY":
                print(f"INVENTORY {row['run_id']}: {row['status']} {row.get('verification_error', '')}")
        print(f"json={args.output / 'validation-summary.json'}")
        print(f"markdown={args.output / 'validation-summary.md'}")
        return 2 if summary["status"] == "CONSOLIDATED_REQUIRES_REVIEW" else 0
    except (ValueError, OSError, KeyError, TypeError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
