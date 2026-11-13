"""Offline report fixtures use the existing recorder with an in-memory gateway."""

import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

import predictive_sla_post_recovery_report as report
import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_validation as provenance
import test_predictive_sla_shadow_v2 as fixtures


def write(path, payload):
    path.write_text(json.dumps(payload), encoding="utf-8")


class OfflineReportTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.base = Path(temporary.name).resolve()
        self.source = self.base / "qos-online-shadow-v2-diagnostics-post-recovery-test"
        self.source.mkdir()
        (self.source / "runs").mkdir()
        self.output = self.base / "qos-shadow-post-recovery-report-test"
        self.config = dict(config_sha256="config", subjects=provenance.SUBJECTS,
                           etcd_url="http://127.0.0.1:2379", source_shadow_config="/frozen/v2/shadow-config.json",
                           source_criteria_status="NOT_PASSED", publication=protocol.PUBLICATION,
                           boundary=protocol.BOUNDARY, timing=protocol.TIMING)
        write(self.source / "shadow-config.json", self.config)
        (self.source / "model.json").write_text("frozen-model")
        patcher = patch.object(diagnostic, "load_config", return_value=self.config)
        patcher.start()
        self.addCleanup(patcher.stop)
        for target in ("predictive_sla_shadow.http_json", "urllib.request.OpenerDirector.open",
                       "subprocess.run", "predictive_sla_shadow_diagnostics.run",
                       "predictive_sla_shadow_diagnostics.preflight"):
            guard = patch(target, side_effect=AssertionError("offline report must not perform runtime operations"))
            guard.start()
            self.addCleanup(guard.stop)

    def make_attempt(self, run_id, stopped=False):
        root = self.source / "runs" / run_id
        root.mkdir()
        common = dict(schema_version=diagnostic.SUMMARY_SCHEMA, run_id=run_id,
                      diagnostics=diagnostic.DIAGNOSTICS, publication=protocol.PUBLICATION,
                      boundary=protocol.BOUNDARY)
        manifest = dict(common, config_sha256=self.config["config_sha256"], duration_s=60,
                        source_shadow_config=self.config["source_shadow_config"], started_ns=time.time_ns(), host="lab")
        write(root / "manifest.json", manifest)
        gateway = fixtures.MemoryGateway()
        for role in ("preflight", "launcher"):
            with (root / f"{role}-transport.ndjson").open("w") as handle:
                trace = diagnostic.RequestTrace(self.config, role, handle, allow_writes=role == "launcher", request=gateway)
                store = diagnostic.DiagnosticStore(self.config["etcd_url"], run_id, trace)
                if role == "launcher":
                    store.reserve(manifest)
                else:
                    store.read()
        domain_reports = []
        for subject in self.config["subjects"]:
            cid = subject["cid"]
            with (root / f"{cid}-transport.ndjson").open("w") as handle:
                trace = diagnostic.RequestTrace(self.config, cid, handle, allow_writes=True, request=gateway)
                store = diagnostic.DiagnosticStore(self.config["etcd_url"], run_id, trace)
                risk = dict(schema_version=protocol.SCHEMA, kind="RISK", cid=cid, run_id=run_id,
                            boundary=protocol.BOUNDARY, observed_ns=10)
                item = dict(risk, kind="PROPOSAL", risk_sha256=protocol.digest(risk))
                if stopped:
                    gateway.fail_after_commit = True
                    with self.assertRaises(TimeoutError):
                        store.put_pair(cid, risk, item)
                    receipt = None
                    publications = []
                else:
                    receipt = store.put_pair(cid, risk, item)
                    publications = [dict(kind="PAIR_PUBLICATION", cid=cid, risk=risk, proposal=item,
                                         pair_mod_revision=receipt["revision"],
                                         pair_publication_ack_ns=receipt["pair_publication_ack_ns"], commit_outcome="CONFIRMED")]
                    store.read()
            (root / f"{cid}.ndjson").write_text("".join(json.dumps(r) + "\n" for r in publications))
            saved = dict(cid=cid, status="STOPPED_ERROR" if stopped else "COMPLETED", error="timed out" if stopped else None,
                         counters=dict(confirmed_publications=int(receipt is not None)))
            write(root / f"{cid}-summary.json", saved)
            domain_reports.append(dict(saved, summary_available=True))
        roles = [s["cid"] for s in self.config["subjects"]] + ["preflight", "launcher"]
        transports = {role: diagnostic.read_trace(root / f"{role}-transport.ndjson") for role in roles}
        summary = dict(common, status="STOPPED_ERROR" if stopped else "COMPLETED", domain_reports=domain_reports,
                       transport_summary=transports, diagnostic_traces_complete=not stopped,
                       originals_unchanged=True, source_errors=[], source_criteria_status="NOT_PASSED",
                       failed_stage="workers" if stopped else None, error=None,
                       deadline_feasibility="UNKNOWN", sla_protection_established=False,
                       artifacts_sha256={p.name: provenance.digest_file(p) for p in root.iterdir() if p.is_file()})
        write(root / "shadow-summary.json", summary)
        return root

    def populate(self):
        return [self.make_attempt(run_id) for run_id in report.KNOWN_RUNS]

    def refresh(self, root):
        path = root / "shadow-summary.json"
        summary = report.read_json(path)
        roles = [s["cid"] for s in self.config["subjects"]] + ["preflight", "launcher"]
        summary["transport_summary"] = {role: diagnostic.read_trace(root / f"{role}-transport.ndjson") for role in roles}
        summary["artifacts_sha256"] = {p.name: provenance.digest_file(p) for p in root.iterdir()
                                      if p.is_file() and p.name != "shadow-summary.json"}
        write(path, summary)

    def test_five_console_runs_all_retained_with_raw_metrics_and_no_network_or_mutation(self):
        self.populate()
        before = report.inventory(self.source)
        result = report.build(self.source, self.output)
        self.assertEqual(result["status"], "CONSOLIDATED")
        self.assertEqual(result["attempt_counts"], {"COMPLETED": 5})
        self.assertEqual(result["verified_finalized_worker_transport"]["etcd_pair_transaction"]["ack_validated"], 10)
        self.assertEqual(result["verified_finalized_worker_transport"]["etcd_snapshot_read"]["started"], 10)
        self.assertEqual(result["verified_finalized_supervisor_transport"]["etcd_snapshot_read"]["started"], 5)
        self.assertEqual(report.inventory(self.source), before)
        self.assertFalse(result["promotion_eligible"])
        self.assertEqual(result["source_v4_criteria_status"], "NOT_PASSED")
        self.assertEqual(result["deadline_feasibility"], "UNKNOWN")
        self.assertTrue((self.output / "manifest.json").is_file())
        self.assertTrue((self.output / "validation-summary.md").is_file())
        self.assertEqual(result, provenance.seal(result, "report_sha256"))

    def test_missing_receipt_is_unknown_not_zero_success_and_empty_directory_is_inventoried(self):
        self.populate()
        extra = self.source / "runs" / ("1" * 32)
        extra.mkdir()
        write(extra / "manifest.json", dict(started_ns=1))
        result = report.build(self.source, self.output)
        self.assertEqual(result["status"], "CONSOLIDATED_WITH_UNFINALIZED_SOURCES")
        self.assertEqual(result["attempt_counts"]["UNFINALIZED_UNKNOWN"], 1)
        attempt = next(a for a in result["attempts"] if a["run_id"] == extra.name)
        self.assertEqual(attempt["verification"], "INVENTORY_ONLY")
        self.assertNotIn("worker_transport", attempt)
        self.assertFalse(result["complete_outcome_coverage"])
        self.assertEqual(result["verified_finalized_worker_transport"]["etcd_pair_transaction"]["ack_validated"], 10)

    def test_stopped_extra_preserved_and_failed_requests_counted_without_reclassifying_commit(self):
        self.populate()
        self.make_attempt("2" * 32, stopped=True)
        result = report.build(self.source, self.output)
        self.assertEqual(result["status"], "CONSOLIDATED_WITH_STOPPED_SOURCES")
        self.assertEqual(result["attempt_counts"]["STOPPED_ERROR"], 1)
        group = result["verified_finalized_worker_transport"]["etcd_pair_transaction"]
        self.assertEqual((group["started"], group["ack_validated"], group["timeouts"], group["unconfirmed_writes"]),
                         (12, 10, 2, 2))

    def test_tampered_artifact_hash_is_retained_as_unverified_and_excluded_not_silently_accepted(self):
        root = self.populate()[0]
        with (root / "preflight-transport.ndjson").open("a") as handle:
            handle.write("{}\n")
        result = report.build(self.source, self.output)
        self.assertEqual(result["status"], "CONSOLIDATED_REQUIRES_REVIEW")
        self.assertEqual(result["attempt_counts"], {"COMPLETED": 4, "UNVERIFIED": 1})
        self.assertEqual(result["verified_finalized_worker_transport"]["etcd_pair_transaction"]["ack_validated"], 8)

    def test_missing_known_run_prevents_complete_cohort_claim(self):
        self.make_attempt(report.KNOWN_RUNS[0])
        result = report.build(self.source, self.output)
        self.assertEqual(len(result["known_console_runs_missing"]), 4)
        self.assertEqual(result["status"], "CONSOLIDATED_REQUIRES_REVIEW")

    def test_duplicate_start_is_rejected_even_after_rebuilding_receipt_hashes_and_summaries(self):
        root = self.populate()[0]
        path = root / "preflight-transport.ndjson"
        lines = path.read_text().splitlines(keepends=True)
        path.write_text(lines[0] + "".join(lines))
        self.refresh(root)
        result = report.build(self.source, self.output)
        invalid = next(a for a in result["attempts"] if a["run_id"] == root.name)
        self.assertIn("duplicado", invalid["verification_error"])

    def test_http_receipt_does_not_substitute_for_validated_ack(self):
        root = self.populate()[0]
        cid = self.config["subjects"][0]["cid"]
        path = root / f"{cid}-transport.ndjson"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [r for r in rows if not (r["kind"] == "STORE_OPERATION_FINISHED" and r["status"] == "ACK_VALIDATED")]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        self.refresh(root)
        result = report.build(self.source, self.output)
        invalid = next(a for a in result["attempts"] if a["run_id"] == root.name)
        self.assertIn("confirmações", invalid["verification_error"])

    def test_received_snapshot_requires_store_validation_in_a_completed_attempt(self):
        root = self.populate()[0]
        path = root / "preflight-transport.ndjson"
        rows = [json.loads(line) for line in path.read_text().splitlines()]
        rows = [r for r in rows if r["kind"] != "STORE_OPERATION_FINISHED"]
        path.write_text("".join(json.dumps(r) + "\n" for r in rows))
        self.refresh(root)
        result = report.build(self.source, self.output)
        invalid = next(a for a in result["attempts"] if a["run_id"] == root.name)
        self.assertIn("snapshots", invalid["verification_error"])

    def test_locally_rejected_read_is_not_a_sent_or_committed_request(self):
        root = self.make_attempt(report.KNOWN_RUNS[0], stopped=True)
        path = root / "preflight-transport.ndjson"
        row = dict(schema_version=diagnostic.TRACE_SCHEMA, role="preflight", kind="STORE_OPERATION_FINISHED",
                   operation="etcd_snapshot_read", request_id=None, status="REJECTED_LOCALLY", elapsed_ms=1,
                   commit_outcome="NOT_APPLICABLE")
        path.write_text(json.dumps(row) + "\n")
        summary, _ = report.trace(path, "preflight", self.config)
        self.assertEqual(summary["requests_started"], 0)
        self.assertEqual(len(summary["store_failures"]), 1)

    def test_partial_complete_trace_and_foreign_configuration_are_not_accepted(self):
        roots = self.populate()
        path = roots[0] / "preflight-transport.ndjson"
        with path.open("a") as handle:
            handle.write('{"unfinished":')
        self.refresh(roots[0])
        path = roots[1] / "manifest.json"
        manifest = report.read_json(path)
        manifest["config_sha256"] = "foreign"
        write(path, manifest)
        self.refresh(roots[1])
        result = report.build(self.source, self.output)
        self.assertEqual(result["attempt_counts"]["UNVERIFIED"], 2)

    def test_new_attempt_appearing_during_audit_blocks_output(self):
        self.populate()
        original = report.inventory
        count = 0
        def changing_inventory(root):
            nonlocal count
            count += 1
            if count == 2:
                (self.source / "runs" / ("3" * 32)).mkdir()
            return original(root)
        with patch.object(report, "inventory", side_effect=changing_inventory), self.assertRaisesRegex(ValueError, "mudaram"):
            report.build(self.source, self.output)
        self.assertFalse(self.output.exists())

    def test_output_never_overwrites_source_or_existing_report_and_symlink_is_rejected(self):
        self.populate()
        for output in (self.source, self.source / "runs/report"):
            with self.assertRaises(ValueError):
                report.build(self.source, output)
        self.output.mkdir()
        with self.assertRaises(ValueError):
            report.build(self.source, self.output)
        (self.source / "alias").symlink_to(self.source / "model.json")
        with self.assertRaises(ValueError):
            report.inventory(self.source)

    def test_raw_samples_are_pooled_not_run_means_and_interrupted_is_not_zero_latency(self):
        first = {"read": dict(started=3, received=2, timeouts=0, errors=0, ack_validated=0,
                               unconfirmed_writes=0, values_ms=[1, 1])}
        second = {"read": dict(started=1, received=1, timeouts=0, errors=0, ack_validated=0,
                                unconfirmed_writes=0, values_ms=[10])}
        report.merge_groups(first, second)
        result = report.finish_groups(first)["read"]
        self.assertEqual(result["received_http_ms"]["mean"], 4)
        self.assertEqual(result["received_http_ms"]["p95_nearest_rank"], 10)
        self.assertEqual(result["unfinished"], 1)

    def test_cli_prints_short_inventory_and_preserves_review_status(self):
        self.make_attempt(report.KNOWN_RUNS[0])
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            code = report.main(["--source-root", str(self.source), "--output", str(self.output)])
        self.assertEqual(code, 2)
        self.assertIn("missing_known=4", output.getvalue())
        self.assertIn("offline=true", output.getvalue())


if __name__ == "__main__":
    unittest.main()
