import copy
import io
import json
import tempfile
import time
import unittest
import urllib.error
from pathlib import Path
from unittest.mock import Mock, patch

import predictive_sla_shadow as legacy
import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_shadow_v2 as atomic
import predictive_sla_validation as provenance
import test_predictive_sla_shadow as old_tests
import test_predictive_sla_shadow_v2 as fixtures
from test_predictive_sla_preventive_entry_study import selected_model


RUN_ID, BASE = fixtures.RUN_ID, fixtures.BASE


def rows(handle):
    return [json.loads(line) for line in handle.getvalue().splitlines()]


class RequestTraceTests(unittest.TestCase):
    def setUp(self):
        self.handle = io.StringIO()
        self.gateway = fixtures.MemoryGateway()
        self.trace = diagnostic.RequestTrace(fixtures.config(), "test", self.handle, True, self.gateway)
        self.store = diagnostic.DiagnosticStore("http://127.0.0.1:2379", RUN_ID, self.trace)
        self.subject = provenance.SUBJECTS[0]
        self.risk, self.proposal = fixtures.pair(self.subject)

    def test_success_records_request_then_validated_ack_without_logging_payload(self):
        with patch.object(diagnostic.time, "monotonic_ns", side_effect=[0, 1_000_000, 5_000_000, 6_000_000]):
            receipt = self.store.put_pair(self.subject["cid"], self.risk, self.proposal)
        result = rows(self.handle)
        self.assertEqual([r["kind"] for r in result],
                         ["REQUEST_STARTED", "REQUEST_FINISHED", "STORE_OPERATION_FINISHED"])
        self.assertEqual(result[1]["elapsed_ms"], 4)
        self.assertEqual(result[2]["elapsed_ms"], 6)
        self.assertEqual(result[1]["status"], "HTTP_JSON_RECEIVED")
        self.assertEqual(result[1]["commit_outcome"], "UNKNOWN")
        self.assertEqual(result[2]["status"], "ACK_VALIDATED")
        self.assertEqual(result[2]["commit_outcome"], "CONFIRMED")
        self.assertEqual(result[2]["pair_mod_revision"], receipt["revision"])
        self.assertEqual(result[2]["pair_publication_ack_ns"], receipt["pair_publication_ack_ns"])
        self.assertEqual(len(self.gateway.calls), 1)
        for row in result:
            self.assertNotIn("payload", row)
            self.assertNotIn("risk", row)
            self.assertNotIn("proposal", row)
        summary = diagnostic.trace_summary(result)
        self.assertEqual(summary["confirmed_pair_acks"], 1)
        self.assertEqual(summary["unconfirmed_writes"], [])

    def test_timeout_before_or_after_commit_remains_unknown_with_elapsed_and_no_retry(self):
        for after_commit in (False, True):
            self.setUp()
            self.gateway.fail_before_commit = not after_commit
            self.gateway.fail_after_commit = after_commit
            with patch.object(diagnostic.time, "monotonic_ns", side_effect=[0, 1, 1_250_000_001, 1_300_000_000]), \
                    self.assertRaises(TimeoutError):
                self.store.put_pair(self.subject["cid"], self.risk, self.proposal)
            result = rows(self.handle)
            self.assertEqual(result[1]["status"], "TIMEOUT")
            self.assertEqual(result[1]["elapsed_ms"], 1250)
            self.assertEqual(result[1]["configured_timeout_s"], 1)
            self.assertEqual(result[1]["commit_outcome"], "UNKNOWN")
            self.assertFalse(result[1]["retry_attempted"])
            self.assertEqual(result[2]["commit_outcome"], "UNKNOWN")
            self.assertEqual(len(self.gateway.calls), 1)
            summary = diagnostic.trace_summary(result)
            self.assertEqual(summary["confirmed_pair_acks"], 0)
            self.assertEqual(summary["groups"][0]["failed_elapsed_ms"]["mean"], 1250)
            self.assertIsNone(summary["groups"][0]["received_elapsed_ms"]["mean"])
            self.assertEqual(len(summary["unconfirmed_writes"]), 1)
            self.assertEqual(len(self.gateway.kvs), 2 if after_commit else 0)

    def test_json_received_is_not_confirmation_when_atomic_ack_validation_fails(self):
        self.trace.request = Mock(return_value=dict(header=dict(revision="2"), succeeded=True, responses=[]))
        with self.assertRaises(ValueError):
            self.store.put_pair(self.subject["cid"], self.risk, self.proposal)
        result = rows(self.handle)
        self.assertEqual(result[1]["status"], "HTTP_JSON_RECEIVED")
        self.assertEqual(result[2]["status"], "VALIDATION_REJECTED")
        self.assertEqual(result[2]["commit_outcome"], "UNKNOWN")
        summary = diagnostic.trace_summary(result)
        self.assertEqual(summary["confirmed_pair_acks"], 0)
        self.assertEqual(len(summary["store_failures"]), 1)
        self.assertEqual(len(summary["unconfirmed_writes"]), 1)

    def test_locally_invalid_pair_is_not_sent_even_after_an_earlier_success(self):
        self.store.read()
        before = len(self.gateway.calls)
        with self.assertRaises(ValueError):
            self.store.put_pair("unknown", self.risk, self.proposal)
        self.assertEqual(len(self.gateway.calls), before)
        result = rows(self.handle)[-1]
        self.assertEqual(result["status"], "REJECTED_LOCALLY")
        self.assertEqual(result["commit_outcome"], "NOT_SENT")
        self.assertIsNone(result["request_id"])

    def test_client_is_forwarded_once_without_changing_timeout_or_using_a_proxy_adapter(self):
        client = Mock(return_value={"ok": True})
        with patch.object(legacy, "http_json", client):
            trace = diagnostic.RequestTrace(fixtures.config(), "preflight", self.handle)
            url = self.subject["url"] + "/predictor/qos"
            self.assertEqual(trace(url), {"ok": True})
        client.assert_called_once_with(url, None)
        self.assertEqual(diagnostic.DIAGNOSTICS["request_timeout_s"], 1)
        self.assertEqual(diagnostic.protocol.TIMING, fixtures.old_protocol.TIMING)

    def test_timeout_http_error_and_response_error_are_distinct(self):
        errors = [(urllib.error.URLError(TimeoutError("socket timed out")), "TIMEOUT"),
                  (urllib.error.HTTPError("http://127.0.0.1:6060/predictor/qos", 503, "Unavailable", {}, None), "HTTP_ERROR"),
                  (ValueError("invalid JSON"), "RESPONSE_ERROR"), (ConnectionRefusedError("refused"), "REQUEST_ERROR")]
        for error, expected in errors:
            self.handle = io.StringIO()
            trace = diagnostic.RequestTrace(fixtures.config(), "test", self.handle, request=Mock(side_effect=error))
            with self.assertRaises(type(error)):
                trace(self.subject["url"] + "/predictor/qos")
            result = rows(self.handle)[-1]
            self.assertEqual(result["status"], expected)
            self.assertEqual(result["commit_outcome"], "NOT_APPLICABLE")
            self.assertGreaterEqual(result["elapsed_ms"], 0)
            self.assertFalse(result["retry_attempted"])

    def test_readonly_trace_refuses_transactions_before_transport(self):
        self.trace.allow_writes = False
        with self.assertRaises(ValueError):
            self.store.put_pair(self.subject["cid"], self.risk, self.proposal)
        self.assertEqual(self.gateway.calls, [])
        result = rows(self.handle)
        self.assertEqual(result[0]["kind"], "REQUEST_REJECTED_LOCALLY")
        self.assertEqual(result[0]["commit_outcome"], "NOT_SENT")
        self.assertEqual(result[1]["status"], "REJECTED_LOCALLY")
        self.assertEqual(result[1]["commit_outcome"], "NOT_SENT")

    def test_foreign_endpoint_namespace_or_hidden_write_is_rejected(self):
        key = atomic.b64((self.store.prefix + "manifest").encode())
        payload = dict(compare=[dict(target="VERSION", result="EQUAL", key=key, version="0")],
                       success=[dict(request_put=dict(key=key, value=atomic.b64(b"{}")))])
        bad = [dict(payload, failure=[dict(request_delete_range=dict(key=key))]),
               dict(payload, success=[dict(request_put=dict(key=key, value="e30=", lease="1"))]),
               dict(payload, compare=[])]
        for body in bad:
            with self.assertRaises(ValueError):
                self.trace(self.store.url + "/v3/kv/txn", body)
        with self.assertRaises(ValueError):
            self.trace("http://external.invalid/v3/kv/range", {})
        with self.assertRaises(ValueError):
            self.trace(self.store.url + "/v3/kv/range",
                       dict(key=atomic.b64(b"/foreign/"), range_end=atomic.b64(b"/foreign0"), serializable=False))
        self.assertEqual(self.gateway.calls, [])

    def test_reserve_and_range_validate_the_unchanged_v2_store_contract(self):
        self.store.reserve({})
        self.assertEqual(self.store.read()["values"]["manifest"], {})
        with self.assertRaises(ValueError):
            self.store.reserve({})
        result = rows(self.handle)
        validations = [row for row in result if row["kind"] == "STORE_OPERATION_FINISHED"]
        self.assertEqual([row["status"] for row in validations],
                         ["ACK_VALIDATED", "SNAPSHOT_VALIDATED", "VALIDATION_REJECTED"])
        self.assertEqual(len(self.gateway.calls), 3)

    def test_interrupted_request_keeps_unknown_elapsed_and_commit_not_zero(self):
        def killed(url, payload=None):
            raise KeyboardInterrupt()
        self.trace.request = killed
        with self.assertRaises(KeyboardInterrupt):
            self.store.put_pair(self.subject["cid"], self.risk, self.proposal)
        result = diagnostic.trace_summary(rows(self.handle))
        self.assertEqual(result["requests_started"], 1)
        self.assertEqual(result["requests_finished"], 0)
        self.assertIsNone(result["interrupted_requests"][0]["elapsed_ms"])
        self.assertEqual(result["interrupted_requests"][0]["commit_outcome"], "UNKNOWN")
        self.assertEqual(result["confirmed_pair_acks"], 0)
        self.assertEqual(len(result["unconfirmed_writes"]), 1)

    def test_partial_last_line_does_not_discard_previous_request_start(self):
        beginning = dict(kind="REQUEST_STARTED", request_id="cid:1", operation="etcd_pair_transaction",
                         endpoint="http://127.0.0.1:2379/v3/kv/txn", started_ns=BASE, writing=True)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "trace.ndjson"
            path.write_text(json.dumps(beginning) + '\n{"kind":"REQUEST_FIN')
            result = diagnostic.read_trace(path)
        self.assertEqual(result["requests_started"], 1)
        self.assertIsNone(result["interrupted_requests"][0]["elapsed_ms"])
        self.assertTrue(result["partial_final_line"])
        self.assertFalse(diagnostic.trace_complete(result))
        self.assertIsNone(diagnostic.read_trace(Path("absent-transport.ndjson")))


class DiagnosticRuntimeTests(unittest.TestCase):
    def test_binding_restores_frozen_globals_even_when_the_worker_raises(self):
        originals = atomic.http_json, atomic.AtomicShadowStore
        trace = diagnostic.RequestTrace(fixtures.config(), "test", io.StringIO())
        with self.assertRaises(TimeoutError):
            with diagnostic.transport_bindings(trace):
                self.assertIs(atomic.http_json, trace)
                self.assertIsInstance(atomic.AtomicShadowStore("http://127.0.0.1:2379", RUN_ID), diagnostic.DiagnosticStore)
                with self.assertRaises(ValueError):
                    with diagnostic.transport_bindings(trace):
                        pass
                raise TimeoutError("failure")
        self.assertEqual((atomic.http_json, atomic.AtomicShadowStore), originals)

    def test_preflight_only_reads_with_exact_original_safety_checks(self):
        def respond(url, payload=None):
            if url.endswith("/v3/kv/range"):
                return dict(header=dict(revision="1"))
            subject = next(s for s in provenance.SUBJECTS if url.startswith(s["url"]))
            if url.endswith("/predictor/status"):
                return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                            agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                            agentic=dict(actuation_enabled=False, live_executions=0))
            return dict(enabled=True, latest=[dict(old_tests.sample(0, subject=subject), ts_ns=time.time_ns())])
        handle = io.StringIO()
        request = Mock(side_effect=respond)
        trace = diagnostic.RequestTrace(fixtures.config(), "preflight", handle, request=request)
        self.assertEqual(len(diagnostic.preflight(fixtures.config(), trace)), 2)
        self.assertEqual(request.call_count, 5)
        self.assertTrue(all(c.args[0].endswith(("/predictor/status", "/predictor/qos", "/v3/kv/range"))
                            for c in request.call_args_list))
        self.assertEqual(diagnostic.trace_summary(rows(handle))["unconfirmed_writes"], [])

    def test_worker_uses_original_forecaster_and_stops_on_real_timeout_without_retry(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.json"
            model.write_text(json.dumps(selected_model().to_dict()))
            config = fixtures.config()
            config["model"]["sha256"] = provenance.digest_file(model)
            gateway = fixtures.MemoryGateway()
            gateway.fail_after_commit = True
            def respond(url, payload=None):
                if "/v3/kv/" in url:
                    return gateway(url, payload)
                subject = provenance.SUBJECTS[0]
                if url.endswith("/predictor/status"):
                    return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                                agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                                agentic=dict(actuation_enabled=False, live_executions=0))
                return dict(enabled=True, latest=[dict(old_tests.sample(0), ts_ns=time.time_ns() - 1_000_000)])
            with patch.object(legacy, "http_json", side_effect=respond), self.assertRaises(SystemExit):
                diagnostic.worker(config, str(model), RUN_ID, provenance.SUBJECTS[0], str(root), .02)
            report = json.loads((root / "192.168.10.10-summary.json").read_text())
            trace = diagnostic.read_trace(root / "192.168.10.10-transport.ndjson")
        self.assertEqual(report["status"], "STOPPED_ERROR")
        self.assertEqual(report["counters"]["unconfirmed_publications"], 1)
        self.assertEqual(report["counters"].get("confirmed_publications", 0), 0)
        self.assertEqual(trace["request_failures"][0]["operation"], "etcd_pair_transaction")
        self.assertEqual(trace["request_failures"][0]["commit_outcome"], "UNKNOWN")
        self.assertEqual(len(gateway.calls), 1)
        self.assertEqual(len(gateway.kvs), 2)
        self.assertIsNone(report["timings"]["pair_publication_ms"]["mean"])
        self.assertFalse(report["boundary"]["authority_request"])
        self.assertFalse(report["boundary"]["actuator_request"])

    def test_unsafe_guard_is_preserved_and_never_reaches_etcd(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            model = root / "model.json"
            model.write_text(json.dumps(selected_model().to_dict()))
            config = fixtures.config()
            config["model"]["sha256"] = provenance.digest_file(model)
            request = Mock(return_value=dict(cid=provenance.SUBJECTS[0]["cid"], config=dict(auto_mitigate=True)))
            with patch.object(legacy, "http_json", request), self.assertRaises(SystemExit):
                diagnostic.worker(config, str(model), RUN_ID, provenance.SUBJECTS[0], str(root), .02)
            trace = diagnostic.read_trace(root / "192.168.10.10-transport.ndjson")
        self.assertEqual(request.call_count, 1)
        self.assertEqual(trace["groups"][0]["operation"], "telemetry_status_read")
        self.assertEqual(trace["confirmed_pair_acks"], 0)


class FrozenDiagnosticTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.FrozenAtomicConfigTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        atomic.freeze(self.fixture.source, self.fixture.output)
        self.source = self.fixture.path
        run = self.source.parent / "runs" / RUN_ID
        run.mkdir(parents=True)
        provenance.write_new_json(run / "shadow-summary.json", dict(status="STOPPED_ERROR"))
        (run / "192.168.11.10.ndjson").write_text('{"kind":"PAIR_PUBLICATION_UNCONFIRMED"}\n')
        self.output = self.source.parent.parent / "qos-online-shadow-v2-diagnostics-test"
        self.path = self.output / "shadow-config.json"

    def traced_preflight(self, config, trace):
        # Supervisor-only fixture; actual five-read safety preflight is tested
        # independently in DiagnosticRuntimeTests.
        trace.request = Mock(return_value={})
        trace(config["subjects"][0]["url"] + "/predictor/status")

    def traced_context(self, failed=False):
        context, processes = self.fixture.launcher_context(failed=failed)
        original_factory = context.Process.side_effect
        def create(target, args):
            process = original_factory(target, args)
            original_start = process.start
            def start():
                original_start()
                if process.exitcode == 0:
                    config, _, _, subject, output, _ = args
                    root = Path(output)
                    with (root / f"{subject['cid']}-transport.ndjson").open("x") as handle:
                        trace = diagnostic.RequestTrace(config, subject["cid"], handle, request=Mock(return_value={}))
                        trace(subject["url"] + "/predictor/status")
                    report_path = root / f"{subject['cid']}-summary.json"
                    report = json.loads(report_path.read_text())
                    report["counters"] = dict(confirmed_publications=0)
                    report_path.write_text(json.dumps(report))
            process.start = start
            return process
        context.Process.side_effect = create
        return context, processes

    def test_freeze_preserves_v2_failure_v1_sources_model_and_not_passed_v4(self):
        hashes = atomic.previous_artifacts(self.source)
        result = diagnostic.freeze(self.source, self.output)
        self.assertEqual(diagnostic.load_config(self.path), result)
        self.assertEqual(atomic.previous_artifacts(self.source), hashes)
        self.assertEqual(result["source_v2_artifacts_sha256"], hashes)
        self.assertEqual(result["source_criteria_status"], "NOT_PASSED")
        self.assertEqual(result["timing"], atomic.load_config(self.source)["timing"])
        self.assertEqual((self.output / "model.json").read_bytes(), (self.source.parent / "model.json").read_bytes())
        with self.assertRaises(ValueError):
            diagnostic.freeze(self.source, self.output)
        with self.assertRaises(ValueError):
            diagnostic.freeze(self.source, self.source.parent)

    def test_resealed_timeout_policy_boundary_or_code_changes_fail_before_network(self):
        original = diagnostic.freeze(self.source, self.output)
        changes = [lambda c: c["timing"].update(request_timeout_s=5),
                   lambda c: c["diagnostics"].update(request_timeout_s=5),
                   lambda c: c["policy"].update(threshold=.7),
                   lambda c: c["boundary"].update(authority_request=True),
                   lambda c: c["code_sha256"].update(unknown="bad")]
        for change in changes:
            current = copy.deepcopy(original)
            change(current)
            self.path.write_text(json.dumps(provenance.seal(current, "config_sha256")))
            with patch.object(legacy, "http_json") as request, self.assertRaises(ValueError):
                diagnostic.load_config(self.path)
            request.assert_not_called()

    def test_modified_v2_journal_blocks_new_run_without_rewriting_it(self):
        diagnostic.freeze(self.source, self.output)
        artifact = self.source.parent / "runs" / RUN_ID / "192.168.11.10.ndjson"
        artifact.write_text('{"tampered":true}\n')
        with self.assertRaises(ValueError):
            diagnostic.load_config(self.path)
        self.assertEqual(artifact.read_text(), '{"tampered":true}\n')

    def test_opt_in_and_duration_checks_precede_network_and_filesystem_outputs(self):
        with patch.object(diagnostic, "load_config") as load, self.assertRaises(ValueError):
            diagnostic.run(self.path, 60, False)
        load.assert_not_called()
        with patch.object(diagnostic, "load_config") as load, self.assertRaises(ValueError):
            diagnostic.run(self.path, 1, True)
        load.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_launcher_new_runs_have_diagnostics_and_preserve_all_sources(self):
        diagnostic.freeze(self.source, self.output)
        before = atomic.previous_artifacts(self.source)
        for _ in range(2):
            context, processes = self.traced_context()
            gateway = fixtures.MemoryGateway()
            with patch.object(diagnostic, "preflight", side_effect=self.traced_preflight), patch.object(legacy, "http_json", side_effect=gateway), \
                    patch.object(diagnostic.multiprocessing, "get_context", return_value=context), patch("builtins.print"):
                self.assertTrue(diagnostic.run(self.path, 60, True))
            self.assertFalse(any(p.terminated for p in processes))
        runs = list((self.output / "runs").iterdir())
        self.assertEqual(len(runs), 2)
        for run in runs:
            report = json.loads((run / "shadow-summary.json").read_text())
            self.assertEqual(report["schema_version"], diagnostic.SUMMARY_SCHEMA)
            self.assertEqual(report["status"], "COMPLETED")
            self.assertTrue(report["diagnostic_traces_complete"])
            self.assertTrue(report["originals_unchanged"])
            self.assertEqual(report["source_criteria_status"], "NOT_PASSED")
            self.assertEqual(report["deadline_feasibility"], "UNKNOWN")
            self.assertEqual(report["transport_summary"]["launcher"]["groups"][0]["operation"], "etcd_namespace_reserve")
            self.assertFalse(report["boundary"]["authority_request"])
            self.assertFalse(report["boundary"]["actuator_request"])
            self.assertFalse(report["boundary"]["llm_consulted"])
        self.assertEqual(atomic.previous_artifacts(self.source), before)

    def test_missing_worker_traces_cannot_be_a_completed_diagnostic(self):
        diagnostic.freeze(self.source, self.output)
        context, _ = self.fixture.launcher_context()
        gateway = fixtures.MemoryGateway()
        with patch.object(diagnostic, "preflight", side_effect=self.traced_preflight), \
                patch.object(legacy, "http_json", side_effect=gateway), \
                patch.object(diagnostic.multiprocessing, "get_context", return_value=context), patch("builtins.print"):
            self.assertFalse(diagnostic.run(self.path, 60, True))
        run = next((self.output / "runs").iterdir())
        report = json.loads((run / "shadow-summary.json").read_text())
        self.assertEqual(report["failed_stage"], "diagnostic_trace")
        self.assertFalse(report["diagnostic_traces_complete"])

    def test_failed_worker_only_interrupts_owned_peer_and_does_not_invent_zero_counts(self):
        diagnostic.freeze(self.source, self.output)
        context, processes = self.fixture.launcher_context(failed=True)
        gateway = fixtures.MemoryGateway()
        with patch.object(diagnostic, "preflight"), patch.object(legacy, "http_json", side_effect=gateway), \
                patch.object(diagnostic.multiprocessing, "get_context", return_value=context), patch("builtins.print"):
            self.assertFalse(diagnostic.run(self.path, 60, True))
        run = next((self.output / "runs").iterdir())
        report = json.loads((run / "shadow-summary.json").read_text())
        self.assertEqual(report["status"], "STOPPED_ERROR")
        self.assertTrue(processes[1].terminated)
        self.assertEqual(report["domain_reports"][1]["status"], "INTERRUPTED")
        self.assertFalse(report["domain_reports"][1]["summary_available"])
        self.assertNotIn("counters", report["domain_reports"][1])
        self.assertIsNone(report["transport_summary"][provenance.SUBJECTS[1]["cid"]])

    def test_preflight_timeout_is_recorded_without_namespace_writes_or_started_workers(self):
        diagnostic.freeze(self.source, self.output)
        with patch.object(legacy, "http_json", side_effect=TimeoutError("timed out")) as request, \
                patch.object(diagnostic.multiprocessing, "get_context") as context, patch("builtins.print"):
            self.assertFalse(diagnostic.run(self.path, 60, True))
        request.assert_called_once()
        context.assert_not_called()
        run = next((self.output / "runs").iterdir())
        report = json.loads((run / "shadow-summary.json").read_text())
        self.assertEqual(report["failed_stage"], "preflight")
        self.assertEqual(report["transport_summary"]["preflight"]["request_failures"][0]["status"], "TIMEOUT")
        self.assertIsNone(report["transport_summary"]["launcher"])
        self.assertTrue(all(row["status"] == "NOT_STARTED" for row in report["domain_reports"]))

    def test_lost_namespace_ack_is_unknown_and_stops_without_retry_or_workers(self):
        diagnostic.freeze(self.source, self.output)
        gateway = fixtures.MemoryGateway()
        gateway.fail_after_commit = True
        with patch.object(diagnostic, "preflight"), patch.object(legacy, "http_json", side_effect=gateway), \
                patch.object(diagnostic.multiprocessing, "get_context") as context, patch("builtins.print"):
            self.assertFalse(diagnostic.run(self.path, 60, True))
        context.assert_not_called()
        self.assertEqual(len(gateway.calls), 1)
        run = next((self.output / "runs").iterdir())
        report = json.loads((run / "shadow-summary.json").read_text())
        self.assertEqual(report["failed_stage"], "namespace_reservation")
        failure = report["transport_summary"]["launcher"]["request_failures"][0]
        self.assertEqual(failure["operation"], "etcd_namespace_reserve")
        self.assertEqual(failure["commit_outcome"], "UNKNOWN")
        self.assertTrue(report["originals_unchanged"])


if __name__ == "__main__":
    unittest.main()
