import copy
import io
import json
import signal
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import predictive_sla_shadow_diagnostics as diagnostic
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_shadow_fast_ramp as pilot
import predictive_sla_shadow_ramp as slow
import test_predictive_sla_shadow_ramp as slow_tests
import predictive_sla_shadow_ramp_analysis as analysis
import predictive_sla_validation as provenance
import test_predictive_sla_shadow_v2 as atomic_tests
import test_predictive_sla_shadow_diagnostics as diagnostic_tests
from test_predictive_sla_validation import create_case
from qos_damped_holt import QosDampedHoltModel


BASE, RUN_ID = slow_tests.BASE, slow_tests.RUN_ID
traces, VALUES = slow_tests.traces, slow_tests.VALUES


class RuntimeSafetyTests(unittest.TestCase):
    def test_flags_precede_files_network_or_traffic(self):
        for traffic, publication in ((False, False), (True, False), (False, True)):
            with patch.object(pilot, "load_protocol") as load, self.assertRaises(ValueError):
                pilot.run(Path("absent/protocol.json"), traffic, publication)
            load.assert_not_called()
        with patch.object(pilot, "load_protocol") as load, self.assertRaises(ValueError):
            pilot.collect(Path("absent/protocol.json"), False)
        load.assert_not_called()

    def test_preflight_is_readonly_and_checks_native_lab_before_shadow_reads(self):
        plan = {"schema": "plan"}
        config = {"schema": "config"}
        order = []
        with patch.object(pilot, "load_protocol", return_value=plan), \
                patch.object(pilot.collector, "preflight", side_effect=lambda p: order.append("lab") or {"status":"READY"}), \
                patch.object(diagnostic, "load_config", return_value=config), \
                patch.object(diagnostic, "preflight", side_effect=lambda p: order.append("shadow")), \
                patch.object(pilot.subprocess, "Popen") as popen:
            self.assertEqual(pilot.preflight(Path("protocol.json")), {"status":"READY"})
        self.assertEqual(order, ["lab", "shadow"])
        popen.assert_not_called()

    def test_collection_uses_existing_case_cleanup_and_shared_lock_without_other_changes(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            plan = dict(case={"case_id":"online-fast-ramp"})
            with patch.object(pilot, "load_protocol", return_value=plan), patch.object(pilot.sys, "platform", "linux"), \
                    patch.object(pilot.signal, "signal") as signals, patch.object(pilot.fcntl, "flock") as flock, \
                    patch.object(pilot.collector, "collect_case") as collect:
                pilot.collect(root / "protocol.json", True)
            collect.assert_called_once_with(plan, plan["case"], root.resolve() / "pilot" / "workload")
            self.assertEqual(flock.call_count, 1)
            self.assertEqual(signals.call_count, 2)

    def test_busy_lab_lock_prevents_any_workload(self):
        with patch.object(pilot, "load_protocol", return_value={}), patch.object(pilot.sys, "platform", "linux"), \
                patch.object(pilot.signal, "signal"), patch.object(pilot.fcntl, "flock", side_effect=BlockingIOError()), \
                patch.object(pilot.collector, "collect_case") as collect, self.assertRaises(BlockingIOError):
            pilot.collect(Path("protocol.json"), True)
        collect.assert_not_called()

    def test_collector_stop_requests_owned_cleanup_without_force_kill(self):
        process = Mock()
        process.poll.side_effect = [None, None, 2, 2]
        with patch.object(pilot.time, "sleep"):
            pilot.stop_collection(process, 5)
        process.send_signal.assert_called_once_with(signal.SIGTERM)
        process.kill.assert_not_called()
        process.terminate.assert_not_called()

    def test_unknown_shadow_group_is_never_signalled(self):
        process = Mock(pid=123)
        process.poll.return_value = None
        with patch.object(pilot.os, "getpgid", return_value=777), patch.object(pilot.os, "killpg") as kill, self.assertRaises(ValueError):
            pilot.stop_shadow(process)
        kill.assert_not_called()

    def test_failed_shadow_cannot_start_traffic_during_readiness_wait(self):
        process = Mock()
        process.poll.return_value = 2
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(ValueError):
            pilot.await_ready({}, Path(directory), process, set(), 10)

    def test_ready_requires_confirmed_forecast_observe_not_priming_risk(self):
        config, _, journals = traces([.2, .2])
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / RUN_ID
            root.mkdir()
            for cid, events in journals.items():
                (root / f"{cid}.ndjson").write_text("".join(json.dumps(event) + "\n" for event in events))
            with patch.object(pilot.time, "time_ns", return_value=BASE + 2_050_000_000):
                self.assertTrue(slow.ready(config, root))
            for cid, events in journals.items():
                (root / f"{cid}.ndjson").write_text("".join(json.dumps(event) + "\n" for event in events[:3]))
            with patch.object(pilot.time, "time_ns", return_value=BASE + 50_000_000):
                self.assertFalse(slow.ready(config, root))

    def test_compact_output_does_not_claim_deployment_or_deadline_pass(self):
        report = analysis.analyze(*self.fixture_for_report())
        with patch("sys.stdout", new_callable=io.StringIO) as output:
            pilot.print_compact(report)
        self.assertIn("joint_pre_onset", output.getvalue())
        self.assertIn("strict_matched=", output.getvalue())
        self.assertNotIn("strict_activations=", output.getvalue())
        self.assertNotIn("PASSED", output.getvalue())

    def fixture_for_report(self):
        config, series, journals = traces(VALUES)
        return config, RUN_ID, series, journals


class FrozenRampTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Reuse one expensive real frozen lineage. Each test copies it into an
        # isolated sibling with paths kept original; source mutations are undone.
        cls.fixture = diagnostic_tests.FrozenDiagnosticTests(methodName="runTest")
        cls.fixture.setUp()
        diagnostic.freeze(cls.fixture.source, cls.fixture.output)
        cls.source = cls.fixture.path
        cls.config = diagnostic.load_config(cls.source)
        cls.idle = cls.source.parent / "runs" / RUN_ID
        cls.idle.mkdir(parents=True)
        provenance.write_new_json(cls.idle / "manifest.json", dict(config_sha256=cls.config["config_sha256"]))
        for name in ("preflight-transport.ndjson", "launcher-transport.ndjson"):
            (cls.idle / name).write_text('{"kind":"synthetic_fixture"}\n')
        for subject in cls.config["subjects"]:
            for suffix in (".ndjson", "-transport.ndjson"):
                (cls.idle / (subject["cid"] + suffix)).write_text('{"kind":"synthetic_fixture"}\n')
            provenance.write_new_json(cls.idle / (subject["cid"] + "-summary.json"), dict(cid=subject["cid"], status="COMPLETED"))
        cls.summary = dict(schema_version=diagnostic.SUMMARY_SCHEMA, status="COMPLETED", run_id=RUN_ID,
            originals_unchanged=True, diagnostic_traces_complete=True, boundary=protocol.BOUNDARY,
            domain_reports=[dict(cid=s["cid"], status="COMPLETED", counters=dict(activations=0, confirmed_publications=31))
                            for s in cls.config["subjects"]],
            artifacts_sha256={path.name: provenance.digest_file(path) for path in cls.idle.iterdir()})
        provenance.write_new_json(cls.idle / "shadow-summary.json", cls.summary)

    @classmethod
    def tearDownClass(cls):
        cls.fixture.doCleanups()

    def destination(self, name):
        return self.source.parent.parent / ("qos-online-shadow-v2-diagnostics-fast-ramp-" + name)

    def test_freeze_real_lineage_keeps_idle_failed_v4_model_policy_and_sources(self):
        before = atomic_tests.online.previous_artifacts(self.source)
        output = self.destination("freeze")
        with patch.object(pilot.collector, "preflight", side_effect=AssertionError("network")), \
                patch.object(pilot.subprocess, "Popen", side_effect=AssertionError("traffic")):
            result = pilot.freeze(self.source, self.idle, output)
            self.assertEqual(result, pilot.load_protocol(output / "protocol.json"))
        self.assertEqual(result["source_criteria_status"], "NOT_PASSED")
        self.assertEqual(result["policy"], self.config["policy"])
        self.assertEqual(result["case"]["profile"], "fast-ramp")
        self.assertEqual(result["case"]["duration_s"], 126)
        self.assertEqual(result["shadow_duration_s"], 200)
        self.assertEqual(result["source_artifacts_sha256"], before)
        self.assertEqual(atomic_tests.online.previous_artifacts(self.source), before)
        self.assertEqual((output / "model.json").read_bytes(), (self.source.parent / "model.json").read_bytes())
        self.assertFalse(result["promotion_eligible"])
        self.assertFalse(result["deployment_eligible"])
        with self.assertRaises(ValueError):
            pilot.freeze(self.source, self.idle, output)

    def test_missing_fast_profile_is_rejected_before_creating_output(self):
        with self.assertRaisesRegex(ValueError, "rampa rápida"):
            pilot.case_from({"cases": [{"profile": "slow-ramp"}]})

    def test_fast_profile_is_exact_native_case_without_changing_source(self):
        _, original, _ = pilot.source_state(self.source, self.idle)
        before = copy.deepcopy(original)
        expected = copy.deepcopy(next(c for c in original["cases"] if c["profile"] == "fast-ramp"))
        expected["case_id"] = "online-fast-ramp"
        self.assertEqual(pilot.case_from(original), expected)
        self.assertEqual(original, before)
        self.assertEqual(expected["stages"], [
            {"rate_mbit": 20, "duration_s": 40},
            *[{"rate_mbit": rate, "duration_s": 4} for rate in (40, 60, 80, 100)],
            {"rate_mbit": 100, "duration_s": 40},
            {"rate_mbit": 20, "duration_s": 30},
        ])
        self.assertEqual(pilot.RUNTIME, slow.RUNTIME)
        self.assertTrue(set(slow.CODE_FILES) <= set(pilot.CODE_FILES))
        self.assertIn("predictive_sla_shadow_fast_ramp.py", pilot.CODE_FILES)

    def test_slow_output_is_refused_and_source_bytes_are_unchanged(self):
        output = self.source.parent.parent / "qos-online-shadow-v2-diagnostics-ramp-preserved"
        output.mkdir()
        marker = output / "protocol.json"
        marker.write_text("previous slow run")
        with self.assertRaises(ValueError):
            pilot.freeze(self.source, self.idle, output)
        self.assertEqual(marker.read_text(), "previous slow run")

    def test_resealed_workload_model_policy_timeouts_or_boundary_changes_are_rejected(self):
        output = self.destination("tamper")
        original = pilot.freeze(self.source, self.idle, output)
        path = output / "protocol.json"
        for change in (lambda p: p["case"].update(profile="slow-ramp"),
                       lambda p: p["case"]["stages"][0].update(rate_mbit=120),
                       lambda p: p["collection"].update(udp_port=5001),
                       lambda p: p["policy"].update(threshold=.75),
                       lambda p: p["runtime"].update(startup_timeout_s=100),
                       lambda p: p["boundary"].update(authority_request=True),
                       lambda p: p.update(shadow_duration_s=500)):
            current = copy.deepcopy(original)
            change(current)
            path.write_text(json.dumps(provenance.seal(current, "protocol_sha256")))
            with self.assertRaises(ValueError):
                pilot.load_protocol(path)

    def test_modified_idle_artifact_is_rejected_without_rewriting_it(self):
        output = self.destination("source-change")
        pilot.freeze(self.source, self.idle, output)
        artifact = self.idle / "manifest.json"
        contents = artifact.read_bytes()
        self.addCleanup(artifact.write_bytes, contents)
        artifact.write_text('{"tampered":true}\n')
        with self.assertRaises(ValueError):
            pilot.load_protocol(output / "protocol.json")
        self.assertEqual(artifact.read_text(), '{"tampered":true}\n')

    def test_failed_or_active_idle_cannot_freeze_new_traffic_plan(self):
        path = self.idle / "shadow-summary.json"
        contents = path.read_bytes()
        self.addCleanup(path.write_bytes, contents)
        for ordinal, change in enumerate((lambda s: s.update(status="STOPPED_ERROR"),
                                         lambda s: s["domain_reports"][0]["counters"].update(activations=1),
                                         lambda s: s.update(artifacts_sha256={}))):
            summary = copy.deepcopy(self.summary)
            change(summary)
            path.write_text(json.dumps(summary))
            output = self.destination("bad-idle-" + str(ordinal))
            with self.assertRaises(ValueError):
                pilot.freeze(self.source, self.idle, output)
            self.assertFalse(output.exists())

    def test_offline_evaluation_reads_exact_new_workload_and_corresponding_owned_shadow_journals(self):
        output = self.destination("paired-evaluation")
        p = pilot.freeze(self.source, self.idle, output)
        native_root = create_case(p, p["case"], output / "pilot")
        native_root.rename(output / "pilot" / "workload")
        native_root = output / "pilot" / "workload"
        record_path = native_root / "run.json"
        record = json.loads(record_path.read_text())
        record.update(cleanup_errors=[], process_return_codes_after_cleanup=[-2, -2])
        record_path.write_text(json.dumps(provenance.seal(record, "run_sha256")))
        series, _, _ = provenance._read_case(p, p["case"], native_root)
        config = diagnostic.load_config(output / "shadow-config.json")
        model = QosDampedHoltModel.load(output / "model.json")
        values = [.2, .2] + series[0]["values"] + [.2, .2]
        _, _, journals = traces(values, config=config, model=model,
                               base_ns=series[0]["timestamps_ns"][0] - 4_000_000_000, domain_offset=.001)
        shadow = output / "runs" / RUN_ID
        shadow.mkdir(parents=True)
        manifest_started = record["started_ns"] - 6_000_000_000
        provenance.write_new_json(shadow / "manifest.json", dict(config_sha256=config["config_sha256"],
            started_ns=manifest_started, duration_s=p["shadow_duration_s"]))
        for cid, events in journals.items():
            (shadow / f"{cid}.ndjson").write_text("".join(json.dumps(e) + "\n" for e in events))
            (shadow / f"{cid}-transport.ndjson").write_text('{"kind":"synthetic_fixture"}\n')
            provenance.write_new_json(shadow / f"{cid}-summary.json", dict(status="COMPLETED"))
        (shadow / "preflight-transport.ndjson").write_text('{"kind":"synthetic_fixture"}\n')
        (shadow / "launcher-transport.ndjson").write_text('{"kind":"synthetic_fixture","pid":12345}\n')
        provenance.write_new_json(shadow / "shadow-summary.json", dict(schema_version=diagnostic.SUMMARY_SCHEMA,
            status="COMPLETED", originals_unchanged=True, diagnostic_traces_complete=True, boundary=p["boundary"],
            artifacts_sha256={path.name: provenance.digest_file(path) for path in shadow.iterdir()}))
        receipt = provenance.seal(dict(schema_version=pilot.RECEIPT_SCHEMA, status="COLLECTED",
            protocol_sha256=p["protocol_sha256"], boundary=p["boundary"], originals_unchanged=True,
            source_errors=[], cleanup_errors=[], shadow_exit_code=0, collector_exit_code=0,
            shadow_launcher_pid=12345, started_ns=manifest_started - 1, shadow_run=str(shadow)), "run_sha256")
        with patch.object(pilot.collector, "preflight", side_effect=AssertionError("network")), \
                patch.object(pilot.subprocess, "Popen", side_effect=AssertionError("traffic")):
            report = pilot.evaluate(output / "protocol.json", receipt)
        self.assertEqual(report["measurement_status"], "PAIRED")
        self.assertTrue(report["originals_unchanged"])
        self.assertEqual(report["source_criteria_status"], "NOT_PASSED")
        self.assertEqual(report["schema_version"], pilot.REPORT_SCHEMA)
        self.assertEqual(report["profile"], "fast-ramp")
        self.assertEqual(report["workload"], p["case"])
        self.assertTrue(all(len(d["episode_timings"]) >= 1 for d in report["domains"]))
        self.assertTrue(all(d["joint_pre_sampled_onset"] + d["joint_at_or_after_sampled_onset"] +
                            d["joint_without_recorded_agreement"] == len(d["episode_timings"])
                            for d in report["domains"]))
        wrong = provenance.seal(dict(receipt, shadow_launcher_pid=99), "run_sha256")
        with self.assertRaisesRegex(ValueError, "processo lançado"):
            pilot.evaluate(output / "protocol.json", wrong)
        self.assertFalse(report["boundary"]["authority_request"])
        self.assertFalse(report["boundary"]["actuator_request"])
        self.assertFalse(report["boundary"]["llm_consulted"])
        late_config, late_series, late_journals = traces(VALUES, forecast_delay_ns=2_200_000_000)
        late_report = analysis.analyze(late_config, RUN_ID, late_series, late_journals)
        self.assertTrue(all(d["joint_at_or_after_sampled_onset"] == 1 for d in late_report["domains"]))


class CoupledLauncherTests(unittest.TestCase):
    def settings(self):
        return dict(protocol_sha256="protocol", case=dict(duration_s=126), runtime=pilot.RUNTIME,
                    shadow_duration_s=200, boundary=protocol.BOUNDARY)

    def launch(self, root, scenario):
        self.processes = []
        class Process:
            def __init__(inner, args, **kwargs):
                inner.index, inner.args, inner.kwargs = len(self.processes), args, kwargs
                inner.pid, inner.returncode, inner.polls = 1_000_000 + inner.index, None, 0
                self.processes.append(inner)
            def poll(inner):
                inner.polls += 1
                if scenario == "shadow_failed" and inner.index == 0:
                    inner.returncode = 2
                if inner.index == 1 and scenario == "completed" and inner.polls >= 2:
                    inner.returncode = 0
                return inner.returncode
            def wait(inner, timeout):
                inner.returncode = 0
                return 0
        def stop(inner):
            if inner is not None and inner.returncode is None:
                inner.returncode = 143
        config, series, journals = traces(VALUES)
        report = analysis.analyze(config, RUN_ID, series, journals)
        with patch.object(pilot, "load_protocol", return_value=self.settings()), patch.object(pilot, "preflight"), \
                patch.object(diagnostic, "load_config", return_value=config), \
                patch.object(pilot.subprocess, "Popen", side_effect=Process), \
                patch.object(pilot, "await_ready", return_value=root / "runs" / RUN_ID), \
                patch.object(pilot, "stop_collection", side_effect=lambda p,t: stop(p)) as cleanup, \
                patch.object(pilot, "stop_shadow", side_effect=stop), patch.object(pilot.time, "sleep"), \
                patch.object(pilot, "evaluate", return_value=report) as evaluate, patch("builtins.print"):
            result = pilot.run(root / "protocol.json", True, True)
        return result, cleanup, evaluate

    def test_success_launches_only_scoped_new_sessions_and_writes_paired_report(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            result, cleanup, evaluate = self.launch(root, "completed")
            self.assertTrue(result)
            self.assertEqual(len(self.processes), 2)
            self.assertTrue(all(p.kwargs["start_new_session"] for p in self.processes))
            self.assertIn("--allow-shadow-publication", self.processes[0].args)
            self.assertIn("_collect", self.processes[1].args)
            self.assertIn(str(pilot.ROOT / "predictive_sla_shadow_fast_ramp.py"), self.processes[1].args)
            self.assertNotIn(str(pilot.ROOT / "predictive_sla_shadow_ramp.py"), self.processes[1].args)
            self.assertIn("--allow-lab-traffic", self.processes[1].args)
            self.assertTrue((root / "pilot" / "paired-timing.json").exists())
            receipt = json.loads((root / "pilot" / "pilot-run.json").read_text())
            self.assertEqual(receipt["status"], "COLLECTED")
            self.assertFalse(receipt["boundary"]["actuator_request"])
            evaluate.assert_called_once()
            cleanup.assert_called_once()

    def test_shadow_failure_interrupts_owned_collector_and_cannot_be_evaluated_as_success(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            result, cleanup, evaluate = self.launch(root, "shadow_failed")
            self.assertFalse(result)
            self.assertEqual(self.processes[1].returncode, 143)
            evaluate.assert_not_called()
            self.assertFalse((root / "pilot" / "paired-timing.json").exists())
            receipt = json.loads((root / "pilot" / "pilot-run.json").read_text())
            self.assertEqual(receipt["status"], "STOPPED_ERROR")
            self.assertEqual(receipt["shadow_exit_code"], 2)
            self.assertEqual(receipt["collector_exit_code"], 143)
            cleanup.assert_called_once_with(self.processes[1], pilot.RUNTIME["collector_cleanup_timeout_s"])

    def test_failed_readiness_never_spawns_collector(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            shadow = Mock(pid=999_999, returncode=2)
            shadow.poll.return_value = 2
            with patch.object(pilot, "load_protocol", return_value=self.settings()), patch.object(pilot, "preflight"), \
                    patch.object(diagnostic, "load_config", return_value={}), \
                    patch.object(pilot.subprocess, "Popen", return_value=shadow) as popen, \
                    patch.object(pilot, "await_ready", side_effect=ValueError("not ready")), \
                    patch.object(pilot, "stop_collection"), patch.object(pilot, "stop_shadow"), patch("builtins.print"):
                self.assertFalse(pilot.run(root / "protocol.json", True, True))
            self.assertEqual(popen.call_count, 1)
            receipt = json.loads((root / "pilot" / "pilot-run.json").read_text())
            self.assertIsNone(receipt["collector_exit_code"])
            self.assertEqual(receipt["status"], "STOPPED_ERROR")

    def test_existing_pilot_output_is_never_overwritten_or_started_again(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory).resolve()
            (root / "pilot").mkdir()
            owned = root / "pilot" / "preserved.json"
            owned.write_text("original")
            with patch.object(pilot, "load_protocol", return_value=self.settings()), patch.object(pilot, "preflight"), \
                    patch.object(pilot.subprocess, "Popen") as popen, self.assertRaises(FileExistsError):
                pilot.run(root / "protocol.json", True, True)
            popen.assert_not_called()
            self.assertEqual(owned.read_text(), "original")


if __name__ == "__main__":
    unittest.main()
