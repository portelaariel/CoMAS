"""Offline monitoring/ownership tests. No live ETCD, Docker or lab traffic."""

import contextlib
import copy
import io
import json
from pathlib import Path
import signal
import tempfile
import types
import unittest
from unittest.mock import Mock, patch

import predictive_sla_instrumented_ramp as tool


def metrics(value=10):
    rows = {family + "_count": value for family in tool.DISK_FAMILIES}
    rows.update({family + "_sum": value / 100 for family in tool.DISK_FAMILIES})
    return dict(rows, etcd_server_has_leader=1, process_start_time_seconds=100)


def scrape_text():
    return "\n".join(f"{key} {value}" for key, value in metrics().items()) + "\n"


class ParsingTests(unittest.TestCase):
    def test_pinned_helpers_match_without_invoking_recovery(self):
        root = Path(__file__).resolve().parents[1]
        self.assertEqual(tool.digest(root / "scripts/check_etcd2_recovery.py"), tool.CHECK_SHA)
        self.assertEqual(tool.digest(root / "scripts/recover_etcd2_member.py"), tool.RECOVERY_SHA)
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "bad.py"
            path.write_text("raise RuntimeError('must not execute')")
            with self.assertRaises(ValueError):
                tool.pinned_module("bad", path, tool.RECOVERY_SHA)

    def test_metrics_labels_buckets_and_unrelated_metric_not_retained(self):
        text = scrape_text() + '# HELP sample\nunrelated 3\netcd_disk_test_bucket{le="+Inf"} 9\n'
        parsed = tool.parse_metrics(text)
        self.assertNotIn("unrelated", parsed)
        self.assertEqual(parsed['etcd_disk_test_bucket{le="+Inf"}'], 9)
        self.assertEqual(parsed["etcd_server_has_leader"], 1)

    def test_missing_duplicate_nonfinite_and_invalid_metrics_rejected(self):
        for text in ("", scrape_text() + "etcd_server_has_leader 1\n",
                     scrape_text().replace("etcd_server_has_leader 1", "etcd_server_has_leader NaN"),
                     scrape_text() + "not valid prometheus text\n"):
            with self.subTest(text=text), self.assertRaises(ValueError):
                tool.parse_metrics(text)

    def test_scrape_is_bounded_get_no_proxy_no_redirect_no_kv_or_health(self):
        body = io.BytesIO(scrape_text().encode())
        body.status = 200
        with patch.object(tool.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = body
            self.assertEqual(tool.scrape("http://127.0.0.1:2379"), metrics())
        request = build.return_value.open.call_args.args[0]
        self.assertEqual(request.method, "GET")
        self.assertEqual(request.full_url, "http://127.0.0.1:2379/metrics")
        self.assertIsNone(request.data)
        self.assertEqual(build.return_value.open.call_args.kwargs["timeout"], 1)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsNone(tool.NoRedirect().redirect_request(None, None, 302, "", {}, "http://other"))

    def test_foreign_endpoint_and_oversized_body_fail_closed(self):
        for url in ("http://example.com:2379", "http://127.0.0.1:2379/health", "http://127.0.0.1:0"):
            with self.subTest(url=url), patch.object(tool.urllib.request, "build_opener") as build:
                with self.assertRaises(ValueError):
                    tool.scrape(url)
                build.assert_not_called()
        body = io.BytesIO(b"x" * 9)
        body.status = 200
        with patch.object(tool, "MAX_BODY", 8), patch.object(tool.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = body
            with self.assertRaises(ValueError):
                tool.scrape("http://127.0.0.1:2379")

    def test_failed_scrape_is_missing_not_zero_or_immediate_retry(self):
        with patch.object(tool, "scrape", side_effect=TimeoutError("timed out")) as scrape:
            row = tool.metric_sample("etcd1", "http://127.0.0.1:2379")
        self.assertEqual(row["status"], "MISSING")
        self.assertNotIn("metrics", row)
        self.assertGreaterEqual(row["elapsed_ms"], 0)
        scrape.assert_called_once()

    def test_adjacent_histogram_delta_not_lifetime_mean(self):
        before = dict(status="SUCCESS", monotonic_ns=1_000_000_000, metrics=metrics(10))
        after = dict(status="SUCCESS", monotonic_ns=6_000_000_000, metrics=metrics(12))
        row = tool.metric_delta(before, after)
        self.assertEqual(row["elapsed_s"], 5)
        for disk in row["disk"].values():
            self.assertEqual(disk["operations"], 2)
            self.assertAlmostEqual(disk["mean_ms"], 10)
        zero = tool.metric_delta(before, dict(after, metrics=metrics(10)))
        self.assertTrue(all(row["mean_ms"] is None for row in zero["disk"].values()))

    def test_missing_reset_restart_and_nonpositive_interval_not_normal_deltas(self):
        a = dict(status="SUCCESS", monotonic_ns=1, metrics=metrics(10))
        b = dict(status="SUCCESS", monotonic_ns=2, metrics=metrics(9))
        self.assertIsNone(tool.metric_delta(None, b))
        self.assertIsNone(tool.metric_delta(a, dict(status="MISSING")))
        self.assertEqual(tool.metric_delta(a, b)["status"], "COUNTER_RESET")
        b["metrics"]["process_start_time_seconds"] += 1
        self.assertEqual(tool.metric_delta(a, b)["status"], "PROCESS_RESTART_OR_IDENTITY_CHANGE")
        with self.assertRaises(ValueError):
            tool.metric_delta(a, a)


class LinuxTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.root = Path(temp.name)
        self.proc = self.root / "proc"
        self.proc.mkdir()
        (self.proc / "123").mkdir()
        self.cg = self.root / "cgroup"
        self.cg.mkdir()
        (self.cg / "cgroup.controllers").write_text("cpu memory io")
        (self.proc / "123/cgroup").write_text("0::/docker/test\n")
        self.group = self.cg / "docker/test"
        self.group.mkdir(parents=True)
        for name, value in {"cgroup.procs": "123\n", "cpu.stat": "usage_usec 100\nnr_throttled 2\n",
                            "cpu.max": "max 100000\n", "memory.current": "2048\n",
                            "memory.events": "oom 0\n", "io.stat": "8:0 rbytes=10 wbytes=20\n"}.items():
            (self.group / name).write_text(value)

    def test_cgroup_discovery_binds_host_pid_no_root_or_traversal(self):
        self.assertEqual(tool.cgroup_path(123, self.proc, self.cg), self.group.resolve())
        for line in ("0::/\n", "0::/../outside\n", "0::/docker/test\n0::/other\n"):
            (self.proc / "123/cgroup").write_text(line)
            with self.subTest(line=line), self.assertRaises(ValueError):
                tool.cgroup_path(123, self.proc, self.cg)

    def test_wrong_pid_and_unsupported_cgroup_fail_no_migration(self):
        (self.group / "cgroup.procs").write_text("999\n")
        with self.assertRaises(ValueError):
            tool.cgroup_path(123, self.proc, self.cg)
        (self.cg / "cgroup.controllers").unlink()
        with self.assertRaises(ValueError):
            tool.cgroup_path(123, self.proc, self.cg)

    def test_raw_host_samples_retain_steal_iowait_without_double_counting_guest(self):
        for name, value in {"stat": "cpu 1 2 3 4 5 6 7 8 99 88\ncpu0 1\n", "loadavg": "0 0 0 1/50 1",
                            "meminfo": "MemAvailable: 123 kB\n", "vmstat": "pgpgin 3\npgpgout 4\n",
                            "diskstats": "8 0 sda 1 2 3\n"}.items():
            (self.proc / name).write_text(value)
        (self.proc / "pressure").mkdir()
        for kind in ("cpu", "io", "memory"):
            (self.proc / "pressure" / kind).write_text("some avg10=0.0 total=123\n")
        row = tool.host_sample({"etcd1": self.group}, self.proc)
        self.assertEqual(row["cpu_ticks"], list(range(1, 9)))
        self.assertEqual(row["vmstat"]["pgpgout"], 4)
        self.assertEqual(row["containers"]["etcd1"]["cpu"]["nr_throttled"], 2)
        self.assertIn("sda", row["diskstats"])


class OwnershipTests(unittest.TestCase):
    def test_no_authorization_no_preflight_or_child_or_files(self):
        args = types.SimpleNamespace(allow_lab_traffic=False, allow_shadow_publication=True)
        with patch.object(tool, "validate_before") as before, patch.object(tool.subprocess, "Popen") as child:
            with self.assertRaises(ValueError):
                tool.run(args, None, None)
            before.assert_not_called()
            child.assert_not_called()

    def test_stop_only_owned_supervisor_sigint_never_kill_tree(self):
        child = Mock()
        child.poll.return_value = None
        with patch.object(tool.os, "killpg") as group:
            tool.stop_owned(child)
        child.send_signal.assert_called_once_with(signal.SIGINT)
        child.wait.assert_called_once_with(timeout=240)
        group.assert_not_called()
        child.kill.assert_not_called()
        child.terminate.assert_not_called()

    def test_exited_child_not_signalled_and_race_is_harmless(self):
        child = Mock()
        child.poll.return_value = 0
        tool.stop_owned(child)
        child.send_signal.assert_not_called()
        child.poll.side_effect = [None, 0]
        child.send_signal.side_effect = ProcessLookupError()
        tool.stop_owned(child)

    def test_logs_are_only_bounded_reads_of_selected_names(self):
        with tempfile.TemporaryDirectory() as temp, patch.object(tool.subprocess, "run") as command:
            command.return_value.returncode = 0
            result = tool.capture_logs(["etcd1", "etcd3"], Path(temp), 10**10, 20 * 10**9)
        self.assertEqual(set(result), {"etcd1", "etcd3"})
        for call in command.call_args_list:
            self.assertIn("logs", call.args[0])
            self.assertNotIn("exec", call.args[0])
            self.assertEqual(call.kwargs["timeout"], 20)
        self.assertTrue(all(row["status"] == "CAPTURED" for row in result.values()))

    def test_monitor_gap_clears_previous_no_cross_gap_delta(self):
        with tempfile.TemporaryDirectory() as temp:
            monitor = tool.Monitor(Path(temp), {}, {"etcd1": "http://127.0.0.1:2379"})
            rows = [dict(status="SUCCESS", monotonic_ns=1, metrics=metrics()), dict(status="MISSING"),
                    dict(status="SUCCESS", monotonic_ns=3, metrics=metrics(12))]
            waits = iter((False, False, True))
            def wait(duration):
                if next(waits):
                    monitor.stop.set()
            with patch.object(tool, "metric_sample", side_effect=copy.deepcopy(rows)), patch.object(monitor.stop, "wait", side_effect=wait):
                monitor.metrics_loop()
            observed = [json.loads(line) for line in (Path(temp) / "etcd-metrics.ndjson").read_text().splitlines()]
        self.assertEqual(monitor.counts["etcd1"], dict(success=2, missing=1))
        self.assertTrue(all(row["interval_delta"] is None for row in observed))
        self.assertFalse(monitor.errors)


class WorkflowTests(unittest.TestCase):
    def workflow(self, *, pilot_exit=0, baseline_missing=False, changed_identity=False):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        root = Path(temp.name)
        args = types.SimpleNamespace(protocol=root / "protocol.json", recovery_receipt=root / "recovery.json",
            recovery_tool=root / "helper.py", read_check_tool=root / "check.py",
            allow_lab_traffic=True, allow_shadow_publication=True)
        for path in (args.protocol, args.recovery_receipt, args.recovery_tool, args.read_check_tool,
                     root / "shadow-config.json", root / "plan.json"):
            path.write_text("{}\n")
        p = dict(shadow_duration_s=244, source_criteria_status="NOT_PASSED", boundary=dict(authority_request=False))
        state = dict(identity=dict(etcd1="original", etcd2="stopped", etcd3="original", recovered="active"),
                     urls=dict(etcd1="url1", etcd2="url2", etcd3="url3"), cgroups=dict(etcd1="/fake"))
        after = copy.deepcopy(state)
        if changed_identity:
            after["identity"]["recovered"] = "changed"
        monitor = Mock()
        monitor.counts = {name: dict(success=2, missing=int(baseline_missing))
                          for name in ("host", "etcd1", "etcd2", "etcd3")}
        monitor.errors = []
        child = Mock(pid=123, returncode=pilot_exit)
        child.poll.return_value = pilot_exit
        def launch(*args, **kwargs):
            (root / "pilot").mkdir()
            receipt = dict(status="COLLECTED" if pilot_exit == 0 else "STOPPED_ERROR",
                error=None if pilot_exit == 0 else "timed out", originals_unchanged=True,
                cleanup_errors=[], shadow_exit_code=pilot_exit, collector_exit_code=pilot_exit)
            (root / "pilot/pilot-run.json").write_text(json.dumps(receipt))
            kwargs["stdout"].write("status=COMPLETED\n" if pilot_exit == 0 else "status=STOPPED_ERROR\n")
            kwargs["stdout"].flush()
            return child
        logs = {name: dict(status="CAPTURED", sha256="test") for name in state["cgroups"]}
        with contextlib.ExitStack() as stack:
            stack.enter_context(patch.object(tool, "validate_before", return_value=(p, state, {"etcd1": root})))
            stack.enter_context(patch.object(tool, "runtime_state", return_value=(after, {})))
            stack.enter_context(patch.object(tool.ramp, "load_protocol", return_value=p))
            stack.enter_context(patch.object(tool, "Monitor", return_value=monitor))
            stack.enter_context(patch.object(tool, "capture_logs", return_value=logs))
            stack.enter_context(patch.object(tool.time, "sleep"))
            stack.enter_context(patch.object(tool.signal, "signal", return_value=signal.SIG_DFL))
            popen = stack.enter_context(patch.object(tool.subprocess, "Popen", side_effect=launch))
            stack.enter_context(contextlib.redirect_stdout(io.StringIO()))
            stack.enter_context(contextlib.redirect_stderr(io.StringIO()))
            result = tool.run(args, None, Mock())
        report = json.loads((root / "instrumentation/instrumentation-summary.json").read_text())
        return result, report, popen, root

    def test_one_complete_attempt_keeps_native_timeout_policy_and_separate_files(self):
        code, report, child, root = self.workflow()
        self.assertEqual((code, report["status"]), (0, "OBSERVED_COMPLETED"))
        self.assertEqual(report["source_criteria_status"], "NOT_PASSED")
        self.assertFalse(report["promotion_eligible"])
        self.assertEqual(report["deadline"], "UNKNOWN")
        self.assertTrue(report["sources_and_runtimes_unchanged"])
        self.assertEqual((report["monitoring_etcd_writes_requested"], report["container_changes_requested"]), (0, 0))
        child.assert_called_once()
        command = child.call_args.args[0]
        self.assertIn("--allow-lab-traffic", command)
        self.assertIn("--allow-shadow-publication", command)
        self.assertNotIn("--timeout", command)
        self.assertTrue(child.call_args.kwargs["start_new_session"])
        self.assertTrue((root / "instrumentation/observation-plan.json").is_file())
        self.assertEqual(set(report["artifact_sha256"]), {"observation-plan.json", "launcher.log"})

    def test_native_timeout_keeps_failed_pilot_receipt_never_relaunches(self):
        code, report, child, _ = self.workflow(pilot_exit=2)
        self.assertEqual(code, 2)
        self.assertEqual(report["pilot"]["status"], "STOPPED_ERROR")
        self.assertEqual(report["pilot"]["error"], "timed out")
        self.assertEqual(report["pilot_exit_code"], 2)
        self.assertEqual(report["status"], "REVIEW_REQUIRED")
        child.assert_called_once()

    def test_monitoring_baseline_failure_does_not_launch_ramp(self):
        code, report, child, root = self.workflow(baseline_missing=True)
        self.assertEqual(code, 2)
        self.assertIn("tráfego não iniciado", report["error"])
        child.assert_not_called()
        self.assertFalse((root / "pilot").exists())

    def test_changed_runtime_cannot_report_success(self):
        code, report, child, _ = self.workflow(changed_identity=True)
        self.assertEqual(code, 2)
        self.assertIn("runtime/cgroup", report["verification_error"])
        self.assertNotIn("sources_and_runtimes_unchanged", report)
        child.assert_called_once()

    def test_preflight_failure_does_not_create_observation_or_start_child(self):
        args = types.SimpleNamespace(protocol=Path("/not-used/protocol.json"), recovery_receipt=Path("/none"),
                                     allow_lab_traffic=True, allow_shadow_publication=True)
        with patch.object(tool, "validate_before", side_effect=ValueError("metrics indisponível")), \
             patch.object(tool.subprocess, "Popen") as child:
            with self.assertRaisesRegex(ValueError, "metrics indisponível"):
                tool.run(args, None, Mock())
        child.assert_not_called()


if __name__ == "__main__":
    unittest.main()
