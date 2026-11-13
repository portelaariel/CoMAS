"""Offline HTTP/Docker doubles: these tests do not validate a live ETCD server."""

import contextlib
import copy
import importlib.util
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
import urllib.error


ROOT = Path(__file__).resolve().parents[1]


def module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    result = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(result)
    return result


check = module("check_etcd_recovery", ROOT / "scripts/check_etcd2_recovery.py")
fixtures = module("etcd_recovery_fixtures", ROOT / "tests/test_etcd2_member_recovery.py")
helper = fixtures.recovery
RUN_ID = "a" * 32
RUNTIME = "comas-etcd2-recovered-" + RUN_ID[:12]


def read_response(name):
    return dict(header=dict(cluster_id=str(fixtures.CLUSTER),
                            member_id=str(int(helper.MEMBERS[name][0], 16)),
                            revision="100", raft_term="9"))


class ReadOnlyDocker:
    def __init__(self):
        self.rows = fixtures.originals()
        for name, port in (("etcd1", "2379"), ("etcd2", "2380"), ("etcd3", "2390")):
            self.rows[name]["HostConfig"]["PortBindings"]["2379/tcp"][0]["HostPort"] = port
        self.saved = copy.deepcopy(self.rows)
        recovered = copy.deepcopy(self.rows["etcd2"])
        recovered.update(Name="/" + RUNTIME, Id="new-runtime")
        recovered["State"].update(Running=True, Status="running")
        recovered["Config"]["Labels"] = {helper.LABEL: RUN_ID}
        recovered["NetworkSettings"]["Networks"][helper.NETWORK] = dict(IPAddress="192.168.253.12")
        self.rows[RUNTIME] = recovered
        self.calls = []
        self.alarms = []

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        if args[0] == "inspect":
            return json.dumps([self.rows[name] for name in args[1:]])
        if args[0] == "exec":
            if args[-2:] == ("member", "list"):
                return json.dumps(fixtures.members())
            if args[-2:] == ("alarm", "list"):
                return json.dumps(dict(alarms=self.alarms))
            if args[-2:] == ("endpoint", "status"):
                endpoint = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--endpoints="))
                name = next(name for name, (_, ip) in helper.MEMBERS.items() if endpoint == f"http://{ip}:2379")
                return json.dumps([dict(Status=fixtures.status(name))])
        raise AssertionError(f"Not an allowed read-only Docker operation: {args}")


class HttpTests(unittest.TestCase):
    def test_uint64_decimal_strings_do_not_lose_precision(self):
        self.assertEqual(check.uint64(str(fixtures.CLUSTER)), fixtures.CLUSTER)
        for value in (None, float(fixtures.CLUSTER), True, "1.0", "-1", "0", str(2**64)):
            with self.subTest(value=value), self.assertRaises(ValueError):
                check.uint64(value)

    def test_read_request_is_exact_key_linearizable_and_has_no_proxy_or_redirect(self):
        response = io.BytesIO(json.dumps(read_response("etcd1")).encode())
        response.status = 200
        with patch.object(check.urllib.request, "build_opener") as build:
            build.return_value.open.return_value = response
            self.assertEqual(check.read_key("http://127.0.0.1:2379"), read_response("etcd1"))
        call = build.return_value.open.call_args
        request = call.args[0]
        self.assertEqual(request.full_url, "http://127.0.0.1:2379/v3/kv/range")
        self.assertEqual(request.method, "POST")
        self.assertEqual(json.loads(request.data), dict(key=check.base64.b64encode(check.KEY.encode()).decode(),
                                                       keys_only=True, serializable=False))
        self.assertEqual(call.kwargs["timeout"], 1)
        self.assertEqual(build.call_args.args[0].proxies, {})
        self.assertIsInstance(build.call_args.args[1], check.NoRedirect)
        self.assertIsNone(check.NoRedirect().redirect_request(None, None, 302, "", {}, "http://evil"))

    def test_external_or_non_http_endpoint_is_not_called(self):
        for url in ("http://example.com:2379", "https://127.0.0.1:2379", "http://127.0.0.1:2379/txn"):
            with self.subTest(url=url), patch.object(check.urllib.request, "build_opener") as build:
                with self.assertRaises(ValueError):
                    check.read_key(url)
                build.assert_not_called()

    def test_empty_read_success_but_wrong_identity_and_missing_header_rejected(self):
        member = int(helper.MEMBERS["etcd1"][0], 16)
        self.assertEqual(check.validate_read(read_response("etcd1"), fixtures.CLUSTER, member), 100)
        for response in ({}, read_response("etcd2")):
            with self.assertRaises(ValueError):
                check.validate_read(response, fixtures.CLUSTER, member)
        with self.assertRaises(ValueError):
            check.validate_read(read_response("etcd1"), fixtures.CLUSTER + 1, member)

    def test_mixed_failed_samples_not_excluded_from_counts_or_retried(self):
        urls = {name: name for name in helper.MEMBERS}
        calls = []
        def request(name):
            calls.append(name)
            if name == "etcd2":
                raise urllib.error.URLError(TimeoutError("timed out"))
            if name == "etcd3":
                return {}
            return read_response(name)
        with patch.object(check.time, "sleep"):
            rows = check.measure(urls, helper.MEMBERS, fixtures.CLUSTER, 2, request)
        self.assertEqual(calls, ["etcd1", "etcd2", "etcd3", "etcd2", "etcd3", "etcd1"])
        self.assertEqual(check.latency_summary(rows["etcd1"])["successful"], 2)
        summary = check.latency_summary(rows["etcd2"])
        self.assertEqual((summary["timeouts"], summary["failed"]), (2, 2))
        self.assertIsNone(summary["mean_ms"])
        self.assertEqual(check.latency_summary(rows["etcd3"])["failed"], 2)

    def test_success_over_socket_timeout_not_mislabeled_as_timeout(self):
        rows = [dict(status="SUCCESS", elapsed_ms=1100), dict(status="TIMEOUT", elapsed_ms=1002)]
        summary = check.latency_summary(rows)
        self.assertEqual((summary["successful_over_1000ms"], summary["timeouts"]), (1, 1))
        self.assertEqual(summary["p95_successful_ms"], 1100)

    def test_pinned_helper_must_be_the_version_used_for_recovery(self):
        self.assertEqual(check.load_helper(ROOT / "scripts/recover_etcd2_member.py").MEMBERS, helper.MEMBERS)
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "different.py"
            path.write_text("raise RuntimeError('must not execute')")
            with self.assertRaises(ValueError):
                check.load_helper(path)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.base = Path(temp.name)
        self.receipt_path = self.base / "recovery/recovery.json"
        self.receipt_path.parent.mkdir()
        self.docker = ReadOnlyDocker()
        self.receipt = dict(status="RECOVERED", original_containers_unchanged=True, cleanup_errors=[],
                            tool_sha256=check.RECOVERY_SHA256, runtime=RUNTIME, run_id=RUN_ID,
                            recovered_status=dict(raftAppliedIndex=100))
        self.plan = dict(saved=self.docker.saved, image=fixtures.IMAGE, state=dict(cluster_id=fixtures.CLUSTER))
        self.receipt_path.write_text(json.dumps(self.receipt))
        (self.receipt_path.parent / "plan.json").write_text(json.dumps(self.plan))

    def run_check(self, request=None):
        port_names = {"2379": "etcd1", "2380": "etcd2", "2390": "etcd3"}
        if request is None:
            request = lambda url: read_response(port_names[url.rsplit(":", 1)[1]])
        with patch.object(check.time, "sleep"), contextlib.redirect_stdout(io.StringIO()), \
                contextlib.redirect_stderr(io.StringIO()):
            code = check.run(helper, self.docker, self.receipt_path, 2, request)
        reports = list(self.base.glob("etcd-post-recovery-*/read-check.json"))
        self.assertEqual(len(reports), 1)
        return code, json.loads(reports[0].read_text())

    def test_success_keeps_originals_receipt_and_plan_unchanged(self):
        saved = copy.deepcopy(self.docker.rows)
        hashes = [check.digest(path) for path in (self.receipt_path, self.receipt_path.parent / "plan.json")]
        code, report = self.run_check()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "OBSERVED_READS_OK")
        self.assertTrue(report["originals_unchanged"] and report["runtime_unchanged"] and report["sources_unchanged"])
        self.assertTrue(all(row["successful"] == 2 for row in report["summary"].values()))
        self.assertEqual(self.docker.rows, saved)
        self.assertEqual(hashes, [check.digest(path) for path in (self.receipt_path, self.receipt_path.parent / "plan.json")])
        self.assertFalse(report["promotion_eligible"])

    def test_timeout_remains_a_read_failure_not_recovery_success(self):
        def request(url):
            raise TimeoutError("timed out")
        code, report = self.run_check(request)
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "OBSERVED_READ_FAILURES")
        self.assertTrue(all(row["timeouts"] == 2 for row in report["summary"].values()))

    def test_started_original_stops_observation_without_mutation(self):
        self.docker.rows["etcd2"]["State"].update(Running=True, Status="running")
        code, report = self.run_check(lambda url: self.fail("HTTP must not be called"))
        self.assertEqual(code, 2)
        self.assertEqual(report["status"], "STOPPED_ERROR")
        self.assertEqual(report["records"], {})

    def test_alarm_stops_observation_without_disarming(self):
        self.docker.alarms = [dict(alarm="NOSPACE", memberID="123")]
        code, report = self.run_check(lambda url: self.fail("HTTP must not be called"))
        self.assertEqual(code, 2)
        self.assertIn("alarmes", report["error"])
        self.assertFalse(any("disarm" in call for call in self.docker.calls))

    def test_runtime_restart_detected_and_not_automatically_fixed(self):
        def request(url):
            self.docker.rows[RUNTIME]["RestartCount"] = 1
            return read_response({"2379": "etcd1", "2380": "etcd2", "2390": "etcd3"}[url.rsplit(":", 1)[1]])
        code, report = self.run_check(request)
        self.assertEqual(code, 2)
        self.assertIn("reiniciou/mudou", report["verification_error"])

    def test_failed_recovery_receipt_is_not_observed(self):
        self.receipt["status"] = "STOPPED_ERROR"
        self.receipt_path.write_text(json.dumps(self.receipt))
        with self.assertRaises(ValueError):
            check.run(helper, self.docker, self.receipt_path, 2)
        self.assertEqual(list(self.base.glob("etcd-post-recovery-*")), [])


if __name__ == "__main__":
    unittest.main()
