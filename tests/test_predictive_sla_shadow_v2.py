import base64
import copy
import io
import json
import tempfile
import time
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import Mock, patch

import predictive_sla_shadow as legacy
import predictive_sla_shadow_protocol as old_protocol
import predictive_sla_shadow_protocol_v2 as protocol
import predictive_sla_shadow_v2 as online
import predictive_sla_validation as provenance
import predictive_sla_validation_v4 as v4
import test_predictive_sla_shadow as old_tests
from test_predictive_sla_preventive_entry_study import selected_model


BASE, RUN_ID = old_tests.BASE, old_tests.RUN_ID


def config():
    result = old_tests.config()
    result["publication"] = protocol.PUBLICATION
    return result


def pair(subject, values=None, offset=0):
    values = old_tests.WARNING_VALUES if values is None else values
    agent = protocol.OnlineRiskAgent(selected_model(), subject, v4.POLICY)
    for i, value in enumerate(values):
        sample = old_tests.sample(i, value, subject)
        sample["ts_ns"] += offset
        now = sample["ts_ns"] + 1_000_000
        record = agent.ingest(sample, now)
    risk = protocol.envelope(config(), RUN_ID, record, now + 1)
    return risk, protocol.proposal(config(), risk, now + 3)


def snapshot(pairs=None):
    pairs = pairs or [pair(subject) for subject in provenance.SUBJECTS]
    values, revisions = {}, {}
    for i, (risk, item) in enumerate(pairs):
        for kind, value in (("risks", risk), ("proposals", item)):
            key = f"{kind}/{risk['cid']}"
            values[key], revisions[key] = value, 2 + i
    return dict(values=values, mod_revisions=revisions, snapshot_revision=10)


class MemoryGateway:
    """Deterministic atomic gateway model; no network/real ETCD writes.

    Hooks read the committed store while one put is only in the private stage,
    and after both are committed. A timeout may occur before or after commit.
    """

    def __init__(self):
        self.current_revision = 1
        self.kvs, self.calls = {}, []
        self.during_prepare = None
        self.after_commit = None
        self.fail_before_commit = False
        self.fail_after_commit = False

    def __call__(self, url, payload=None):
        self.calls.append((url, copy.deepcopy(payload)))
        if url.endswith("/v3/kv/range"):
            prefix = base64.b64decode(payload["key"]).decode()
            rows = [copy.deepcopy(value) for key, value in self.kvs.items() if key.startswith(prefix)]
            return dict(header=dict(revision=str(self.current_revision)), kvs=rows, count=str(len(rows)))
        if not url.endswith("/v3/kv/txn"):
            raise AssertionError("unexpected non-atomic write: " + url)
        for comparison in payload.get("compare", []):
            key = base64.b64decode(comparison["key"]).decode()
            if comparison != dict(target="VERSION", result="EQUAL", key=comparison["key"], version="0"):
                raise AssertionError("unexpected comparison")
            if key in self.kvs:
                return dict(header=dict(revision=str(self.current_revision)), succeeded=False)
        staged = copy.deepcopy(self.kvs)
        next_revision = self.current_revision + 1
        for i, operation in enumerate(payload["success"]):
            put = operation["request_put"]
            key = base64.b64decode(put["key"]).decode()
            staged[key] = dict(key=put["key"], value=put["value"], mod_revision=str(next_revision))
            if i == 0 and self.during_prepare is not None:
                self.during_prepare()
        if self.fail_before_commit:
            raise TimeoutError("before commit")
        self.kvs, self.current_revision = staged, next_revision
        if self.after_commit is not None:
            self.after_commit()
        if self.fail_after_commit:
            raise TimeoutError("ack lost after commit")
        return dict(header=dict(revision=str(next_revision)), succeeded=True,
                    responses=[dict(response_put=dict(header=dict(revision=str(next_revision))))
                               for _ in payload["success"]])


class AtomicContractTests(unittest.TestCase):
    def setUp(self):
        self.now = old_tests.sample(len(old_tests.WARNING_VALUES) - 1)["ts_ns"] + 2_000_000
        self.data = snapshot()

    def assess(self, data=None, now=None):
        return protocol.consensus(config(), RUN_ID, self.data if data is None else data,
                                  self.now if now is None else now)

    def test_frozen_forecaster_policy_and_timing_are_reused_without_changes(self):
        self.assertIs(protocol.OnlineRiskAgent, old_protocol.OnlineRiskAgent)
        self.assertEqual(protocol.TIMING, old_protocol.TIMING)
        self.assertEqual(protocol.BOUNDARY, old_protocol.BOUNDARY)
        self.assertEqual(protocol.SUBJECT, old_protocol.SUBJECT)

    def test_valid_atomic_pairs_agree_without_any_authorization(self):
        result = self.assess()
        self.assertEqual(result["status"], "SHADOW_PREVENT_AGREED")
        self.assertEqual(result["pair_mod_revisions"], {s["cid"]: 2 + i for i, s in enumerate(provenance.SUBJECTS)})
        for field in ("authorized", "authority_requested", "actuation_requested"):
            self.assertFalse(result[field])

    def test_same_revision_is_required_even_when_hashes_match(self):
        data = copy.deepcopy(self.data)
        cid = provenance.SUBJECTS[0]["cid"]
        data["mod_revisions"][f"proposals/{cid}"] += 1
        result = self.assess(data)
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertIn("mesma revisão", result["reason"])

    def test_missing_invalid_or_future_commit_metadata_cannot_agree(self):
        key = "risks/" + provenance.SUBJECTS[0]["cid"]
        for value in (None, True, 0, -1, 2.0, "2", 11):
            data = copy.deepcopy(self.data)
            data["mod_revisions"][key] = value
            with self.subTest(value=value):
                self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")
        data = copy.deepcopy(self.data)
        del data["mod_revisions"][key]
        self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")

    def test_missing_domain_priming_and_disagreement_have_distinct_reasons(self):
        missing = dict(values={}, mod_revisions={}, snapshot_revision=1)
        self.assertEqual(self.assess(missing)["status"], "WAITING_PROPOSALS")
        priming = snapshot([pair(s, [.2]) for s in provenance.SUBJECTS])
        result = self.assess(priming, BASE + 2_000_000)
        self.assertEqual(result["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["reason"], "PREDICTION_UNAVAILABLE")
        self.assertEqual(set(result["abstentions"].values()), {"PRIMING"})
        mixed = snapshot([pair(provenance.SUBJECTS[0]),
                          pair(provenance.SUBJECTS[1], [.2] * len(old_tests.WARNING_VALUES))])
        self.assertEqual(self.assess(mixed)["status"], "DISAGREED")

    def test_identity_model_policy_hash_and_vote_checks_are_not_relaxed(self):
        cid = provenance.SUBJECTS[0]["cid"]
        for field, value in (("model_sha256", "wrong"), ("model_id", "wrong"), ("run_id", "0" * 32),
                             ("policy", {}), ("schema_version", old_protocol.SCHEMA),
                             ("expires_ns", self.now + 20_000_000_000), ("subject", {})):
            data = copy.deepcopy(self.data)
            risk = data["values"][f"risks/{cid}"]
            risk[field] = value
            data["values"][f"proposals/{cid}"]["risk_sha256"] = protocol.digest(risk)
            with self.subTest(field=field):
                self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")
        data = copy.deepcopy(self.data)
        data["values"][f"proposals/{cid}"].update(decision="OBSERVE", reason="NO_FRESH_ACTIVE_CANDIDATE")
        self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")
        data = copy.deepcopy(self.data)
        data["values"][f"risks/{cid}"]["record"]["evaluation"]["forecast"]["horizons"][0]["lower_bound"] = 10
        data["values"][f"proposals/{cid}"]["risk_sha256"] = protocol.digest(data["values"][f"risks/{cid}"])
        self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")

    def test_precommit_payload_cannot_claim_an_ack_and_timestamp_order_is_checked(self):
        cid = provenance.SUBJECTS[0]["cid"]
        for field in ("risk_publication_ack_ns", "pair_publication_ack_ns", "mod_revision"):
            data = copy.deepcopy(self.data)
            data["values"][f"proposals/{cid}"][field] = self.now
            self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")
        data = copy.deepcopy(self.data)
        data["values"][f"proposals/{cid}"]["evaluated_ns"] = BASE
        self.assertEqual(self.assess(data)["status"], "INSUFFICIENT_EVIDENCE")

    def test_expiry_future_observation_and_time_skew_still_reject(self):
        self.assertEqual(self.assess(now=self.now + 6_000_000_000)["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(self.assess(now=BASE)["status"], "INSUFFICIENT_EVIDENCE")
        skewed = snapshot([pair(provenance.SUBJECTS[0]), pair(provenance.SUBJECTS[1], offset=3_000_000_000)])
        self.assertEqual(self.assess(skewed, self.now + 3_000_000_000)["reason"], "OBSERVATION_TIME_SKEW")


class AtomicTransportTests(unittest.TestCase):
    def setUp(self):
        self.gateway = MemoryGateway()
        self.store = online.AtomicShadowStore("http://127.0.0.1:2379", RUN_ID, self.gateway)
        self.subject = provenance.SUBJECTS[0]
        self.risk, self.item = pair(self.subject)

    def test_one_request_commits_only_the_two_allowed_keys_at_one_revision(self):
        receipt = self.store.put_pair(self.subject["cid"], self.risk, self.item)
        self.assertEqual(len(self.gateway.calls), 1)
        url, payload = self.gateway.calls[0]
        self.assertTrue(url.endswith("/v3/kv/txn"))
        self.assertEqual(len(payload["success"]), 2)
        data = self.store.read()
        self.assertEqual(set(data["mod_revisions"].values()), {receipt["revision"]})
        self.assertEqual(data["values"][f"risks/{self.subject['cid']}"], self.risk)
        self.assertIn("predictive-sla-shadow-v2/", self.store.prefix)
        self.assertFalse(hasattr(self.store, "put"))
        self.assertFalse(hasattr(self.store, "delete"))

    def test_reader_sees_old_or_new_complete_pair_never_staged_first_put(self):
        self.store.put_pair(self.subject["cid"], self.risk, self.item)
        second = provenance.SUBJECTS[1]
        self.store.put_pair(second["cid"], *pair(second))
        original = self.store.read()
        observed = []
        self.gateway.during_prepare = lambda: observed.append(self.store.read())
        self.gateway.after_commit = lambda: observed.append(self.store.read())
        new_risk, new_item = pair(self.subject, old_tests.WARNING_VALUES + [.76])
        self.store.put_pair(self.subject["cid"], new_risk, new_item)
        self.assertEqual(observed[0], original)
        self.assertEqual(observed[1]["values"][f"risks/{self.subject['cid']}"], new_risk)
        self.assertEqual(observed[1]["values"][f"proposals/{self.subject['cid']}"], new_item)
        now = new_risk["observed_ns"] + 2_000_000
        for data in observed:
            self.assertEqual(protocol.consensus(config(), RUN_ID, data, now)["status"], "SHADOW_PREVENT_AGREED")

    def test_failure_before_commit_leaves_old_complete_pair(self):
        self.store.put_pair(self.subject["cid"], self.risk, self.item)
        original = self.store.read()
        self.gateway.fail_before_commit = True
        with self.assertRaises(TimeoutError):
            self.store.put_pair(self.subject["cid"], *pair(self.subject, old_tests.WARNING_VALUES + [.76]))
        self.assertEqual(self.store.read(), original)

    def test_timeout_after_commit_can_leave_complete_pair_but_no_ack(self):
        self.gateway.fail_after_commit = True
        with self.assertRaises(TimeoutError):
            self.store.put_pair(self.subject["cid"], self.risk, self.item)
        data = self.store.read()
        self.assertEqual(len(data["values"]), 2)
        self.assertEqual(len(set(data["mod_revisions"].values())), 1)

    def test_unknown_cid_cross_run_foreign_binding_or_unbound_hash_never_writes(self):
        for cid, risk, item in (("other", self.risk, self.item),
                               (self.subject["cid"], {**self.risk, "run_id": "0" * 32}, self.item),
                               (self.subject["cid"], self.risk, {**self.item, "cid": "other"}),
                               (self.subject["cid"], self.risk, {**self.item, "risk_sha256": "wrong"})):
            with self.subTest(cid=cid), self.assertRaises(ValueError):
                self.store.put_pair(cid, risk, item)
        self.assertEqual(self.gateway.calls, [])

    def test_reservation_is_exclusive_and_uses_only_version_zero_marker(self):
        self.store.reserve({})
        with self.assertRaises(ValueError):
            self.store.reserve({})
        payload = self.gateway.calls[0][1]
        self.assertEqual(payload["compare"][0]["version"], "0")
        self.assertEqual(len(payload["success"]), 1)

    def test_malformed_atomic_ack_never_becomes_confirmed_publication(self):
        good = dict(header=dict(revision="4"), succeeded=True, responses=[dict(response_put={})] * 2)
        responses = [dict(header=dict(revision="4"), succeeded=False),
                     {**good, "responses": []}, {**good, "responses": [dict(response_put={})]},
                     {**good, "header": {"revision": True}},
                     {**good, "responses": [dict(response_put={}), dict(response_range={})]},
                     {**good, "responses": [dict(response_put={}), dict(response_put=dict(header=dict(revision="5")))]}]
        for response in responses:
            with self.subTest(response=response), self.assertRaises(ValueError):
                online.AtomicShadowStore(self.store.url, RUN_ID, Mock(return_value=response)).put_pair(
                    self.subject["cid"], self.risk, self.item)

    def test_range_requires_consistent_metadata_namespace_and_complete_values(self):
        self.store.put_pair(self.subject["cid"], self.risk, self.item)
        response = self.gateway(self.store.url + "/v3/kv/range", {"key": online.b64(self.store.prefix.encode())})
        changes = [lambda r: r.update(more=True), lambda r: r.update(count="3"),
                   lambda r: r["header"].update(revision="0"), lambda r: r["kvs"][0].update(mod_revision=None),
                   lambda r: r["kvs"][0].update(mod_revision="99"), lambda r: r["kvs"][0].update(lease="2"),
                   lambda r: r["kvs"][0].update(key=online.b64(b"/foreign")),
                   lambda r: r["kvs"][0].update(value=online.b64(b'{"x":NaN}')),
                   lambda r: r["kvs"].append(copy.deepcopy(r["kvs"][0]))]
        for change in changes:
            modified = copy.deepcopy(response)
            change(modified)
            with self.subTest(change=change), self.assertRaises(ValueError):
                online.AtomicShadowStore(self.store.url, RUN_ID, Mock(return_value=modified)).read()


class AtomicRuntimeTests(unittest.TestCase):
    def record(self):
        return protocol.OnlineRiskAgent(selected_model(), provenance.SUBJECTS[0], v4.POLICY).ingest(
            old_tests.sample(0), BASE + 1)

    def durations(self):
        return dict(proposal_evaluation_ms=[], pair_publication_ms=[], observation_to_pair_publication_ack_ms=[])

    def test_common_ack_is_only_post_response_and_not_counted_as_two_requests(self):
        gateway, handle, durations, counters = MemoryGateway(), io.StringIO(), self.durations(), Counter()
        store = online.AtomicShadowStore("http://127.0.0.1:2379", RUN_ID, gateway)
        with patch.object(online.time, "time_ns", return_value=BASE + 10):
            online.publish_record(store, config(), RUN_ID, self.record(), BASE + 2, handle, durations, counters)
        rows = [json.loads(line) for line in handle.getvalue().splitlines()]
        self.assertEqual([r["kind"] for r in rows], ["PAIR_PUBLICATION_ATTEMPT", "PAIR_PUBLICATION"])
        self.assertEqual(rows[1]["commit_outcome"], "CONFIRMED")
        self.assertEqual(rows[1]["pair_mod_revision"], 2)
        self.assertGreaterEqual(rows[1]["pair_publication_ack_ns"], rows[0]["pair_publication_started_ns"])
        self.assertEqual(len(durations["pair_publication_ms"]), 1)
        self.assertEqual(counters["confirmed_publications"], 1)
        for body in (rows[1]["risk"], rows[1]["proposal"]):
            self.assertNotIn("pair_publication_ack_ns", body)
            self.assertNotIn("risk_publication_ack_ns", body)

    def test_lost_ack_is_preserved_as_unknown_without_retry_or_zero_latency(self):
        gateway, handle, durations, counters = MemoryGateway(), io.StringIO(), self.durations(), Counter()
        gateway.fail_after_commit = True
        store = online.AtomicShadowStore("http://127.0.0.1:2379", RUN_ID, gateway)
        with patch.object(online.time, "time_ns", return_value=BASE + 10), self.assertRaises(TimeoutError):
            online.publish_record(store, config(), RUN_ID, self.record(), BASE + 2, handle, durations, counters)
        rows = [json.loads(line) for line in handle.getvalue().splitlines()]
        self.assertEqual(rows[-1]["kind"], "PAIR_PUBLICATION_UNCONFIRMED")
        self.assertEqual(rows[-1]["commit_outcome"], "UNKNOWN")
        self.assertFalse(rows[-1]["retry_attempted"])
        self.assertEqual(counters["unconfirmed_publications"], 1)
        self.assertEqual(counters["confirmed_publications"], 0)
        self.assertEqual(durations["pair_publication_ms"], [])
        self.assertEqual(len(gateway.calls), 1)

    def test_preflight_only_reads_and_explicit_opt_in_precedes_network(self):
        now = time.time_ns()
        def respond(url, payload=None):
            if url.endswith("/v3/kv/range"):
                return dict(header=dict(revision="1"))
            subject = next(s for s in provenance.SUBJECTS if url.startswith(s["url"]))
            if url.endswith("/predictor/status"):
                return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                            agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                            agentic=dict(actuation_enabled=False, live_executions=0))
            return dict(enabled=True, latest=[{**old_tests.sample(0, subject=subject), "ts_ns": now}])
        with patch.object(online, "http_json", side_effect=respond) as request:
            self.assertEqual(len(online.preflight(config())), 2)
            self.assertEqual(request.call_count, 5)
            self.assertTrue(all(c.args[0].endswith(("/predictor/status", "/predictor/qos", "/v3/kv/range"))
                                for c in request.call_args_list))
        with patch.object(online, "load_config") as load, self.assertRaises(ValueError):
            online.run(Path("missing"), 60, False)
        load.assert_not_called()

    def run_worker(self, directory, unsafe=False, changed_model=False):
        model_path = directory / "model.json"
        model_path.write_text(json.dumps(selected_model().to_dict()))
        settings = config()
        settings["model"]["sha256"] = "wrong" if changed_model else provenance.digest_file(model_path)
        gateway = MemoryGateway()
        def respond(url, payload=None):
            if "/v3/kv/" in url:
                return gateway(url, payload)
            subject = provenance.SUBJECTS[0]
            if url.endswith("/predictor/status"):
                return dict(cid=subject["cid"], config=dict(auto_mitigate=unsafe, dry_run=True, agentic_mode="shadow",
                            agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                            agentic=dict(actuation_enabled=False, live_executions=0))
            return dict(enabled=True, latest=[{**old_tests.sample(0), "ts_ns": time.time_ns() - 1_000_000}])
        with patch.object(online, "http_json", side_effect=respond):
            online.worker(settings, str(model_path), RUN_ID, provenance.SUBJECTS[0], str(directory), .02)
        return gateway

    def test_worker_reports_common_publication_and_leaves_unmeasured_latencies_null(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            gateway = self.run_worker(directory)
            result = json.loads((directory / "192.168.10.10-summary.json").read_text())
            self.assertEqual(result["status"], "COMPLETED")
            self.assertEqual(result["counters"]["confirmed_publications"], 1)
            self.assertIsNone(result["timings"]["forecast_ms"]["mean"])
            self.assertEqual(result["timings"]["pair_publication_ms"]["count"], 1)
            self.assertNotIn("risk_publication_ms", result["timings"])
            for field in ("authority_latency_ms", "actuation_latency_ms", "llm_latency_ms"):
                self.assertIsNone(result[field])
            self.assertEqual(result["deadline_feasibility"], "UNKNOWN")
            self.assertFalse(result["sla_protection_established"])
            self.assertTrue(all(url.endswith(("/v3/kv/range", "/v3/kv/txn")) for url, _ in gateway.calls))

    def test_unsafe_runtime_or_changed_model_stops_before_etcd_write(self):
        for settings in (dict(unsafe=True), dict(changed_model=True)):
            with tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with self.subTest(settings=settings), self.assertRaises(SystemExit):
                    self.run_worker(directory, **settings)
                result = json.loads((directory / "192.168.10.10-summary.json").read_text())
                self.assertEqual(result["status"], "STOPPED_ERROR")
                self.assertEqual(result["counters"].get("publication_attempts", 0), 0)
                self.assertIsNone(result["timings"]["pair_publication_ms"]["mean"])

    def test_first_runtime_guard_is_not_delayed_on_a_fresh_process_clock(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            with patch.object(online.time, "monotonic", return_value=0), self.assertRaises(SystemExit):
                self.run_worker(directory, unsafe=True)
            result = json.loads((directory / "192.168.10.10-summary.json").read_text())
            self.assertEqual(result["counters"].get("publication_attempts", 0), 0)


class FrozenAtomicConfigTests(unittest.TestCase):
    def setUp(self):
        self.fixture = old_tests.FrozenShadowTests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        legacy.freeze(self.fixture.fixture.path, self.fixture.output, "http://127.0.0.1:2379")
        self.source = self.fixture.path
        run = self.source.parent / "runs" / RUN_ID
        run.mkdir(parents=True)
        provenance.write_new_json(run / "shadow-summary.json", {"status": "COMPLETED"})
        (run / "192.168.10.10.ndjson").write_text('{"kind":"SHADOW_CONSENSUS"}\n')
        self.output = self.source.parent.parent / "qos-online-shadow-v2-test"
        self.path = self.output / "shadow-config.json"

    def test_freeze_preserves_exact_model_v1_artifacts_and_not_passed_v4(self):
        before = online.previous_artifacts(self.source)
        result = online.freeze(self.source, self.output)
        self.assertEqual(result, online.load_config(self.path))
        self.assertEqual(result["source_v1_artifacts_sha256"], before)
        self.assertEqual(online.previous_artifacts(self.source), before)
        self.assertEqual(result["source_criteria_status"], "NOT_PASSED")
        self.assertEqual((self.output / "model.json").read_bytes(), (self.source.parent / "model.json").read_bytes())
        self.assertEqual(legacy.load_config(self.source)["schema_version"], legacy.CONFIG_SCHEMA)
        with self.assertRaises(ValueError):
            online.freeze(self.source, self.output)
        with self.assertRaises(ValueError):
            online.freeze(self.source, self.source.parent)

    def test_modified_v1_run_is_rejected_before_any_network(self):
        online.freeze(self.source, self.output)
        artifact = self.source.parent / "runs" / RUN_ID / "192.168.10.10.ndjson"
        with artifact.open("a") as handle:
            handle.write(" ")
        with patch.object(online, "http_json") as request, self.assertRaises(ValueError):
            online.load_config(self.path)
        request.assert_not_called()

    def test_resealed_transport_policy_timing_code_and_boundary_changes_rejected(self):
        original = online.freeze(self.source, self.output)
        changes = [lambda p: p["publication"].update(method="two_puts"),
                   lambda p: p["timing"].update(max_sample_age_s=99),
                   lambda p: p["policy"].update(threshold=.7),
                   lambda p: p["boundary"].update(authority_request=True),
                   lambda p: p["code_sha256"].update(predictive_sla_shadow_v2="wrong")]
        for change in changes:
            current = copy.deepcopy(original)
            change(current)
            self.path.write_text(json.dumps(provenance.seal(current, "config_sha256")))
            with self.subTest(change=change), self.assertRaises(ValueError):
                online.load_config(self.path)

    def launcher_context(self, failed=False):
        processes = []
        class Process:
            def __init__(self, target, args):
                self.args, self.index = args, len(processes)
                self.pid, self.exitcode, self.alive, self.terminated = None, None, False, False
                processes.append(self)

            def start(self):
                self.pid = self.index + 1
                if failed and self.index == 1:
                    self.alive = True
                    return
                status = "STOPPED_ERROR" if failed else "COMPLETED"
                self.exitcode = 2 if failed else 0
                subject, output = self.args[3], Path(self.args[4])
                provenance.write_new_json(output / f"{subject['cid']}-summary.json",
                                          dict(cid=subject["cid"], status=status))

            def is_alive(self):
                return self.alive

            def terminate(self):
                self.terminated, self.alive, self.exitcode = True, False, -15

            def join(self, timeout):
                pass

        context = Mock()
        context.Process.side_effect = Process
        return context, processes

    def test_launcher_uses_new_namespace_and_exclusive_runs_without_changing_v1(self):
        online.freeze(self.source, self.output)
        original_hashes = online.previous_artifacts(self.source)
        for _ in range(2):
            context, processes = self.launcher_context()
            gateway = MemoryGateway()
            with patch.object(online, "preflight"), patch.object(online, "http_json", side_effect=gateway), \
                    patch.object(online.multiprocessing, "get_context", return_value=context), patch("builtins.print"):
                self.assertTrue(online.run(self.path, 60, True))
            self.assertEqual(len(processes), 2)
            self.assertFalse(any(p.terminated for p in processes))
            key = base64.b64decode(gateway.calls[0][1]["compare"][0]["key"]).decode()
            self.assertIn("/predictive-sla-shadow-v2/", key)
        runs = list((self.output / "runs").iterdir())
        self.assertEqual(len(runs), 2)
        for run in runs:
            report = json.loads((run / "shadow-summary.json").read_text())
            self.assertTrue(report["originals_unchanged"])
            self.assertEqual(report["source_criteria_status"], "NOT_PASSED")
            self.assertEqual(report["deadline_feasibility"], "UNKNOWN")
            self.assertFalse(report["sla_protection_established"])
            self.assertFalse(report["boundary"]["authority_request"])
        self.assertEqual(online.previous_artifacts(self.source), original_hashes)

    def test_launcher_worker_failure_only_terminates_its_own_peer_and_cannot_complete(self):
        online.freeze(self.source, self.output)
        context, processes = self.launcher_context(failed=True)
        gateway = MemoryGateway()
        with patch.object(online, "preflight"), patch.object(online, "http_json", side_effect=gateway), \
                patch.object(online.multiprocessing, "get_context", return_value=context), patch("builtins.print"):
            self.assertFalse(online.run(self.path, 60, True))
        self.assertFalse(processes[0].terminated)
        self.assertTrue(processes[1].terminated)
        run = next((self.output / "runs").iterdir())
        report = json.loads((run / "shadow-summary.json").read_text())
        self.assertEqual(report["status"], "STOPPED_ERROR")
        self.assertEqual(report["domain_reports"][1]["status"], "INTERRUPTED")


if __name__ == "__main__":
    unittest.main()
