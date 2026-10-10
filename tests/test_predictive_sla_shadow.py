import base64
import copy
import io
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import predictive_sla_shadow as online
import predictive_sla_shadow_protocol as shadow
import predictive_sla_validation as v1
import predictive_sla_validation_v4 as v4
import test_predictive_sla_validation_v4 as fixtures
from test_predictive_sla_preventive_entry_study import selected_model
from test_predictive_sla_damped_replay import series


RUN_ID = "f" * 32
BASE = 1_800_000_000_000_000_000
WARNING_VALUES = [.2] * 10 + [.4, .6, .7, .75]


def config():
    return dict(config_sha256="config", model=dict(sha256="model", model_id=selected_model().resolved_model_id()),
                policy=v4.POLICY, subjects=v1.SUBJECTS, etcd_url="http://127.0.0.1:2379")


def sample(index, value=.2, subject=None):
    subject = subject or v1.SUBJECTS[0]
    dpid, port = map(int, subject["port_id"].split(":"))
    return dict(schema_version=1, cid=subject["cid"], port_id=subject["port_id"], dpid=dpid, port_no=port,
                capacity_bps=subject["capacity_bps"], ts_ns=BASE + index * 2_000_000_000,
                interval_s=2, valid=True, quality="VALID", utilization_ratio=value)


def pair(subject, values, offset=0):
    agent = shadow.OnlineRiskAgent(selected_model(), subject, v4.POLICY)
    for i, value in enumerate(values):
        current = sample(i, value, subject)
        current["ts_ns"] += offset
        now = current["ts_ns"] + 1_000_000
        record = agent.ingest(current, now)
    risk = shadow.envelope(config(), RUN_ID, record, now + 1)
    item = shadow.proposal(config(), risk, now + 2, now + 3)
    return {f"risks/{subject['cid']}": risk, f"proposals/{subject['cid']}": item}


class OnlineRiskTests(unittest.TestCase):
    def test_online_matches_frozen_v4_scored_prefix(self):
        values = [.2] * 20 + [.2 + .025 * i for i in range(35)] + [.2] * 20
        subject = series(values)
        _, offline = v4.replay_candidate(selected_model(), subject)
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        records = []
        for i, value in enumerate(values):
            s = sample(i, value)
            records.append(agent.ingest(s, s["ts_ns"] + 1_000_000))
        for row in offline["rows"]:
            measured = records[row["index"]]
            for name in ("candidate", "active", "activation", "clear_transition", "entry_inhibited"):
                self.assertEqual(measured[name], row[name], (row["index"], name))
            self.assertEqual([f["predicted_value"] for f in measured["evaluation"]["forecast"]["horizons"]],
                             [p["predicted_value"] for p in row["predictions"]])

    def test_future_samples_cannot_change_preceding_records(self):
        prefix = [.2] * 10 + [.4, .5, .6, .7]
        def replay(values):
            agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
            return [agent.ingest(sample(i, v), sample(i)["ts_ns"] + 1000) for i, v in enumerate(values)]
        self.assertEqual(replay(prefix + [.2] * 10)[:len(prefix)], replay(prefix + [1.2] * 10)[:len(prefix)])

    def test_duplicates_are_not_extra_samples_and_changed_duplicate_resets(self):
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        s = sample(0)
        first = agent.ingest(s, BASE + 1)
        self.assertIsNone(agent.ingest(s, BASE + 2))
        self.assertEqual(agent.count, 1)
        with self.assertRaises(ValueError):
            agent.ingest({**s, "utilization_ratio": .5}, BASE + 3)
        self.assertGreater(agent.generation, first["generation"])
        self.assertEqual(agent.count, 0)

    def test_missing_sample_restarts_model_and_persistence(self):
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        for i, value in enumerate(WARNING_VALUES):
            agent.ingest(sample(i, value), sample(i)["ts_ns"] + 1)
        self.assertTrue(agent.active)
        result = agent.ingest(sample(len(WARNING_VALUES) + 1, .7), sample(len(WARNING_VALUES) + 1)["ts_ns"] + 1)
        self.assertEqual(result["status"], "PRIMING")
        self.assertEqual(result["reset_reason"], "MISSED_OR_IRREGULAR_SAMPLE")
        self.assertFalse(agent.active)
        self.assertEqual(agent.count, 1)

    def test_quality_marker_abstains_and_does_not_become_zero(self):
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        invalid = {**sample(0), "valid": False, "quality": "COUNTER_RESET", "utilization_ratio": None}
        result = agent.ingest(invalid, BASE + 1)
        self.assertEqual(shadow.vote(result), ("ABSTAIN", "INVALID_QUALITY"))
        self.assertIsNone(result["sample"]["utilization_ratio"])
        self.assertEqual(agent.count, 0)

    def test_stale_future_wrong_binding_nonfinite_and_out_of_order_rejected(self):
        mutations = [dict(cid="other"), dict(port_id="1:1"), dict(capacity_bps=1),
                     dict(utilization_ratio=float("nan")), dict(utilization_ratio=True), dict(ts_ns=True)]
        for changed in mutations:
            agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                agent.ingest({**sample(0), **changed}, BASE + 1)
        for now in (BASE - 1, BASE + 6_000_000_000):
            with self.assertRaises(ValueError):
                shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY).ingest(sample(0), now)
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        agent.ingest(sample(1), sample(1)["ts_ns"] + 1)
        with self.assertRaises(ValueError):
            agent.ingest(sample(0), sample(1)["ts_ns"] + 2)

    def test_current_breach_blocks_entry_but_does_not_clear_existing_alert(self):
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        for i, value in enumerate([.2] * 10 + [1.2]):
            result = agent.ingest(sample(i, value), sample(i)["ts_ns"] + 1)
        self.assertTrue(result["candidate"])
        self.assertTrue(result["entry_inhibited"])
        self.assertFalse(result["active"])
        self.assertEqual(shadow.vote(result)[0], "OBSERVE")
        agent = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY)
        for i, value in enumerate(WARNING_VALUES + [1.]):
            result = agent.ingest(sample(i, value), sample(i)["ts_ns"] + 1)
        self.assertTrue(result["active"])
        self.assertFalse(result["entry_inhibited"])
        self.assertEqual(shadow.vote(result)[0], "OBSERVE")


class ConsensusTests(unittest.TestCase):
    def setUp(self):
        self.values = {**pair(v1.SUBJECTS[0], WARNING_VALUES),
                       **pair(v1.SUBJECTS[1], WARNING_VALUES)}
        self.now = sample(len(WARNING_VALUES) - 1)["ts_ns"] + 2_000_000

    def assess(self, values=None, now=None):
        return shadow.consensus(config(), RUN_ID, self.values if values is None else values,
                                self.now if now is None else now)

    def test_agreement_never_requests_authority_or_actuation(self):
        result = self.assess()
        self.assertEqual(result["status"], "SHADOW_PREVENT_AGREED")
        self.assertFalse(result["authorized"])
        self.assertFalse(result["authority_requested"])
        self.assertFalse(result["actuation_requested"])

    def test_missing_domain_priming_and_disagreement(self):
        self.assertEqual(self.assess({})["status"], "WAITING_PROPOSALS")
        one = pair(v1.SUBJECTS[1], [.2])
        # Make other side also current at the earlier timestamp.
        both = {**pair(v1.SUBJECTS[0], [.2]), **one}
        self.assertEqual(self.assess(both, BASE + 2_000_000)["status"], "INSUFFICIENT_EVIDENCE")
        both = {**self.values, **pair(v1.SUBJECTS[1], [.2] * len(WARNING_VALUES))}
        self.assertEqual(self.assess(both)["status"], "DISAGREED")

    def test_stale_future_wrong_model_policy_run_subject_and_ack_rejected(self):
        cid = v1.SUBJECTS[0]["cid"]
        for field, value in [("model_sha256", "wrong"), ("model_id", "wrong"), ("run_id", "0" * 32),
                             ("subject", dict(type="link", id="another")), ("policy", {}),
                             ("expires_ns", self.now + 20_000_000_000)]:
            changed = copy.deepcopy(self.values)
            risk = changed[f"risks/{cid}"]
            risk[field] = value
            changed[f"proposals/{cid}"]["risk_sha256"] = shadow.digest(risk)
            with self.subTest(field=field):
                self.assertEqual(self.assess(changed)["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(self.assess(now=self.now + 6_000_000_000)["status"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(self.assess(now=BASE)["status"], "INSUFFICIENT_EVIDENCE")
        changed = copy.deepcopy(self.values)
        changed[f"proposals/{cid}"]["risk_publication_ack_ns"] = BASE - 1
        self.assertEqual(self.assess(changed)["status"], "INSUFFICIENT_EVIDENCE")

    def test_window_pair_skew_rejected_not_silently_correlated(self):
        changed = {**self.values, **pair(v1.SUBJECTS[1], WARNING_VALUES, offset=3_000_000_000)}
        self.assertEqual(self.assess(changed, self.now + 3_000_000_000)["reason"], "OBSERVATION_TIME_SKEW")

    def test_rehashed_false_vote_and_forecast_rejected(self):
        cid = v1.SUBJECTS[0]["cid"]
        changed = copy.deepcopy(self.values)
        changed[f"proposals/{cid}"].update(decision="OBSERVE", reason="NO_FRESH_ACTIVE_CANDIDATE")
        self.assertEqual(self.assess(changed)["status"], "INSUFFICIENT_EVIDENCE")
        changed = copy.deepcopy(self.values)
        changed[f"risks/{cid}"]["record"]["evaluation"]["forecast"]["horizons"][0]["lower_bound"] = 10
        changed[f"proposals/{cid}"]["risk_sha256"] = shadow.digest(changed[f"risks/{cid}"])
        self.assertEqual(self.assess(changed)["status"], "INSUFFICIENT_EVIDENCE")


class TransportAndRuntimeTests(unittest.TestCase):
    def runtime_response(self, url, payload=None):
        if "/v3/kv/" in url:
            return dict(header=dict(revision="1"))
        subject = v1.SUBJECTS[0]
        if url.endswith("/predictor/status"):
            return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                        agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                        agentic=dict(actuation_enabled=False, live_executions=0))
        return dict(enabled=True, latest=[{**sample(0), "ts_ns": time.time_ns() - 1_000_000}])

    def test_worker_logs_online_timestamps_but_keeps_unmeasured_stages_null(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            model_path = output / "model.json"
            model_path.write_text(json.dumps(selected_model().to_dict()))
            with patch.object(online, "http_json", side_effect=self.runtime_response):
                online.worker(config(), str(model_path), RUN_ID, v1.SUBJECTS[0], str(output), .01)
            summary = json.loads((output / "192.168.10.10-summary.json").read_text())
            self.assertEqual(summary["status"], "COMPLETED")
            for key in ("authority_latency_ms", "actuation_latency_ms", "llm_latency_ms"):
                self.assertIsNone(summary[key])
            self.assertEqual(summary["deadline_feasibility"], "UNKNOWN")
            self.assertFalse(summary["sla_protection_established"])
            rows = [json.loads(line) for line in (output / "192.168.10.10.ndjson").read_text().splitlines()]
            forecast = next(row for row in rows if row["kind"] == "LOCAL_EVALUATION")
            ack = next(row for row in rows if row["kind"] == "RISK_PUBLICATION")
            self.assertLessEqual(forecast["telemetry_read_started_ns"], forecast["telemetry_received_ns"])
            self.assertLessEqual(forecast["processing_completed_ns"], ack["risk_publication_ack_ns"])
            self.assertIsNone(forecast["forecast_available_ns"])
            self.assertIsNone(summary["timings"]["forecast_ms"]["mean"])
            self.assertGreaterEqual(summary["timings"]["risk_publication_ms"]["count"], 1)

    def test_unsafe_runtime_stops_before_any_etcd_write(self):
        unsafe = self.runtime_response(v1.SUBJECTS[0]["url"] + "/predictor/status")
        unsafe["config"]["auto_mitigate"] = True
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory)
            model_path = output / "model.json"
            model_path.write_text(json.dumps(selected_model().to_dict()))
            with patch.object(online, "http_json", return_value=unsafe) as request, self.assertRaises(SystemExit):
                online.worker(config(), str(model_path), RUN_ID, v1.SUBJECTS[0], str(output), .01)
            self.assertEqual(request.call_count, 1)
            summary = json.loads((output / "192.168.10.10-summary.json").read_text())
            self.assertEqual(summary["status"], "STOPPED_ERROR")
            self.assertIsNone(summary["timings"]["risk_publication_ms"]["mean"])

    def test_store_only_ranges_its_namespace_and_puts_four_exact_keys(self):
        request = Mock(return_value={"header": {"revision": "4"}, "kvs": []})
        store = online.ShadowStore("http://127.0.0.1:2379", RUN_ID, request)
        store.read()
        prefix = base64.b64decode(request.call_args.args[1]["key"]).decode()
        self.assertEqual(prefix, store.prefix)
        store.put("risks/192.168.10.10", {})
        key = base64.b64decode(request.call_args.args[1]["key"]).decode()
        self.assertEqual(key, store.prefix + "risks/192.168.10.10")
        for suffix in ("../authority", "claims/192.168.10.10", "risks/other", "manifest"):
            with self.assertRaises(ValueError):
                store.put(suffix, {})
        self.assertEqual(request.call_count, 2)

    def test_gateway_malformed_extra_foreign_truncated_and_nonfinite_rejected(self):
        prefix = online.ShadowStore("http://127.0.0.1:2379", RUN_ID).prefix
        for response in ({}, {"header": {}, "more": True},
                         {"header": {}, "kvs": [{"key": online.b64(b"/foreign"), "value": online.b64(b"{}")}]},
                         {"header": {}, "kvs": [{"key": online.b64((prefix + "unknown").encode()), "value": online.b64(b"{}")}]},
                         {"header": {}, "kvs": [{"key": online.b64((prefix + "manifest").encode()), "value": online.b64(b'{"x":NaN}')}]},
                         {"header": {}, "kvs": [{"key": online.b64((prefix + "manifest").encode()), "value": online.b64(b"{")}]},):
            with self.subTest(response=response), self.assertRaises(ValueError):
                online.ShadowStore("http://127.0.0.1:2379", RUN_ID, Mock(return_value=response)).read()

    def test_unique_run_reservation_requires_atomic_success(self):
        request = Mock(return_value={"header": {"revision": "2"}, "succeeded": True})
        store = online.ShadowStore("http://127.0.0.1:2379", RUN_ID, request)
        store.reserve({})
        self.assertEqual(request.call_args.args[1]["compare"][0]["version"], "0")
        request.return_value["succeeded"] = False
        with self.assertRaises(ValueError):
            store.reserve({})

    def test_urls_and_write_opt_in_checked_before_network(self):
        for url in ("https://127.0.0.1:2379", "http://example.org:2379", "http://127.0.0.1:2379/path",
                    "http://user@127.0.0.1:2379", "http://127.0.0.1:2379?x"):
            with self.assertRaises(ValueError):
                online.loopback_url(url)
        with patch.object(online, "load_config") as load, self.assertRaises(ValueError):
            online.run(Path("missing"), 60, False)
        load.assert_not_called()

    def test_failed_second_write_preserves_first_ack_but_no_fake_next_latency(self):
        store = Mock()
        store.put.side_effect = ["2", TimeoutError("timeout")]
        handle, durations = io.StringIO(), dict(risk_publication_ms=[], proposal_evaluation_ms=[], proposal_publication_ms=[])
        record = shadow.OnlineRiskAgent(selected_model(), v1.SUBJECTS[0], v4.POLICY).ingest(sample(0), BASE + 1)
        with self.assertRaises(TimeoutError):
            online.publish_record(store, config(), RUN_ID, record, BASE + 2, handle, durations)
        lines = [json.loads(line) for line in handle.getvalue().splitlines()]
        self.assertEqual([line["kind"] for line in lines], ["RISK_PUBLICATION"])
        self.assertEqual(len(durations["risk_publication_ms"]), 1)
        self.assertEqual(durations["proposal_publication_ms"], [])

    def test_preflight_only_reads_status_qos_and_gateway(self):
        now = time.time_ns()
        def respond(url, payload=None):
            if "/v3/kv/range" in url:
                return dict(header=dict(revision="1"))
            subject = next(s for s in v1.SUBJECTS if url.startswith(s["url"]))
            if url.endswith("/predictor/status"):
                return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True, agentic_mode="shadow",
                            agentic_live_actuation_opt_in=False, poll_interval_s=2, qos_telemetry_enabled=True),
                            agentic=dict(actuation_enabled=False, live_executions=0))
            return dict(enabled=True, latest=[{**sample(0, subject=subject), "ts_ns": now}])
        with patch.object(online, "http_json", side_effect=respond) as request:
            self.assertEqual(len(online.preflight(config())), 2)
        self.assertEqual(request.call_count, 5)
        self.assertTrue(all(call.args[0].endswith(("/predictor/status", "/predictor/qos", "/v3/kv/range"))
                            for call in request.call_args_list))


class FrozenShadowTests(unittest.TestCase):
    def setUp(self):
        # Reuse the full frozen-provenance tree, not an imported test class.
        self.fixture = fixtures.ProspectiveV4Tests(methodName="runTest")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.p = self.fixture.freeze()
        self.fixture.cases(self.p)
        self.summary_path = self.fixture.campaign / "campaign-summary.json"
        v1.write_new_json(self.summary_path, v4.evaluate_campaign(self.fixture.path, self.fixture.campaign))
        self.output = self.fixture.path.parent.parent / "qos-online-shadow-test"
        self.path = self.output / "shadow-config.json"

    def test_freeze_copies_exact_model_and_preserves_not_passed_result(self):
        before = v1.digest_file(self.summary_path)
        result = online.freeze(self.fixture.path, self.output, "http://127.0.0.1:2379")
        self.assertEqual(result, online.load_config(self.path))
        self.assertEqual(result["source_criteria_status"], "NOT_PASSED")
        self.assertEqual(v1.digest_file(self.summary_path), before)
        self.assertEqual(v1.digest_file(self.output / "model.json"), result["model"]["sha256"])
        self.assertFalse(result["boundary"]["authority_request"])
        self.assertFalse(result["boundary"]["deployment_eligible"])
        with self.assertRaises(ValueError):
            online.freeze(self.fixture.path, self.output, "http://127.0.0.1:2379")

    def test_resealed_changes_to_code_binding_policy_model_and_sources_rejected(self):
        original = online.freeze(self.fixture.path, self.output, "http://127.0.0.1:2379")
        for change in (lambda p: p["policy"].update(threshold=.7), lambda p: p["subjects"][0].update(port_id="1:1"),
                       lambda p: p["boundary"].update(authority_request=True), lambda p: p["timing"].update(max_sample_age_s=99),
                       lambda p: p["code_sha256"].update(predictive_sla_shadow="changed")):
            current = copy.deepcopy(original)
            change(current)
            self.path.write_text(json.dumps(v1.seal(current, "config_sha256")))
            with self.assertRaises(ValueError):
                online.load_config(self.path)
        self.path.write_text(json.dumps(original))
        with (self.output / "model.json").open("a") as handle:
            handle.write(" ")
        with self.assertRaises(ValueError):
            online.load_config(self.path)

    def test_protected_source_mutation_rejected_without_network(self):
        online.freeze(self.fixture.path, self.output, "http://127.0.0.1:2379")
        source = next(iter(json.loads(self.summary_path.read_text())["source_sha256"]))
        with Path(source).open("a") as handle:
            handle.write(" ")
        with patch.object(online, "http_json") as request, self.assertRaises(ValueError):
            online.load_config(self.path)
        request.assert_not_called()


if __name__ == "__main__":
    unittest.main()
