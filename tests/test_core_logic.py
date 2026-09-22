import ast
import math
import unittest
import uuid
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from collaborative_decision import score_collaborative_evidence
from offline_model import OfflineModel, inverse_transform_value, transform_value


ROOT = Path(__file__).resolve().parents[1]


def load_definitions(relative_path, names, namespace):
    """Load selected pure definitions without importing service dependencies."""
    source = (ROOT / relative_path).read_text(encoding="utf-8")
    tree = ast.parse(source, filename=relative_path)
    selected = [
        node for node in tree.body
        if isinstance(node, (ast.ClassDef, ast.FunctionDef)) and node.name in names
    ]
    module = ast.Module(body=selected, type_ignores=[])
    exec(compile(module, relative_path, "exec"), namespace)
    return namespace


class PredictorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"HoltPredictor", "ResidualAnomalyDetector", "SeriesState"},
            {
                "Optional": Optional,
                "Tuple": Tuple,
                "Dict": Dict,
                "Any": Any,
                "deque": deque,
                "transform_value": transform_value,
                "inverse_transform_value": inverse_transform_value,
                "OfflineModel": OfflineModel,
                "ONLINE_MODEL_ADAPTATION": False,
                "HISTORY_WINDOW": 120,
                "Z_THRESHOLD": 4.0,
                "WARMUP_SAMPLES": 15,
                "MIN_RATE_BPS": 1.0,
                "FLOW_IDLE_RESET_SAMPLES": 2,
                "CONTROLLER_ID": "test-controller",
                "_exporter": None,
                "uuid": uuid,
                "now_ns": lambda: 1,
            },
        )

    def test_holt_predictor_tracks_level_and_trend(self):
        predictor = self.symbols["HoltPredictor"](alpha=0.5, beta=0.5)
        self.assertEqual(predictor.predict(), 0.0)
        predictor.update(10.0)
        self.assertEqual(predictor.predict(), 10.0)
        predictor.update(14.0)
        self.assertGreater(predictor.predict(3), predictor.predict(1))

    def test_detector_rejects_outlier_from_baseline(self):
        detector = self.symbols["ResidualAnomalyDetector"](
            window=10, z_threshold=4.0, warmup=3
        )
        for value in (0.0, 0.0, 0.0):
            self.assertEqual(detector.score(value), (0.0, False))
        baseline_size = len(detector.residuals)
        z_score, is_anomaly = detector.score(10.0)
        self.assertTrue(is_anomaly)
        self.assertGreater(z_score, detector.z_threshold)
        self.assertEqual(len(detector.residuals), baseline_size)

    def test_offline_detector_is_ready_without_warmup(self):
        detector = self.symbols["ResidualAnomalyDetector"](
            window=10,
            z_threshold=4.0,
            warmup=0,
            fixed_center=0.0,
            fixed_scale=0.1,
        )
        self.assertTrue(detector.ready)
        self.assertEqual(detector.score(0.0), (0.0, False))
        z_score, is_anomaly = detector.score(1.0)
        self.assertTrue(is_anomaly)
        self.assertGreater(z_score, detector.z_threshold)

    def test_detector_uses_independent_spike_and_drop_thresholds(self):
        detector = self.symbols["ResidualAnomalyDetector"](
            window=10,
            z_threshold=4.0,
            drop_z_threshold=8.0,
            warmup=0,
            fixed_center=0.0,
            fixed_scale=1.0,
        )
        self.assertEqual(detector.score(5.0), (5.0, True))
        self.assertEqual(detector.score(-5.0), (-5.0, False))
        self.assertEqual(detector.score(-9.0), (-9.0, True))

    def test_series_uses_offline_model_and_does_not_absorb_attack(self):
        model = OfflineModel(
            alpha=0.35,
            beta=0.1,
            transform="log1p",
            residual_center=0.0,
            residual_scale=0.1,
            z_threshold=4.0,
            created_at="test",
        )
        series = self.symbols["SeriesState"](
            "flow:1:10.0.0.1->10.0.0.4",
            {"type": "flow", "dpid": 1, "nw_src": "10.0.0.1", "nw_dst": "10.0.0.4"},
            model,
        )

        self.assertIsNone(series.ingest(0, 0.0))
        self.assertIsNone(series.ingest(12_500, 1.0))       # 100 kbit/s: prime
        self.assertIsNone(series.ingest(25_000, 2.0))       # baseline estável
        samples_before_attack = series.predictor.n
        anomaly = series.ingest(1_275_000, 3.0)             # 10 Mbit/s: spike

        self.assertIsNotNone(anomaly)
        self.assertEqual(anomaly["kind"], "THROUGHPUT_SPIKE")
        self.assertEqual(anomaly["detection_mode"], "offline")
        self.assertEqual(series.predictor.n, samples_before_attack)

    def test_offline_series_tolerates_one_idle_sample_then_resets(self):
        model = OfflineModel(
            alpha=0.9,
            beta=0.0,
            transform="log1p",
            residual_center=0.0,
            residual_scale=0.4376674,
            z_threshold=3.75,
            drop_z_threshold=20.0,
            created_at="test",
        )
        series = self.symbols["SeriesState"](
            "flow:1:10.0.0.1->10.0.0.8",
            {"type": "flow", "dpid": 1,
             "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            model,
        )

        self.assertIsNone(series.ingest(0, 0.0))
        self.assertIsNone(series.ingest(1, 10.0))          # 0,8 bps: parcial
        self.assertEqual(series.predictor.n, 0)
        self.assertIsNone(series.ingest(125_001, 11.0))    # primeiro intervalo cheio
        self.assertIsNone(series.ingest(250_001, 12.0))    # segundo priming
        self.assertEqual(series.predictor.n, 2)
        self.assertIsNone(series.ingest(375_001, 13.0))    # baseline já pontuado
        self.assertEqual(series.predictor.n, 3)

        self.assertIsNone(series.ingest(375_001, 14.0))    # lacuna entre rajadas
        self.assertEqual(series.predictor.n, 3)
        self.assertEqual(series.idle_samples, 1)

        anomaly = series.ingest(1_625_001, 15.0)           # ataque após a lacuna
        self.assertIsNotNone(anomaly)
        self.assertEqual(anomaly["kind"], "THROUGHPUT_SPIKE")
        self.assertEqual(series.idle_samples, 0)

        self.assertIsNone(series.ingest(1_625_001, 16.0))  # primeira amostra vazia
        self.assertEqual(series.predictor.n, 3)
        self.assertIsNone(series.ingest(1_625_001, 17.0))  # fluxo encerrado
        self.assertEqual(series.predictor.n, 0)
        self.assertEqual(series.predicted_bps, 0.0)

    def test_two_sample_priming_does_not_flag_first_full_interval(self):
        model = OfflineModel(
            alpha=0.9,
            beta=0.0,
            transform="log1p",
            residual_center=0.0,
            residual_scale=0.4376674,
            z_threshold=3.75,
            drop_z_threshold=20.0,
            created_at="test",
            series_priming_samples=2,
        )
        series = self.symbols["SeriesState"](
            "flow:1:10.0.0.1->10.0.0.8",
            {"type": "flow", "dpid": 1,
             "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            model,
        )

        self.assertIsNone(series.ingest(0, 0.0))
        self.assertIsNone(series.ingest(16_679, 1.0))       # 133.432 bps
        self.assertIsNone(series.ingest(147_274, 2.0))      # 1.044.760 bps
        self.assertEqual(series.predictor.n, 2)
        self.assertIsNone(series.ingest(277_869, 3.0))      # baseline estabilizado

        samples_before_attack = series.predictor.n
        anomaly = series.ingest(12_777_869, 4.0)            # 100 Mbit/s
        self.assertIsNotNone(anomaly)
        self.assertEqual(anomaly["kind"], "THROUGHPUT_SPIKE")
        self.assertEqual(series.predictor.n, samples_before_attack)

    def test_repeated_anomalies_are_aggregated_during_cooldown(self):
        class FakeMitigator:
            def __init__(self):
                self.calls = 0

            def maybe_mitigate(self, anomaly):
                self.calls += 1
                return {"attempted": True, "executed": False, "reason": "test"}

        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"PredictorEngine"},
            {
                "Any": Any,
                "Dict": Dict,
                "List": List,
                "Optional": Optional,
                "Tuple": Tuple,
                "OfflineModel": OfflineModel,
                "deque": deque,
                "threading": __import__("threading"),
                "Mitigator": FakeMitigator,
                "now_ns": lambda: 1,
                "EVENT_COOLDOWN_S": 60.0,
                "CONTROLLER_ID": "test-controller",
                "_metric": lambda *_args: None,
                "_etcd": None,
                "COLLABORATION_ENABLED": False,
                "AGENTIC_ENABLED": False,
                "AGENTIC_SHADOW": True,
                "AGENTIC_MODE": "shadow",
            },
        )
        engine = symbols["PredictorEngine"]()

        def anomaly(anomaly_id, timestamp_ns, observed_bps):
            return {
                "anomaly_id": anomaly_id,
                "kind": "THROUGHPUT_SPIKE",
                "key": "flow:1:10.0.0.1->10.0.0.4",
                "meta": {"type": "flow"},
                "observed_bps": observed_bps,
                "z_score": observed_bps / 100.0,
                "ts_detect_ns": timestamp_ns,
            }

        self.assertTrue(engine.register_anomaly(anomaly("first", 1_000_000_000, 100.0), True))
        self.assertFalse(engine.register_anomaly(anomaly("duplicate", 2_000_000_000, 200.0), True))
        self.assertEqual(len(engine.anomalies), 1)
        self.assertEqual(engine.anomalies[0]["suppressed_count"], 1)
        self.assertEqual(engine.anomalies[0]["peak_observed_bps"], 200.0)
        self.assertEqual(engine.anomalies_suppressed, 1)
        self.assertEqual(engine.mitigator.calls, 1)

        self.assertTrue(engine.register_anomaly(anomaly("next", 63_000_000_000, 150.0), True))
        self.assertEqual(len(engine.anomalies), 2)
        self.assertEqual(engine.mitigator.calls, 2)

    def test_collaborative_score_requires_quorum_and_compatible_models(self):
        score = score_collaborative_evidence
        weights = {
            "severity": 0.25,
            "corroboration": 0.25,
            "rate_ratio": 0.13,
            "persistence": 0.12,
            "model_reliability": 0.08,
            "freshness": 0.05,
            "topology": 0.05,
            "agreement": 0.07,
        }

        def evidence(cid, model="model-a", z_score=20.0):
            return {
                "cid": cid,
                "ts_ns": 10_000_000_000,
                "z_score": z_score,
                "threshold": 4.0,
                "observed_bps": 100_000_000.0,
                "predicted_bps": 1_000_000.0,
                "persistence_windows": 3,
                "model_reliability": 1.0,
                "flow_specificity": 1.0,
                "model_id": model,
            }

        kwargs = {
            "now_ns_value": 10_000_000_000,
            "expected_domains": 2,
            "min_domains": 2,
            "weights": weights,
            "freshness_s": 12.0,
            "persistence_windows": 3,
            "rate_ratio_max": 10.0,
            "suspect_threshold": 0.4,
            "alert_threshold": 0.6,
            "decision_threshold": 0.8,
        }
        waiting = score([evidence("domain-0")], **kwargs)
        self.assertEqual(waiting["decision"], "WAITING_QUORUM")
        self.assertEqual(waiting["confirming_domains"], ["domain-0"])

        approved = score([evidence("domain-0"), evidence("domain-1", z_score=18.0)],
                         **kwargs)
        self.assertEqual(approved["decision"], "MITIGATE")
        self.assertGreaterEqual(approved["score"], 0.8)
        self.assertEqual(len(approved["contributions"]), 8)

        mismatch = score([evidence("domain-0"), evidence("domain-1", model="model-b")],
                         **kwargs)
        self.assertEqual(mismatch["decision"], "MODEL_MISMATCH")

    def test_collaborative_score_uses_recorded_precision_at_decision_threshold(self):
        def evidence(severity):
            return {
                "cid": "domain-0",
                "ts_ns": 10_000_000_000,
                "z_score": 1.0 + 2.0 * severity,
                "threshold": 1.0,
                "observed_bps": 10.0,
                "predicted_bps": 1.0,
                "persistence_windows": 1,
                "model_reliability": 1.0,
                "flow_specificity": 1.0,
                "model_id": "model-a",
            }

        kwargs = {
            "now_ns_value": 10_000_000_000,
            "expected_domains": 1,
            "min_domains": 1,
            "weights": {"severity": 1.0},
            "freshness_s": 12.0,
            "persistence_windows": 1,
            "rate_ratio_max": 10.0,
            "suspect_threshold": 0.4,
            "alert_threshold": 0.6,
            "decision_threshold": 0.8,
        }

        rounded_to_threshold = score_collaborative_evidence(
            [evidence(0.7999996)], **kwargs
        )
        self.assertEqual(rounded_to_threshold["score"], 0.8)
        self.assertEqual(rounded_to_threshold["decision"], "MITIGATE")

        remains_below_threshold = score_collaborative_evidence(
            [evidence(0.7999994)], **kwargs
        )
        self.assertEqual(remains_below_threshold["score"], 0.799999)
        self.assertEqual(remains_below_threshold["decision"], "CORROBORATED")

    def test_collaborative_engine_defers_local_mitigation(self):
        class FakeMitigator:
            def __init__(self):
                self.calls = 0

            def maybe_mitigate(self, anomaly):
                self.calls += 1
                return {"attempted": True}

        class FakeCollaboration:
            def __init__(self, engine):
                self.submitted = []

            def submit(self, anomaly):
                self.submitted.append(anomaly["anomaly_id"])

            def snapshot(self):
                return {"requested": True, "active": True, "decisions": []}

        class FakeEtcd:
            def put(self, *_args, **_kwargs):
                return None

        def canonical(anomaly):
            meta = anomaly.get("meta", {})
            if anomaly.get("kind") == "THROUGHPUT_SPIKE" and meta.get("type") == "flow":
                return f"{meta.get('nw_src')}->{meta.get('nw_dst')}"
            return None

        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"PredictorEngine"},
            {
                "Any": Any, "Dict": Dict, "List": List, "Optional": Optional,
                "Tuple": Tuple, "OfflineModel": OfflineModel, "deque": deque,
                "threading": __import__("threading"), "Mitigator": FakeMitigator,
                "CollaborativeDecisionManager": FakeCollaboration,
                "canonical_flow_key": canonical, "now_ns": lambda: 1,
                "EVENT_COOLDOWN_S": 60.0, "CONTROLLER_ID": "domain-0",
                "_metric": lambda *_args: None, "_etcd": FakeEtcd(),
                "json": __import__("json"),
                "COLLABORATION_ENABLED": True,
                "AGENTIC_ENABLED": False,
                "AGENTIC_SHADOW": True,
                "AGENTIC_MODE": "shadow",
            },
        )
        engine = symbols["PredictorEngine"]()
        event = {
            "anomaly_id": "first",
            "kind": "THROUGHPUT_SPIKE",
            "key": "flow:1:10.0.0.1->10.0.0.8",
            "meta": {"type": "flow", "dpid": 1,
                     "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            "observed_bps": 100_000_000.0,
            "predicted_bps": 1_000_000.0,
            "z_score": 20.0,
            "threshold": 4.0,
            "ts_detect_ns": 1_000_000_000,
        }
        self.assertTrue(engine.register_anomaly(event, mitigable=True))
        self.assertEqual(engine.mitigator.calls, 0)
        self.assertEqual(engine.collaboration.submitted, ["first"])
        self.assertEqual(event["mitigation"]["reason"],
                         "aguardando decisão colaborativa")

    def test_agentic_decision_only_updates_its_observation_episode(self):
        def canonical(anomaly):
            meta = anomaly.get("meta", {})
            return f"{meta.get('nw_src')}->{meta.get('nw_dst')}"

        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"PredictorEngine"},
            {
                "Any": Any, "Dict": Dict, "List": List,
                "Optional": Optional, "Tuple": Tuple,
                "OfflineModel": OfflineModel,
                "canonical_flow_key": canonical,
                "COLLAB_WINDOW_S": 4.0,
                "AGENTIC_MODE": "shadow",
            },
        )
        engine = object.__new__(symbols["PredictorEngine"])
        engine.lock = __import__("threading").RLock()
        old_event = {
            "meta": {"nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            "ts_detect_ns": 1_000_000_000,
        }
        current_event = {
            "meta": {"nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            "ts_detect_ns": 9_000_000_000,
        }
        engine.anomalies = deque([current_event, old_event])
        decision = {"decision": "AGREED", "window_ids": [2]}

        engine.apply_agentic_decision(
            "10.0.0.1->10.0.0.8", decision
        )

        self.assertEqual(current_event["agentic_shadow"], decision)
        self.assertNotIn("agentic_shadow", old_event)

    def test_agentic_live_boundary_requires_local_non_degraded_winner(self):
        class FakeMitigator:
            def __init__(self):
                self.calls = 0

            def maybe_mitigate(self, _anomaly):
                self.calls += 1
                return {
                    "attempted": True,
                    "executed": True,
                    "reason": "FlowBlocker HTTP 200",
                }

        def canonical(anomaly):
            meta = anomaly.get("meta", {})
            return f"{meta.get('nw_src')}->{meta.get('nw_dst')}"

        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"PredictorEngine"},
            {
                "Any": Any, "Dict": Dict, "List": List,
                "Optional": Optional, "Tuple": Tuple,
                "OfflineModel": OfflineModel,
                "canonical_flow_key": canonical,
                "AGENTIC_ENABLED": True,
                "AGENTIC_MODE": "authority-live",
                "AGENTIC_LIVE_ACTUATION": True,
                "AUTO_MITIGATE": True,
                "DRY_RUN": False,
                "CONTROLLER_ID": "domain-0",
                "_metric": lambda *_args: None,
            },
        )
        engine = object.__new__(symbols["PredictorEngine"])
        engine.lock = __import__("threading").RLock()
        engine.mitigator = FakeMitigator()
        event = {
            "meta": {
                "type": "flow",
                "nw_src": "10.0.0.1",
                "nw_dst": "10.0.0.8",
            },
        }
        engine.anomalies = deque([event])
        decision = {
            "authority": {
                "authorized": True,
                "authorization": {
                    "authorized": True,
                    "flow": "10.0.0.1->10.0.0.8",
                },
                "claim": {
                    "won": True,
                    "degraded": False,
                    "coordinator": "domain-0",
                },
            },
        }

        result = engine.mitigate_agentic(
            "10.0.0.1->10.0.0.8", decision
        )
        self.assertTrue(result["executed"])
        self.assertEqual(engine.mitigator.calls, 1)

        decision["authority"]["claim"]["degraded"] = True
        denied = engine.mitigate_agentic(
            "10.0.0.1->10.0.0.8", decision
        )
        self.assertFalse(denied["attempted"])
        self.assertEqual(engine.mitigator.calls, 1)

    def test_mcda_observation_preserves_agentic_live_result(self):
        def canonical(anomaly):
            meta = anomaly.get("meta", {})
            return f"{meta.get('nw_src')}->{meta.get('nw_dst')}"

        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"PredictorEngine"},
            {
                "Any": Any, "Dict": Dict, "List": List,
                "Optional": Optional, "Tuple": Tuple,
                "OfflineModel": OfflineModel,
                "canonical_flow_key": canonical,
                "AGENTIC_ENABLED": True,
                "AGENTIC_MODE": "authority-live",
            },
        )
        engine = object.__new__(symbols["PredictorEngine"])
        engine.lock = __import__("threading").RLock()
        live_result = {
            "attempted": True,
            "executed": True,
            "reason": "FlowBlocker HTTP 200",
        }
        event = {
            "meta": {"nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
            "mitigation": live_result,
        }
        engine.anomalies = deque([event])
        mcda = {
            "decision": "MITIGATE",
            "mitigation": {
                "attempted": False,
                "executed": False,
                "reason": "MCDA observacional durante authority-live",
            },
        }

        engine.apply_collaborative_decision(
            "10.0.0.1->10.0.0.8", mcda
        )

        self.assertEqual(event["mitigation"], live_result)
        self.assertEqual(event["collaboration"], mcda)


class FlowRuleTests(unittest.TestCase):
    def test_flowblocker_builds_openflow10_drop(self):
        symbols = load_definitions(
            "flow_blocker/flow_blocker_cnsm.py",
            {"build_block_flow"},
            {"Dict": dict, "Any": object, "FLOW_PRIORITY": 32768,
             "IDLE_TIMEOUT": 0, "HARD_TIMEOUT": 0},
        )
        flow = symbols["build_block_flow"](1, "10.0.0.1", "10.0.0.4")
        self.assertEqual(flow["priority"], 32768)
        self.assertEqual(flow["actions"], [])
        self.assertEqual(
            flow["match"],
            {"dl_type": 2048, "nw_src": "10.0.0.1", "nw_dst": "10.0.0.4"},
        )

    def test_simpleswitch_rules_are_disjoint_and_below_drop_priority(self):
        symbols = load_definitions(
            "rest_client/Simpleswitch_cnsm.py",
            {"build_flow", "build_ipv4_flow", "build_arp_flow"},
            {
                "SEND_OUT": None,
                "FORWARD_PRIORITY": 3000,
                "ETH_TYPE_IP": 0x0800,
                "ETH_TYPE_ARP": 0x0806,
                "IPV4_IDLE_TIMEOUT": 30,
                "IPV4_HARD_TIMEOUT": 0,
                "ARP_IDLE_TIMEOUT": 5,
                "ARP_HARD_TIMEOUT": 5,
            },
        )
        ipv4_flow = symbols["build_ipv4_flow"](
            1, "10.0.0.1", "10.0.0.4", 1, 2, 99
        )
        arp_flow = symbols["build_arp_flow"](
            1, "00:00:00:00:00:01", "00:00:00:00:00:04", 1, 2, 99
        )
        self.assertEqual(ipv4_flow["match"]["dl_type"], 0x0800)
        self.assertEqual(arp_flow["match"]["dl_type"], 0x0806)
        self.assertLess(ipv4_flow["priority"], 32768)
        self.assertEqual(ipv4_flow["idle_timeout"], 30)


class CollectorTests(unittest.TestCase):
    def test_drop_rule_and_shadowed_forward_rule_are_not_ingested(self):
        symbols = load_definitions(
            "flow_predictor_cnsm.py",
            {"blocked_flow_pairs", "Collector"},
            {
                "Any": Any,
                "Dict": Dict,
                "List": List,
                "Optional": Optional,
                "deque": deque,
                "threading": __import__("threading"),
                "time": __import__("time"),
                "HISTORY_WINDOW": 120,
                "FLOW_SURGE_WARMUP": 15,
            },
        )

        class FakeEngine:
            def __init__(self):
                self.ingested = []

            def ingest(self, key, meta, byte_count, timestamp):
                self.ingested.append((key, byte_count))

        engine = FakeEngine()
        collector = symbols["Collector"](engine)
        flow_stats = {
            "1": [
                {
                    "match": {"nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
                    "actions": [],
                    "byte_count": 200_000_000,
                },
                {
                    "match": {"nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
                    "actions": ["OUTPUT:2"],
                    "byte_count": 150_000_000,
                },
                {
                    "match": {"nw_src": "10.0.0.2", "nw_dst": "10.0.0.3"},
                    "actions": ["OUTPUT:3"],
                    "byte_count": 42,
                },
            ]
        }
        responses = {
            "/stats/switches": [1],
            "/stats/port/1": {"1": []},
            "/stats/flow/1": flow_stats,
        }
        collector._get = responses.get
        collector._collect_once()

        self.assertEqual(
            engine.ingested,
            [("flow:1:10.0.0.2->10.0.0.3", 42)],
        )


class CollaborativeManagerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.namespace = {
            "Any": Any,
            "Dict": Dict,
            "List": List,
            "Optional": Optional,
            "Tuple": Tuple,
            "threading": __import__("threading"),
            "hashlib": __import__("hashlib"),
            "json": __import__("json"),
            "math": math,
            "CONTROLLER_ID": "domain-0",
            "COLLAB_WINDOW_S": 4.0,
            "COLLAB_CLAIM_TTL_S": 60.0,
            "FLOW_IDLE_RESET_SAMPLES": 2,
            "Z_THRESHOLD": 4.0,
            "clip01": lambda value: max(0.0, min(1.0, float(value))),
            "canonical_flow_key": lambda anomaly: (
                f"{anomaly['meta']['nw_src']}->{anomaly['meta']['nw_dst']}"
            ),
            "now_ns": lambda: 10_000_000_000,
            "_metric": lambda *_args: None,
            "logger": __import__("types").SimpleNamespace(
                error=lambda *_args, **_kwargs: None
            ),
        }
        load_definitions(
            "flow_predictor_cnsm.py",
            {"CollaborativeDecisionManager"},
            cls.namespace,
        )

    def bare_manager(self):
        manager = object.__new__(self.namespace["CollaborativeDecisionManager"])

        class Engine:
            offline_model = None
            detection_mode = "offline"

            def __init__(self):
                self.applied = []

            def apply_collaborative_decision(self, flow, decision):
                self.applied.append((flow, decision))

        manager.engine = Engine()
        manager.lock = __import__("threading").RLock()
        manager.wake = __import__("threading").Event()
        manager.local_candidates = {}
        manager.dirty_flows = set()
        manager.decisions = {}
        manager.decision_events = deque(maxlen=200)
        manager.last_decision_key = {}
        manager.last_logged_state = {}
        manager.mitigation_results = {}
        manager.claims = {}
        manager.claim_leases = {}
        manager.claims_won = 0
        manager.claims_lost = 0
        return manager

    def test_authority_live_keeps_mcda_observational(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        manager.local_candidates[flow] = {
            "window_id": 2,
            "evidence": {"ts_ns": 9_500_000_000},
        }
        manager._read_evidence = lambda _flow: []
        manager._claim_mitigation = lambda *_args, **_kwargs: self.fail(
            "MCDA não deve disputar claim em authority-live"
        )
        globals_dict = manager._evaluate_candidates.__globals__
        replacements = {
            "COLLAB_EVIDENCE_TTL_S": 12.0,
            "COLLAB_EXPECTED_DOMAINS": 2,
            "COLLAB_MIN_DOMAINS": 2,
            "COLLAB_WEIGHTS": {},
            "COLLAB_PERSISTENCE_WINDOWS": 3,
            "COLLAB_RATE_RATIO_MAX": 10.0,
            "COLLAB_SUSPECT_THRESHOLD": 0.4,
            "COLLAB_ALERT_THRESHOLD": 0.6,
            "COLLAB_DECISION_THRESHOLD": 0.8,
            "AGENTIC_ENABLED": True,
            "AGENTIC_MODE": "authority-live",
            "score_collaborative_evidence": lambda *_args, **_kwargs: {
                "decision": "MITIGATE",
                "score": 0.95,
                "confirming_domains": ["domain-0", "domain-1"],
                "window_ids": [2],
            },
        }
        missing = object()
        original = {
            name: globals_dict.get(name, missing) for name in replacements
        }
        globals_dict.update(replacements)
        try:
            manager._evaluate_candidates()
        finally:
            for name, value in original.items():
                if value is missing:
                    globals_dict.pop(name, None)
                else:
                    globals_dict[name] = value

        decision = manager.decisions[flow]
        self.assertEqual(decision["published_ns"], 10_000_000_000)
        self.assertGreaterEqual(decision["published_ns"], decision["evaluated_ns"])
        self.assertIsNone(decision["claim"])
        self.assertFalse(decision["mitigation"]["attempted"])
        self.assertEqual(decision["mitigation"]["owner"], "agentic")
        self.assertEqual(len(manager.engine.applied), 1)

    def test_local_switch_views_are_aggregated_without_summing_rates(self):
        manager = self.bare_manager()

        def anomaly(dpid, z_score, observed):
            return {
                "kind": "THROUGHPUT_SPIKE",
                "meta": {"type": "flow", "dpid": dpid,
                         "nw_src": "10.0.0.1", "nw_dst": "10.0.0.8"},
                "ts_detect_ns": 5_000_000_000,
                "z_score": z_score,
                "threshold": 4.0,
                "observed_bps": observed,
                "predicted_bps": 1_000_000.0,
            }

        manager.submit(anomaly(1, 10.0, 80_000_000.0))
        manager.submit(anomaly(2, 20.0, 100_000_000.0))
        evidence = manager.local_candidates["10.0.0.1->10.0.0.8"]["evidence"]
        self.assertEqual(evidence["dpids"], [1, 2])
        self.assertEqual(evidence["observed_bps"], 100_000_000.0)
        self.assertEqual(evidence["z_score"], 20.0)

    def test_local_evidence_is_forwarded_to_shadow_agent(self):
        manager = self.bare_manager()

        class FakeAgentic:
            def __init__(self):
                self.rows = []

            def submit_evidence(self, evidence):
                self.rows.append(evidence)

        manager.engine.agentic = FakeAgentic()
        manager.submit({
            "kind": "THROUGHPUT_SPIKE",
            "meta": {
                "type": "flow",
                "dpid": 1,
                "nw_src": "10.0.0.1",
                "nw_dst": "10.0.0.8",
            },
            "ts_detect_ns": 5_000_000_000,
            "z_score": 12.0,
            "threshold": 4.0,
            "observed_bps": 50_000_000.0,
            "predicted_bps": 1_000_000.0,
        })

        self.assertEqual(len(manager.engine.agentic.rows), 1)
        self.assertEqual(
            manager.engine.agentic.rows[0]["flow"],
            "10.0.0.1->10.0.0.8",
        )

    def test_shadow_failure_does_not_interrupt_mcda_submission(self):
        manager = self.bare_manager()

        class FailingAgentic:
            def submit_evidence(self, _evidence):
                raise RuntimeError("shadow unavailable")

        manager.engine.agentic = FailingAgentic()
        accepted = manager.submit({
            "kind": "THROUGHPUT_SPIKE",
            "meta": {
                "type": "flow",
                "dpid": 1,
                "nw_src": "10.0.0.1",
                "nw_dst": "10.0.0.8",
            },
            "ts_detect_ns": 5_000_000_000,
            "z_score": 12.0,
            "threshold": 4.0,
            "observed_bps": 50_000_000.0,
            "predicted_bps": 1_000_000.0,
        })

        self.assertTrue(accepted)
        self.assertTrue(manager.wake.is_set())
        self.assertIn("10.0.0.1->10.0.0.8", manager.local_candidates)

    def test_model_identity_includes_the_priming_contract(self):
        manager = self.bare_manager()

        def model(priming_samples):
            return OfflineModel(
                alpha=0.9,
                beta=0.0,
                transform="log1p",
                residual_center=0.0,
                residual_scale=0.3,
                z_threshold=5.0,
                drop_z_threshold=20.0,
                created_at="ignored",
                series_priming_samples=priming_samples,
                training={
                    "dataset_sha256": "same-dataset",
                    "metrics": {"precision": 0.9},
                },
            )

        manager.engine.offline_model = model(1)
        one_sample_id, reliability = manager._model_identity()
        manager.engine.offline_model = model(2)
        two_sample_id, _ = manager._model_identity()

        self.assertNotEqual(one_sample_id, two_sample_id)
        self.assertEqual(reliability, 0.9)

    def test_model_identity_includes_idle_reset_contract(self):
        manager = self.bare_manager()
        manager.engine.offline_model = OfflineModel(
            alpha=0.9,
            beta=0.0,
            transform="log1p",
            residual_center=0.0,
            residual_scale=0.3,
            z_threshold=5.0,
            drop_z_threshold=20.0,
            created_at="ignored",
            series_priming_samples=2,
            training={"dataset_sha256": "same-dataset"},
        )

        self.namespace["FLOW_IDLE_RESET_SAMPLES"] = 1
        immediate_id, _ = manager._model_identity()
        self.namespace["FLOW_IDLE_RESET_SAMPLES"] = 2
        tolerant_id, _ = manager._model_identity()

        self.assertNotEqual(immediate_id, tolerant_id)

    def test_atomic_claim_has_a_single_winner(self):
        class Version:
            def __init__(self, key):
                self.key = key

            def __eq__(self, value):
                return ("version", self.key, value)

        class Transactions:
            @staticmethod
            def version(key):
                return Version(key)

            @staticmethod
            def put(key, value, lease):
                return ("put", key, value, lease)

        class Lease:
            id = 123

        class FakeEtcd:
            transactions = Transactions()

            def __init__(self):
                self.values = {}

            def lease(self, _ttl):
                return Lease()

            def transaction(self, compare, success, failure):
                _, key, expected = compare[0]
                if (0 if key not in self.values else 1) != expected:
                    return False, failure
                _, _, value, _lease = success[0]
                self.values[key] = value.encode("utf-8")
                return True, success

            def get(self, key):
                return self.values.get(key), None

        self.namespace["_etcd"] = FakeEtcd()
        decision = {
            "score": 0.95,
            "confirming_domains": ["domain-0", "domain-1"],
        }
        first = self.bare_manager()
        second = self.bare_manager()

        self.namespace["CONTROLLER_ID"] = "domain-0"
        first_claim = first._claim_mitigation("10.0.0.1->10.0.0.8", decision)
        self.namespace["CONTROLLER_ID"] = "domain-1"
        second_claim = second._claim_mitigation("10.0.0.1->10.0.0.8", decision)

        self.assertTrue(first_claim["won"])
        self.assertFalse(second_claim["won"])
        self.assertEqual(second_claim["coordinator"], "domain-0")


if __name__ == "__main__":
    unittest.main()
