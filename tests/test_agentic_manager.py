import ast
import json
import math
import threading
import types
import unittest
from collections import deque
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from agent_protocol import agent_flow_hash
from agent_authority import claim_agentic_mitigation, evaluate_agentic_authority
from domain_agent import DomainAgent, domain_role


ROOT = Path(__file__).resolve().parents[1]


def load_manager(namespace):
    source = (ROOT / "flow_predictor_cnsm.py").read_text(encoding="utf-8")
    tree = ast.parse(source, filename="flow_predictor_cnsm.py")
    selected = [
        node for node in tree.body
        if isinstance(node, ast.ClassDef) and node.name == "AgenticShadowManager"
    ]
    exec(compile(ast.Module(body=selected, type_ignores=[]),
                 "flow_predictor_cnsm.py", "exec"), namespace)
    return namespace["AgenticShadowManager"]


class AgenticShadowManagerTests(unittest.TestCase):
    NOW_NS = 10_000_000_000

    class FakeEtcd:
        class Lease:
            id = 1

        class Metadata:
            def __init__(self, key):
                self.key = key.encode("utf-8")

        class Version:
            def __init__(self, key):
                self.key = key

            def __eq__(self, value):
                return ("version", self.key, value)

        class Transactions:
            @staticmethod
            def version(key):
                return AgenticShadowManagerTests.FakeEtcd.Version(key)

            @staticmethod
            def put(key, value, lease_id):
                return ("put", key, value, lease_id)

        def __init__(self):
            self.values = {}
            self.transactions = self.Transactions()

        def lease(self, _ttl):
            return self.Lease()

        def put(self, key, value, lease=None):
            self.values[key] = value.encode("utf-8")

        def get_prefix(self, prefix):
            return [
                (value, self.Metadata(key)) for key, value in self.values.items()
                if key.startswith(prefix)
            ]

        def transaction(self, *, compare, success, failure):
            _kind, key, expected = compare[0]
            won = expected == 0 and key not in self.values
            for kind, operation_key, value, _lease_id in (success if won else failure):
                if kind == "put":
                    self.values[operation_key] = value.encode("utf-8")
            return won, []

        def get(self, key):
            return self.values.get(key), None

    @classmethod
    def setUpClass(cls):
        cls.etcd = cls.FakeEtcd()
        cls.metrics = []
        cls.manager_class = load_manager({
            "Any": Any,
            "Dict": Dict,
            "List": List,
            "Optional": Optional,
            "Tuple": Tuple,
            "threading": threading,
            "deque": deque,
            "json": json,
            "math": math,
            "time": __import__("time"),
            "DomainAgent": DomainAgent,
            "domain_role": domain_role,
            "agent_flow_hash": agent_flow_hash,
            "CONTROLLER_ID": "domain-0",
            "AGENT_PROPOSAL_THRESHOLD": 0.65,
            "COLLAB_PERSISTENCE_WINDOWS": 3,
            "COLLAB_RATE_RATIO_MAX": 10.0,
            "AGENT_PROPOSAL_TTL_S": 12.0,
            "AGENT_REQUIRED_VOTES": 2,
            "AGENT_NEGOTIATION_WINDOW_S": 4.0,
            "COLLAB_EVALUATION_INTERVAL_S": 0.5,
            "AGENT_TOPOLOGY_CACHE_S": 5.0,
            "FLOWBLOCKER_URL": "http://flow-blocker",
            "REQUEST_TIMEOUT_S": 1.0,
            "WHITELIST_IPS": set(),
            "AGENTIC_ENABLED": True,
            "AGENTIC_SHADOW": True,
            "AGENTIC_MODE": "shadow",
            "AGENTIC_LIVE_ACTUATION": False,
            "AUTO_MITIGATE": True,
            "DRY_RUN": True,
            "AGENT_CLAIM_TTL_S": 60.0,
            "evaluate_agentic_authority": evaluate_agentic_authority,
            "claim_agentic_mitigation": claim_agentic_mitigation,
            "now_ns": lambda: cls.NOW_NS,
            "_metric": lambda tag, message: cls.metrics.append((tag, message)),
            "_etcd": cls.etcd,
            "logger": types.SimpleNamespace(
                warning=lambda *_args, **_kwargs: None,
                error=lambda *_args, **_kwargs: None,
            ),
            "requests": types.SimpleNamespace(),
        })

    def setUp(self):
        self.etcd.values.clear()
        self.metrics.clear()

    @staticmethod
    def evidence(cid="domain-0"):
        return {
            "schema_version": 1,
            "cid": cid,
            "flow": "10.0.0.1->10.0.0.8",
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.8",
            "window_id": 2,
            "ts_ns": 9_500_000_000,
            "observed_bps": 100_000_000.0,
            "predicted_bps": 1_000_000.0,
            "z_score": 15.0,
            "threshold": 5.0,
            "persistence_windows": 2,
            "model_id": "holt:model-a",
            "model_reliability": 0.92,
        }

    def bare_manager(self):
        manager = object.__new__(self.manager_class)

        class Engine:
            collaboration = None

            def __init__(self):
                self.applied = []
                self.live_calls = []

            def apply_agentic_decision(self, flow, decision):
                self.applied.append((flow, decision))

            def mitigate_agentic(self, flow, decision):
                self.live_calls.append((flow, decision.get("event_id")))
                return {
                    "attempted": True,
                    "executed": True,
                    "reason": "FlowBlocker HTTP 200",
                }

        manager.engine = Engine()
        manager.agent = DomainAgent(
            "domain-0", proposal_threshold=0.65,
            persistence_windows=3, rate_ratio_max=10.0,
            proposal_ttl_s=12.0, required_votes=2,
            negotiation_window_s=4.0,
        )
        manager.lock = threading.RLock()
        manager.wake = threading.Event()
        manager.local_evidence = {}
        manager.local_proposals = {}
        manager.dirty_flows = set()
        manager.decisions = {}
        manager.decision_events = deque(maxlen=200)
        manager.last_event_key = {}
        manager.last_logged_state = {}
        manager.domain_hosts = {}
        manager.topology_cached_at = 0.0
        manager.topology_retry_at = {}
        manager.errors = 0
        manager.topology_errors = 0
        manager.proposals_published = 0
        manager.agreements = 0
        manager.disagreements = 0
        manager.waiting_events = 0
        manager.expired_proposals = 0
        manager.authority_evaluations = 0
        manager.authorizations = 0
        manager.authority_denials = 0
        manager.claims_won = 0
        manager.claims_lost = 0
        manager.live_attempts = 0
        manager.live_executions = 0
        manager.live_failures = 0
        manager.started_ns = self.NOW_NS
        return manager

    def test_runtime_publishes_structured_proposal_and_never_executes(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        manager.local_evidence[flow] = self.evidence()
        manager.dirty_flows.add(flow)
        manager._topology_context = types.MethodType(
            lambda _self, _evidence: (
                "SOURCE", ["domain-0", "domain-1"],
                "domain-0", "domain-1",
            ),
            manager,
        )

        manager._publish_dirty_proposals()

        proposal = manager.local_proposals[flow]
        self.assertEqual(proposal["proposal"], "MITIGATE")
        self.assertEqual(proposal["role"], "SOURCE")
        self.assertEqual(manager.proposals_published, 1)
        self.assertTrue(any(key.startswith("flowpredictor/agent-proposal/")
                            for key in self.etcd.values))

        peer = DomainAgent(
            "domain-1", proposal_threshold=0.65,
            persistence_windows=3, rate_ratio_max=10.0,
            proposal_ttl_s=12.0, required_votes=2,
            negotiation_window_s=4.0,
        ).build_proposal(
            self.evidence("domain-1"),
            role="DESTINATION",
            relevant_domains=["domain-0", "domain-1"],
            source_cid="domain-0",
            destination_cid="domain-1",
            created_ns=self.NOW_NS,
        )
        peer_key = (f"flowpredictor/agent-proposal/{agent_flow_hash(flow)}/"
                    f"{peer['window_id']}/domain-1")
        self.etcd.put(peer_key, json.dumps(peer))

        manager._evaluate_negotiations()

        decision = manager.decisions[flow]
        self.assertEqual(decision["decision"], "AGREED")
        self.assertFalse(decision["authoritative"])
        self.assertFalse(decision["execution"]["attempted"])
        self.assertEqual(len(manager.engine.applied), 1)
        self.assertEqual(manager.engine.applied[0][0], flow)
        self.assertEqual(len(manager.decision_events), 1)
        event = manager.decision_events[0]
        self.assertEqual(event["decision"], "AGREED")
        self.assertEqual(event["state_entered_ns"], self.NOW_NS)
        self.assertTrue(event["event_id"].startswith("domain-0:"))

        manager._evaluate_negotiations()
        self.assertEqual(len(manager.decision_events), 1)
        self.assertEqual(manager.agreements, 1)

    def test_authority_dry_run_validates_claims_and_never_executes(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        manager.engine.collaboration = types.SimpleNamespace(
            lock=threading.RLock(),
            decisions={flow: {
                "flow": flow,
                "decision": "MITIGATE",
                "score": 0.95,
                "confirming_domains": ["domain-0", "domain-1"],
                "evaluated_ns": self.NOW_NS,
                "window_ids": [2],
            }},
            decision_events=deque(maxlen=200),
        )
        source = DomainAgent(
            "domain-0", proposal_threshold=0.65,
            persistence_windows=3, rate_ratio_max=10.0,
            proposal_ttl_s=12.0, required_votes=2,
            negotiation_window_s=4.0,
        ).build_proposal(
            self.evidence("domain-0"), role="SOURCE",
            relevant_domains=["domain-0", "domain-1"],
            source_cid="domain-0", destination_cid="domain-1",
            created_ns=self.NOW_NS,
        )
        destination = DomainAgent(
            "domain-1", proposal_threshold=0.65,
            persistence_windows=3, rate_ratio_max=10.0,
            proposal_ttl_s=12.0, required_votes=2,
            negotiation_window_s=4.0,
        ).build_proposal(
            self.evidence("domain-1"), role="DESTINATION",
            relevant_domains=["domain-0", "domain-1"],
            source_cid="domain-0", destination_cid="domain-1",
            created_ns=self.NOW_NS,
        )
        manager.local_proposals[flow] = source
        source_key = (
            f"flowpredictor/agent-proposal/{agent_flow_hash(flow)}/2/domain-0"
        )
        destination_key = (
            f"flowpredictor/agent-proposal/{agent_flow_hash(flow)}/2/domain-1"
        )
        self.etcd.put(source_key, json.dumps(source))
        self.etcd.put(destination_key, json.dumps(destination))
        globals_dict = self.manager_class._evaluate_negotiations.__globals__
        original_mode = globals_dict["AGENTIC_MODE"]
        globals_dict["AGENTIC_MODE"] = "authority-dry-run"
        try:
            manager._evaluate_negotiations()
        finally:
            globals_dict["AGENTIC_MODE"] = original_mode

        decision = manager.decisions[flow]
        self.assertTrue(decision["authoritative"])
        self.assertFalse(decision["actuation_enabled"])
        self.assertTrue(decision["authority"]["authorized"])
        self.assertTrue(decision["authority"]["claim"]["won"])
        self.assertTrue(decision["execution"]["would_execute"])
        self.assertFalse(decision["execution"]["attempted"])
        self.assertFalse(decision["execution"]["executed"])
        frozen = decision["authority"]["mcda_comparison"]
        self.assertTrue(frozen["available"])
        self.assertTrue(frozen["matches"])
        self.assertEqual(frozen["basis"], "authority_evaluation")
        self.assertEqual(frozen["captured_ns"], self.NOW_NS)
        self.assertEqual(manager.authorizations, 1)
        self.assertEqual(manager.claims_won, 1)

    def test_authority_live_executes_only_once_for_the_claim_winner(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        for cid, role in (("domain-0", "SOURCE"),
                          ("domain-1", "DESTINATION")):
            proposal = DomainAgent(
                cid, proposal_threshold=0.65,
                persistence_windows=3, rate_ratio_max=10.0,
                proposal_ttl_s=12.0, required_votes=2,
                negotiation_window_s=4.0,
            ).build_proposal(
                self.evidence(cid), role=role,
                relevant_domains=["domain-0", "domain-1"],
                source_cid="domain-0", destination_cid="domain-1",
                created_ns=self.NOW_NS,
            )
            key = (
                f"flowpredictor/agent-proposal/{agent_flow_hash(flow)}/"
                f"2/{cid}"
            )
            self.etcd.put(key, json.dumps(proposal))
            if cid == "domain-0":
                manager.local_proposals[flow] = proposal

        globals_dict = self.manager_class._evaluate_negotiations.__globals__
        original = {
            name: globals_dict[name]
            for name in ("AGENTIC_MODE", "AGENTIC_LIVE_ACTUATION",
                         "AUTO_MITIGATE", "DRY_RUN")
        }
        globals_dict.update({
            "AGENTIC_MODE": "authority-live",
            "AGENTIC_LIVE_ACTUATION": True,
            "AUTO_MITIGATE": True,
            "DRY_RUN": False,
        })
        try:
            manager._evaluate_negotiations()
            manager._evaluate_negotiations()
        finally:
            globals_dict.update(original)

        decision = manager.decisions[flow]
        self.assertTrue(decision["authoritative"])
        self.assertTrue(decision["actuation_enabled"])
        self.assertTrue(decision["authority"]["authorized"])
        self.assertTrue(decision["authority"]["claim"]["won"])
        self.assertTrue(decision["execution"]["attempted"])
        self.assertTrue(decision["execution"]["executed"])
        self.assertEqual(decision["execution"]["owner"], "agentic")
        self.assertEqual(len(manager.engine.live_calls), 1)
        self.assertEqual(manager.live_attempts, 1)
        self.assertEqual(manager.live_executions, 1)
        self.assertEqual(manager.live_failures, 0)

    def test_expired_proposal_does_not_delete_new_dirty_evidence(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        old = self.evidence()
        old.update({"window_id": 2, "expires_ns": self.NOW_NS - 1})
        new = self.evidence()
        new["window_id"] = 3
        manager.local_proposals[flow] = old
        manager.local_evidence[flow] = new
        manager.dirty_flows.add(flow)

        manager._evaluate_negotiations()

        self.assertNotIn(flow, manager.local_proposals)
        self.assertEqual(manager.local_evidence[flow]["window_id"], 3)
        self.assertIn(flow, manager.dirty_flows)

    def test_new_evidence_resets_episode_when_observation_ttl_expired(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        old = self.evidence()
        old.update({
            "observation_ns": old["ts_ns"],
            "expires_ns": 40_000_000_000,
        })
        manager.local_proposals[flow] = old
        manager.local_evidence[flow] = self.evidence()
        manager.decisions[flow] = {"decision": "AGREED"}
        manager.last_logged_state[flow] = "AGREED"
        manager.agent.states[flow] = {"state": "AGREED"}
        new = self.evidence()
        new.update({"window_id": 3, "ts_ns": 29_500_000_000})
        original_now = self.__class__.NOW_NS
        self.__class__.NOW_NS = 30_000_000_000
        try:
            self.assertTrue(manager.submit_evidence(new))
        finally:
            self.__class__.NOW_NS = original_now

        self.assertNotIn(flow, manager.decisions)
        self.assertNotIn(flow, manager.last_logged_state)
        self.assertNotIn(flow, manager.agent.states)
        self.assertEqual(manager.local_evidence[flow]["window_id"], 3)

    def test_expired_topology_cache_fails_closed(self):
        manager = self.bare_manager()
        manager.domain_hosts = {
            "10.0.0.1": {"cid": "domain-0"},
            "10.0.0.8": {"cid": "domain-1"},
        }
        manager.topology_cached_at = -1.0
        globals_dict = self.manager_class._load_domain_hosts.__globals__
        original_requests = globals_dict["requests"]

        class RequestException(Exception):
            pass

        globals_dict["requests"] = types.SimpleNamespace(
            get=lambda *_args, **_kwargs: (_ for _ in ()).throw(RequestException()),
            exceptions=types.SimpleNamespace(RequestException=RequestException),
        )
        try:
            self.assertEqual(manager._load_domain_hosts(), {})
        finally:
            globals_dict["requests"] = original_requests

    def test_unknown_topology_is_retried_while_evidence_is_valid(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        manager.local_evidence[flow] = self.evidence()
        manager.dirty_flows.add(flow)
        contexts = iter([
            ("UNKNOWN", [], None, None),
            ("SOURCE", ["domain-0", "domain-1"],
             "domain-0", "domain-1"),
        ])
        manager._topology_context = types.MethodType(
            lambda _self, _evidence: next(contexts), manager
        )

        manager._publish_dirty_proposals()

        self.assertEqual(manager.local_proposals[flow]["proposal"], "WAIT")
        self.assertIn(flow, manager.topology_retry_at)

        manager.topology_retry_at[flow] = 0.0
        manager._publish_dirty_proposals()

        self.assertEqual(manager.local_proposals[flow]["proposal"], "MITIGATE")
        self.assertNotIn(flow, manager.topology_retry_at)

    def test_stale_dirty_evidence_is_pruned_without_a_proposal(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        manager.local_evidence[flow] = self.evidence()
        manager.dirty_flows.add(flow)
        manager.decisions[flow] = {"decision": "WAITING"}
        manager.last_logged_state[flow] = "WAITING"
        manager.agent.states[flow] = {"state": "WAITING"}
        original_now = self.__class__.NOW_NS
        self.__class__.NOW_NS = 30_000_000_000
        manager._topology_context = types.MethodType(
            lambda *_args: self.fail("stale evidence reached topology lookup"),
            manager,
        )
        try:
            manager._publish_dirty_proposals()
        finally:
            self.__class__.NOW_NS = original_now

        self.assertNotIn(flow, manager.local_evidence)
        self.assertNotIn(flow, manager.dirty_flows)
        self.assertNotIn(flow, manager.decisions)
        self.assertNotIn(flow, manager.agent.states)

    def test_etcd_key_must_match_proposal_identity(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        proposal = DomainAgent(
            "domain-1", proposal_threshold=0.65,
            persistence_windows=3, rate_ratio_max=10.0,
            proposal_ttl_s=12.0, required_votes=2,
            negotiation_window_s=4.0,
        ).build_proposal(
            self.evidence("domain-1"),
            role="DESTINATION",
            relevant_domains=["domain-0", "domain-1"],
            source_cid="domain-0",
            destination_cid="domain-1",
            created_ns=self.NOW_NS,
        )
        forged_key = (
            f"flowpredictor/agent-proposal/{agent_flow_hash(flow)}/"
            f"{proposal['window_id']}/domain-0"
        )
        self.etcd.put(forged_key, json.dumps(proposal))

        self.assertEqual(manager._read_proposals(flow), [])

    def test_expiry_clears_current_episode_state(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        expired = self.evidence()
        expired["expires_ns"] = self.NOW_NS - 1
        manager.local_proposals[flow] = expired
        manager.local_evidence[flow] = self.evidence()
        manager.decisions[flow] = {"decision": "AGREED"}
        manager.last_logged_state[flow] = "AGREED"
        manager.agent.states[flow] = {"state": "AGREED"}

        manager._evaluate_negotiations()

        self.assertNotIn(flow, manager.decisions)
        self.assertNotIn(flow, manager.last_logged_state)
        self.assertNotIn(flow, manager.agent.states)

    def test_mcda_comparison_requires_the_same_episode(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        collaboration = types.SimpleNamespace(
            lock=threading.RLock(),
            decisions={flow: {
                "decision": "MITIGATE",
                "score": 0.95,
                "confirming_domains": ["domain-0", "domain-1"],
                "evaluated_ns": self.NOW_NS,
                "window_ids": [99],
            }},
        )
        manager.engine.collaboration = collaboration
        agent_decision = {"decision": "AGREED", "window_ids": [2]}

        different = manager._legacy_comparison(flow, agent_decision)
        self.assertFalse(different["available"])
        self.assertIsNone(different["matches"])

        collaboration.decisions[flow]["window_ids"] = [2]
        same = manager._legacy_comparison(flow, agent_decision)
        self.assertTrue(same["available"])
        self.assertTrue(same["matches"])

    def test_mcda_comparison_uses_history_after_current_episode_advances(self):
        manager = self.bare_manager()
        flow = "10.0.0.1->10.0.0.8"
        collaboration = types.SimpleNamespace(
            lock=threading.RLock(),
            decisions={flow: {
                "flow": flow,
                "decision": "SUSPECT",
                "score": 0.7,
                "confirming_domains": ["domain-0"],
                "evaluated_ns": self.NOW_NS + 2,
                "window_ids": [3],
            }},
            decision_events=deque([{
                "flow": flow,
                "decision": "MITIGATE",
                "score": 0.95,
                "confirming_domains": ["domain-0", "domain-1"],
                "evaluated_ns": self.NOW_NS + 1,
                "published_ns": self.NOW_NS + 2,
                "window_ids": [2],
            }], maxlen=200),
        )
        manager.engine.collaboration = collaboration

        comparison = manager._legacy_comparison(
            flow, {"decision": "AGREED", "window_ids": [2]}
        )

        self.assertTrue(comparison["available"])
        self.assertTrue(comparison["matches"])
        self.assertEqual(comparison["matched_window_ids"], [2])
        self.assertEqual(comparison["mcda"]["decision"], "MITIGATE")
        self.assertEqual(comparison["mcda"]["published_ns"], self.NOW_NS + 2)


if __name__ == "__main__":
    unittest.main()
