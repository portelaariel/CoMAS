import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from llm_auditor.agent_explanation import (
    OUTPUT_TOKENS, build_packets, explain, main, request_payload,
    sha, validate_narrative,
)
from llm_auditor.ollama import OllamaAuditError


FLOW = "10.0.0.1->10.0.0.8"


def fixture():
    full = {
        "cid": "domain-0", "flow": FLOW, "model_id": "frozen-model",
        "window_id": 1, "observation_ns": 100, "created_ns": 110,
        "expires_ns": 10000, "role": "SOURCE", "proposal": "MITIGATE",
        "confidence": 0.7, "reason": "evidência local e contexto superam o limiar do agente",
        "observed_bps": 1000, "predicted_bps": 200, "z_score": 8,
        "threshold": 3, "criteria": {"severity": 0.9}, "persistence_windows": 2,
    }
    summary = {k: v for k, v in full.items() if k not in {
        "observed_bps", "predicted_bps", "z_score", "threshold", "criteria", "persistence_windows",
    }}
    event = {
        "event_id": "domain-0:execution:1", "flow": FLOW,
        "decision": "AGREED", "state_entered_ns": 200,
        "required_votes": 1, "mitigate_votes": ["domain-0"],
        "relevant_domains": ["domain-0"], "proposals": [summary],
        "authority": {"authorized": True, "claim": {"won": True, "coordinator": "domain-0"}},
        "execution": {"attempted": True, "executed": True},
    }
    rows = [{
        "_audit_source_line": 1, "sampled_ns": 250,
        "status": {"cid": "domain-0"},
        "agentic": {"cid": "domain-0", "proposals": [full],
                    "decision_events": [event],
                    "config": {"proposal_threshold": 0.65, "weights": {"severity": 0.35}}},
    }]
    report = {
        "run": {"directory": "/unused", "flow": FLOW},
        "episodes": [{
            "episode_id": "episode-1", "flow": FLOW,
            "source_event_ids": [event["event_id"]],
            "protocol_consistency": "CONSISTENT", "scenario_correctness": "CORRECT",
            "decision_stage": "FINAL", "execution_status": "EXECUTED",
            "operational_effectiveness": "EFFECTIVE", "comparative_alignment": "ALIGNED",
            "checks": [],
        }],
    }
    return report, rows


def result_for(packet):
    keys = [k for k in packet["evidence"] if k.startswith("P")]
    refs = {**{k: [k] for k in keys}, "consensus": ["D01"],
            "authority_and_execution": ["G01"], "audit_outcome": ["V01"]}
    return {"event_id": packet["event_id"], "sections": {
        key: {"explanation": "Explanation requiring review.", "evidence_ids": ids}
        for key, ids in refs.items()
    }}


class Response:
    def __init__(self, body):
        self.body = body

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return json.dumps(self.body).encode()


class AgentDecisionEvidenceTests(unittest.TestCase):
    def test_exact_snapshot_enrichment_and_sources(self):
        report, rows = fixture()
        originals = copy.deepcopy((report, rows))
        packet = build_packets(report, rows)[0]
        proposal = packet["evidence"]["P01"]
        self.assertEqual(proposal["detail_basis"], "EXACT_PROPOSAL_SNAPSHOT")
        self.assertEqual(proposal["facts"]["observed_bps"], 1000)
        self.assertTrue(proposal["numeric_comparisons"]["recorded_z_meets_holt_threshold"])
        self.assertEqual(proposal["unavailable_fields"], [])
        self.assertEqual(proposal["source_refs"][0]["event_id"], packet["event_id"])
        self.assertEqual((report, rows), originals)

    def test_other_window_model_or_revision_not_borrowed(self):
        for field in ("window_id", "model_id", "created_ns", "observation_ns"):
            report, rows = fixture()
            full = rows[0]["agentic"]["proposals"][0]
            full[field] = "other" if field == "model_id" else full[field] + 1
            packet = build_packets(report, rows)[0]
            proposal = packet["evidence"]["P01"]
            with self.subTest(field=field):
                self.assertEqual(proposal["detail_basis"], "DECISION_SUMMARY_ONLY")
                self.assertNotIn("observed_bps", proposal["facts"])
                self.assertIn("observed_bps", proposal["unavailable_fields"])
                self.assertIn("producer_policy.proposal_threshold", proposal["unavailable_fields"])

    def test_peer_snapshot_policy_is_not_producer_policy(self):
        report, rows = fixture()
        rows[0]["agentic"]["cid"] = "domain-1"
        packet = build_packets(report, rows)[0]
        self.assertEqual(packet["evidence"]["P01"]["producer_policy_observed_with_snapshot"], {})

    def test_no_full_snapshot_never_invents_measurements_or_defaults(self):
        report, rows = fixture()
        rows[0]["agentic"]["proposals"] = []
        p = build_packets(report, rows)[0]["evidence"]["P01"]
        self.assertEqual(p["facts"]["confidence"], 0.7)
        self.assertEqual(p["numeric_comparisons"], {})
        self.assertNotIn("observed_bps", p["facts"])
        self.assertIn("threshold", p["unavailable_fields"])

    def test_conflicting_payload_same_identity_rejected(self):
        report, rows = fixture()
        changed = copy.deepcopy(rows[0]["agentic"]["proposals"][0])
        changed["observed_bps"] = 9000
        rows[0]["agentic"]["proposals"].append(changed)
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            build_packets(report, rows)
        report, rows = fixture()
        rows[0]["agentic"]["proposals"][0]["confidence"] = 0.9
        with self.assertRaisesRegex(ValueError, "Conflicting"):
            build_packets(report, rows)

    def test_inconsistent_policy_does_not_choose_one(self):
        report, rows = fixture()
        later = copy.deepcopy(rows[0])
        later["_audit_source_line"] = 2
        later["agentic"]["decision_events"] = []
        later["agentic"]["config"]["proposal_threshold"] = 0.99
        rows.append(later)
        p = build_packets(report, rows)[0]["evidence"]["P01"]
        self.assertEqual(p["producer_policy_observed_with_snapshot"], {})
        self.assertIn("producer_policy.proposal_threshold", p["unavailable_fields"])

    def test_selects_audited_execution_not_later_unrelated_event(self):
        report, rows = fixture()
        other = copy.deepcopy(rows[0]["agentic"]["decision_events"][0])
        other["event_id"] = "not-in-audit"
        other["state_entered_ns"] = 10000
        rows[0]["agentic"]["decision_events"].append(other)
        packet = build_packets(report, rows)[0]
        self.assertEqual(packet["event_id"], "domain-0:execution:1")

    def test_explicit_disagreement_supported_without_forging_votes(self):
        report, rows = fixture()
        event = rows[0]["agentic"]["decision_events"][0]
        event.update(decision="DISAGREED", authority={"authorized": False}, execution={})
        event["proposals"][0]["proposal"] = "NORMAL"
        rows[0]["agentic"]["proposals"] = []
        packet = build_packets(report, rows, event_id=event["event_id"])[0]
        self.assertEqual(packet["selection"], "explicit_event")
        self.assertEqual(packet["evidence"]["D01"]["facts"]["decision"], "DISAGREED")
        self.assertEqual(packet["evidence"]["P01"]["facts"]["proposal"], "NORMAL")

    def test_unknown_checks_and_audit_verdicts_preserved(self):
        report, rows = fixture()
        ep = report["episodes"][0]
        ep["operational_effectiveness"] = "UNKNOWN"
        ep["protocol_consistency"] = "INCONSISTENT"
        ep["checks"] = [{"name": "bad", "status": "FAIL"}, {"name": "missing", "status": "UNKNOWN"}]
        p = build_packets(report, rows)[0]["evidence"]["V01"]
        self.assertEqual(p["facts"]["operational_effectiveness"], "UNKNOWN")
        self.assertEqual(len(p["checks_not_passed"]), 2)

    def test_two_real_agent_payloads_fit_context_with_separate_policy_sources(self):
        from domain_agent import DomainAgent
        report, _ = fixture()
        full = []
        agents = [DomainAgent("domain-0"), DomainAgent("domain-1", proposal_threshold=0.66)]
        for i, agent in enumerate(agents):
            full.append(agent.build_proposal(
                {"flow": FLOW, "src_ip": "10.0.0.1", "dst_ip": "10.0.0.8",
                 "ts_ns": 1000000000, "window_id": 1, "model_id": "frozen-model",
                 "z_score": 8, "threshold": 3, "observed_bps": 100000000,
                 "predicted_bps": 10000000, "persistence_windows": 3},
                role="SOURCE" if i == 0 else "DESTINATION", relevant_domains=["domain-0", "domain-1"],
                source_cid="domain-0", destination_cid="domain-1", created_ns=1100000000,
            ))
        event = agents[0].decide(full, flow=FLOW, now_ns_value=1200000000)
        event.update(event_id="real-payload", state_entered_ns=1200000000)
        report["episodes"][0]["source_event_ids"] = ["real-payload"]
        rows = [{"_audit_source_line": i + 1, "sampled_ns": 1300000000,
                 "agentic": {"cid": agent.cid, "decision_events": [event] if i == 0 else [],
                             "proposals": [full[i]], "config": {
                                 "proposal_threshold": agent.proposal_threshold, "weights": agent.weights}}}
                for i, agent in enumerate(agents)]
        packet = build_packets(report, rows)[0]
        self.assertEqual(packet["evidence"]["P01"]["producer_policy_observed_with_snapshot"]["proposal_threshold"], 0.65)
        self.assertEqual(packet["evidence"]["P02"]["producer_policy_observed_with_snapshot"]["proposal_threshold"], 0.66)
        self.assertEqual(packet["evidence"]["P02"]["producer_policy_source_refs"][0]["line"], 2)
        self.assertEqual(request_payload(packet, model="test", num_ctx=6144)["options"]["num_ctx"], 6144)

    def test_missing_event_or_cross_flow_fails_before_inference(self):
        report, rows = fixture()
        with self.assertRaises(ValueError):
            build_packets(report, rows, event_id="unrecorded")
        report["episodes"][0]["source_event_ids"].append("missing")
        with self.assertRaises(ValueError):
            build_packets(report, rows)
        report, rows = fixture()
        report["episodes"][0]["flow"] = "other->flow"
        with self.assertRaises(ValueError):
            build_packets(report, rows)


class AgentDecisionNarrativeTests(unittest.TestCase):
    def setUp(self):
        report, rows = fixture()
        self.packet = build_packets(report, rows)[0]

    def test_structure_cannot_certify_false_prose_or_english(self):
        result = result_for(self.packet)
        result["sections"]["P01"]["explanation"] = "Invented claim; not checked semantically."
        validation = validate_narrative(result, self.packet)
        self.assertTrue(validation["structure_valid"])
        self.assertFalse(validation["prose_factually_verified"])
        self.assertFalse(validation["english_language_verified"])
        self.assertTrue(validation["manual_review_required"])

    def test_wrong_event_references_duplicates_and_empty_text_rejected(self):
        for mutation in ("event", "reference", "duplicate", "empty", "extra"):
            result = result_for(self.packet)
            if mutation == "event":
                result["event_id"] = "forged"
            elif mutation == "reference":
                result["sections"]["P01"]["evidence_ids"] = ["P99"]
            elif mutation == "duplicate":
                result["sections"]["P01"]["evidence_ids"] = ["P01", "P01"]
            elif mutation == "empty":
                result["sections"]["P01"]["explanation"] = "   "
            else:
                result["sections"]["made_up"] = {}
            with self.subTest(mutation=mutation), self.assertRaises(OllamaAuditError):
                validate_narrative(result, self.packet)

    def test_payload_english_no_thinking_or_actions_and_context_guard(self):
        payload = request_payload(self.packet, model="test", num_ctx=6144)
        self.assertIn("in clear English", payload["messages"][0]["content"])
        self.assertFalse(payload["think"])
        self.assertNotIn("tools", payload)
        with self.assertRaises(ValueError):
            request_payload(self.packet, model="test", num_ctx=1800)

    def body(self):
        return {"done": True, "done_reason": "stop", "prompt_eval_count": 1500,
                "eval_count": 300, "message": {"content": json.dumps(result_for(self.packet))}}

    def test_transport_preserves_raw_response_and_review_status(self):
        payload = request_payload(self.packet, model="test", num_ctx=6144)
        seen = []

        def opener(request, timeout):
            seen.append((request.full_url, json.loads(request.data), timeout))
            return Response(self.body())

        record = explain(self.packet, payload, url="http://127.0.0.1:12436/api/chat", timeout=5, opener=opener)
        self.assertEqual(record["status"], "GENERATED_REQUIRES_REVIEW")
        self.assertEqual(len(seen), 1)
        self.assertEqual(record["raw_response"], self.body())
        self.assertFalse(record["validation"]["prose_factually_verified"])

    def test_transport_failure_and_truncation_not_accepted(self):
        payload = request_payload(self.packet, model="test", num_ctx=6144)
        for mode in ("timeout", "truncated", "output_limit", "context"):
            def opener(request, timeout):
                if mode == "timeout":
                    raise TimeoutError("timed out")
                body = self.body()
                if mode == "truncated":
                    body["done_reason"] = "length"
                elif mode == "output_limit":
                    body["eval_count"] = OUTPUT_TOKENS
                else:
                    body["prompt_eval_count"] = 6000
                return Response(body)
            record = explain(self.packet, payload, url="http://127.0.0.1:12436/api/chat", timeout=5, opener=opener)
            with self.subTest(mode=mode):
                self.assertEqual(record["status"], "REJECTED")
                self.assertNotIn("result", record)
                if mode != "timeout":
                    self.assertIn("raw_response", record)


class AgentDecisionCLITests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        report, rows = fixture()
        report["run"]["directory"] = str(self.root)
        self.audit = self.root / "audit.json"
        self.timeline = self.root / "timeline.ndjson"
        self.audit.write_text(json.dumps(report))
        self.timeline.write_text("\n".join(json.dumps(row) for row in rows) + "\n")
        self.before = {p: sha(p) for p in (self.audit, self.timeline)}

    def args(self, output="explanation"):
        return ["--audit", str(self.audit), "--output", str(self.root / output)]

    def test_prepare_is_offline_preserves_sources_and_protects_output(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args() + ["--prepare-only"]), 0)
            self.assertEqual(main(self.args() + ["--prepare-only"]), 2)
        receipt = json.loads((self.root / "explanation/narrative.json").read_text())
        self.assertEqual(receipt["network_requests"], 0)
        self.assertTrue(receipt["originals_unchanged"])
        self.assertEqual({p: sha(p) for p in self.before}, self.before)
        self.assertTrue((self.root / "explanation/evidence.json").exists())

    def test_empty_audit_makes_no_llm_call(self):
        report = json.loads(self.audit.read_text())
        report["episodes"] = []
        self.audit.write_text(json.dumps(report))
        with patch("urllib.request.OpenerDirector.open", side_effect=AssertionError("network")), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args()), 0)
        receipt = json.loads((self.root / "explanation/narrative.json").read_text())
        self.assertEqual(receipt["status"], "NO_AGENT_DECISION")
        self.assertEqual(receipt["network_requests"], 0)

    def test_sources_and_invalid_urls_not_output_targets(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--audit", str(self.audit), "--output", str(self.audit)]), 2)
            self.assertEqual(main(self.args() + ["--ollama-url", "http://user:password@localhost"]), 2)
            self.assertEqual(main(self.args() + ["--ollama-url", "http://localhost/v3/kv/put"]), 2)
        self.assertFalse((self.root / "explanation").exists())
        self.assertEqual({p: sha(p) for p in self.before}, self.before)

    def test_rejected_inference_is_saved_not_silently_retried(self):
        with patch("urllib.request.OpenerDirector.open", side_effect=TimeoutError("timed out")) as network, contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args()), 2)
        self.assertEqual(network.call_count, 1)
        receipt = json.loads((self.root / "explanation/narrative.json").read_text())
        self.assertEqual(receipt["status"], "REJECTED")
        self.assertIn("timed out", receipt["records"][0]["error"])
        self.assertTrue((self.root / "explanation/evidence.json").exists())
        self.assertEqual({p: sha(p) for p in self.before}, self.before)

    def test_success_stays_review_only_and_preserves_per_request_response(self):
        report, rows = fixture()
        packet = build_packets(report, rows)[0]
        body = {"done": True, "done_reason": "stop", "prompt_eval_count": 1500,
                "eval_count": 300, "message": {"content": json.dumps(result_for(packet))}}
        with patch("urllib.request.OpenerDirector.open", return_value=Response(body)), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(main(self.args()), 0)
        output = self.root / "explanation"
        receipt = json.loads((output / "narrative.json").read_text())
        self.assertEqual(receipt["status"], "GENERATED_REQUIRES_REVIEW")
        self.assertEqual(receipt["network_requests"], 1)
        self.assertTrue((output / "response-001.json").exists())
        self.assertIn("HUMAN REVIEW REQUIRED", (output / "presentation.md").read_text())
        self.assertEqual({p: sha(p) for p in self.before}, self.before)


if __name__ == "__main__":
    unittest.main()
