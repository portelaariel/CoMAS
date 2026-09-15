"""Verifier regression: no Ollama service and no expected oracle in inputs."""

import copy
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_auditor.core import audit_run, compare_verdicts, evaluation_evidence
from llm_auditor.cli import main as audit_main
from llm_auditor.deterministic_campaign import main as regression_main
from llm_auditor.rules import VERDICT_FIELDS, verify_evidence
from llm_auditor.validation_dataset import load_holdout_dataset
import test_llm_auditor as runtime_fixtures
from test_llm_auditor import agreed_event, timeline_row


class VerifierTests(unittest.TestCase):
    def setUp(self):
        self.cases = {case["case_id"]: case for case in load_holdout_dataset()["cases"]}

    def evidence(self, case_id="h01"):
        return copy.deepcopy(self.cases[case_id]["evidence"])

    def test_declared_fixtures_are_regression_not_an_independent_benchmark(self):
        for case_id, case in self.cases.items():
            with self.subTest(case_id=case_id):
                evidence = self.evidence(case_id)
                self.assertFalse(set(VERDICT_FIELDS) & evidence.keys())
                actual = verify_evidence(evidence)
                self.assertTrue(compare_verdicts(case["expected"], actual)["all_match"], actual)

    def test_h07_is_final_inconsistent_and_suppressed_independently(self):
        result = verify_evidence(self.evidence("h07"))
        self.assertEqual(result["decision_stage"], "FINAL")
        self.assertEqual(result["protocol_consistency"], "INCONSISTENT")
        self.assertEqual(result["execution_status"], "DRY_RUN_SUPPRESSED")
        check = next(item for item in result["checks"] if item["name"] == "agreed_has_required_quorum")
        self.assertEqual(check["evidence"]["distinct_votes"], 1)
        self.assertEqual(check["status"], "FAIL")

    def test_state_and_quorum_flag_are_not_quorum_evidence(self):
        evidence = self.evidence("h07")
        evidence["quorum_reached"] = True
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "INCONSISTENT")

    def test_repeated_vote_identity_does_not_increase_quorum(self):
        evidence = self.evidence()
        evidence["required_votes"] = 2
        evidence["mitigate_votes"] *= 2
        evidence["relevant_domains"].append("second-domain")
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "INCONSISTENT")

    def test_configured_lower_quorum_is_not_replaced_with_domain_count(self):
        evidence = self.evidence()
        evidence["relevant_domains"].append("second-domain")
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "CONSISTENT")

    def test_missing_vote_list_is_unknown_not_known_empty(self):
        evidence = self.evidence()
        del evidence["mitigate_votes"]
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "INSUFFICIENT_EVIDENCE")
        evidence["mitigate_votes"] = []
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "INCONSISTENT")

    def test_missing_authority_and_claim_are_not_denial_or_other_coordinator(self):
        evidence = self.evidence()
        for key in ("authority_authorized", "claim_winners", "other_coordinator_elected", "known_claim_coordinator"):
            evidence.pop(key, None)
        evidence["normalized_facts"].pop("atomic_claim_winner_events")
        result = verify_evidence(evidence)
        self.assertEqual(result["protocol_consistency"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(result["execution_status"], "UNKNOWN")

    def test_missing_execution_is_not_dry_run_suppression(self):
        evidence = self.evidence()
        evidence["normalized_facts"].pop("executed_events")
        result = verify_evidence(evidence)
        self.assertEqual(result["execution_status"], "UNKNOWN")
        self.assertEqual(result["protocol_consistency"], "INSUFFICIENT_EVIDENCE")

    def test_attempt_without_recorded_outcome_is_unknown_not_failed(self):
        evidence = self.evidence("h12")
        del evidence["normalized_facts"]["executed_events"]
        self.assertEqual(verify_evidence(evidence)["execution_status"], "UNKNOWN")

    def test_failed_attempt_and_executed_action_have_different_efficacy_rules(self):
        failed = verify_evidence(self.evidence("h12"))
        unknown = verify_evidence(self.evidence("h16"))
        self.assertEqual(failed["operational_effectiveness"], "INEFFECTIVE")
        self.assertEqual(unknown["operational_effectiveness"], "UNKNOWN")

    def test_explicit_negative_and_absent_veto_are_different(self):
        evidence = self.evidence("h13")
        for key in ("veto_domains", "veto_proposals", "policy_veto_received"):
            del evidence[key]
        self.assertEqual(verify_evidence(evidence)["protocol_consistency"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(verify_evidence(self.evidence("h13"))["protocol_consistency"], "INCONSISTENT")

    def test_invalid_laboratory_context_cannot_establish_correctness(self):
        for status in ("INVALID", "CONTAMINATED"):
            evidence = self.evidence()
            evidence["laboratory_context"]["validation_status"] = status
            self.assertEqual(verify_evidence(evidence)["scenario_correctness"], "UNKNOWN")

    def test_declared_run_classification_cannot_override_decision(self):
        evidence = self.evidence("h09")
        evidence["laboratory_context"]["classification"] = "TP"
        self.assertEqual(verify_evidence(evidence)["scenario_correctness"], "INCORRECT")

    def test_actuation_precedes_dry_run_label(self):
        result = verify_evidence(self.evidence("h14"))
        self.assertEqual(result["execution_status"], "EXECUTED")
        self.assertEqual(result["protocol_consistency"], "INCONSISTENT")
        self.assertEqual(result["operational_effectiveness"], "EFFECTIVE")

    def test_live_kill_switch_without_attempt_is_not_a_failed_attempt(self):
        evidence = self.evidence()
        evidence["execution_mode"] = "authority-live"
        self.assertEqual(verify_evidence(evidence)["execution_status"], "UNKNOWN")

    def test_checks_and_every_dimension_have_traceable_support(self):
        result = verify_evidence(self.evidence())
        ids = {check["check_id"] for check in result["checks"]}
        for dimension in VERDICT_FIELDS:
            self.assertTrue(result["verdict_support"][dimension])
            self.assertTrue(set(result["verdict_support"][dimension]) <= ids)
        for check in result["checks"]:
            self.assertTrue(check["rule_id"])
            self.assertTrue(check["reason"])
            self.assertTrue(check["source_refs"])

    def test_proof_is_not_leaked_into_experimental_evaluation(self):
        evidence = self.evidence()
        evidence.update(verify_evidence(evidence))
        hidden = evaluation_evidence(evidence)
        for field in VERDICT_FIELDS + ["checks", "verdict_support", "rules_version", "limitations"]:
            self.assertNotIn(field, hidden)


class RuntimeVerifierTests(unittest.TestCase):
    def audit(self, rows, *, scenario="ddos", classification="TP", metadata=None, summary=None):
        with tempfile.TemporaryDirectory() as tmp:
            helper = runtime_fixtures.LLMAuditorTests()
            helper.write_run(tmp, rows, scenario=scenario, classification=classification)
            for filename, additions in (("metadata.json", metadata), ("summary.json", summary)):
                if additions:
                    path = Path(tmp) / filename
                    data = json.loads(path.read_text())
                    target = data["runs"][0] if filename == "summary.json" else data
                    target.update(additions)
                    path.write_text(json.dumps(data))
            return audit_run(Path(tmp))["episodes"][0]

    def test_runtime_quorum_is_checked_per_event_not_pooled(self):
        first = agreed_event("domain-0", 200, won=True)
        second = agreed_event("domain-1", 210, won=False)
        first["mitigate_votes"] = ["domain-0"]
        second["mitigate_votes"] = ["domain-1"]
        result = self.audit([timeline_row("domain-0", 200, [first]), timeline_row("domain-1", 210, [second])])
        self.assertEqual(result["protocol_consistency"], "INCONSISTENT")
        self.assertFalse(result["quorum_reached"])

    def test_runtime_missing_execution_counts_stay_null(self):
        event = agreed_event("domain-0", 200, won=True)
        del event["execution"]
        result = self.audit([timeline_row("domain-0", 200, [event])])
        self.assertIsNone(result["normalized_facts"]["executed_events"])
        self.assertEqual(result["execution_status"], "UNKNOWN")
        self.assertEqual(result["protocol_consistency"], "INSUFFICIENT_EVIDENCE")

    def test_repeated_winner_events_do_not_create_multiple_owners(self):
        rows = [timeline_row("domain-0", time, [agreed_event("domain-0", time, won=True)])
                for time in (200, 210)]
        result = self.audit(rows)
        self.assertEqual(result["protocol_consistency"], "CONSISTENT")
        self.assertEqual(result["claim_winners"], ["domain-0"])
        self.assertEqual(result["normalized_facts"]["atomic_claim_winner_events"], 2)

    def test_non_overlapping_claim_owners_are_legal_lease_successors(self):
        first = agreed_event("domain-0", 200, won=True)
        second = agreed_event("domain-1", 1100, won=True)
        second["authority"]["claim"].update(claimed_ns=1000, expires_ns=2000)
        result = self.audit([timeline_row("domain-0", 200, [first]), timeline_row("domain-1", 1100, [second])])
        self.assertEqual(result["protocol_consistency"], "CONSISTENT")

    def test_unknown_lease_intervals_do_not_prove_overlapping_winners(self):
        events = [agreed_event(cid, time, won=True) for cid, time in (("domain-0", 200), ("domain-1", 210))]
        for event in events:
            event["authority"]["claim"].pop("expires_ns")
        result = self.audit([timeline_row(event["authority"]["claim"]["coordinator"], 200, [event]) for event in events])
        self.assertEqual(result["protocol_consistency"], "INSUFFICIENT_EVIDENCE")

    def test_earlier_invalid_waiting_state_is_not_hidden_by_later_agreed(self):
        rows = runtime_fixtures.LLMAuditorTests().valid_rows()
        rows[0]["agentic"]["decision_events"][0]["missing_domains"] = []
        self.assertEqual(self.audit(rows)["protocol_consistency"], "INCONSISTENT")

    def test_mcda_does_not_determine_scenario_when_agent_is_intermediate(self):
        rows = runtime_fixtures.LLMAuditorTests().valid_rows()[:1]
        rows[0]["collaboration"]["decision_events"][0].update(
            decision="MITIGATE", confirming_domains=["domain-0", "domain-1"], min_domains=2)
        self.assertEqual(self.audit(rows)["scenario_correctness"], "UNKNOWN")

    def test_invalid_summary_blocks_scenario_and_effectiveness_claims(self):
        event = agreed_event("domain-0", 200, won=True)
        event["mode"] = "authority-live"
        event["execution"].update(attempted=True, executed=True)
        result = self.audit([timeline_row("domain-0", 200, [event])],
                            metadata={"agentic_mode": "authority-live"},
                            summary={"measurement_valid": False, "attack_disrupted": True})
        self.assertEqual(result["execution_status"], "EXECUTED")
        self.assertEqual(result["scenario_correctness"], "UNKNOWN")
        self.assertEqual(result["operational_effectiveness"], "UNKNOWN")

    def test_source_reference_resolves_to_actual_ndjson_event_and_value(self):
        event = agreed_event("domain-0", 200, won=True)
        result = self.audit([timeline_row("domain-0", 200, [event])])
        check = next(check for check in result["checks"] if check["name"] == "agreed_has_required_quorum")
        refs = check["source_refs"]
        self.assertTrue(any(ref["line"] == 1 and ref["event_id"] == event["event_id"]
                            and ref["pointer"] == "/agentic/decision_events/0/mitigate_votes" for ref in refs))

    def test_malformed_timeline_is_not_silently_dropped(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_fixtures.LLMAuditorTests().write_run(tmp, [])
            (Path(tmp) / "timeline.ndjson").write_text("{broken\n")
            with self.assertRaisesRegex(ValueError, "line 1"):
                audit_run(Path(tmp))

    def test_conflicting_duplicate_event_payload_is_rejected(self):
        first = agreed_event("domain-0", 200, won=True)
        second = copy.deepcopy(first)
        second["mitigate_votes"] = []
        with self.assertRaisesRegex(ValueError, "conflicting payloads"):
            self.audit([timeline_row("domain-0", 200, [first, second])])

    def test_no_inference_occurs_in_audit_mode(self):
        with patch("llm_auditor.ollama.OllamaAuditClient._chat", side_effect=AssertionError("LLM forbidden")):
            result = self.audit(runtime_fixtures.LLMAuditorTests().valid_rows())
        self.assertEqual(result["rules_version"], "2.0")

    def test_malformed_metadata_is_not_treated_as_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_fixtures.LLMAuditorTests().write_run(tmp, [])
            (Path(tmp) / "metadata.json").write_text("{broken\n")
            with self.assertRaisesRegex(ValueError, "metadata.json"):
                audit_run(Path(tmp))

    def test_missing_attack_boundary_leaves_ground_truth_unknown(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_fixtures.LLMAuditorTests().write_run(tmp, runtime_fixtures.LLMAuditorTests().valid_rows())
            (Path(tmp) / "attack_start_ns.txt").unlink()
            result = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(result["scenario_correctness"], "UNKNOWN")

    def test_proposal_vote_and_model_claims_are_independently_checked(self):
        event = agreed_event("domain-0", 200, won=True)
        event["proposals"] = [
            {"cid": "domain-0", "proposal": "MITIGATE", "model_id": "different-model"},
            {"cid": "domain-1", "proposal": "NORMAL", "model_id": "different-model"},
        ]
        result = self.audit([timeline_row("domain-0", 200, [event])])
        failures = {check["name"] for check in result["checks"] if check["status"] == "FAIL"}
        self.assertTrue({"agreed_has_no_normal_proposal", "agreed_votes_match_proposals",
                         "agreed_models_match_proposals"} <= failures)

    def test_single_named_winner_with_wrong_coordinator_is_inconsistent(self):
        event = agreed_event("domain-0", 200, won=True)
        event["authority"]["claim"]["coordinator"] = "domain-1"
        result = self.audit([timeline_row("domain-0", 200, [event])])
        self.assertEqual(result["protocol_consistency"], "INCONSISTENT")

    def test_positive_non_action_execution_is_not_hidden_by_agreed_counts(self):
        rows = runtime_fixtures.LLMAuditorTests().valid_rows()
        rows[0]["agentic"]["decision_events"][0]["execution"] = {
            "attempted": True, "executed": True, "would_execute": False,
        }
        result = self.audit(rows)
        self.assertEqual(result["execution_status"], "EXECUTED")
        self.assertEqual(result["protocol_consistency"], "INCONSISTENT")

    def test_incomplete_mcda_evidence_is_not_ignored_when_agent_agrees(self):
        rows = runtime_fixtures.LLMAuditorTests().valid_rows()
        del rows[1]["collaboration"]["decision_events"][0]["min_domains"]
        self.assertEqual(self.audit(rows)["protocol_consistency"], "INSUFFICIENT_EVIDENCE")


class VerifierCLITests(unittest.TestCase):
    def test_regression_cli_performs_no_inference_and_protects_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "nested" / "regression.json"
            with patch("llm_auditor.ollama.OllamaAuditClient._chat", side_effect=AssertionError("LLM forbidden")):
                self.assertEqual(regression_main(["--output", str(output)]), 0)
            result = json.loads(output.read_text())
            self.assertEqual(result["summary"]["complete_matches"], 16)
            before = output.read_bytes()
            self.assertEqual(regression_main(["--output", str(output)]), 2)
            self.assertEqual(output.read_bytes(), before)

    def test_audit_cli_protects_existing_reports_and_input_artifacts(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            helper = runtime_fixtures.LLMAuditorTests()
            helper.write_run(run_dir, helper.valid_rows())
            output = Path(tmp) / "nested" / "audit.json"
            args = [str(run_dir), "--output", str(output)]
            self.assertEqual(audit_main(args), 0)
            before = output.read_bytes()
            self.assertEqual(audit_main(args), 2)
            self.assertEqual(output.read_bytes(), before)
            metadata = run_dir / "metadata.json"
            before = metadata.read_bytes()
            self.assertEqual(audit_main([str(run_dir), "--output", str(metadata), "--overwrite"]), 2)
            self.assertEqual(metadata.read_bytes(), before)

    def test_audit_cli_renders_non_mitigation_episode_without_a_claim_winner(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_fixtures.LLMAuditorTests().write_run(tmp, [timeline_row("domain-0", 200, [{
                "flow": runtime_fixtures.FLOW, "decision": "VETOED", "veto_domains": ["domain-0"],
            }])])
            self.assertEqual(audit_main([tmp]), 0)
            markdown = (Path(tmp) / "llm_audit_audit.md").read_text()
            self.assertIn("vetoed_has_veto_evidence", markdown)
            self.assertIn("/agentic/decision_events/0/veto_domains", markdown)


if __name__ == "__main__":
    unittest.main()
