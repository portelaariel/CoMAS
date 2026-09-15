import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_auditor.certificate import attach_certificate, build_certificate, digest
from llm_auditor.certificate_explanation import (
    CertificateExplanationClient, OUTPUT_TOKENS, certificate_messages,
    context_budget, validate_explanation,
)
from llm_auditor.cli import apply_llm, main
from llm_auditor.core import audit_run, evaluation_evidence
from llm_auditor.ollama import OllamaAuditError
from llm_auditor.rules import VERDICT_FIELDS
from llm_auditor.validation_dataset import load_holdout_dataset
import test_llm_auditor as auditor_test_support
from test_llm_auditor import FakeResponse, agreed_event, timeline_row


def valid_result(certificate):
    return {
        "summary": "Vereditos condicionados aos registros; a eficácia não foi testada.",
        "dimensions": {
            field: {
                "verdict": certificate["verdicts"][field],
                "explanation": "Resultado conforme as verificações citadas.",
                "evidence_ids": list(certificate["verdict_support"][field]),
            }
            for field in VERDICT_FIELDS
        },
    }


def ollama_body(result, **overrides):
    return {
        "model": "qwen3.5:9b", "done": True, "done_reason": "stop",
        "message": {"content": json.dumps(result)},
        "prompt_eval_count": 1800, "eval_count": 450,
        "total_duration": 10_000_000_000, "load_duration": 1_000_000,
        **overrides,
    }


class CertificateTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.run_dir = Path(self.tmp.name) / "run"
        self.run_dir.mkdir()
        helper = auditor_test_support.LLMAuditorTests()
        helper.write_run(self.run_dir, helper.valid_rows())
        self.report = audit_run(self.run_dir)
        self.episode = self.report["episodes"][0]
        self.bundle = build_certificate(self.episode)
        self.certificate = self.bundle["certificate"]

    def client(self, body, **kwargs):
        return CertificateExplanationClient(
            opener=lambda request, timeout: FakeResponse(body), **kwargs
        )

    def test_deterministic_and_does_not_mutate_source(self):
        original = copy.deepcopy(self.episode)
        self.assertEqual(self.bundle, build_certificate(self.episode))
        self.assertEqual(self.episode, original)
        self.assertEqual(self.certificate["verdicts"],
                         {field: original[field] for field in VERDICT_FIELDS})

    def test_every_check_is_resolvable_via_ledger(self):
        check_map = {check["check_id"]: check for check in self.episode["checks"]}
        members = [check_id for group in self.bundle["ledger"]["groups"].values()
                   for check_id in group["check_ids"]]
        self.assertEqual(set(members), set(check_map))
        self.assertEqual(len(members), len(check_map))
        for group in self.bundle["ledger"]["groups"].values():
            self.assertTrue(check_map[group["witness_check_id"]]["source_refs"])

    def test_no_full_trace_or_long_event_ids_in_prompt(self):
        prompt = json.dumps(certificate_messages(self.certificate))
        for key in ("observations", "source_event_ids", "source_refs", "entered_ns"):
            self.assertNotIn(f'\\"{key}\\"', prompt)
        self.assertNotIn("domain-0:agreement:200", prompt)
        self.assertNotIn("classification", self.certificate["context"]["laboratory_context"])

    def test_source_hash_stable_after_attachment_and_llm_result(self):
        attach_certificate(self.episode)
        self.episode["llm_explanation"] = {"result": {"summary": "retry"}}
        self.episode["certificate_context"] = {"anything": 1}
        self.assertEqual(build_certificate(self.episode), self.bundle)

    def test_source_hash_changes_for_changed_proof(self):
        self.episode["checks"][0]["evidence"]["extra"] = "changed"
        changed = build_certificate(self.episode)
        self.assertNotEqual(self.certificate["source_audit_sha256"],
                            changed["certificate"]["source_audit_sha256"])

    def test_duplicate_check_id_rejected(self):
        self.episode["checks"].append(copy.deepcopy(self.episode["checks"][0]))
        with self.assertRaises(ValueError):
            build_certificate(self.episode)

    def test_status_groups_do_not_hide_fail_or_unknown(self):
        original = self.episode["checks"][0]
        for status in ("FAIL", "UNKNOWN"):
            changed = copy.deepcopy(original)
            changed.update(check_id=f"extra-{status}", status=status)
            self.episode["checks"].append(changed)
        bundle = build_certificate(self.episode)
        matches = [entry for entry in bundle["certificate"]["evidence"]
                   if entry["rule"] == original["name"]]
        self.assertEqual({entry["status"] for entry in matches}, {"PASS", "FAIL", "UNKNOWN"})
        self.assertEqual(bundle["certificate"]["coverage"]["status_counts"]["FAIL"], 1)

    def test_long_witness_is_explicitly_abbreviated(self):
        self.episode["checks"][0]["evidence"]["values"]["long"] = "x" * 1000
        self.episode["checks"][0]["evidence"]["values"]["many"] = list(range(20))
        bundle = build_certificate(self.episode)
        values = bundle["certificate"]["evidence"][0]["witness"]["values"]
        self.assertTrue(values["long"]["abbreviated"])
        self.assertEqual(values["many"][-1]["omitted_items"], 16)
        self.assertEqual(len(bundle["ledger"]["abbreviations"]), 2)
        self.assertEqual(len(self.episode["checks"][0]["evidence"]["values"]["long"]), 1000)

    def test_simulation_and_actual_attempts_remain_distinct(self):
        counts = self.certificate["context"]["execution_counts_by_layer"]
        self.assertEqual(counts["mcda"]["recorded_attempted_execution_events"], 1)
        self.assertEqual(counts["mcda"]["simulated_execution_events"], 1)
        self.assertEqual(counts["mcda"]["attempted_execution_events"], 0)
        entry = next(entry for entry in self.certificate["evidence"]
                     if entry["rule"] == "mcda_simulated_attempt_has_dry_run_evidence")
        self.assertEqual(entry["witness"]["values"]["raw_execution"],
                         {"attempted": True, "executed": False, "reason": "DRY_RUN"})

    def test_41_event_regression_compacts_repeats_not_votes(self):
        helper = auditor_test_support.LLMAuditorTests()
        rows = helper.valid_rows()[:1]
        for i in range(20):
            mcda = {
                "event_id": f"mcda:{i}", "flow": self.episode["flow"],
                "decision": "MITIGATE", "evaluated_ns": 180 + i,
                "confirming_domains": ["domain-0", "domain-1"], "min_domains": 2,
                "mitigation": {"attempted": i < 9, "executed": False,
                               "reason": "DRY_RUN" if i < 9 else "COOLDOWN"},
            }
            agent = [] if i == 19 else [agreed_event(
                "domain-0" if i == 0 else "domain-1", 200 + i, won=i == 0)]
            rows.append(timeline_row("domain-0" if i == 0 else "domain-1",
                                     200 + i, agent, [mcda]))
        helper.write_run(self.run_dir, rows)
        episode = audit_run(self.run_dir)["episodes"][0]
        certificate = build_certificate(episode)["certificate"]
        self.assertEqual(episode["event_count"], 41)
        self.assertEqual(episode["protocol_consistency"], "CONSISTENT")
        self.assertLess(len(certificate["evidence"]), len(episode["checks"]))
        quorum = next(entry for entry in certificate["evidence"]
                      if entry["rule"] == "agreed_has_required_quorum")
        self.assertEqual(quorum["check_count"], 19)
        self.assertEqual(quorum["witness"]["values"]["required_votes"], 2)
        self.assertEqual(certificate["context"]["normalized_facts"]["authorized_non_winner_events"], 18)
        self.assertEqual(certificate["context"]["execution_counts_by_layer"]["mcda"]
                         ["simulated_execution_events"], 9)
        self.assertTrue(context_budget(certificate, 4096)["preflight_fits_estimate"])

    def test_no_protocol_checks_explicitly_reported(self):
        self.episode["checks"] = [item for item in self.episode["checks"]
                                  if item["dimension"] != "protocol_consistency"]
        self.episode["protocol_consistency"] = "INSUFFICIENT_EVIDENCE"
        bundle = build_certificate(self.episode)
        entry = next(item for item in bundle["certificate"]["evidence"]
                     if item["dimension"] == "protocol_consistency")
        self.assertEqual(entry["check_count"], 0)
        self.assertEqual(entry["status"], "UNKNOWN")
        self.assertEqual(bundle["ledger"]["groups"][entry["id"]]["check_ids"], [])

    def test_valid_response_structure_does_not_certify_prose(self):
        checks = validate_explanation(valid_result(self.certificate), self.certificate)
        self.assertTrue(checks["evidence_references_valid"])
        self.assertFalse(checks["prose_factually_verified"])
        self.assertTrue(checks["manual_review_required"])

    def test_changed_verdict_rejected(self):
        result = valid_result(self.certificate)
        result["dimensions"]["execution_status"]["verdict"] = "NOT_REQUESTED"
        with self.assertRaises(OllamaAuditError):
            validate_explanation(result, self.certificate)

    def test_unknown_or_cross_dimension_reference_rejected(self):
        for evidence_id in ("E999", self.certificate["verdict_support"]["decision_stage"][0]):
            result = valid_result(self.certificate)
            result["dimensions"]["protocol_consistency"]["evidence_ids"] = [evidence_id]
            with self.subTest(evidence_id=evidence_id), self.assertRaises(OllamaAuditError):
                validate_explanation(result, self.certificate)

    def test_empty_duplicate_or_blank_output_rejected(self):
        for change in ("empty", "duplicate", "blank", "long"):
            result = valid_result(self.certificate)
            item = result["dimensions"]["execution_status"]
            if change == "empty":
                item["evidence_ids"] = []
            elif change == "duplicate":
                item["evidence_ids"] *= 2
            elif change == "blank":
                item["explanation"] = "   "
            else:
                result["summary"] = "x" * 901
            with self.subTest(change=change), self.assertRaises(OllamaAuditError):
                validate_explanation(result, self.certificate)

    def test_non_pass_group_must_be_cited(self):
        self.episode["checks"][0]["status"] = "UNKNOWN"
        certificate = build_certificate(self.episode)["certificate"]
        result = valid_result(certificate)
        unknown_id = next(entry["id"] for entry in certificate["evidence"]
                          if entry["status"] == "UNKNOWN")
        result["dimensions"]["protocol_consistency"]["evidence_ids"].remove(unknown_id)
        with self.assertRaises(OllamaAuditError):
            validate_explanation(result, certificate)

    def test_new_client_sends_only_certificate_and_records_completion(self):
        captured = {}
        def opener(request, timeout):
            captured.update(json.loads(request.data))
            return FakeResponse(ollama_body(valid_result(self.certificate)))
        client = CertificateExplanationClient(base_url="http://127.0.0.1:12435", opener=opener)
        response = client.explain(self.certificate)
        self.assertEqual(json.loads(captured["messages"][1]["content"]), self.certificate)
        self.assertEqual(captured["messages"][0]["role"], "system")
        self.assertEqual(captured["options"]["num_predict"], OUTPUT_TOKENS)
        self.assertFalse(captured["think"])
        self.assertEqual(response["status"], "ACCEPTED_STRUCTURALLY")
        self.assertEqual(response["completion"]["done_reason"], "stop")
        self.assertEqual(response["context_budget"]["observed_prompt_tokens"], 1800)
        self.assertFalse(response["context_budget"]["input_completeness_verified"])

    def test_truncation_missing_completion_and_missing_tokens_rejected(self):
        for override in ({"done_reason": "length"}, {"done": False},
                         {"done_reason": None}, {"eval_count": OUTPUT_TOKENS},
                         {"prompt_eval_count": None}, {"prompt_eval_count": True},
                         {"eval_count": 0}, {"prompt_eval_count": 3500}):
            body = ollama_body(valid_result(self.certificate), **override)
            with self.subTest(override=override), self.assertRaises(OllamaAuditError):
                self.client(body).explain(self.certificate)

    def test_malformed_body_content_and_invented_extra_field_rejected(self):
        result = valid_result(self.certificate)
        result["confidence"] = 1
        for body in ([], ollama_body(result), ollama_body({}, message={"content": "broken"}),
                     ollama_body({}, message="not-an-object")):
            with self.subTest(body=body), self.assertRaises(OllamaAuditError):
                self.client(body).explain(self.certificate)

    def test_tampered_certificate_rejected_before_network(self):
        certificate = copy.deepcopy(self.certificate)
        certificate["context"]["event_count"] = 100
        with patch("urllib.request.urlopen") as network, self.assertRaises(OllamaAuditError):
            CertificateExplanationClient().explain(certificate)
        network.assert_not_called()

    def test_oversized_certificate_rejected_before_network(self):
        certificate = copy.deepcopy(self.certificate)
        certificate["context"]["too_large"] = "x" * 20_000
        certificate["sha256"] = digest({key: value for key, value in certificate.items() if key != "sha256"})
        with patch("urllib.request.urlopen") as network, self.assertRaises(OllamaAuditError):
            CertificateExplanationClient().explain(certificate)
        network.assert_not_called()

    def test_invalid_context_size_rejected(self):
        for value in (0, True, 1000):
            with self.subTest(value=value), self.assertRaises(ValueError):
                context_budget(self.certificate, value)

    def test_explain_preserves_verdicts_and_rejected_response(self):
        body = ollama_body(valid_result(self.certificate), done_reason="length")
        before = {field: self.episode[field] for field in VERDICT_FIELDS}
        apply_llm(self.report, mode="explain", client=self.client(body))
        self.assertEqual(before, {field: self.episode[field] for field in VERDICT_FIELDS})
        self.assertEqual(self.episode["llm_explanation"]["status"], "REJECTED")
        self.assertEqual(self.episode["llm_explanation"]["raw_response"], body)
        self.assertEqual(self.episode["explanation_certificate"], self.certificate)

    def test_certificate_cli_never_contacts_ollama(self):
        with patch("urllib.request.urlopen") as network, contextlib.redirect_stdout(io.StringIO()):
            status = main([str(self.run_dir), "--mode", "certificate"])
        network.assert_not_called()
        self.assertEqual(status, 0)
        report = json.loads((self.run_dir / "llm_audit_certificate.json").read_text())
        self.assertEqual(report["episodes"][0]["explanation_certificate"], self.certificate)
        self.assertNotIn("llm_explanation", report["episodes"][0])

    def test_rejected_cli_returns_error_but_saves_full_proof(self):
        body = ollama_body(valid_result(self.certificate), done_reason="length")
        with patch("urllib.request.urlopen", return_value=FakeResponse(body)), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = main([str(self.run_dir), "--mode", "explain"])
        self.assertEqual(status, 2)
        report = json.loads((self.run_dir / "llm_audit_explain.json").read_text())
        self.assertEqual(report["episodes"][0]["checks"], self.episode["checks"])
        self.assertEqual(report["episodes"][0]["llm_explanation"]["status"], "REJECTED")
        self.assertIn("Rejected:", (self.run_dir / "llm_audit_explain.md").read_text())

    def test_accepted_cli_saves_explanation_and_citations(self):
        body = ollama_body(valid_result(self.certificate))
        with patch("urllib.request.urlopen", return_value=FakeResponse(body)), \
                contextlib.redirect_stdout(io.StringIO()):
            status = main([str(self.run_dir), "--mode", "explain"])
        self.assertEqual(status, 0)
        report = json.loads((self.run_dir / "llm_audit_explain.json").read_text())
        explanation = report["episodes"][0]["llm_explanation"]
        self.assertEqual(explanation["status"], "ACCEPTED_STRUCTURALLY")
        self.assertIn("evidence:", (self.run_dir / "llm_audit_explain.md").read_text())

    def test_network_failure_still_saves_certificate_and_error(self):
        with patch("urllib.request.urlopen", side_effect=OSError("tunnel unavailable")), \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = main([str(self.run_dir), "--mode", "explain"])
        self.assertEqual(status, 2)
        report = json.loads((self.run_dir / "llm_audit_explain.json").read_text())
        episode = report["episodes"][0]
        self.assertEqual(episode["explanation_certificate"], self.certificate)
        self.assertIn("tunnel unavailable", episode["llm_explanation"]["error"])

    def test_preflight_rejection_preserves_proof_without_network(self):
        with patch("urllib.request.urlopen") as network, \
                contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            status = main([str(self.run_dir), "--mode", "explain", "--num-ctx", "2048"])
        network.assert_not_called()
        self.assertEqual(status, 2)
        report = json.loads((self.run_dir / "llm_audit_explain.json").read_text())
        self.assertEqual(report["episodes"][0]["checks"], self.episode["checks"])

    def test_certificate_and_prior_llm_do_not_leak_into_evaluation(self):
        attach_certificate(self.episode)
        self.episode["certificate_context"] = context_budget(self.certificate, 4096)
        self.episode["llm_explanation"] = {"result": valid_result(self.certificate)}
        evidence = evaluation_evidence(self.episode)
        for key in ("explanation_certificate", "certificate_ledger", "certificate_context", "llm_explanation"):
            self.assertNotIn(key, evidence)

    def test_frozen_evaluator_and_corpus_hashes_still_match(self):
        self.assertEqual(len(load_holdout_dataset()["cases"]), 16)


if __name__ == "__main__":
    unittest.main()
