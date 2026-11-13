import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_auditor.certificate_explanation import CertificateExplanationClient
from llm_auditor.explanation_campaign import (
    CRITICAL_CASE_IDS, explain_campaign, explanation_contract_hashes,
    main, prepare_report, summarize,
)
from llm_auditor.rules import VERDICT_FIELDS
from llm_auditor.validation_dataset import HOLDOUT_PATH, load_holdout_dataset
from test_llm_auditor import FakeResponse
from test_llm_certificate import ollama_body, valid_result


class ExplanationCampaignTests(unittest.TestCase):
    def setUp(self):
        self.report = prepare_report()
        self.calls = []
        self.chat_count = 0

    def opener(self, request, timeout):
        self.calls.append((request.full_url, request.get_method(), timeout))
        if request.full_url.endswith("/api/version"):
            return FakeResponse({"version": "0.34.0"})
        if request.full_url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": "qwen3.5:9b", "digest": "sha256:test-model"}]})
        self.chat_count += 1
        payload = json.loads(request.data)
        certificate = json.loads(payload["messages"][1]["content"])
        return FakeResponse(ollama_body(valid_result(certificate)))

    def client(self, opener=None, **kwargs):
        return CertificateExplanationClient(num_ctx=6144, opener=opener or self.opener, **kwargs)

    def test_default_subset_has_four_violations_and_two_missing_evidence_cases(self):
        cases = self.report["cases"]
        self.assertEqual(tuple(case["case_id"] for case in cases), CRITICAL_CASE_IDS)
        self.assertEqual(sum(case["group"] == "protocol-violation" for case in cases), 4)
        self.assertEqual(sum(case["group"] == "insufficient-evidence" for case in cases), 2)
        by_id = {case["case_id"]: case for case in cases}
        self.assertEqual(by_id["h15"]["audit"]["protocol_consistency"], "INSUFFICIENT_EVIDENCE")
        self.assertEqual(by_id["h16"]["audit"]["operational_effectiveness"], "UNKNOWN")
        self.assertEqual(by_id["h14"]["audit"]["execution_status"], "EXECUTED")
        self.assertEqual(self.report["summary"]["oracle_mismatches"], 0)
        self.assertEqual(self.report["summary"]["estimated_context_oversized"], 0)

    def test_inputs_and_targets_have_traceable_frozen_provenance(self):
        self.assertEqual(self.report["dataset"]["role"], "previously-inspected-regression-corpus")
        self.assertTrue(self.report["dataset"]["subset_selected"])
        self.assertEqual(self.report["dataset"]["dataset_sha256"], load_holdout_dataset()["dataset_sha256"])
        for case in self.report["cases"]:
            certificate = case["audit"]["explanation_certificate"]
            self.assertEqual(certificate["context"]["evidence_origin"], "synthetic_protocol_fixture")
            self.assertTrue(case["review_targets"])
            for target in case["review_targets"]:
                ledger = case["audit"]["certificate_ledger"]["groups"][target["evidence_id"]]
                self.assertTrue(ledger["check_ids"])
            for field in VERDICT_FIELDS:
                self.assertEqual(certificate["verdicts"][field], case["audit"][field])

    def test_filtered_case_retains_original_fixture_index(self):
        report = prepare_report(case_ids=["h15"])
        self.assertEqual(len(report["cases"]), 1)
        self.assertIn("/cases/14/evidence", report["cases"][0]["audit"]["evidence_artifact"])
        self.assertEqual(len(prepare_report(case_ids=["h02"])["cases"]), 1)

    def test_invalid_or_duplicate_selection_rejected(self):
        for ids in ([], ["unknown"], ["h07", "h07"]):
            with self.subTest(ids=ids), self.assertRaises(ValueError):
                prepare_report(case_ids=ids)

    def test_serial_inference_captures_metadata_and_retains_manual_review(self):
        snapshots = []
        explain_campaign(self.report, client=self.client(),
                         checkpoint=lambda report: snapshots.append(copy.deepcopy(report)))
        self.assertEqual(self.report["campaign_status"], "COMPLETED")
        self.assertEqual(self.report["summary"]["structurally_accepted"], 6)
        self.assertEqual(self.report["summary"]["pending_manual_review"], 6)
        self.assertFalse(self.report["summary"]["prose_factually_verified"])
        self.assertEqual(self.report["environment"]["ollama_version"], "0.34.0")
        self.assertEqual(self.report["environment"]["model_digest"], "sha256:test-model")
        self.assertEqual(self.calls[0][1], "GET")
        self.assertEqual(self.calls[1][1], "GET")
        self.assertEqual(self.chat_count, 6)
        self.assertEqual(snapshots[0]["evaluations"], [])
        self.assertIn("explanation_certificate", snapshots[0]["cases"][0]["audit"])
        self.assertEqual([item["case_id"] for item in self.report["evaluations"]], list(CRITICAL_CASE_IDS))

    def test_only_certificate_is_sent_without_oracle_rationale_or_case_title(self):
        sent = []
        def opener(request, timeout):
            if request.data:
                payload = json.loads(request.data)
                certificate = json.loads(payload["messages"][1]["content"])
                sent.append(certificate)
                self.assertEqual(payload["options"]["num_ctx"], 6144)
                self.assertEqual(payload["options"]["seed"], 42)
                self.assertEqual(payload["keep_alive"], 0)
                self.assertNotIn("expected", certificate)
                for key in ("oracle_comparison", "oracle_rationale", "title", "group", "review_targets"):
                    self.assertNotIn(key, certificate)
            return self.opener(request, timeout)
        explain_campaign(self.report, client=self.client(opener))
        self.assertEqual(len(sent), 6)
        self.assertEqual(sent[0], self.report["cases"][0]["audit"]["explanation_certificate"])

    def test_non_pass_citations_are_required_not_optional(self):
        def opener(request, timeout):
            if request.data:
                certificate = json.loads(json.loads(request.data)["messages"][1]["content"])
                result = valid_result(certificate)
                if self.chat_count == 0:
                    required = next(entry["id"] for entry in certificate["evidence"] if entry["status"] == "FAIL")
                    result["dimensions"]["protocol_consistency"]["evidence_ids"].remove(required)
                self.chat_count += 1
                return FakeResponse(ollama_body(result))
            return self.opener(request, timeout)
        explain_campaign(self.report, client=self.client(opener))
        self.assertEqual(self.report["campaign_status"], "COMPLETED_WITH_REJECTIONS")
        self.assertEqual(self.report["summary"]["rejected"], 1)
        self.assertEqual(self.report["summary"]["structurally_accepted"], 5)
        self.assertIn("raw_response", self.report["evaluations"][0]["llm_explanation"])

    def test_truncated_response_rejected_but_remaining_cases_continue(self):
        def opener(request, timeout):
            response = self.opener(request, timeout)
            if request.data and self.chat_count == 1:
                certificate = json.loads(json.loads(request.data)["messages"][1]["content"])
                return FakeResponse(ollama_body(valid_result(certificate), done_reason="length"))
            return response
        explain_campaign(self.report, client=self.client(opener))
        self.assertEqual(len(self.report["evaluations"]), 6)
        self.assertEqual(self.report["evaluations"][0]["llm_explanation"]["status"], "REJECTED")
        self.assertEqual(self.report["campaign_status"], "COMPLETED_WITH_REJECTIONS")

    def test_transport_failure_preserves_prior_cases_and_stops_repeated_attempts(self):
        snapshots = []
        def opener(request, timeout):
            if request.data and self.chat_count == 1:
                raise OSError("reverse tunnel unavailable")
            return self.opener(request, timeout)
        explain_campaign(self.report, client=self.client(opener),
                         checkpoint=lambda report: snapshots.append(copy.deepcopy(report)))
        self.assertEqual(self.report["campaign_status"], "PARTIAL_ERROR")
        self.assertEqual(len(self.report["evaluations"]), 2)
        self.assertEqual(self.report["summary"]["structurally_accepted"], 1)
        self.assertEqual(snapshots[-1]["summary"]["rejected"], 1)

    def test_structural_acceptance_never_certifies_incorrect_free_prose(self):
        def opener(request, timeout):
            if request.data:
                certificate = json.loads(json.loads(request.data)["messages"][1]["content"])
                result = valid_result(certificate)
                result["summary"] = "Todos os checks passaram, nenhuma violação ocorreu."
                return FakeResponse(ollama_body(result))
            return self.opener(request, timeout)
        explain_campaign(self.report, client=self.client(opener))
        # This deliberately contradictory prose passes structural checks only.
        # The regression must not mislabel it as factually verified.
        item = self.report["evaluations"][0]
        self.assertEqual(item["llm_explanation"]["status"], "ACCEPTED_STRUCTURALLY")
        self.assertFalse(item["llm_explanation"]["grounding_validation"]["prose_factually_verified"])
        self.assertEqual(item["manual_review"]["status"], "PENDING")
        for key in ("complete_match_rate", "classification_accuracy", "confidence"):
            self.assertNotIn(key, self.report["summary"])

    def test_unavailable_environment_metadata_is_explicit_not_invented(self):
        def opener(request, timeout):
            if not request.data:
                return FakeResponse({"models": []})
            return self.opener(request, timeout)
        explain_campaign(self.report, client=self.client(opener))
        environment = self.report["environment"]
        self.assertIsNone(environment["ollama_version"])
        self.assertIsNone(environment["model_digest"])
        self.assertEqual(len(environment["warnings"]), 2)
        self.assertEqual(self.report["campaign_status"], "COMPLETED")

    def test_changed_contract_or_client_settings_rejected_before_network(self):
        changed = prepare_report()
        changed["explanation_contract"]["contract_version"] = "changed"
        for report, client in ((changed, self.client()), (prepare_report(), self.client(seed=7))):
            with self.assertRaises(ValueError):
                explain_campaign(report, client=client)
        self.assertEqual(self.calls, [])

    def test_existing_responses_cannot_be_silently_repeated(self):
        explain_campaign(self.report, client=self.client())
        with self.assertRaises(ValueError):
            explain_campaign(self.report, client=self.client())
        self.assertEqual(self.chat_count, 6)

    def test_precheck_blocks_oversized_context_and_oracle_mismatch(self):
        mismatched = prepare_report()
        mismatched["cases"][0]["oracle_comparison"]["all_match"] = False
        for report in (prepare_report(num_ctx=2048), mismatched):
            client = CertificateExplanationClient(num_ctx=report["inference_parameters"]["num_ctx"], opener=self.opener)
            explain_campaign(report, client=client)
            self.assertEqual(report["campaign_status"], "BLOCKED_PRECHECK")
            self.assertEqual(report["evaluations"], [])
        self.assertEqual(self.calls, [])

    def test_manifest_cli_has_no_network_calls_and_preserves_full_proof(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "nested" / "manifest.json"
            with patch("urllib.request.urlopen") as network, contextlib.redirect_stdout(io.StringIO()):
                status = main(["--manifest-only", "--output", str(path)])
            network.assert_not_called()
            self.assertEqual(status, 0)
            report = json.loads(path.read_text())
            self.assertEqual(report["campaign_status"], "MANIFEST_ONLY")
            self.assertEqual(len(report["cases"]), 6)
            self.assertEqual(report["evaluations"], [])
            self.assertTrue(report["cases"][0]["audit"]["checks"][0]["source_refs"])
            self.assertTrue(path.with_suffix(".md").exists())

    def test_successful_cli_saves_six_responses_and_short_progress(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "results.json"
            out = io.StringIO()
            with patch("urllib.request.urlopen", side_effect=self.opener), contextlib.redirect_stdout(out):
                status = main(["--output", str(path), "--ollama-url", "http://127.0.0.1:12435"])
            self.assertEqual(status, 0)
            report = json.loads(path.read_text())
            self.assertEqual(report["summary"]["pending_manual_review"], 6)
            self.assertIn("h07: ACCEPTED_STRUCTURALLY", out.getvalue())
            self.assertLess(len(out.getvalue()), 1000)

    def test_partial_cli_error_retains_completed_responses(self):
        def opener(request, timeout):
            if request.data and self.chat_count == 1:
                raise OSError("broken tunnel")
            return self.opener(request, timeout)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "partial.json"
            with patch("urllib.request.urlopen", side_effect=opener), contextlib.redirect_stdout(io.StringIO()):
                status = main(["--output", str(path)])
            self.assertEqual(status, 2)
            report = json.loads(path.read_text())
            self.assertEqual(report["campaign_status"], "PARTIAL_ERROR")
            self.assertEqual(report["summary"]["structurally_accepted"], 1)

    def test_interrupt_preserves_prior_response_and_marks_status(self):
        def opener(request, timeout):
            if request.data and self.chat_count == 1:
                raise KeyboardInterrupt()
            return self.opener(request, timeout)
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "interrupted.json"
            with patch("urllib.request.urlopen", side_effect=opener), \
                    contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                status = main(["--output", str(path)])
            self.assertEqual(status, 130)
            report = json.loads(path.read_text())
            self.assertEqual(report["campaign_status"], "INTERRUPTED")
            self.assertEqual(len(report["evaluations"]), 1)

    def test_saved_outputs_are_protected_without_overwrite(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "manifest.json"
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--manifest-only", "--output", str(path)]), 0)
            original = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--manifest-only", "--output", str(path)]), 2)
            self.assertEqual(path.read_bytes(), original)

    def test_frozen_corpus_and_experiment_artifacts_are_not_output_targets(self):
        original = HOLDOUT_PATH.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--manifest-only", "--output", str(HOLDOUT_PATH), "--overwrite"]), 2)
        self.assertEqual(HOLDOUT_PATH.read_bytes(), original)
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            for name in ("metadata.json", "summary.json", "timeline.ndjson", "attack_start_ns.txt", "same.md"):
                self.assertEqual(main(["--manifest-only", "--output", str(Path(tmp) / name)]), 2)

    def test_cli_rejects_invalid_selection_and_context(self):
        with tempfile.TemporaryDirectory() as tmp, contextlib.redirect_stderr(io.StringIO()):
            path = Path(tmp) / "invalid.json"
            for options in (["--case", "missing"], ["--case", "h07", "--case", "h07"], ["--num-ctx", "1000"]):
                self.assertEqual(main(["--manifest-only", "--output", str(path), *options]), 2)
            self.assertFalse(path.exists())

    def test_pending_manual_review_count_does_not_imply_approval(self):
        explain_campaign(self.report, client=self.client())
        self.report["evaluations"][0]["manual_review"]["status"] = "REVIEWED_EXTERNALLY"
        self.assertEqual(summarize(self.report)["pending_manual_review"], 5)
        self.assertFalse(summarize(self.report)["prose_factually_verified"])

    def test_frozen_evaluator_client_and_schema_hashes_still_match(self):
        dataset = load_holdout_dataset()
        self.assertEqual(self.report["frozen_evaluation_contract"], dataset["evaluation_contract"])
        self.assertEqual(self.report["explanation_contract"], explanation_contract_hashes())


if __name__ == "__main__":
    unittest.main()
