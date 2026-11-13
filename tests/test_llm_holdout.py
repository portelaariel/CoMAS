import contextlib
import io
import json
import tempfile
import unittest
from collections import Counter
from pathlib import Path
from unittest.mock import patch

from llm_auditor.core import VERDICT_FIELDS
from llm_auditor.ollama import OllamaAuditError
from llm_auditor.protocol_campaign import (
    evaluate_campaign,
    main,
    new_report,
)
from llm_auditor.validation_dataset import (
    canonical_sha256,
    current_contract_hashes,
    load_holdout_dataset,
    verify_frozen_contract,
)


class LLMHoldoutTests(unittest.TestCase):
    def setUp(self):
        self.dataset = load_holdout_dataset()
        self.cases = self.dataset["cases"]
        self.by_id = {case["case_id"]: case for case in self.cases}

    def response(self, case_id):
        result = dict(self.by_id[case_id]["expected"])
        result.update({
            "confidence": 1.0,
            "summary": "synthetic response",
            "supporting_evidence": [],
            "contradicting_evidence": [],
            "missing_information": [],
        })
        return {
            "result": result,
            "metrics": {"total_duration_ns": 1_000_000_000},
            "inference_parameters": {"seed": 42},
        }

    def test_dataset_has_sixteen_cases_and_five_explicit_groups(self):
        self.assertEqual(len(self.cases), 16)
        self.assertEqual(Counter(case["group"] for case in self.cases), {
            "nominal-variation": 6,
            "protocol-violation": 4,
            "scenario-discrepancy": 2,
            "execution-outcome": 2,
            "insufficient-evidence": 2,
        })
        self.assertEqual(self.dataset["dataset_role"],
                         "post-development-synthetic-validation")
        self.assertEqual(self.dataset["evaluation_contract"],
                         current_contract_hashes())

    def test_frozen_contract_rejects_prompt_or_schema_changes(self):
        changed = dict(self.dataset["evaluation_contract"])
        changed["prompt_template_sha256"] = "changed"
        with self.assertRaisesRegex(ValueError, "contrato de inferência alterado"):
            verify_frozen_contract(changed)

    def test_oracles_cover_missing_data_and_operational_outcomes(self):
        missing = self.by_id["h15"]
        self.assertNotIn("executed_events", missing["evidence"]["normalized_facts"])
        self.assertEqual(missing["expected"]["protocol_consistency"],
                         "INSUFFICIENT_EVIDENCE")
        self.assertEqual(missing["expected"]["execution_status"], "UNKNOWN")
        self.assertEqual(missing["expected"]["operational_effectiveness"], "UNKNOWN")
        self.assertEqual(self.by_id["h11"]["expected"]["operational_effectiveness"],
                         "EFFECTIVE")
        self.assertEqual(self.by_id["h12"]["expected"]["execution_status"], "FAILED")
        self.assertEqual(self.by_id["h12"]["expected"]["operational_effectiveness"],
                         "INEFFECTIVE")
        self.assertEqual(self.by_id["h16"]["expected"]["operational_effectiveness"],
                         "UNKNOWN")

    def test_counterexamples_keep_protocol_separate_from_scenario(self):
        for case_id in ("h07", "h08", "h13", "h14"):
            self.assertEqual(self.by_id[case_id]["expected"]["protocol_consistency"],
                             "INCONSISTENT")
        for case_id in ("h09", "h10"):
            oracle = self.by_id[case_id]["expected"]
            self.assertEqual(oracle["protocol_consistency"], "CONSISTENT")
            self.assertEqual(oracle["scenario_correctness"], "INCORRECT")
        self.assertEqual(self.by_id["h14"]["expected"]["execution_status"],
                         "EXECUTED")

    def test_evaluation_does_not_receive_oracles_groups_titles_or_rationales(self):
        seen = []

        def evaluate(evidence):
            seen.append(evidence)
            for field in VERDICT_FIELDS + ["expected", "title", "group", "oracle_rationale"]:
                self.assertNotIn(field, evidence)
            return self.response(evidence["fixture_id"])

        report = new_report(
            self.cases, model="fake", seeds=[42], temperature=0.0,
            num_ctx=4096, keep_alive=0, suite="holdout-v1",
        )
        client = type("Client", (), {"evaluate": staticmethod(evaluate)})()
        evaluate_campaign(report, client_factory=lambda seed: client)
        self.assertEqual(len(seen), 16)
        self.assertEqual(report["summary"]["individual_fields_matched"], 80)
        self.assertEqual(report["summary"]["complete_matches"], 16)
        self.assertEqual(report["summary"]["group_results"]["protocol-violation"]
                         ["unique_cases"], 4)
        self.assertEqual(report["selected_cases_sha256"], canonical_sha256(self.cases))

    def test_manifest_only_creates_files_without_contacting_ollama(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "nested" / "manifest.json"
            with patch("llm_auditor.protocol_campaign.OllamaAuditClient") as client:
                status = main([
                    "--suite", "holdout-v1", "--manifest-only",
                    "--output", str(output),
                ])
            client.assert_not_called()
            self.assertEqual(status, 0)
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(report["campaign_status"], "MANIFEST_ONLY")
            self.assertEqual(report["summary"]["evaluations_planned"], 16)
            self.assertEqual(report["summary"]["evaluations_completed"], 0)
            self.assertEqual(report["dataset"]["dataset_sha256"],
                             self.dataset["dataset_sha256"])
            self.assertTrue(output.with_suffix(".md").is_file())

    def test_cli_refuses_overwriting_a_saved_manifest(self):
        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "manifest.json"
            argv = ["--suite", "holdout-v1", "--manifest-only", "--output", str(output)]
            main(argv)
            original = output.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as caught:
                    main(argv)
            self.assertEqual(caught.exception.code, 2)
            self.assertEqual(output.read_bytes(), original)

    def test_partial_error_preserves_completed_evaluations(self):
        call_count = 0

        def evaluate(evidence):
            nonlocal call_count
            call_count += 1
            if call_count == 2:
                raise OllamaAuditError("synthetic transport failure")
            return self.response(evidence["fixture_id"])

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "partial.json"
            with patch("llm_auditor.protocol_campaign.OllamaAuditClient") as client:
                client.return_value.evaluate.side_effect = evaluate
                with contextlib.redirect_stderr(io.StringIO()):
                    status = main([
                        "--suite", "holdout-v1", "--output", str(output),
                    ])
            report = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(status, 2)
            self.assertEqual(report["campaign_status"], "PARTIAL_ERROR")
            self.assertEqual(report["summary"]["evaluations_completed"], 1)
            self.assertEqual(report["summary"]["evaluations_planned"], 16)


if __name__ == "__main__":
    unittest.main()
