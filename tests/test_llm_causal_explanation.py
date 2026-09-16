import copy
import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from llm_auditor.causal_certificate import (
    CAUSAL_CERTIFICATE_VERSION, build_causal_certificate,
)
from llm_auditor.causal_explanation import (
    CAUSAL_EXPLANATION_CONTRACT_VERSION, CausalExplanationClient,
    causal_messages, validate_causal_explanation,
)
from llm_auditor.causal_explanation_campaign import (
    causal_contract_hashes, explain_causal_campaign, main,
    prepare_causal_report,
)
from llm_auditor.certificate import build_certificate, digest
from llm_auditor.ollama import OllamaAuditError
from llm_auditor.rules import VERDICT_FIELDS
from llm_auditor.validation_dataset import HOLDOUT_PATH
from test_llm_auditor import FakeResponse
from test_llm_certificate import ollama_body


def causal_result(certificate):
    return {
        "summary": "Resumo condicionado ao certificado determinístico.",
        "dimensions": {
            field: {
                "verdict": certificate["decisive_causes"][field]["verdict"],
                "cause_code": certificate["decisive_causes"][field]["cause_code"],
                "explanation": "A causa e as evidências decisivas foram preservadas.",
                "evidence_ids": list(
                    certificate["decisive_causes"][field]["decisive_evidence_ids"]
                ),
            }
            for field in VERDICT_FIELDS
        },
    }


class CausalCertificateTests(unittest.TestCase):
    def setUp(self):
        self.report = prepare_causal_report()
        self.by_id = {case["case_id"]: case for case in self.report["cases"]}

    def cause(self, case_id, field):
        return self.by_id[case_id]["causal_review"][field]

    def test_v2_derives_from_preserved_v1_certificate(self):
        audit = copy.deepcopy(self.by_id["h08"]["audit"])
        v1 = build_certificate(audit)["certificate"]
        v2 = build_causal_certificate(audit)["certificate"]
        self.assertEqual(v1["certificate_version"], "1.0")
        self.assertEqual(v2["certificate_version"], CAUSAL_CERTIFICATE_VERSION)
        self.assertEqual(v2["derived_from_certificate_v1_sha256"], v1["sha256"])
        self.assertEqual(v2["sha256"], digest({k: v for k, v in v2.items() if k != "sha256"}))

    def test_h08_identifies_two_winners_without_optional_null_as_cause(self):
        cause = self.cause("h08", "protocol_consistency")
        self.assertEqual(cause["cause_code"], "recorded_protocol_violation")
        self.assertEqual(cause["decisive_evidence_ids"], ["E07"])
        values = cause["facts"]["violations"][0]["triggering_values"]
        self.assertEqual(values["claim_winners"], ["172.24.5.10", "172.25.8.10"])
        self.assertFalse(values["other_coordinator_elected"])
        self.assertNotIn("known_claim_coordinator", values)

    def test_h07_only_fail_groups_are_decisive(self):
        cause = self.cause("h07", "protocol_consistency")
        self.assertEqual(cause["decisive_evidence_ids"], ["E01", "E03"])
        self.assertEqual({item["rule"] for item in cause["facts"]["violations"]}, {
            "agreed_has_required_quorum", "agreed_has_no_normal_proposal",
        })
        self.assertNotIn("E02", cause["decisive_evidence_ids"])

    def test_not_applicable_is_caused_by_no_applicable_actuation(self):
        for case_id, status in (("h07", "DRY_RUN_SUPPRESSED"),
                                ("h13", "NOT_REQUESTED")):
            with self.subTest(case_id=case_id):
                cause = self.cause(case_id, "operational_effectiveness")
                self.assertEqual(cause["cause_code"], "no_applicable_local_actuation")
                self.assertEqual(cause["facts"], {"execution_status": status})

    def test_recorded_execution_and_effectiveness_require_observations(self):
        h14_execution = self.cause("h14", "execution_status")
        self.assertEqual(h14_execution["cause_code"], "recorded_execution")
        self.assertEqual(h14_execution["facts"], {"normalized_facts.executed_events": 1})
        h14_effect = self.cause("h14", "operational_effectiveness")
        self.assertEqual(h14_effect["cause_code"], "recorded_disruption_after_execution")
        self.assertTrue(h14_effect["facts"]["operational_evidence.attack_disrupted"])
        h16_effect = self.cause("h16", "operational_effectiveness")
        self.assertEqual(h16_effect["cause_code"], "operational_outcome_unavailable")
        self.assertFalse(h16_effect["facts"]["operational_evidence.observations_available"])

    def test_missing_evidence_is_not_converted_to_zero(self):
        protocol = self.cause("h15", "protocol_consistency")
        self.assertEqual(protocol["cause_code"], "protocol_prerequisites_unavailable")
        self.assertEqual(protocol["decisive_evidence_ids"], ["E01", "E02", "E03"])
        self.assertIn("required_votes", protocol["facts"]["unresolved_checks"][0]["unavailable_fields"])
        execution = self.cause("h15", "execution_status")
        self.assertEqual(execution["cause_code"], "execution_evidence_incomplete")
        self.assertNotIn("normalized_facts.executed_events", execution["facts"])

    def test_causal_facts_contain_no_nulls(self):
        def contains_none(value):
            if isinstance(value, dict):
                return any(contains_none(item) for item in value.values())
            if isinstance(value, list):
                return any(contains_none(item) for item in value)
            return value is None
        for case in self.report["cases"]:
            for cause in case["causal_review"].values():
                self.assertFalse(contains_none(cause["facts"]), case["case_id"])

    def test_all_cases_fit_context_and_match_oracle_before_inference(self):
        self.assertEqual(self.report["summary"]["oracle_mismatches"], 0)
        self.assertEqual(self.report["summary"]["estimated_context_oversized"], 0)
        for case in self.report["cases"]:
            self.assertLess(case["audit"]["certificate_context"]["estimated_total_tokens"], 6144)


class CausalExplanationTests(unittest.TestCase):
    def setUp(self):
        self.report = prepare_causal_report()
        self.certificate = self.report["cases"][0]["audit"]["explanation_certificate"]

    def client(self, body, **kwargs):
        return CausalExplanationClient(
            num_ctx=6144, opener=lambda request, timeout: FakeResponse(body), **kwargs
        )

    def test_exact_verdict_cause_and_decisive_references_are_required(self):
        result = causal_result(self.certificate)
        validation = validate_causal_explanation(result, self.certificate)
        self.assertTrue(validation["cause_codes_match"])
        self.assertFalse(validation["prose_factually_verified"])
        for mutation in ("verdict", "cause", "missing", "reordered"):
            changed = copy.deepcopy(result)
            item = changed["dimensions"]["protocol_consistency"]
            if mutation == "verdict":
                item["verdict"] = "CONSISTENT"
            elif mutation == "cause":
                item["cause_code"] = "made_up"
            elif mutation == "missing":
                item["evidence_ids"] = item["evidence_ids"][:-1]
            else:
                item["evidence_ids"] = list(reversed(item["evidence_ids"]))
            with self.subTest(mutation=mutation), self.assertRaises(OllamaAuditError):
                validate_causal_explanation(changed, self.certificate)

    def test_prompt_contains_certificate_but_not_campaign_oracle(self):
        messages = causal_messages(self.certificate)
        sent = json.loads(messages[1]["content"])
        self.assertEqual(sent, self.certificate)
        for key in ("expected", "oracle_comparison", "oracle_rationale", "title", "group"):
            self.assertNotIn(key, sent)
        self.assertIn("null fora de unavailable_fields não é causa", messages[0]["content"])

    def test_client_records_normal_completion(self):
        captured = {}
        def opener(request, timeout):
            captured.update(json.loads(request.data))
            return FakeResponse(ollama_body(causal_result(self.certificate)))
        response = CausalExplanationClient(num_ctx=6144, opener=opener).explain(self.certificate)
        self.assertEqual(response["contract_version"], CAUSAL_EXPLANATION_CONTRACT_VERSION)
        self.assertEqual(response["status"], "ACCEPTED_STRUCTURALLY")
        self.assertEqual(response["completion"]["done_reason"], "stop")
        self.assertEqual(json.loads(captured["messages"][1]["content"]), self.certificate)
        self.assertFalse(response["grounding_validation"]["prose_factually_verified"])

    def test_truncation_tampering_and_undersized_context_are_rejected(self):
        body = ollama_body(causal_result(self.certificate), done_reason="length")
        with self.assertRaises(OllamaAuditError):
            self.client(body).explain(self.certificate)
        tampered = copy.deepcopy(self.certificate)
        tampered["decisive_causes"]["execution_status"]["cause_code"] = "changed"
        with self.assertRaises(OllamaAuditError):
            self.client(ollama_body(causal_result(tampered))).explain(tampered)
        with self.assertRaises(OllamaAuditError):
            CausalExplanationClient(num_ctx=2048).explain(self.certificate)

    def test_structural_acceptance_does_not_approve_false_prose(self):
        result = causal_result(self.certificate)
        result["summary"] = "Não ocorreu nenhuma violação e todos os checks passaram."
        response = self.client(ollama_body(result)).explain(self.certificate)
        self.assertEqual(response["status"], "ACCEPTED_STRUCTURALLY")
        self.assertTrue(response["grounding_validation"]["manual_review_required"])
        self.assertFalse(response["grounding_validation"]["prose_factually_verified"])


class CausalExplanationCampaignTests(unittest.TestCase):
    def setUp(self):
        self.report = prepare_causal_report()
        self.calls = []
        self.chat_count = 0

    def opener(self, request, timeout):
        self.calls.append(request.full_url)
        if request.full_url.endswith("/api/version"):
            return FakeResponse({"version": "0.34.0"})
        if request.full_url.endswith("/api/tags"):
            return FakeResponse({"models": [{"name": "qwen3.5:9b", "digest": "sha256:test"}]})
        self.chat_count += 1
        certificate = json.loads(json.loads(request.data)["messages"][1]["content"])
        return FakeResponse(ollama_body(causal_result(certificate)))

    def client(self, opener=None, **kwargs):
        return CausalExplanationClient(num_ctx=6144, opener=opener or self.opener, **kwargs)

    def test_six_structural_acceptances_remain_pending_human_review(self):
        explain_causal_campaign(self.report, client=self.client())
        self.assertEqual(self.report["campaign_status"], "COMPLETED")
        self.assertEqual(self.report["summary"]["structurally_accepted"], 6)
        self.assertEqual(self.report["summary"]["pending_manual_review"], 6)
        self.assertEqual(self.chat_count, 6)

    def test_raw_invalid_response_continues_but_transport_failure_stops(self):
        first = prepare_causal_report()
        def invalid(request, timeout):
            response = self.opener(request, timeout)
            if request.data and self.chat_count == 1:
                certificate = json.loads(json.loads(request.data)["messages"][1]["content"])
                result = causal_result(certificate)
                result["dimensions"]["protocol_consistency"]["evidence_ids"] = ["E999"]
                return FakeResponse(ollama_body(result))
            return response
        explain_causal_campaign(first, client=self.client(invalid))
        self.assertEqual(first["campaign_status"], "COMPLETED_WITH_REJECTIONS")
        self.assertEqual(len(first["evaluations"]), 6)

        second = prepare_causal_report()
        self.chat_count = 0
        def broken(request, timeout):
            if request.data and self.chat_count == 1:
                raise OSError("reverse tunnel unavailable")
            return self.opener(request, timeout)
        explain_causal_campaign(second, client=self.client(broken))
        self.assertEqual(second["campaign_status"], "PARTIAL_ERROR")
        self.assertEqual(len(second["evaluations"]), 2)

    def test_changed_contract_or_settings_rejected_before_network(self):
        changed = prepare_causal_report()
        changed["causal_explanation_contract"]["contract_version"] = "changed"
        for report, client in ((changed, self.client()),
                               (prepare_causal_report(), self.client(seed=7))):
            with self.assertRaises(ValueError):
                explain_causal_campaign(report, client=client)
        self.assertEqual(self.calls, [])

    def test_manifest_cli_is_offline_and_protects_existing_output(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "causal-v2.json"
            with patch("urllib.request.urlopen") as network, contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(main(["--manifest-only", "--output", str(path)]), 0)
            network.assert_not_called()
            saved = json.loads(path.read_text())
            self.assertEqual(saved["campaign_status"], "MANIFEST_ONLY")
            self.assertEqual(saved["causal_explanation_contract"], causal_contract_hashes())
            original = path.read_bytes()
            with contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(main(["--manifest-only", "--output", str(path)]), 2)
            self.assertEqual(path.read_bytes(), original)

    def test_fixture_and_experiment_artifacts_are_not_output_targets(self):
        original = HOLDOUT_PATH.read_bytes()
        with contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--manifest-only", "--output", str(HOLDOUT_PATH), "--overwrite"]), 2)
        self.assertEqual(HOLDOUT_PATH.read_bytes(), original)


if __name__ == "__main__":
    unittest.main()
