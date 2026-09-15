import json
import tempfile
import unittest
from pathlib import Path

from llm_auditor.cli import apply_llm, main
from llm_auditor.core import (
    audit_run,
    evaluation_evidence,
    extract_decision_events,
    group_decision_events,
)
from llm_auditor.ollama import (
    EVALUATION_SCHEMA,
    EXPLANATION_SCHEMA,
    OllamaAuditClient,
    OllamaAuditError,
    explanation_prompt,
    evaluation_prompt,
)
from llm_auditor.protocol_campaign import (
    evaluate_campaign,
    new_report,
    protocol_cases,
)


FLOW = "10.0.0.1->10.0.0.8"
DOMAINS = ["domain-0", "domain-1"]


def agreed_event(cid, timestamp, *, won):
    return {
        "event_id": f"{cid}:agreement:{timestamp}",
        "flow": FLOW,
        "decision": "AGREED",
        "state_entered_ns": timestamp,
        "mode": "authority-dry-run",
        "relevant_domains": DOMAINS,
        "participating_domains": DOMAINS,
        "required_votes": 2,
        "mitigate_votes": DOMAINS,
        "model_ids": ["model-sha"],
        "authority": {
            "authorized": True,
            "code": "authorized_POLICY_DECISION",
            "claim": {
                "won": won, "coordinator": cid if won else "domain-0",
                "key": "claim:flow", "claimed_ns": 190, "expires_ns": 1000,
            },
        },
        "execution": {
            "attempted": False,
            "executed": False,
            "would_execute": won,
            "reason": (
                "authority-dry-run: claim adquirido; FlowBlocker desconectado"
                if won else
                "authority-dry-run: decisão autorizada, mas outro agente coordena"
            ),
        },
    }


def timeline_row(cid, timestamp, agent_events=None, mcda_events=None):
    return {
        "sampled_ns": timestamp + 10,
        "status": {"cid": cid},
        "agentic": {"cid": cid, "decision_events": agent_events or []},
        "collaboration": {
            "cid": cid, "decision_events": mcda_events or []
        },
    }


class FakeResponse:
    def __init__(self, payload):
        self.payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, traceback):
        return False

    def read(self):
        return self.payload


class LLMAuditorTests(unittest.TestCase):
    def write_run(self, root, rows, *, scenario="ddos", classification="TP"):
        root = Path(root)
        (root / "metadata.json").write_text(json.dumps({
            "scenario": scenario,
            "flow": FLOW,
            "mode": "collaborative-dry-run",
            "agentic_mode": "authority-dry-run",
            "started_ns": 100,
            "git_commit": "abc123",
        }), encoding="utf-8")
        (root / "summary.json").write_text(json.dumps({
            "runs": [{
                "classification": classification,
                "attack_disrupted": False,
            }]
        }), encoding="utf-8")
        (root / "timeline.ndjson").write_text(
            "".join(json.dumps(row) + "\n" for row in rows),
            encoding="utf-8",
        )
        if scenario == "ddos":
            (root / "attack_start_ns.txt").write_text("100\n", encoding="utf-8")

    def valid_rows(self):
        suspect = {
            "event_id": "mcda:suspect", "flow": FLOW,
            "decision": "SUSPECT", "evaluated_ns": 150,
        }
        waiting = {
            "event_id": "agent:waiting", "flow": FLOW,
            "decision": "WAITING_PROPOSALS", "evaluated_ns": 160,
            "missing_domains": ["domain-1"],
        }
        mitigate = {
            "event_id": "mcda:mitigate", "flow": FLOW,
            "decision": "MITIGATE", "evaluated_ns": 180,
            "participating_domains": DOMAINS,
            "confirming_domains": DOMAINS, "min_domains": 2,
        }
        return [
            timeline_row("domain-0", 150, [waiting], [suspect]),
            timeline_row("domain-0", 200, [agreed_event("domain-0", 200, won=True)],
                         [mitigate]),
            timeline_row("domain-1", 210, [agreed_event("domain-1", 210, won=False)]),
        ]

    def test_extracts_both_layers_and_deduplicates_event_id(self):
        rows = self.valid_rows()
        rows.append(rows[-1])
        events = extract_decision_events(rows, flow=FLOW)
        self.assertEqual(len(events), 5)
        self.assertEqual(
            {event["_audit"]["layer"] for event in events},
            {"agentic", "mcda"},
        )

    def test_groups_same_flow_and_splits_on_large_gap(self):
        first = agreed_event("domain-0", 100, won=True)
        second = agreed_event("domain-0", int(20e9), won=True)
        for event in (first, second):
            event["_audit"] = {
                "layer": "agentic", "observed_by": "domain-0",
                "sampled_ns": event["state_entered_ns"],
            }
        episodes = group_decision_events([first, second], gap_s=15)
        self.assertEqual(len(episodes), 2)

    def test_authority_dry_run_is_consistent_and_not_applicable(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(tmp, self.valid_rows())
            report = audit_run(Path(tmp))
        self.assertEqual(report["events_seen"], 5)
        self.assertEqual(len(report["episodes"]), 1)
        episode = report["episodes"][0]
        self.assertEqual(episode["protocol_consistency"], "CONSISTENT")
        self.assertEqual(episode["scenario_correctness"], "CORRECT")
        self.assertEqual(episode["execution_status"], "DRY_RUN_SUPPRESSED")
        self.assertEqual(
            episode["operational_effectiveness"], "NOT_APPLICABLE"
        )
        self.assertEqual(episode["claim_winners"], ["domain-0"])
        self.assertEqual(
            episode["normalized_facts"]["claim_winner_behavior"],
            "SELECTED_WOULD_EXECUTE_DRY_RUN_SUPPRESSED",
        )
        self.assertEqual(
            episode["normalized_facts"]["authorized_non_winner_behavior"],
            "ABSTAINED_OTHER_COORDINATOR",
        )
        self.assertEqual(
            episode["normalized_facts"]["authorized_non_winner_events"], 1
        )
        self.assertEqual(
            [item["state"] for item in episode["transitions"]],
            ["SUSPECT", "WAITING_PROPOSALS", "MITIGATE", "AGREED"],
        )

    def test_two_claim_winners_are_inconsistent(self):
        rows = self.valid_rows()
        rows[-1] = timeline_row(
            "domain-1", 210, [agreed_event("domain-1", 210, won=True)]
        )
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(tmp, rows)
            episode = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(episode["protocol_consistency"], "INCONSISTENT")
        self.assertTrue(any(item["name"] == "single_atomic_claim_winner"
                            and item["status"] == "FAIL" for item in episode["checks"]))

    def test_benign_run_without_events_is_valid_empty_audit(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(tmp, [], scenario="benign", classification="TN")
            report = audit_run(Path(tmp))
        self.assertEqual(report["run"]["audit_status"], "NO_AUDITABLE_EVENTS")
        self.assertEqual(report["run"]["scenario_correctness"], "CORRECT")
        self.assertEqual(report["episodes"], [])

    def test_false_positive_is_scenario_incorrect(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(
                tmp, self.valid_rows(), scenario="benign", classification="FP"
            )
            episode = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(episode["scenario_correctness"], "INCORRECT")

    def test_veto_is_consistent_when_veto_evidence_is_present(self):
        vetoed = {
            "event_id": "agent:vetoed", "flow": FLOW,
            "decision": "VETOED", "evaluated_ns": 200,
            "veto_domains": ["domain-1"],
            "proposals": [{"cid": "domain-1", "proposal": "VETO"}],
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(tmp, [timeline_row("domain-0", 200, [vetoed])])
            episode = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(episode["decision_stage"], "FINAL")
        self.assertEqual(episode["protocol_consistency"], "CONSISTENT")
        # A protocol veto alone does not prove that a policy exception applied.
        self.assertEqual(episode["scenario_correctness"], "UNKNOWN")
        self.assertEqual(episode["execution_status"], "NOT_REQUESTED")

    def test_intermediate_episode_does_not_inherit_run_classification(self):
        waiting = {
            "event_id": "agent:waiting", "flow": FLOW,
            "decision": "WAITING_PROPOSALS", "evaluated_ns": 160,
            "missing_domains": ["domain-1"],
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(
                tmp,
                [timeline_row("domain-0", 160, [waiting])],
                scenario="ddos",
                classification="TP",
            )
            episode = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(episode["decision_stage"], "INTERMEDIATE")
        self.assertEqual(episode["scenario_correctness"], "UNKNOWN")
        self.assertEqual(episode["execution_status"], "NOT_REQUESTED")

    def test_mcda_normal_is_consistent_without_confirming_domains(self):
        normal = {
            "event_id": "mcda:normal", "flow": FLOW,
            "decision": "NORMAL", "evaluated_ns": 200,
            "confirming_domains": [],
        }
        with tempfile.TemporaryDirectory() as tmp:
            self.write_run(
                tmp, [timeline_row("domain-0", 200, mcda_events=[normal])],
                scenario="benign", classification="TN",
            )
            episode = audit_run(Path(tmp))["episodes"][0]
        self.assertEqual(episode["protocol_consistency"], "CONSISTENT")
        self.assertEqual(episode["scenario_correctness"], "CORRECT")
        self.assertEqual(episode["execution_status"], "NOT_REQUESTED")

    def test_evaluation_evidence_hides_deterministic_oracle(self):
        record = {
            "protocol_consistency": "CONSISTENT",
            "scenario_correctness": "CORRECT",
            "operational_effectiveness": "NOT_APPLICABLE",
            "checks": [{"status": "PASS"}],
            "decision_stage": "FINAL",
            "laboratory_context": {
                "scenario": "ddos", "classification": "TP",
                "ground_truth_available": True,
            },
        }
        evidence = evaluation_evidence(record)
        self.assertNotIn("protocol_consistency", evidence)
        self.assertNotIn("checks", evidence)
        self.assertNotIn("decision_stage", evidence)
        self.assertNotIn("execution_status", evidence)
        self.assertNotIn("source_event_ids", evidence)
        self.assertNotIn("classification", evidence["laboratory_context"])

    def test_ollama_request_uses_schema_and_reproducible_parameters(self):
        captured = {}
        explanation = {
            "summary": "Consenso válido em dry-run.",
            "supporting_evidence": ["Quórum 2/2."],
            "contradicting_evidence": [],
            "missing_information": [],
        }

        def opener(request, timeout):
            captured["url"] = request.full_url
            captured["timeout"] = timeout
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse({
                "model": "qwen3.5:9b",
                "message": {"content": json.dumps(explanation)},
                "eval_count": 20,
            })

        client = OllamaAuditClient(
            base_url="http://127.0.0.1:12434", opener=opener
        )
        response = client.explain({"protocol_consistency": "CONSISTENT"})
        payload = captured["payload"]
        self.assertEqual(captured["url"], "http://127.0.0.1:12434/api/chat")
        self.assertEqual(payload["format"], EXPLANATION_SCHEMA)
        self.assertEqual(payload["options"]["temperature"], 0.0)
        self.assertEqual(payload["options"]["seed"], 42)
        self.assertEqual(payload["options"]["num_ctx"], 4096)
        self.assertEqual(payload["keep_alive"], 0)
        self.assertEqual(response["result"], explanation)

    def test_explanation_prompt_distinguishes_winner_from_non_winners(self):
        prompt = explanation_prompt({"protocol_consistency": "CONSISTENT"})
        self.assertIn("O vencedor do claim NÃO se absteve", prompt)
        self.assertIn("Somente os agentes que não venceram", prompt)

    def test_evaluation_contract_distinguishes_suppressed_from_not_requested(self):
        prompt = evaluation_prompt({"execution_mode": "authority-dry-run"})
        self.assertIn("DRY_RUN_SUPPRESSED se execution_mode", prompt)
        self.assertIn("WAITING_PROPOSALS é CONSISTENT", prompt)
        self.assertIn("um não vencedor nunca deve ser classificado", prompt)
        self.assertIn("AGREED, VETOED e NORMAL são finais", prompt)
        self.assertIn("um estado intermediário é UNKNOWN", prompt)
        protocol_description = EVALUATION_SCHEMA["properties"][
            "protocol_consistency"
        ]["description"]
        self.assertIn("quórum ainda incompleto", protocol_description)
        description = EVALUATION_SCHEMA["properties"]["execution_status"][
            "description"
        ]
        self.assertIn("DRY_RUN_SUPPRESSED", description)
        self.assertIn("NOT_REQUESTED", description)
        self.assertIn("SKIPPED_OTHER_COORDINATOR", description)

    def test_protocol_campaign_defines_six_transparent_fixtures(self):
        cases = protocol_cases()
        self.assertEqual(
            [case["case_id"] for case in cases],
            [
                "agreed-executor",
                "waiting-proposals",
                "agreed-non-executor",
                "corroborated",
                "vetoed",
                "normal-benign",
            ],
        )
        for case in cases:
            self.assertEqual(
                case["evidence"]["evidence_origin"],
                "synthetic_protocol_fixture",
            )
            self.assertEqual(case["evidence"]["fixture_id"], case["case_id"])

    def test_protocol_campaign_oracles_keep_intermediate_states_unknown(self):
        cases = {case["case_id"]: case for case in protocol_cases()}
        for case_id in ("waiting-proposals", "corroborated"):
            expected = cases[case_id]["expected"]
            self.assertEqual(expected["decision_stage"], "INTERMEDIATE")
            self.assertEqual(expected["scenario_correctness"], "UNKNOWN")
            self.assertEqual(expected["execution_status"], "NOT_REQUESTED")
        self.assertEqual(
            cases["agreed-non-executor"]["expected"]["execution_status"],
            "SKIPPED_OTHER_COORDINATOR",
        )

    def test_protocol_campaign_aggregates_case_and_field_matches(self):
        cases = protocol_cases()[:2]
        expected_by_id = {
            case["case_id"]: case["expected"] for case in cases
        }

        class Client:
            @staticmethod
            def evaluate(evidence):
                result = dict(expected_by_id[evidence["fixture_id"]])
                result.update({
                    "confidence": 0.9,
                    "summary": "fixture correctly classified",
                    "supporting_evidence": [],
                    "contradicting_evidence": [],
                    "missing_information": [],
                })
                return {
                    "result": result,
                    "metrics": {"total_duration_ns": 1_000_000_000},
                    "inference_parameters": {"seed": 42},
                }

        report = new_report(
            cases,
            model="fixture-model",
            seeds=[42],
            temperature=0.0,
            num_ctx=4096,
            keep_alive="5m",
        )
        evaluate_campaign(report, client_factory=lambda seed: Client())
        self.assertEqual(report["campaign_status"], "COMPLETED")
        self.assertEqual(report["summary"]["complete_matches"], 2)
        self.assertEqual(report["summary"]["complete_match_rate"], 1.0)
        self.assertEqual(
            report["summary"]["field_results"]["execution_status"]["matches"],
            2,
        )

    def test_ollama_rejects_non_json_content(self):
        client = OllamaAuditClient(opener=lambda request, timeout: FakeResponse({
            "message": {"content": "not-json"}
        }))
        with self.assertRaises(OllamaAuditError):
            client.explain({"protocol_consistency": "CONSISTENT"})

    def test_evaluate_mode_records_comparison_with_oracle(self):
        report = {"episodes": [{
            "protocol_consistency": "CONSISTENT",
            "scenario_correctness": "CORRECT",
            "decision_stage": "FINAL",
            "execution_status": "DRY_RUN_SUPPRESSED",
            "operational_effectiveness": "NOT_APPLICABLE",
            "checks": [],
            "laboratory_context": {"scenario": "ddos", "classification": "TP"},
        }]}

        class Client:
            @staticmethod
            def evaluate(evidence):
                return {"result": {
                    "protocol_consistency": "CONSISTENT",
                    "scenario_correctness": "CORRECT",
                    "decision_stage": "FINAL",
                    "execution_status": "DRY_RUN_SUPPRESSED",
                    "operational_effectiveness": "NOT_APPLICABLE",
                    "confidence": 1.0,
                    "summary": "ok",
                    "supporting_evidence": [],
                    "contradicting_evidence": [],
                    "missing_information": [],
                }}

        apply_llm(report, mode="evaluate", client=Client())
        self.assertTrue(report["episodes"][0]["llm_vs_deterministic"]["all_match"])

    def test_cli_writes_audit_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "run"
            run_dir.mkdir()
            self.write_run(run_dir, self.valid_rows())
            output = Path(tmp) / "audit.json"
            status = main([
                str(run_dir), "--mode", "audit", "--output", str(output)
            ])
            self.assertEqual(status, 0)
            self.assertTrue(output.is_file())
            self.assertTrue(output.with_suffix(".md").is_file())
            payload = json.loads(output.read_text(encoding="utf-8"))
            self.assertEqual(payload["episodes"][0]["protocol_consistency"],
                             "CONSISTENT")


if __name__ == "__main__":
    unittest.main()
