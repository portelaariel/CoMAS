import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
from scripts import collect_qos_validation_campaign as collector_v1
from scripts import collect_qos_validation_campaign_v2 as collector_v2
from test_predictive_sla_validation import create_case, create_pilot


class ConfirmationV2Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pilot = self.root / "pilot"
        create_pilot(self.pilot)
        self.parent_path = self.root / "v1/protocol.json"
        self.parent = v1.freeze_protocol(self.pilot, self.parent_path.parent)
        self.old_campaign = self.parent_path.parent / "campaign"
        for ordinal, case in enumerate(self.parent["cases"]):
            create_case(self.parent, case, self.old_campaign, ordinal)
        self.baseline = v1.evaluate_campaign(self.parent_path, self.old_campaign)
        self.assertEqual(self.baseline["status"], "COMPLETED")
        v1.write_new_json(self.old_campaign / "campaign-summary.json", self.baseline)
        self.new_path = self.root / "v2/protocol.json"
        self.freeze_time = self.parent["created_ns"] + 10_000_000_000_000

    def freeze(self):
        with patch.object(v2.time, "time_ns", return_value=self.freeze_time):
            return v2.freeze_protocol(self.parent_path, self.old_campaign, self.new_path.parent)

    def new_cases(self, protocol):
        campaign = self.new_path.parent / "campaign"
        for ordinal, case in enumerate(protocol["cases"]):
            create_case(protocol, case, campaign, ordinal)
        return campaign

    def tree_hashes(self, root):
        return {str(path.relative_to(root)): v1.digest_file(path)
                for path in root.rglob("*") if path.is_file()}

    def test_freeze_preserves_v1_training_and_code_and_only_changes_confirmation(self):
        before = self.tree_hashes(self.root / "v1")
        code = {name: v1.digest_file(v1.ROOT / name) for name in v1.CODE_FILES}
        pilot = self.tree_hashes(self.pilot)
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            protocol = self.freeze()
        self.assertEqual(before, self.tree_hashes(self.root / "v1"))
        self.assertEqual(pilot, self.tree_hashes(self.pilot))
        self.assertEqual(code, {name: v1.digest_file(v1.ROOT / name) for name in v1.CODE_FILES})
        self.assertEqual(v1.load_protocol(self.parent_path), self.parent)
        self.assertEqual(v2.load_protocol(self.new_path), protocol)
        self.assertEqual(protocol["policy"], {**self.parent["policy"], "activation_windows": 1})
        self.assertEqual(protocol["reference_policy"], self.parent["policy"])
        self.assertEqual(protocol["cases"], self.parent["cases"])
        self.assertFalse(protocol["promotion_eligible"])
        self.assertEqual(len(protocol["source_v1"]["excluded_csv_sha256"]), 24)
        for name in self.parent["models"]:
            self.assertEqual((self.parent_path.parent / self.parent["models"][name]["path"]).read_bytes(),
                             (self.new_path.parent / protocol["models"][name]["path"]).read_bytes())
        selection = json.loads((self.new_path.parent / "selection-analysis.json").read_text())
        self.assertIn("post_hoc", selection["scope"])
        self.assertFalse(selection["refit"])

    def test_existing_overlapping_and_incomplete_sources_refused_before_writes(self):
        with self.assertRaises(ValueError):
            v2.freeze_protocol(self.parent_path, self.old_campaign, self.parent_path.parent)
        with self.assertRaisesRegex(ValueError, "sobrepor"):
            v2.freeze_protocol(self.parent_path, self.old_campaign, self.old_campaign / "new")
        case = self.parent["cases"][0]
        record_path = self.old_campaign / case["case_id"] / "run.json"
        record = json.loads(record_path.read_text())
        record["status"] = "FAILED"
        record_path.write_text(json.dumps(v1.seal(record, "run_sha256")))
        with self.assertRaisesRegex(ValueError, "incompleta"):
            self.freeze()
        self.assertFalse(self.new_path.parent.exists())

    def test_v1_summary_must_match_verified_data_not_pasted_metrics(self):
        path = self.old_campaign / "campaign-summary.json"
        report = json.loads(path.read_text())
        report["models"]["coverage90"]["episode_events"]["detected"] += 1
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "relatório v1"):
            self.freeze()
        self.assertFalse(self.new_path.parent.exists())

    def test_v2_freeze_cannot_predate_source_campaign_end(self):
        with self.assertRaisesRegex(ValueError, "encerrada"):
            v2.freeze_protocol(self.parent_path, self.old_campaign, self.new_path.parent)
        self.assertFalse(self.new_path.parent.exists())

    def test_resealed_policy_criteria_models_and_exclusions_cannot_be_changed(self):
        original = self.freeze()
        variants = (
            lambda p: p["policy"].update(activation_windows=2),
            lambda p: p["policy"].update(required_consecutive_horizons=1),
            lambda p: p["acceptance_criteria"].clear(),
            lambda p: p.update(promotion_eligible=True),
            lambda p: p["source_v1"].update(excluded_csv_sha256=[]),
            lambda p: p["models"]["coverage90"].update(path="../v1/models/coverage90.json"),
        )
        for modify in variants:
            payload = copy.deepcopy(original)
            modify(payload)
            self.new_path.write_text(json.dumps(v1.seal(payload, "protocol_sha256")))
            with self.subTest(modify=modify), self.assertRaises(ValueError):
                v2.load_protocol(self.new_path)

    def test_changes_to_code_selection_model_or_old_sources_are_rejected(self):
        self.freeze()
        paths = [self.new_path.parent / "selection-analysis.json",
                 self.new_path.parent / "models/coverage90.json",
                 self.old_campaign / self.parent["cases"][0]["case_id"] / "port_utilization_domain0.csv",
                 self.old_campaign / "campaign-summary.json"]
        for path in paths:
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path), self.assertRaises((ValueError, json.JSONDecodeError)):
                v2.load_protocol(self.new_path)
            path.write_bytes(original)
        with patch.object(v2.v1, "digest_file", return_value="changed"), self.assertRaises(ValueError):
            v2.load_protocol(self.new_path)

    def test_new_complete_campaign_keeps_paired_forecasts_identical_and_never_promotes(self):
        protocol = self.freeze()
        campaign = self.new_cases(protocol)
        before = self.tree_hashes(self.root / "v1")
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = v2.evaluate_campaign(self.new_path, campaign)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["evaluated_runs"], 12)
        self.assertEqual(set(report["checks"]), set(v2.CRITERIA))
        self.assertFalse(report["promotion_eligible"])
        self.assertTrue(all(case["point_forecasts_identical"] and case["candidate_decisions_identical"]
                            for case in report["cases"]))
        self.assertEqual(before, self.tree_hashes(self.root / "v1"))
        for case in report["cases"]:
            self.assertEqual(case["models"]["coverage90"]["activation_windows"], 1)
            self.assertEqual(case["models"]["coverage90-confirmation2"]["activation_windows"], 2)
            self.assertEqual(case["models"]["coverage90"]["aggregate"]["candidate"],
                             case["models"]["coverage90-confirmation2"]["aggregate"]["candidate"])

    def test_v1_case_cannot_be_relabelled_as_new_confirmation_data(self):
        protocol = self.freeze()
        campaign = self.new_cases(protocol)
        case = protocol["cases"][0]
        old = self.old_campaign / case["case_id"] / "port_utilization_domain0.csv"
        new = campaign / case["case_id"] / old.name
        new.write_bytes(old.read_bytes())
        path = campaign / case["case_id"] / "run.json"
        record = json.loads(path.read_text())
        record["sources"][0]["sha256"] = v1.digest_file(new)
        path.write_text(json.dumps(v1.seal(record, "run_sha256")))
        report = v2.evaluate_campaign(self.new_path, campaign)
        self.assertEqual(report["status"], "INCOMPLETE_OR_INVALID")
        self.assertFalse(report["checks"]["all_twelve_runs_valid"])
        self.assertEqual(report["invalid_runs"][0]["case_id"], case["case_id"])

    def test_v1_protocol_rejected_by_v2_cli_before_network(self):
        with patch.object(collector_v1, "preflight") as preflight, patch("sys.stderr", new=io.StringIO()):
            status = collector_v2.main(["--protocol", str(self.parent_path), "--preflight-only"])
        self.assertEqual(status, 2)
        preflight.assert_not_called()

    def test_missing_cases_and_changed_signatures_remain_visible(self):
        protocol = self.freeze()
        campaign = self.new_path.parent / "campaign"
        create_case(protocol, protocol["cases"][0], campaign)
        report = v2.evaluate_campaign(self.new_path, campaign)
        self.assertEqual(report["status"], "INCOMPLETE_OR_INVALID")
        self.assertEqual(len(report["missing_runs"]), 11)
        original = v2.backtest_model

        def altered(**kwargs):
            result, points, candidates = original(**kwargs)
            if kwargs["activation_windows"] == 2:
                points = {**points, ("modified", 0): (999,)}
            return result, points, candidates

        with patch.object(v2, "backtest_model", side_effect=altered):
            report = v2.evaluate_campaign(self.new_path, campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertIn("pareada", report["invalid_runs"][0]["error"])

    def test_criteria_failure_is_not_confused_with_collection_failure_or_promotion(self):
        protocol = self.freeze()
        report = v2.evaluate_campaign(self.new_path, self.new_cases(protocol))
        results = copy.deepcopy(report["cases"])
        controls = [case for case in results if case["profile"] == "stable-low"]
        controls[0]["models"]["coverage90"]["aggregate"]["episode_events"]["total_activations"] = 1
        checks = v2.assess_criteria(results, True)
        self.assertFalse(checks["no_control_activations"])
        self.assertEqual(v2.report_exit_code(dict(status="COMPLETED", criteria_status="NOT_PASSED")), 3)
        self.assertEqual(v2.report_exit_code(dict(status="INCOMPLETE_OR_INVALID", criteria_status="NOT_PASSED")), 2)
        self.assertEqual(v2.report_exit_code(dict(status="COMPLETED", criteria_status="PASSED")), 0)
        ramp = next(case for case in results if case["profile"] == "slow-ramp")
        ramp["models"]["coverage90"]["series"][0]["episode_events"]["eligible_episodes"] = 0
        self.assertFalse(v2.assess_criteria(results, True)["ramp_subjects_have_eligible_episodes"])

    def test_output_names_cannot_modify_v1_models_or_existing_reports(self):
        self.freeze()
        for path in (self.old_campaign / "new", self.new_path.parent / "models/new",
                     self.new_path.parent / "selection-analysis.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                v2.campaign_output(self.new_path, path)
        campaign = self.new_path.parent / "campaign"
        self.assertEqual(v2.campaign_output(self.new_path, campaign), campaign.resolve())
        campaign.mkdir()
        with self.assertRaisesRegex(ValueError, "já existe"):
            v2.campaign_output(self.new_path, campaign)
        preserved = self.new_path.parent / "campaign-review.json"
        preserved.write_text("preserve me")
        with patch("sys.stderr", new=io.StringIO()):
            status = v2.main(["evaluate", "--protocol", str(self.new_path),
                              "--campaign-root", str(campaign), "--output", str(preserved)])
        self.assertEqual(status, 2)
        self.assertEqual(preserved.read_text(), "preserve me")


class CollectorV2SafetyTests(unittest.TestCase):
    def test_no_collection_without_opt_in_and_read_only_preflight(self):
        protocol = dict(cases=[])
        with patch.object(collector_v2, "load_protocol", return_value=protocol), \
                patch.object(collector_v1, "preflight", return_value=dict(status="READY", safety=[{}, {}])) as preflight, \
                patch.object(collector_v1, "collect_case") as collect, \
                patch("sys.stdout", new=io.StringIO()), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(collector_v2.main(["--protocol", "unused.json"]), 2)
            preflight.assert_not_called()
            self.assertEqual(collector_v2.main(["--protocol", "unused.json", "--preflight-only"]), 0)
        collect.assert_not_called()

    def test_failed_preflight_creates_no_output_and_starts_no_traffic(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(collector_v2, "load_protocol", return_value=dict(cases=[])), \
                    patch.object(collector_v1, "preflight", side_effect=ValueError("unsafe")), \
                    patch.object(collector_v1, "collect_case") as collect, \
                    patch.object(collector_v2.sys, "platform", "linux"), \
                    patch("sys.stderr", new=io.StringIO()):
                status = collector_v2.main(["--protocol", str(root / "protocol.json"),
                                           "--output", str(root / "campaign"), "--allow-lab-traffic"])
            self.assertEqual(status, 2)
            self.assertFalse((root / "campaign").exists())
            collect.assert_not_called()

    def test_shared_v1_lock_refuses_concurrent_collection_before_preflight(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch.object(collector_v2, "load_protocol", return_value=dict(cases=[])), \
                    patch.object(collector_v2.fcntl, "flock", side_effect=BlockingIOError("locked")), \
                    patch.object(collector_v1, "preflight") as preflight, \
                    patch.object(collector_v2.sys, "platform", "linux"), \
                    patch("sys.stderr", new=io.StringIO()):
                status = collector_v2.main(["--protocol", str(root / "protocol.json"),
                                           "--output", str(root / "campaign"), "--allow-lab-traffic"])
            self.assertEqual(status, 2)
            self.assertFalse((root / "campaign").exists())
            preflight.assert_not_called()

    def test_completed_collection_retains_failed_criteria_and_unchanged_v1_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            protocol = dict(cases=[dict(case_id="mock-case")], policy=dict(v2.POLICY))
            report = dict(status="COMPLETED", evaluated_runs=12, criteria_status="NOT_PASSED",
                          promotion_eligible=False)
            term = collector_v2.signal.getsignal(collector_v2.signal.SIGTERM)
            with patch.object(collector_v2, "load_protocol", return_value=protocol), \
                    patch.object(collector_v1, "preflight", return_value={}), \
                    patch.object(collector_v1, "collect_case") as collect, \
                    patch.object(collector_v2, "evaluate_campaign", return_value=report), \
                    patch.object(collector_v2.sys, "platform", "linux"), \
                    patch("sys.stdout", new=io.StringIO()):
                status = collector_v2.main(["--protocol", str(root / "protocol.json"),
                                           "--output", str(root / "campaign"), "--allow-lab-traffic"])
            self.assertEqual(status, 3)
            collect.assert_called_once_with(protocol, protocol["cases"][0], (root / "campaign/mock-case").resolve())
            self.assertEqual(json.loads((root / "campaign/campaign-summary.json").read_text()), report)
            self.assertEqual(collector_v2.signal.getsignal(collector_v2.signal.SIGTERM), term)
            self.assertIs(collector_v1.load_protocol, v1.load_protocol)
            self.assertIs(collector_v1.evaluate_campaign, v1.evaluate_campaign)

    def test_interrupted_collection_does_not_create_a_success_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            term = collector_v2.signal.getsignal(collector_v2.signal.SIGTERM)
            with patch.object(collector_v2, "load_protocol", return_value=dict(cases=[dict(case_id="mock")])), \
                    patch.object(collector_v1, "preflight", return_value={}), \
                    patch.object(collector_v1, "collect_case", side_effect=KeyboardInterrupt), \
                    patch.object(collector_v2, "evaluate_campaign") as evaluate, \
                    patch.object(collector_v2.sys, "platform", "linux"), \
                    patch("sys.stderr", new=io.StringIO()):
                status = collector_v2.main(["--protocol", str(root / "protocol.json"),
                                           "--output", str(root / "campaign"), "--allow-lab-traffic"])
            self.assertEqual(status, 130)
            self.assertTrue((root / "campaign/campaign-plan.json").exists())
            self.assertFalse((root / "campaign/campaign-summary.json").exists())
            evaluate.assert_not_called()
            self.assertEqual(collector_v2.signal.getsignal(collector_v2.signal.SIGTERM), term)


if __name__ == "__main__":
    unittest.main()
