import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import predictive_sla_validation_v3 as v3
import predictive_sla_damped_replay as replay
import train_qos_warning_model as training
import qos_warning_selection as warning
from qos_damped_holt import QosDampedHoltModel
from qos_holt import QosHoltModel
from scripts import collect_qos_validation_campaign as old_collector
from scripts import collect_qos_validation_campaign_v3 as collector
from test_predictive_sla_validation import create_case, create_pilot


class ProspectiveV3Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        create_pilot(self.root / "pilot")
        self.v1_path = self.root / "v1/protocol.json"
        self.v1 = v1.freeze_protocol(self.root / "pilot", self.v1_path.parent)
        self.v1_campaign = self.v1_path.parent / "campaign"
        for ordinal, case in enumerate(self.v1["cases"]):
            create_case(self.v1, case, self.v1_campaign, ordinal)
        v1.write_new_json(self.v1_campaign / "campaign-summary.json", v1.evaluate_campaign(self.v1_path, self.v1_campaign))
        self.v2_path = self.root / "v2/protocol.json"
        with patch.object(v2.time, "time_ns", return_value=self.v1["created_ns"] + 10_000_000_000_000):
            self.v2 = v2.freeze_protocol(self.v1_path, self.v1_campaign, self.v2_path.parent)
        self.v2_campaign = self.v2_path.parent / "campaign"
        for ordinal, case in enumerate(self.v2["cases"]):
            create_case(self.v2, case, self.v2_campaign, ordinal)
        v1.write_new_json(self.v2_campaign / "campaign-summary.json", v2.evaluate_campaign(self.v2_path, self.v2_campaign))
        for p in (patch.object(training, "ALPHAS", (.2, .7)), patch.object(training, "BETAS", (0, .2)),
                  patch.object(training, "PHIS", (.8, 1))):
            p.start()
            self.addCleanup(p.stop)
        self.development = self.root / "qos-warning-development-v1"
        self.training = training.fit_campaign(self.v1_path, self.v1_campaign, self.development)
        self.path = self.root / "qos-prospective-v3/protocol.json"
        self.campaign = self.path.parent / "campaign"
        self.freeze_time = self.v1["created_ns"] + 25_000_000_000_000

    def freeze(self):
        with patch.object(v3.time, "time_ns", return_value=self.freeze_time):
            return v3.freeze_protocol(self.v2_path, self.v2_campaign, self.development, self.path.parent)

    def cases(self, protocol, count=12):
        for ordinal, case in enumerate(protocol["cases"][:count]):
            create_case(protocol, case, self.campaign, ordinal)

    def hashes(self):
        return {str(p): v1.digest_file(p) for p in self.root.rglob("*") if p.is_file()}

    def record(self, case_id, modify):
        path = self.campaign / case_id / "run.json"
        payload = json.loads(path.read_text())
        modify(payload)
        path.write_text(json.dumps(v1.seal(payload, "run_sha256")))

    def test_freeze_copies_selected_and_native_bytes_without_fitting_or_network(self):
        before = self.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("search")), \
                patch.object(warning, "calibrate_selected", side_effect=AssertionError("calibration")), \
                patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            protocol = self.freeze()
            self.assertEqual(v3.load_protocol(self.path), protocol)
        self.assertEqual(before, {p: v1.digest_file(Path(p)) for p in before})
        self.assertEqual(protocol["policy"], self.v2["policy"])
        self.assertEqual(protocol["acceptance_criteria"], v2.CRITERIA)
        self.assertEqual(protocol["development"]["selected_parameters"], self.training["selection"]["selected"]["parameters"])
        self.assertFalse(protocol["refit"])
        self.assertFalse(protocol["recalibration"])
        self.assertFalse(protocol["deployment_eligible"])
        self.assertEqual((self.path.parent / protocol["models"][v3.PRIMARY]["path"]).read_bytes(),
                         (self.development / "qos-warning-model.json").read_bytes())
        self.assertEqual((self.path.parent / protocol["models"][v3.REFERENCE]["path"]).read_bytes(),
                         (self.v2_path.parent / self.v2["models"]["coverage90"]["path"]).read_bytes())
        self.assertGreaterEqual(len(protocol["excluded_csv_sha256"]), 48)
        with self.assertRaises(ValueError):
            QosHoltModel.load(self.path.parent / protocol["models"][v3.PRIMARY]["path"])

    def test_freeze_requires_complete_exact_v2_summary_and_existing_selected_receipt(self):
        summary = self.v2_campaign / "campaign-summary.json"
        original = summary.read_bytes()
        payload = json.loads(original)
        payload["evaluated_runs"] = 11
        summary.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError, "relatório v2"):
            self.freeze()
        self.assertFalse(self.path.parent.exists())
        summary.write_bytes(original)
        report = self.development / "qos-warning-evaluation.json"
        payload = json.loads(report.read_text())
        payload["status"] = "NO_FEASIBLE_CANDIDATE"
        report.write_text(json.dumps(v1.seal(payload, "report_sha256")))
        with self.assertRaisesRegex(ValueError, "recibo/modelo"):
            self.freeze()
        self.assertFalse(self.path.parent.exists())

    def test_freeze_cannot_predate_sources_or_overwrite_directories(self):
        with patch.object(v3.time, "time_ns", return_value=self.v1["created_ns"]), \
                self.assertRaisesRegex(ValueError, "posterior"):
            v3.freeze_protocol(self.v2_path, self.v2_campaign, self.development, self.path.parent)
        for target in (self.v1_path.parent, self.development, self.v2_campaign / "qos-prospective-v3"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                v3.freeze_protocol(self.v2_path, self.v2_campaign, self.development, target)
        self.freeze()
        with self.assertRaisesRegex(ValueError, "já existe"):
            self.freeze()

    def test_resealed_configuration_selection_exclusions_or_model_substitution_rejected(self):
        original = self.freeze()
        variants = (
            lambda p: p["policy"].update(activation_windows=2),
            lambda p: p["policy"].update(threshold=.7),
            lambda p: p["acceptance_criteria"].clear(),
            lambda p: p.update(deployment_eligible=True),
            lambda p: p.update(refit=True),
            lambda p: p.update(recalibration=True),
            lambda p: p.update(evaluation_unit="independent_windows"),
            lambda p: p.update(excluded_csv_sha256=[]),
            lambda p: p["development"]["selected_parameters"].update(beta=0),
            lambda p: p["models"][v3.PRIMARY].update(path="../qos-warning-development-v1/qos-warning-model.json"),
        )
        for modify in variants:
            p = copy.deepcopy(original)
            modify(p)
            self.path.write_text(json.dumps(v1.seal(p, "protocol_sha256")))
            with self.subTest(modify=modify), self.assertRaises(ValueError):
                v3.load_protocol(self.path)

    def test_modified_old_data_development_receipt_model_or_code_invalidates_v3(self):
        protocol = self.freeze()
        paths = [self.development / "qos-warning-evaluation.json", self.development / "development-spec.json",
                 self.path.parent / protocol["models"][v3.PRIMARY]["path"],
                 self.v2_campaign / "campaign-summary.json",
                 self.root / "pilot/pilot-192.168.10.10.csv",
                 self.v1_campaign / self.v1["cases"][0]["case_id"] / "port_utilization_domain0.csv"]
        for path in paths:
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            with self.subTest(path=path), self.assertRaises((ValueError, OSError)):
                v3.load_protocol(self.path)
            path.write_bytes(original)
        with patch.object(v3, "code_snapshot", return_value={}), self.assertRaisesRegex(ValueError, "código"):
            v3.load_protocol(self.path)

    def test_saved_selection_must_be_best_feasible_and_match_actual_train_receipt(self):
        path = self.development / "qos-warning-evaluation.json"
        original = json.loads(path.read_text())
        modified = copy.deepcopy(original)
        modified["selection"]["feasible_candidates"] += 1
        path.write_text(json.dumps(v1.seal(modified, "report_sha256")))
        with self.assertRaisesRegex(ValueError, "seleção lexicográfica"):
            self.freeze()
        modified = copy.deepcopy(original)
        modified["selected_training"]["summary"]["evaluated_windows"] += 1
        path.write_text(json.dumps(v1.seal(modified, "report_sha256")))
        with self.assertRaisesRegex(ValueError, "recibo de treino"):
            self.freeze()
        self.assertFalse(self.path.parent.exists())

    def test_complete_new_runs_are_paired_but_do_not_force_forecasts_to_match(self):
        protocol = self.freeze()
        self.cases(protocol)
        before = self.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("search")), \
                patch.object(warning, "calibrate_selected", side_effect=AssertionError("fit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["evaluated_runs"], 12)
        self.assertEqual(before, self.hashes())
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(len(report["source_sha256"]), 36)
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["deployment_eligible"])
        self.assertFalse(report["new_data_used_for_fitting"])
        self.assertFalse(report["statistical_superiority_assessed"])
        self.assertEqual(set(report["checks"]), set(v3.CRITERIA))
        self.assertTrue(report["paired_changes"]["ground_truth_matches"])
        self.assertTrue(all(c["same_series_paired"] and c["observed_episodes_identical"] for c in report["cases"]))
        self.assertEqual(set(report["models"][v3.PRIMARY]["per_profile"]), set(v1.profiles()))
        self.assertEqual(len(report["models"][v3.PRIMARY]["per_run"]), 12)
        self.assertIn("interval_coverage", report["models"][v3.PRIMARY]["forecast_errors"]["2"])
        self.assertEqual(report["models"][v3.PRIMARY]["episode_events"]["timing_basis"], "csv_timestamps")
        self.assertEqual(len(report["cases"][0]["delivery_checks"]), 2)
        a = report["cases"][0]["models"][v3.PRIMARY]["series"][0]["rows"]
        b = report["cases"][0]["models"][v3.REFERENCE]["series"][0]["rows"]
        # The selected family is a distinct forecaster; only observed truth is shared.
        self.assertNotEqual([r["predictions"] for r in a], [r["predictions"] for r in b])

    def test_missing_failed_or_cleanup_failed_runs_are_not_successful_negatives(self):
        p = self.freeze()
        self.cases(p, 1)
        report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["status"], "INCOMPLETE_OR_INVALID")
        self.assertEqual(len(report["missing_runs"]), 11)
        self.assertEqual(v3.report_exit_code(report), 2)
        case_id = p["cases"][0]["case_id"]
        self.record(case_id, lambda r: r.update(cleanup_errors=["qdisc cleanup failed"]))
        report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertIn("cleanup", report["invalid_runs"][0]["error"])
        self.assertEqual(report["models"][v3.PRIMARY]["evaluated_windows"], 0)

    def test_old_csv_cannot_be_relabelled_as_new_and_timestamp_checksum_failures_visible(self):
        p = self.freeze()
        self.cases(p, 1)
        case = p["cases"][0]
        source = self.v2_campaign / case["case_id"] / "port_utilization_domain0.csv"
        target = self.campaign / case["case_id"] / source.name
        target.write_bytes(source.read_bytes())
        self.record(case["case_id"], lambda r: r["sources"][0].update(sha256=v1.digest_file(target)))
        report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertEqual(len(report["invalid_runs"]), 1)
        self.assertFalse(report["checks"]["all_twelve_runs_valid"])

    def test_new_data_checksum_and_postfreeze_times_are_required(self):
        p = self.freeze()
        self.cases(p, 1)
        case_id = p["cases"][0]["case_id"]
        csv = self.campaign / case_id / "port_utilization_domain0.csv"
        original = csv.read_bytes()
        csv.write_bytes(original + b"changed")
        report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertIn("CSV mudou", report["invalid_runs"][0]["error"])
        csv.write_bytes(original)
        self.record(case_id, lambda r: r.update(started_ns=p["created_ns"] - 1))
        report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertIn("posterior ao congelamento", report["invalid_runs"][0]["error"])

    def test_existing_or_symlink_output_cannot_redirect_campaign_writes(self):
        self.freeze()
        external = self.root / "outside"
        external.mkdir()
        target = self.path.parent / "campaign-link"
        target.symlink_to(external, target_is_directory=True)
        with self.assertRaises(ValueError):
            v3.campaign_path(self.path, target, new=True)
        self.campaign.mkdir()
        with self.assertRaisesRegex(ValueError, "já existe"):
            v3.campaign_path(self.path, self.campaign, new=True)

    def test_reused_hash_and_overlapping_runs_rejected_even_with_valid_records(self):
        p = self.freeze()
        self.cases(p, 2)
        original = v1._read_case

        def reused(protocol, case, root):
            subjects, record, hashes = original(protocol, case, root)
            return subjects, record, (["samehash0", "samehash1"] if root.parent == self.campaign else hashes)

        with patch.object(v1, "_read_case", side_effect=reused):
            report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 1)
        self.assertIn("reutilizado", report["invalid_runs"][0]["error"])

        def overlap(protocol, case, root):
            subjects, record, hashes = original(protocol, case, root)
            if root.parent == self.campaign:
                record["started_ns"] = p["created_ns"] + 100 * 1_000_000_000
                record["ended_ns"] = record["started_ns"] + 150 * 1_000_000_000
            return subjects, record, hashes

        with patch.object(v1, "_read_case", side_effect=overlap):
            report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 1)
        self.assertIn("sobrepostas", report["invalid_runs"][0]["error"])

    def test_ground_truth_changes_or_wrong_native_replay_fail_closed(self):
        p = self.freeze()
        self.cases(p, 1)
        with patch.object(replay, "_check_native_reference", side_effect=ValueError("native mismatch")):
            report = v3.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 0)
        self.assertIn("native mismatch", report["invalid_runs"][0]["error"])
        with patch.object(replay, "paired_changes", side_effect=ValueError("observed truth mismatch")):
            with self.assertRaisesRegex(ValueError, "observed truth"):
                v3.evaluate_campaign(self.path, self.campaign)

    def test_sources_changed_mid_replay_prevent_publishing_report(self):
        p = self.freeze()
        self.cases(p, 1)
        original = replay.replay_series
        path = self.campaign / p["cases"][0]["case_id"] / "run.json"

        def changed(model, series, settings):
            result = original(model, series, settings)
            path.write_bytes(path.read_bytes() + b" ")
            return result

        with patch.object(replay, "replay_series", side_effect=changed), self.assertRaisesRegex(ValueError, "mudaram"):
            v3.evaluate_campaign(self.path, self.campaign)

    def test_primary_criteria_and_reference_criteria_remain_separate(self):
        p = self.freeze()
        self.cases(p)
        report = v3.evaluate_campaign(self.path, self.campaign)
        cases = copy.deepcopy(report["cases"])
        reference_before = v3.assess_criteria(cases, True, v3.REFERENCE)
        control = next(c for c in cases if c["profile"] == "stable-low")
        control["models"][v3.PRIMARY]["series"][0]["episode_events"]["activations"].append(
            dict(status="UNMATCHED", reason="no_sustained_episode_within_horizon"))
        self.assertFalse(v3.assess_criteria(cases, True, v3.PRIMARY)["no_control_activations"])
        self.assertEqual(v3.assess_criteria(cases, True, v3.REFERENCE), reference_before)
        self.assertEqual(v3.report_exit_code(dict(status="COMPLETED", criteria_status="NOT_PASSED")), 3)
        self.assertEqual(v3.report_exit_code(dict(status="COMPLETED", criteria_status="PASSED")), 0)

    def test_cli_is_compact_and_no_tuning_overwrite_or_foreign_campaign_allowed(self):
        with patch.object(v3.time, "time_ns", return_value=self.freeze_time), patch("sys.stdout", new=io.StringIO()) as stream:
            status = v3.main(["freeze", "--source-protocol", str(self.v2_path), "--source-campaign", str(self.v2_campaign),
                              "--development-root", str(self.development), "--output", str(self.path.parent)])
        self.assertEqual(status, 0)
        self.assertEqual(len(stream.getvalue().splitlines()), 5)
        for target in (self.v2_campaign, self.path.parent / "models", self.path.parent / "new-runs"):
            with self.subTest(target=target), self.assertRaises(ValueError):
                v3.campaign_path(self.path, target)
        self.cases(v3.load_protocol(self.path), 1)
        args = ["evaluate", "--protocol", str(self.path), "--campaign-root", str(self.campaign),
                "--output", str(self.path.parent / "campaign-review.json")]
        with patch("sys.stdout", new=io.StringIO()) as stream:
            self.assertEqual(v3.main(args), 2)
        self.assertEqual(len(stream.getvalue().splitlines()), 1)
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(v3.main(args), 2)
            with self.assertRaises(SystemExit):
                v3.main(args + ["--threshold", ".7"])


class CollectorV3Tests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.path = Path(self.temporary.name) / "protocol.json"
        self.output = self.path.parent / "campaign"
        self.protocol = dict(cases=[dict(case_id="r01"), dict(case_id="r02")])
        self.load = patch.object(collector, "load_protocol", return_value=self.protocol)
        self.load.start()
        self.addCleanup(self.load.stop)
        self.safety = dict(status="READY", safety=[{}, {}])

    def args(self):
        return ["--protocol", str(self.path), "--output", str(self.output), "--allow-lab-traffic"]

    def test_preflight_read_only_and_traffic_requires_explicit_opt_in(self):
        with patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case") as traffic, patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(collector.main(["--protocol", str(self.path), "--preflight-only"]), 0)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertFalse(self.output.exists())
        traffic.assert_not_called()
        with patch("sys.stderr", new=io.StringIO()), patch.object(old_collector, "preflight") as check:
            self.assertEqual(collector.main(["--protocol", str(self.path), "--output", str(self.output)]), 2)
        check.assert_not_called()

    def test_non_linux_existing_output_and_failed_preflight_never_start_traffic(self):
        with patch.object(collector.sys, "platform", "darwin"), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(collector.main(self.args()), 2)
        with patch.object(collector.sys, "platform", "linux"), patch("sys.stderr", new=io.StringIO()), \
                patch.object(collector.fcntl, "flock"), patch.object(old_collector, "preflight", side_effect=ValueError("namespace")), \
                patch.object(old_collector, "collect_case") as traffic:
            self.assertEqual(collector.main(self.args()), 2)
        self.assertFalse(self.output.exists())
        traffic.assert_not_called()
        self.output.mkdir()
        with patch.object(collector.sys, "platform", "linux"), patch("sys.stderr", new=io.StringIO()), \
                patch.object(old_collector, "preflight") as check:
            self.assertEqual(collector.main(self.args()), 2)
        check.assert_not_called()

    def test_shared_lock_failure_prevents_preflight_and_collection(self):
        with patch.object(collector.sys, "platform", "linux"), patch("sys.stderr", new=io.StringIO()), \
                patch.object(collector.fcntl, "flock", side_effect=BlockingIOError("other collector")), \
                patch.object(old_collector, "preflight") as check:
            self.assertEqual(collector.main(self.args()), 2)
        check.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_mock_collection_preserves_failed_criteria_and_no_runtime_model_deployment(self):
        report = dict(status="COMPLETED", evaluated_runs=12, criteria_status="NOT_PASSED")
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case") as traffic, \
                patch.object(collector, "evaluate_campaign", return_value=report), patch("sys.stdout", new=io.StringIO()) as out:
            self.assertEqual(collector.main(self.args()), 3)
        self.assertEqual(traffic.call_count, 2)
        self.assertEqual(json.loads((self.output / "campaign-summary.json").read_text()), report)
        self.assertIn("criteria=NOT_PASSED", out.getvalue())

    def test_interrupted_or_changed_protocol_preserves_partial_files_without_success_summary(self):
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case", side_effect=KeyboardInterrupt), patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(collector.main(self.args()), 130)
        self.assertTrue((self.output / "campaign-plan.json").exists())
        self.assertFalse((self.output / "campaign-summary.json").exists())
        changed_output = self.path.parent / "campaign-changed"
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(collector, "load_protocol", side_effect=[self.protocol, dict(cases=[])]), \
                patch.object(old_collector, "collect_case") as traffic, patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(collector.main(["--protocol", str(self.path), "--output", str(changed_output), "--allow-lab-traffic"]), 2)
        traffic.assert_not_called()
        self.assertFalse((changed_output / "campaign-summary.json").exists())


if __name__ == "__main__":
    unittest.main()
