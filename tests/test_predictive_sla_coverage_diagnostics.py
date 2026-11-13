import copy
import io
import json
import unittest
from unittest.mock import patch

import predictive_sla_coverage_diagnostics as diagnostic
import predictive_sla_validation as v1
import predictive_sla_validation_v4 as v4
import qos_warning_selection as selection
from test_predictive_sla_diagnostics import episode_fixture
import test_predictive_sla_validation_v4 as v4_fixtures


def fixture():
    values, timestamps, rows, frozen = episode_fixture()
    for row in rows:
        row.update(observed_value=values[row["index"]], entry_inhibited=False,
                   clear_transition=row["index"] == 53,
                   predictions=[dict(horizon_s=12, predicted_value=.9)])
    return timestamps, dict(rows=rows, episode_events=frozen)


class EpisodeCoverageTests(unittest.TestCase):
    def diagnose(self, block, timestamps, age=5):
        return diagnostic.classify_episodes(block, timestamps, maximum_age_s=age, maximum_horizon_s=12)

    def test_second_episode_has_existing_fresh_alert_not_a_new_activation(self):
        timestamps, block = fixture()
        before = copy.deepcopy(block)
        result = self.diagnose(block, timestamps)
        self.assertEqual([e["category"] for e in result], [diagnostic.NEW, diagnostic.EXISTING])
        self.assertEqual(result[1]["latest_pre_onset_evaluation"]["active_alert_started_index"], 44)
        self.assertEqual(result[1]["existing_alert_age_at_onset_s"], 12)
        self.assertEqual(result[1]["latest_renewal_age_s"], 2)
        self.assertIsNone(result[1]["matched_activation_lead_time_s"])
        summary = diagnostic.summarize([dict(episodes=result)])
        self.assertEqual(summary["strict_anticipated"], 1)
        self.assertEqual(summary["existing_alert_fresh_coverage"], 1)
        self.assertEqual(summary["documented_warning_or_fresh_existing_alert"], 2)
        self.assertTrue(summary["partition_complete"])
        self.assertEqual(block, before)

    def test_active_state_without_fresh_candidate_does_not_gain_coverage(self):
        timestamps, block = fixture()
        next(r for r in block["rows"] if r["index"] == 49)["candidate"] = False
        result = self.diagnose(block, timestamps)[1]
        self.assertEqual(result["category"], diagnostic.ABSENT)
        self.assertEqual(result["coverage_reason"], "active_without_renewed_candidate")

    def test_candidate_while_inactive_and_blocked_onset_are_not_preventive_coverage(self):
        timestamps, block = fixture()
        for row in block["rows"]:
            if row["index"] >= 48:
                row.update(active=False, activation=False, candidate=row["index"] >= 50,
                           entry_inhibited=row["index"] >= 50)
        result = self.diagnose(block, timestamps)[1]
        self.assertEqual(result["category"], diagnostic.ABSENT)
        self.assertEqual(result["latest_pre_onset_evaluation"]["index"], 49)
        self.assertTrue(result["diagnostic_context"][-1]["entry_inhibited"])
        next(r for r in block["rows"] if r["index"] == 49)["candidate"] = True
        result = self.diagnose(block, timestamps)[1]
        self.assertEqual(result["coverage_reason"], "candidate_not_yet_active")
        self.assertEqual(result["category"], diagnostic.ABSENT)

    def test_strict_match_survives_latest_clearing_without_claiming_current_coverage(self):
        timestamps, block = fixture()
        for row in block["rows"]:
            if row["index"] >= 45:
                row.update(active=False, candidate=False, activation=False)
        result = self.diagnose(block, timestamps)
        self.assertEqual(result[0]["category"], diagnostic.NEW)
        self.assertFalse(result[0]["fresh_active_coverage"])
        self.assertEqual(result[0]["matched_activation_lead_time_s"], 4)
        total = diagnostic.summarize([dict(episodes=result)])
        self.assertEqual(total["strict_matches_without_latest_fresh_coverage"], 1)
        self.assertEqual(total["no_fresh_pre_onset_alert"], 1)

    def test_missing_pre_onset_window_and_missing_alert_origin_are_unassessable(self):
        for missing in (49, 44, 48):
            timestamps, block = fixture()
            block["rows"] = [r for r in block["rows"] if r["index"] != missing]
            result = self.diagnose(block, timestamps)[1]
            with self.subTest(missing=missing):
                self.assertEqual(result["category"], diagnostic.UNKNOWN)
                self.assertIsNone(result["fresh_active_coverage"])
                self.assertFalse(result["coverage_assessable"])

    def test_actual_timestamp_freshness_is_inclusive_and_not_nominal_lead(self):
        for offset, category in ((3_000_000_000, diagnostic.EXISTING), (3_000_000_001, diagnostic.UNKNOWN)):
            timestamps, block = fixture()
            for index in range(50, len(timestamps)):
                timestamps[index] += offset
            for row in block["rows"]:
                row["ts_ns"] = timestamps[row["index"]]
            block["episode_events"]["episodes"][1]["onset_ts_ns"] = timestamps[50]
            with self.subTest(offset=offset):
                self.assertEqual(self.diagnose(block, timestamps)[1]["category"], category)

    def test_ineligible_episodes_stay_outside_partition_and_denominator(self):
        timestamps, block = fixture()
        block["episode_events"]["episodes"][1]["eligible"] = False
        result = self.diagnose(block, timestamps)
        self.assertEqual(result[1]["category"], diagnostic.INELIGIBLE)
        total = diagnostic.summarize([dict(episodes=result)])
        self.assertEqual(total["eligible_episodes"], 1)
        self.assertEqual(total["ineligible_episodes"], 1)
        self.assertEqual(total["existing_alert_fresh_coverage"], 0)

    def test_future_rows_and_future_truth_never_change_pre_onset_category(self):
        timestamps, block = fixture()
        before = self.diagnose(block, timestamps)
        changed = copy.deepcopy(block)
        for row in changed["rows"]:
            row.update(actual_positive=False, actual_horizons=[10, 10, 10])
            if row["index"] >= 50:
                row.update(active=False, candidate=False, activation=False, predictions=[])
        after = self.diagnose(changed, timestamps)
        fields = ("category", "fresh_active_coverage", "latest_pre_onset_evaluation",
                  "existing_alert_age_at_onset_s", "coverage_reason")
        self.assertEqual([{k: e[k] for k in fields} for e in before],
                         [{k: e[k] for k in fields} for e in after])
        self.assertTrue(all("actual_horizons" not in e["latest_pre_onset_evaluation"] for e in after))

    def test_duplicate_rows_invalid_state_and_nonboolean_flags_are_rejected(self):
        for mutate in (
            lambda b: b["rows"].append(copy.deepcopy(b["rows"][-1])),
            lambda b: b["rows"][0].update(active="true"),
            lambda b: b["rows"][0].update(activation=True),
            lambda b: next(r for r in b["rows"] if r["index"] == 45).update(activation=True),
            lambda b: b["rows"][0].update(ts_ns=1),
        ):
            timestamps, block = fixture()
            mutate(block)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.diagnose(block, timestamps)

    def test_empty_series_is_not_zero_error_or_successful_prediction(self):
        result = diagnostic.summarize([])
        self.assertEqual(result["eligible_episodes"], 0)
        self.assertIsNone(result["descriptive_coverage_rate"])


class CoverageCampaignTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixture = v4_fixtures.ProspectiveV4Tests(methodName="test_complete_new_campaign_is_paired_shadow_with_unchanged_criteria")
        cls.addClassCleanup(cls.fixture.doCleanups)
        cls.fixture.setUp()
        cls.protocol = cls.fixture.freeze()
        cls.fixture.cases(cls.protocol)
        cls.path, cls.campaign = cls.fixture.path, cls.fixture.campaign
        cls.official = v4.evaluate_campaign(cls.path, cls.campaign)
        cls.summary_path = cls.campaign / "campaign-summary.json"
        v1.write_new_json(cls.summary_path, cls.official)
        cls.summary_bytes = cls.summary_path.read_bytes()

    def setUp(self):
        self.assertEqual(self.summary_path.read_bytes(), self.summary_bytes)

    def hashes(self):
        return {str(p): v1.digest_file(p) for p in self.fixture.root.rglob("*") if p.is_file()}

    def test_complete_report_preserves_frozen_metrics_sources_models_and_no_network_or_fit(self):
        before = self.hashes()
        frozen_code = v4.code_snapshot()
        with patch.object(selection, "choose_parameters", side_effect=AssertionError("refit")), \
                patch.object(selection, "calibrate_selected", side_effect=AssertionError("calibration")), \
                patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("fit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = diagnostic.build_report(self.path, self.campaign)
        self.assertEqual(before, self.hashes())
        self.assertEqual(frozen_code, v4.code_snapshot())
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertTrue(report["official_v4_unchanged"])
        self.assertEqual(report["baseline"]["checks"], self.official["checks"])
        self.assertEqual(report["baseline"]["criteria_status"], self.official["criteria_status"])
        for key in ("promotion_eligible", "deployment_eligible", "refit", "recalibration", "sla_protection_established"):
            self.assertFalse(report[key])
        self.assertEqual(report["operational_timing"]["status"], "NOT_MEASURED")
        self.assertIn("posthoc", report["scope"])
        self.assertEqual(report["coverage_policy"]["maximum_age_s"], self.protocol["quality"]["maximum_gap_s"])
        for name, model in report["models"].items():
            self.assertEqual(len(model["series"]), 24)
            self.assertEqual(model["summary"]["strict_anticipated"], self.official["models"][name]["anticipated"])
            self.assertTrue(model["summary"]["partition_complete"])
            for field, value in model["frozen_metrics"].items():
                self.assertEqual(value, self.official["models"][name][field])
            expected = [e for c in self.official["cases"] for s in c["models"][name]["series"]
                        for e in s["episode_events"]["episodes"]]
            self.assertEqual([e["frozen_episode"] for s in model["series"] for e in s["episodes"]], expected)

    def test_resealed_changed_summary_is_rejected_not_repaired(self):
        payload = copy.deepcopy(self.official)
        payload["criteria_status"] = "INVENTED"
        self.summary_path.write_text(json.dumps(v1.seal(payload, "report_sha256")))
        self.addCleanup(self.summary_path.write_bytes, self.summary_bytes)
        with self.assertRaisesRegex(ValueError, "diverge da reavaliação"):
            diagnostic.build_report(self.path, self.campaign)
        self.assertEqual(json.loads(self.summary_path.read_text())["criteria_status"], "INVENTED")

    def test_changed_csv_is_rejected_without_overwrite(self):
        path = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        original = path.read_bytes()
        path.write_bytes(original + b"changed")
        self.addCleanup(path.write_bytes, original)
        with self.assertRaisesRegex(ValueError, "CSV"):
            diagnostic.build_report(self.path, self.campaign)
        self.assertTrue(path.read_bytes().endswith(b"changed"))

    def test_incomplete_campaign_has_no_success_diagnostic(self):
        payload = copy.deepcopy(self.official)
        payload.update(status="INCOMPLETE_OR_INVALID", evaluated_runs=11)
        self.summary_path.write_text(json.dumps(v1.seal(payload, "report_sha256")))
        self.addCleanup(self.summary_path.write_bytes, self.summary_bytes)
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            diagnostic.build_report(self.path, self.campaign)

    def test_sources_or_analysis_code_changed_during_classification_stop_publication(self):
        target = self.path.parent / "coverage-diagnostics-change.json"
        classify = diagnostic.classify_episodes
        called = False

        def changed(*args, **kwargs):
            nonlocal called
            if not called:
                self.summary_path.write_bytes(self.summary_bytes + b" ")
                called = True
            return classify(*args, **kwargs)

        self.addCleanup(self.summary_path.write_bytes, self.summary_bytes)
        with patch.object(diagnostic, "classify_episodes", side_effect=changed), \
                patch("sys.stderr", new=io.StringIO()):
            result = diagnostic.main(["--protocol", str(self.path), "--campaign-root", str(self.campaign),
                                      "--output", str(target)])
        self.assertEqual(result, 2)
        self.assertFalse(target.exists())
        self.summary_path.write_bytes(self.summary_bytes)
        snapshot = diagnostic.code_snapshot()
        with patch.object(diagnostic, "code_snapshot", side_effect=[snapshot, {}]), \
                self.assertRaisesRegex(ValueError, "fontes/código"):
            diagnostic.build_report(self.path, self.campaign)

    def test_output_targets_existing_files_and_symlinks_are_refused_before_analysis(self):
        targets = [self.path, self.campaign / "coverage-diagnostics.json",
                   self.path.parent / "models/coverage-diagnostics.json", self.fixture.root / "coverage-diagnostics.json"]
        link = self.path.parent / "coverage-diagnostics-link.json"
        link.symlink_to(self.summary_path)
        self.addCleanup(link.unlink)
        dangling = self.path.parent / "coverage-diagnostics-dangling.json"
        dangling.symlink_to(self.path.parent / "absent.json")
        self.addCleanup(dangling.unlink)
        for target in [*targets, link, dangling]:
            with self.subTest(target=target), patch.object(diagnostic, "build_report") as build, \
                    patch("sys.stderr", new=io.StringIO()):
                status = diagnostic.main(["--protocol", str(self.path), "--campaign-root", str(self.campaign),
                                          "--output", str(target)])
                self.assertEqual(status, 2)
                build.assert_not_called()

    def test_cli_only_writes_new_descriptive_report_and_console_is_bounded(self):
        target = self.path.parent / "coverage-diagnostics-cli.json"
        self.addCleanup(lambda: target.unlink(missing_ok=True))
        before = self.hashes()
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            status = diagnostic.main(["--protocol", str(self.path), "--campaign-root", str(self.campaign),
                                      "--output", str(target)])
        self.assertEqual(status, 0)
        self.assertEqual({path: sha for path, sha in self.hashes().items() if path != str(target)}, before)
        self.assertLessEqual(len(stdout.getvalue().splitlines()), 8)
        self.assertIn("promotion_eligible=false", stdout.getvalue())
        self.assertIn(f"criteria={self.official['criteria_status']}", stdout.getvalue())
        before_output = target.read_bytes()
        with patch.object(diagnostic, "build_report") as build, patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(diagnostic.main(["--protocol", str(self.path), "--campaign-root", str(self.campaign),
                                             "--output", str(target)]), 2)
            build.assert_not_called()
        self.assertEqual(target.read_bytes(), before_output)


if __name__ == "__main__":
    unittest.main()
