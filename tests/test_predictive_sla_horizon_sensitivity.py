import copy
import io
import json
import math
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_horizon_sensitivity as sensitivity
import predictive_sla_damped_replay as replay
import predictive_sla_validation as v1
import predictive_sla_validation_v3 as v3
import qos_warning_selection as warning
import test_predictive_sla_validation_v3 as fixtures
import test_predictive_sla_damped_replay as helpers
from backtest_sla_risk import _actual_future_outcome


class HorizonGateTests(unittest.TestCase):
    def test_native_and_damped_two_horizon_baseline_is_exact_and_inputs_are_unchanged(self):
        for damped in (False, True):
            model = helpers.model(damped=damped)
            series = helpers.series([.2, .3, .5, .7, .9, 1.1, .4, .2] * 10)
            baseline = replay.replay_series(model, series, v3.POLICY)
            baseline.update(case_id="r01-fast-ramp", profile="fast-ramp", repetition=1, source_sha256="demo")
            before = copy.deepcopy((series, baseline))
            self.assertEqual(sensitivity.replay_gate(model, series, baseline, v3.POLICY, 2), baseline)
            one = sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1)
            self.assertEqual(before, (series, baseline))
            self.assertEqual([r["predictions"] for r in one["rows"]], [r["predictions"] for r in baseline["rows"]])
            self.assertEqual(one["samples"], baseline["samples"])
            self.assertEqual(one["unscored_tail_windows"], baseline["unscored_tail_windows"])
            self.assertEqual(one["episode_events"]["policy"], baseline["episode_events"]["policy"])
            self.assertEqual(replay.aggregate([one])["forecast_errors"], replay.aggregate([baseline])["forecast_errors"])

    def test_one_horizon_never_relabels_future_pulses_as_positive(self):
        model = helpers.model()
        series = helpers.series([.2] * 20 + [.9] * 2 + [.2] * 30)
        baseline = replay.replay_series(model, series, v3.POLICY)
        one = sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1)
        moved_truth = sensitivity._risk_policy(model, {**v3.POLICY, "required_consecutive_horizons": 1})
        self.assertTrue(any(_actual_future_outcome(series["values"], r["index"], moved_truth)["positive"]
                            != r["actual_positive"] for r in one["rows"]))
        self.assertEqual([r["actual_positive"] for r in one["rows"]], [r["actual_positive"] for r in baseline["rows"]])
        self.assertEqual([r["actual_horizons"] for r in one["rows"]], [r["actual_horizons"] for r in baseline["rows"]])
        self.assertEqual(sum(one["candidate"]["confusion"].values()), len(baseline["rows"]))
        # The decision/activation matcher, unlike scoring labels, really uses gate 1.
        raw_one = replay.replay_series(model, series, {**v3.POLICY, "required_consecutive_horizons": 1})
        fields = ("index", "decision", "candidate", "active", "activation", "clear_transition")
        self.assertEqual([{k: r[k] for k in fields} for r in one["rows"]],
                         [{k: r[k] for k in fields} for r in raw_one["rows"]])
        self.assertEqual(one["episode_events"], raw_one["episode_events"])

    def test_only_long_horizon_crossing_can_change_gate_without_changing_forecasts(self):
        model = helpers.model()
        series = helpers.series([.2] * 15 + [.2 + .025 * i for i in range(35)] + [.2] * 20)
        baseline = replay.replay_series(model, series, v3.POLICY)
        one = sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1)
        added = [b for a, b in zip(baseline["rows"], one["rows"]) if not a["candidate"] and b["candidate"]]
        self.assertTrue(added)
        self.assertTrue(any(b["predictions"][1]["predicted_value"] < .8 <= b["predictions"][2]["predicted_value"]
                            for b in added))
        self.assertEqual(one["episode_events"]["policy"]["max_warning_horizon_s"], 12)

    def test_future_values_do_not_enter_past_gate_or_persistence(self):
        model = helpers.model()
        series = helpers.series([.5 + .25 * math.sin(i / 4) for i in range(70)])
        altered = copy.deepcopy(series)
        altered["values"][40:] = [1.3] * 30
        fields = ("index", "predictions", "decision", "candidate", "active", "activation", "clear_transition")
        for required in (1, 2):
            blocks = [sensitivity.replay_gate(model, s, replay.replay_series(model, s, v3.POLICY), v3.POLICY, required)
                      for s in (series, altered)]
            self.assertEqual(*[[{k: r[k] for k in fields} for r in b["rows"] if r["index"] < 40] for b in blocks])

    def test_reset_missing_leads_late_events_and_flat_short_horizon_assertion(self):
        model = helpers.model(flat=True)
        series = helpers.series([.6] * 40)
        baseline = replay.replay_series(model, series, v3.POLICY)
        one = sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1)
        self.assertEqual(one, sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1))
        self.assertFalse(one["structural_diagnostics"]["short_horizons_flat_identical"])
        self.assertIsNone(one["episode_events"]["warning_lead_time_s"]["mean"])
        self.assertEqual(one["episode_events"]["total_activations"], 0)
        self.assertEqual(one["watch_only"]["windows"], len(one["rows"]))

    def test_policy_baseline_truth_and_forecast_drift_fail_closed(self):
        model = helpers.model()
        series = helpers.series([.2] * 10 + [1] * 10 + [.2] * 20)
        baseline = replay.replay_series(model, series, v3.POLICY)
        for settings, required in (({**v3.POLICY, "threshold": .7}, 1),
                                   ({**v3.POLICY, "activation_windows": 2}, 1), (v3.POLICY, 3)):
            with self.assertRaises(ValueError):
                sensitivity.replay_gate(model, series, baseline, settings, required)
        mutations = (
            lambda b: b["candidate"]["confusion"].update(FP=999),
            lambda b: b["rows"][0].update(actual_positive=not b["rows"][0]["actual_positive"]),
            lambda b: b["rows"][0]["predictions"][0].update(possible_breach="tampered"),
            lambda b: b["episode_events"]["episodes"][0].update(onset_index=99),
        )
        for mutate in mutations:
            changed = copy.deepcopy(baseline)
            mutate(changed)
            with self.assertRaises(ValueError):
                sensitivity.replay_gate(model, series, changed, v3.POLICY, 2)


class HorizonSensitivityCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProspectiveV3Tests(methodName="test_complete_new_runs_are_paired_but_do_not_force_forecasts_to_match")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.protocol = self.fixture.freeze()
        self.fixture.cases(self.protocol)
        self.path, self.campaign = self.fixture.path, self.fixture.campaign
        self.official = v3.evaluate_campaign(self.path, self.campaign)
        v1.write_new_json(self.campaign / "campaign-summary.json", self.official)
        self.target = self.path.parent / "horizon-sensitivity-v1.json"

    def test_offline_complete_study_preserves_all_sources_and_does_not_select(self):
        before = self.fixture.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("refit")), \
                patch.object(warning, "calibrate_selected", side_effect=AssertionError("recalibration")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = sensitivity.study(self.path, self.campaign)
        self.assertEqual(before, self.fixture.hashes())
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(report["status"], "SENSITIVITY_COMPLETED")
        self.assertEqual(report["official_v3"]["criteria_status"], self.official["criteria_status"])
        for flag in ("official_v3_unchanged", "baseline_exact", "point_forecasts_identical", "intervals_identical",
                     "scoring_scope_identical", "observed_future_labels_identical", "observed_episode_ground_truth_identical"):
            self.assertTrue(report[flag])
        for flag in ("promotion_eligible", "deployment_eligible", "independent_test", "refit", "recalibration",
                     "new_traffic", "llm_consulted", "statistical_superiority_assessed"):
            self.assertFalse(report[flag])
        self.assertEqual(report["selected_variant"], "NONE")
        self.assertEqual(report["identity_scope"], "within_each_frozen_model_between_gates; not_between_models")
        for name, m in report["models"].items():
            self.assertEqual(m["variants"]["consecutive2"]["summary"], self.official["models"][name])
            self.assertEqual(set(m["variants"]), {"consecutive1", "consecutive2"})
            self.assertTrue(m["paired_changes"]["ground_truth_matches"])
            for item in m["paired_changes"]["paired_episodes"]:
                self.assertNotIn("trained_anticipated", item)
                self.assertIn("one_horizon_anticipated", item)
            summaries = [v["summary"] for v in m["variants"].values()]
            self.assertEqual(summaries[0]["forecast_errors"], summaries[1]["forecast_errors"])
            self.assertEqual(summaries[0]["eligible_episodes"], summaries[1]["eligible_episodes"])
            self.assertEqual(len(summaries[1]["per_run"]), 12)
        output = io.StringIO()
        with patch("sys.stdout", output):
            sensitivity.print_summary(report)
        self.assertEqual(len(output.getvalue().splitlines()), 8)

    def test_cli_new_only_compact_and_official_not_passed_is_not_overwritten(self):
        official_bytes = (self.campaign / "campaign-summary.json").read_bytes()
        self.assertEqual(self.official["criteria_status"], "NOT_PASSED")
        args = ["--protocol", str(self.path), "--campaign-root", str(self.campaign), "--output", str(self.target)]
        with patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(sensitivity.main(args), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 8)
        self.assertEqual((self.campaign / "campaign-summary.json").read_bytes(), official_bytes)
        contents = self.target.read_bytes()
        with patch.object(sensitivity, "study", side_effect=AssertionError("must reject before replay")), \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(sensitivity.main(args), 2)
        self.assertEqual(self.target.read_bytes(), contents)

    def test_resealed_summary_missing_case_or_changed_csv_rejected_without_output(self):
        summary = self.campaign / "campaign-summary.json"
        contents = summary.read_bytes()
        altered = copy.deepcopy(self.official)
        altered["models"][v3.PRIMARY]["watch_windows"] += 1
        summary.write_text(json.dumps(v1.seal(altered, "report_sha256")))
        args = ["--protocol", str(self.path), "--campaign-root", str(self.campaign), "--output", str(self.target)]
        with patch("sys.stderr", io.StringIO()):
            self.assertEqual(sensitivity.main(args), 2)
        self.assertFalse(self.target.exists())
        summary.write_bytes(contents)
        case = self.campaign / self.protocol["cases"][0]["case_id"] / "run.json"
        contents = case.read_bytes()
        case.unlink()
        with self.assertRaisesRegex((ValueError, OSError), "incompleto|No such file"):
            sensitivity.study(self.path, self.campaign)
        case.write_bytes(contents)
        csv = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        csv.write_bytes(csv.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "incompleto|divergente"):
            sensitivity.study(self.path, self.campaign)

    def test_existing_source_model_campaign_and_symlink_targets_rejected_before_replay(self):
        link = self.path.parent / "horizon-sensitivity-link.json"
        link.symlink_to(self.path)
        for target in (self.path, self.campaign / "horizon-sensitivity.json",
                       self.path.parent / "models/horizon-sensitivity.json",
                       self.fixture.v2_path.parent / "horizon-sensitivity.json", link,
                       self.path.parent / "campaign-review.json"):
            args = ["--protocol", str(self.path), "--campaign-root", str(self.campaign), "--output", str(target)]
            with self.subTest(target=target), patch.object(sensitivity, "study", side_effect=AssertionError("replay")), \
                    patch("sys.stderr", io.StringIO()):
                self.assertEqual(sensitivity.main(args), 2)

    def test_source_or_code_change_during_replay_cannot_publish_success(self):
        real = sensitivity.replay_gate
        touched = False
        summary = self.campaign / "campaign-summary.json"
        contents = summary.read_bytes()

        def mutate(*args, **kwargs):
            nonlocal touched
            block = real(*args, **kwargs)
            if not touched:
                summary.write_bytes(contents + b" ")
                touched = True
            return block

        with patch.object(sensitivity, "replay_gate", side_effect=mutate), \
                self.assertRaisesRegex(ValueError, "mudaram durante"):
            sensitivity.study(self.path, self.campaign)
        summary.write_bytes(contents)
        original = sensitivity.code_snapshot()
        with patch.object(sensitivity, "code_snapshot", side_effect=[original, {}]), \
                self.assertRaisesRegex(ValueError, "mudaram durante"):
            sensitivity.study(self.path, self.campaign)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
