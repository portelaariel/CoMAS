import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_diagnostics as diagnostics
import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
from qos_holt import MultiHorizonHoltForecaster, QosHoltModel
from sla_episode_evaluation import evaluate_episodes
from test_predictive_sla_validation import create_case, create_pilot


def episode_fixture():
    values = [0.5] * 65
    values[44:52] = [0.7008, 0.7076, 0.8, 0.9619, 0.7609, 0.6776, 0.8063, 0.9]
    timestamps = [1_000_000_000 + i * 2_000_000_000 for i in range(len(values))]
    rows = [dict(index=i, ts_ns=timestamps[i], candidate=44 <= i <= 51,
                 active=44 <= i <= 52, activation=i == 44,
                 persistent_activation=i == 44, risk_started_index=44 if 44 <= i <= 52 else None)
            for i in range(2, 59)]
    frozen = evaluate_episodes(values=values, observations=rows, timestamps_ns=timestamps,
                               series_id="ramp/d0/2:4", cid="d0", port_id="2:4", comparator="MAX",
                               threshold=0.8, sample_interval_s=2, max_horizon_steps=6)
    return values, timestamps, rows, frozen


class FreshCoverageTests(unittest.TestCase):
    def coverage(self, rows, timestamps, frozen):
        return diagnostics.evaluate_fresh_coverage(rows=rows, episodes=frozen["episodes"],
                                                   timestamps_ns=timestamps, maximum_age_s=5,
                                                   maximum_horizon_s=12)

    def test_existing_alert_can_cover_second_episode_without_changing_one_to_one_matching(self):
        _, timestamps, rows, frozen = episode_fixture()
        before = copy.deepcopy(frozen)
        result = self.coverage(rows, timestamps, frozen)
        self.assertEqual([e["onset_index"] for e in result], [46, 50])
        self.assertEqual([e["strict_anticipated"] for e in result], [True, False])
        self.assertEqual([e["fresh_active_coverage"] for e in result], [True, True])
        self.assertEqual([e["covered_without_new_activation"] for e in result], [False, True])
        self.assertEqual(result[1]["latest_pre_onset_evaluation"]["risk_started_index"], 44)
        self.assertEqual(result[1]["latest_renewal_age_s"], 2)
        self.assertIsNone(result[1]["matched_activation_lead_time_s"])
        self.assertEqual(frozen, before)
        self.assertEqual(frozen["detected"], 1)

    def test_retained_active_state_without_renewed_candidate_is_not_fresh_coverage(self):
        _, timestamps, rows, frozen = episode_fixture()
        next(row for row in rows if row["index"] == 49)["candidate"] = False
        result = self.coverage(rows, timestamps, frozen)
        self.assertFalse(result[1]["fresh_active_coverage"])
        self.assertEqual(result[1]["coverage_reason"], "active_without_renewed_candidate")

    def test_pending_candidate_is_not_coverage_until_alert_is_active(self):
        _, timestamps, rows, frozen = episode_fixture()
        next(row for row in rows if row["index"] == 49)["active"] = False
        result = self.coverage(rows, timestamps, frozen)
        self.assertFalse(result[1]["fresh_active_coverage"])
        self.assertEqual(result[1]["coverage_reason"], "candidate_not_yet_active")

    def test_earlier_matched_activation_is_preserved_when_latest_forecast_has_cleared(self):
        _, timestamps, rows, frozen = episode_fixture()
        next(row for row in rows if row["index"] == 45).update(candidate=False, active=False)
        result = self.coverage(rows, timestamps, frozen)
        self.assertTrue(result[0]["strict_anticipated"])
        self.assertEqual(result[0]["matched_activation_index"], 44)
        self.assertFalse(result[0]["fresh_active_coverage"])
        summary = diagnostics._summarize([dict(episodes=result, control_activation_diagnostics=[])])
        self.assertEqual(summary["anticipated_without_latest_renewal"], 1)
        self.assertEqual(summary["strict_anticipated"], frozen["detected"])

    def test_missing_latest_scored_window_is_unassessable_not_false_or_old_alert_coverage(self):
        _, timestamps, rows, frozen = episode_fixture()
        result = self.coverage([row for row in rows if row["index"] != 49], timestamps, frozen)
        self.assertIsNone(result[1]["fresh_active_coverage"])
        self.assertFalse(result[1]["coverage_assessable"])
        self.assertEqual(result[1]["coverage_reason"], "latest_pre_onset_evaluation_unavailable")
        summary = diagnostics._summarize([dict(episodes=result, control_activation_diagnostics=[])])
        self.assertEqual(summary["eligible_not_assessable"], 1)
        self.assertEqual(summary["coverage_rate_over_all_eligible"], 0.5)

    def test_freshness_boundary_uses_real_timestamps_and_rejects_one_ns_over_limit(self):
        for extra, covered in ((3_000_000_000, True), (3_000_000_001, None)):
            _, timestamps, rows, frozen = episode_fixture()
            for i in range(50, len(timestamps)):
                timestamps[i] += extra
            for row in rows:
                row["ts_ns"] = timestamps[row["index"]]
            for episode in frozen["episodes"]:
                episode["onset_ts_ns"] = timestamps[episode["onset_index"]]
            result = self.coverage(rows, timestamps, frozen)
            with self.subTest(extra=extra):
                self.assertIs(result[1]["fresh_active_coverage"], covered)
                self.assertEqual(result[1]["coverage_assessable"], covered is True)

    def test_at_onset_activation_and_future_candidate_cannot_anticipate_episode(self):
        _, timestamps, rows, frozen = episode_fixture()
        previous = next(row for row in rows if row["index"] == 49)
        previous.update(candidate=False, active=False)
        result = self.coverage(rows, timestamps, frozen)
        self.assertFalse(result[1]["fresh_active_coverage"])
        self.assertEqual(result[1]["latest_pre_onset_evaluation"]["index"], 49)

    def test_invalid_or_duplicate_rows_timestamps_onsets_and_age_limits_are_rejected(self):
        _, timestamps, rows, frozen = episode_fixture()
        for bad_rows in ([*rows, rows[-1]], [{**rows[0], "ts_ns": 1}, *rows[1:]],
                         [{**rows[0], "candidate": "true"}, *rows[1:]]):
            with self.assertRaises(ValueError):
                self.coverage(bad_rows, timestamps, frozen)
        for age in (0, -1, float("nan"), float("inf"), 13):
            with self.assertRaises(ValueError):
                diagnostics.evaluate_fresh_coverage(rows=rows, episodes=frozen["episodes"],
                                                    timestamps_ns=timestamps, maximum_age_s=age,
                                                    maximum_horizon_s=12)
        bad = copy.deepcopy(frozen)
        bad["episodes"][0]["onset_index"] = True
        with self.assertRaises(ValueError):
            self.coverage(rows, timestamps, bad)


class DiagnosticsCampaignTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pilot = self.root / "pilot"
        create_pilot(self.pilot)
        self.v1_path = self.root / "v1/protocol.json"
        parent = v1.freeze_protocol(self.pilot, self.v1_path.parent)
        old_campaign = self.v1_path.parent / "campaign"
        for ordinal, case in enumerate(parent["cases"]):
            create_case(parent, case, old_campaign, ordinal)
        v1.write_new_json(old_campaign / "campaign-summary.json", v1.evaluate_campaign(self.v1_path, old_campaign))
        self.protocol_path = self.root / "v2/protocol.json"
        with patch.object(v2.time, "time_ns", return_value=parent["created_ns"] + 10_000_000_000_000):
            self.protocol = v2.freeze_protocol(self.v1_path, old_campaign, self.protocol_path.parent)
        self.campaign = self.protocol_path.parent / "campaign"
        for ordinal, case in enumerate(self.protocol["cases"]):
            create_case(self.protocol, case, self.campaign, ordinal)
        self.baseline = v2.evaluate_campaign(self.protocol_path, self.campaign)
        v1.write_new_json(self.campaign / "campaign-summary.json", self.baseline)

    def hashes(self):
        return {str(p.relative_to(self.root)): v1.digest_file(p) for p in self.root.rglob("*") if p.is_file()}

    def sample(self):
        case = self.protocol["cases"][1]
        series, _, _ = v1._read_case(self.protocol, case, self.campaign / case["case_id"])
        model = QosHoltModel.load(self.protocol_path.parent / self.protocol["models"]["coverage90"]["path"])
        return model, series[0]

    def test_complete_diagnostic_preserves_all_sources_and_frozen_results_without_network_or_refit(self):
        before = self.hashes()
        code = {name: v1.digest_file(v1.ROOT / name) for name in v2.CODE_FILES}
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = diagnostics.build_report(self.protocol_path, self.campaign)
        self.assertEqual(self.hashes(), before)
        self.assertEqual(code, {name: v1.digest_file(v1.ROOT / name) for name in v2.CODE_FILES})
        self.assertEqual(v2.load_protocol(self.protocol_path), self.protocol)
        self.assertEqual(report["baseline"]["checks"], self.baseline["checks"])
        self.assertEqual(report["baseline"]["criteria_status"], self.baseline["criteria_status"])
        self.assertEqual(report["baseline"]["models"], self.baseline["models"])
        self.assertFalse(report["promotion_eligible"])
        self.assertIn("posthoc", report["scope"])
        self.assertEqual(report["coverage_policy"]["maximum_age_s"], 5)
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        for name, block in report["models"].items():
            self.assertEqual(len(block["series"]), 24)
            self.assertTrue(block["summary"]["frozen_signal_crosscheck"])
            self.assertEqual(block["summary"]["strict_anticipated"],
                             self.baseline["models"][name]["episode_events"]["detected"])

    def test_native_replay_keeps_forecasts_activation_indices_and_priming_tail_scope(self):
        model, series = self.sample()
        rows = diagnostics.replay_series(model, series, self.protocol["policy"])
        self.assertEqual(rows[0]["index"], model.priming_samples - 1)
        self.assertEqual(rows[-1]["index"], len(series["values"]) - 7)
        self.assertTrue(all(row["future_observations"] for row in rows))
        for row in rows:
            for forecast, actual in zip(row["forecast_horizons"], row["future_observations"]):
                self.assertEqual(forecast["predicted_value"], actual["predicted_value"])
                self.assertEqual(actual["actual_value"], series["values"][row["index"] + actual["horizon_steps"]])

    def test_future_changes_do_not_change_past_predictions_or_alert_state(self):
        model, series = self.sample()
        modified = copy.deepcopy(series)
        cutoff = 30
        modified["values"][cutoff:] = [0.01] * (len(series["values"]) - cutoff)
        before = diagnostics.replay_series(model, series, self.protocol["policy"])
        after = diagnostics.replay_series(model, modified, self.protocol["policy"])
        keys = ("index", "ts_ns", "candidate", "active", "activation", "risk_started_index", "forecast_horizons", "holt_states")
        self.assertEqual([{k: r[k] for k in keys} for r in before if r["index"] < cutoff],
                         [{k: r[k] for k in keys} for r in after if r["index"] < cutoff])

    def test_holt_level_trend_and_control_predictions_are_evidence_not_new_model_settings(self):
        report = diagnostics.build_report(self.protocol_path, self.campaign)
        controls = [d for s in report["models"]["coverage90"]["series"]
                    for d in s["control_activation_diagnostics"]]
        self.assertTrue(controls)
        for diagnostic in controls:
            row = diagnostic["evaluation"]
            self.assertTrue(row["candidate"])
            for state, forecast in zip(row["holt_states"], row["forecast_horizons"]):
                self.assertAlmostEqual(max(0, state["level"] + state["horizon_steps"] * state["trend"]),
                                       forecast["predicted_value"], places=11)
        self.assertEqual(v2.load_protocol(self.protocol_path)["models"], self.protocol["models"])

    def test_replay_drift_is_rejected_instead_of_silently_changing_signals(self):
        model, series = self.sample()

        class ChangedForecaster(MultiHorizonHoltForecaster):
            def update(self, observed):
                rows = super().update(observed)
                for row in rows:
                    for key in ("predicted_value", "lower_bound", "upper_bound"):
                        row[key] += 0.01
                return rows

        with patch.object(diagnostics, "MultiHorizonHoltForecaster", ChangedForecaster):
            with self.assertRaisesRegex(ValueError, "diverge"):
                diagnostics.replay_series(model, series, self.protocol["policy"])

    def test_tampered_summary_or_csv_is_rejected_and_no_source_is_repaired(self):
        path = self.campaign / "campaign-summary.json"
        original = path.read_bytes()
        changed = json.loads(original)
        changed["criteria_status"] = "PASSED" if changed["criteria_status"] != "PASSED" else "NOT_PASSED"
        path.write_text(json.dumps(changed))
        with self.assertRaisesRegex(ValueError, "relatório v2"):
            diagnostics.build_report(self.protocol_path, self.campaign)
        self.assertEqual(json.loads(path.read_text()), changed)
        path.write_bytes(original)
        csv = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        csv.write_bytes(csv.read_bytes() + b"changed")
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            diagnostics.build_report(self.protocol_path, self.campaign)

    def test_incomplete_campaign_does_not_receive_a_success_diagnostic(self):
        path = self.campaign / self.protocol["cases"][0]["case_id"] / "run.json"
        record = json.loads(path.read_text())
        record["status"] = "FAILED"
        path.write_text(json.dumps(v1.seal(record, "run_sha256")))
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            diagnostics.build_report(self.protocol_path, self.campaign)

    def test_output_targets_preserve_protocol_models_campaign_and_existing_report(self):
        for path in (self.protocol_path, self.protocol_path.parent / "models/supplementary-diagnostics.json",
                     self.campaign / "supplementary-diagnostics.json", self.root / "supplementary-diagnostics.json"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                diagnostics.output_path(self.protocol_path, path)
        output = self.protocol_path.parent / "supplementary-diagnostics-v1.json"
        output.write_text("preserve me")
        with patch.object(diagnostics, "build_report") as build, patch("sys.stderr", new=io.StringIO()):
            status = diagnostics.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                       "--output", str(output)])
        self.assertEqual(status, 2)
        build.assert_not_called()
        self.assertEqual(output.read_text(), "preserve me")

    def test_source_change_during_replay_stops_before_writing_output(self):
        output = self.protocol_path.parent / "supplementary-diagnostics-v1.json"
        source = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        original_replay = diagnostics.replay_series
        changed = False

        def replay(model, series, policy):
            nonlocal changed
            if not changed:
                source.write_bytes(source.read_bytes() + b"changed-during-analysis")
                changed = True
            return original_replay(model, series, policy)

        with patch.object(diagnostics, "replay_series", side_effect=replay), patch("sys.stderr", new=io.StringIO()):
            status = diagnostics.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                       "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertFalse(output.exists())
        self.assertTrue(source.read_bytes().endswith(b"changed-during-analysis"))

    def test_cli_creates_only_new_supplement_and_does_not_treat_policy_failure_as_diagnostic_failure(self):
        before = self.hashes()
        self.assertEqual(self.baseline["criteria_status"], "NOT_PASSED")
        output = self.protocol_path.parent / "supplementary-diagnostics-v1.json"
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            status = diagnostics.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                       "--output", str(output)])
        self.assertEqual(status, 0)
        after = self.hashes()
        self.assertEqual({name: sha for name, sha in after.items() if name != "v2/supplementary-diagnostics-v1.json"}, before)
        self.assertIn("promotion_eligible=false", stdout.getvalue())
        self.assertIn(f"criteria={self.baseline['criteria_status']}", stdout.getvalue())

    def test_console_is_bounded_and_all_control_details_remain_in_json(self):
        report = diagnostics.build_report(self.protocol_path, self.campaign)
        item = next(i for i in report["models"]["coverage90"]["series"] if i["control_activation_diagnostics"])
        example = copy.deepcopy(item["control_activation_diagnostics"][0])
        item["control_activation_diagnostics"] = [example] * 20
        lines = diagnostics.console_lines(report)
        self.assertLessEqual(len(lines), 9)
        self.assertTrue(any("additional_control_diagnostics_in_json=" in line for line in lines))
        self.assertEqual(len(item["control_activation_diagnostics"]), 20)


if __name__ == "__main__":
    unittest.main()
