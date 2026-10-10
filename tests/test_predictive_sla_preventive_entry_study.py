import copy
import io
import json
import math
import unittest
from unittest.mock import patch

import predictive_sla_preventive_entry_study as entry
import predictive_sla_horizon_sensitivity as sensitivity
import predictive_sla_damped_replay as replay
import predictive_sla_validation as v1
import predictive_sla_validation_v3 as v3
import qos_warning_selection as warning
import test_predictive_sla_validation_v3 as fixtures
import test_predictive_sla_damped_replay as helpers
from qos_damped_holt import DampedHorizonModel, QosDampedHoltModel


def selected_model(alpha=.35, beta=.2, phi=.95):
    return QosDampedHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=.9,
                             priming_samples=2, created_at="test", horizons=tuple(
                                 DampedHorizonModel(h, alpha, beta, .3, 20, phi=phi) for h in (2, 4, 6)))


def one_horizon(model, series):
    baseline = replay.replay_series(model, series, v3.POLICY)
    return sensitivity.replay_gate(model, series, baseline, v3.POLICY, 1)


class PreventiveEntryCoreTests(unittest.TestCase):
    def test_isolated_pulse_entry_is_inhibited_but_observation_and_forecast_are_retained(self):
        model = selected_model()
        series = helpers.series([.2] * 20 + [1.1] + [.2] * 25)
        raw = one_horizon(model, series)
        before = copy.deepcopy((series, raw))
        self.assertTrue(raw["rows"][19]["activation"])
        gated = entry.replay_entry(series, raw, v3.POLICY)
        self.assertEqual((series, raw), before)
        self.assertEqual(gated["episode_events"]["total_activations"], 0)
        channel = gated["entry_diagnostic"]["observed_channel"]
        self.assertEqual(channel["threshold_crossing_samples"], 1)
        self.assertEqual(channel["sustained_confirmations"], 0)
        pulse = next(r for r in gated["rows"] if r["index"] == 20)
        self.assertTrue(pulse["candidate"])
        self.assertTrue(pulse["entry_inhibited"])
        self.assertFalse(pulse["activation"])
        self.assertEqual(pulse["observed_state"]["observed_value"], 1.1)
        self.assertEqual([r["predictions"] for r in raw["rows"]], [r["predictions"] for r in gated["rows"]])
        self.assertEqual(raw["candidate"], gated["candidate"])
        classified = gated["entry_diagnostic"]["classified_activations"]
        self.assertEqual(classified[0]["phase"], "AT_OR_ABOVE_THRESHOLD")
        self.assertEqual(classified[0]["kind"], "raw_forecast_activation")

    def test_blocked_alarm_can_activate_later_below_threshold_not_just_be_deleted(self):
        series = helpers.series([.2] * 20 + [3] + [.2] * 25)
        raw = one_horizon(selected_model(), series)
        gated = entry.replay_entry(series, raw, v3.POLICY)
        at_pulse, after = (next(r for r in gated["rows"] if r["index"] == i) for i in (20, 21))
        self.assertTrue(at_pulse["raw_activation"])
        self.assertTrue(at_pulse["entry_inhibited"])
        self.assertTrue(after["activation"])
        self.assertFalse(after["raw_activation"])
        self.assertFalse(after["observed_state"]["threshold_breach"])
        self.assertEqual(gated["episode_events"]["unmatched_activations"], 1)
        for b in (raw, gated):
            b.update(case_id="r01-short-pulses", profile="short-pulses")
        pair = entry._pair([raw], [gated])
        self.assertEqual([(e["change"], e["index"]) for e in pair["activation_changes"]], [("REMOVED", 20), ("ADDED", 21)])

    def test_existing_active_ramp_alert_survives_current_breach_and_clears_by_raw_rule(self):
        series = helpers.series([.2] * 15 + [.2 + .025 * i for i in range(35)] + [.2] * 25)
        raw = one_horizon(selected_model(), series)
        gated = entry.replay_entry(series, raw, v3.POLICY)
        self.assertEqual(raw["episode_events"], gated["episode_events"])
        crossing = [r for r in gated["rows"] if r["observed_state"]["threshold_breach"] and r["active"]]
        self.assertTrue(crossing)
        self.assertTrue(all(not r["entry_inhibited"] for r in crossing))
        self.assertEqual([r["clear_transition"] for r in raw["rows"]], [r["clear_transition"] for r in gated["rows"]])
        self.assertEqual(gated, entry.replay_entry(series, raw, v3.POLICY))  # Per-series reset.

    def test_threshold_equality_sustained_and_priming_tail_crossings_are_not_hidden(self):
        model = selected_model(alpha=1, beta=0, phi=1)
        series = helpers.series([.8, .8] + [.2] * 10 + [.8] * 3 + [.2] * 10 + [.8] * 2)
        raw = one_horizon(model, series)
        gated = entry.replay_entry(series, raw, v3.POLICY)
        observed = gated["entry_diagnostic"]["observed_channel"]
        self.assertEqual(observed["threshold_crossing_samples"], 7)
        self.assertEqual(observed["sustained_confirmations"], 3)
        self.assertEqual(len(observed["rows"]), len(series["values"]))
        self.assertTrue(observed["rows"][0]["threshold_breach"])
        self.assertFalse(observed["rows"][0]["sustained_episode_active"])
        self.assertTrue(observed["rows"][1]["confirmation_transition"])
        self.assertTrue(observed["rows"][-1]["confirmation_transition"])
        self.assertFalse(any(r["activation"] for r in gated["rows"]))
        self.assertEqual(raw["candidate"], gated["candidate"])
        self.assertTrue(replay.paired_changes([raw], [gated])["ground_truth_matches"])

    def test_future_observations_cannot_change_past_observed_channel_or_entry_state(self):
        series = helpers.series([.5 + .25 * math.sin(i / 4) for i in range(70)])
        altered = copy.deepcopy(series)
        altered["values"][40:] = [1.3] * 30
        blocks = [entry.replay_entry(s, one_horizon(selected_model(), s), v3.POLICY) for s in (series, altered)]
        fields = ("index", "decision", "predictions", "active", "activation", "clear_transition",
                  "entry_inhibited", "entry_eligible", "persistence_input_decision", "observed_state")
        self.assertEqual(*[[{k: r[k] for k in fields} for r in b["rows"] if r["index"] < 40] for b in blocks])
        self.assertEqual(blocks[0]["entry_diagnostic"]["observed_channel"]["rows"][:40],
                         blocks[1]["entry_diagnostic"]["observed_channel"]["rows"][:40])

    def test_missing_leads_watch_and_changed_observed_contract_are_visible(self):
        series = helpers.series([.6] * 40)
        raw = one_horizon(helpers.model(flat=True), series)
        gated = entry.replay_entry(series, raw, v3.POLICY)
        self.assertEqual(gated["watch_only"], raw["watch_only"])
        self.assertIsNone(gated["episode_events"]["warning_lead_time_s"]["mean"])
        self.assertEqual(gated["entry_diagnostic"]["observed_channel"]["threshold_crossing_samples"], 0)
        with self.assertRaises(ValueError):
            entry.replay_entry(series, raw, {**v3.POLICY, "threshold": .9})
        changed = copy.deepcopy(raw)
        changed["rows"][0]["observed_value"] = .7
        with self.assertRaisesRegex(ValueError, "observação"):
            entry.replay_entry(series, changed, v3.POLICY)
        series = helpers.series([.2] * 10 + [.9] * 10 + [.2] * 20)
        changed = one_horizon(selected_model(), series)
        changed["episode_events"]["episodes"][0]["confirmation_index"] += 1
        with self.assertRaisesRegex(ValueError, "confirmações"):
            entry.replay_entry(series, changed, v3.POLICY)


class PreventiveEntryCampaignTests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.ProspectiveV3Tests(methodName="test_complete_new_runs_are_paired_but_do_not_force_forecasts_to_match")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.protocol = self.fixture.freeze()
        self.fixture.cases(self.protocol)
        self.path, self.campaign = self.fixture.path, self.fixture.campaign
        self.official = v3.evaluate_campaign(self.path, self.campaign)
        v1.write_new_json(self.campaign / "campaign-summary.json", self.official)
        self.source = self.path.parent / "horizon-sensitivity-v1.json"
        self.previous = sensitivity.study(self.path, self.campaign)
        v1.write_new_json(self.source, self.previous)
        self.target = self.path.parent / "preventive-entry-v1.json"

    def args(self, target=None):
        return ["--protocol", str(self.path), "--campaign-root", str(self.campaign),
                "--source-study", str(self.source), "--output", str(target or self.target)]

    def test_complete_offline_study_preserves_sources_and_exact_raw_baseline(self):
        before = self.fixture.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("fit")), \
                patch.object(warning, "calibrate_selected", side_effect=AssertionError("calibration")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = entry.study(self.path, self.campaign, self.source)
        self.assertEqual(before, self.fixture.hashes())
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(report["entry_rule"], entry.ENTRY_RULE)
        self.assertEqual(report["selected_variant"], "NONE")
        self.assertEqual(report["official_v3"]["criteria_status"], self.official["criteria_status"])
        for key in ("independent_test", "promotion_eligible", "deployment_eligible", "runtime_changed", "refit",
                    "recalibration", "new_traffic", "llm_consulted", "statistical_superiority_assessed"):
            self.assertFalse(report[key])
        for key in ("official_v3_unchanged", "source_study_unchanged", "baseline_exact", "observed_crossings_retained",
                    "existing_alert_renewal_retained", "observed_episode_ground_truth_identical",
                    "forecasts_intervals_raw_candidates_and_window_labels_identical"):
            self.assertTrue(report[key])
        for name, model in report["models"].items():
            baseline = model["variants"]["ungated_one_horizon"]
            after = model["variants"]["preventive_entry_one_horizon"]
            previous = self.previous["models"][name]["variants"]["consecutive1"]
            self.assertEqual(baseline["series"], previous["series"])
            self.assertEqual(baseline["summary"], previous["summary"])
            self.assertEqual(baseline["summary"]["candidate"], after["summary"]["candidate"])
            self.assertEqual(baseline["summary"]["forecast_errors"], after["summary"]["forecast_errors"])
            self.assertTrue(model["paired_changes"]["ground_truth_matches"])
            for b in after["series"]:
                self.assertEqual(len(b["entry_diagnostic"]["observed_channel"]["rows"]), b["samples"])
                self.assertTrue(all(r["entry_eligible"] for r in b["rows"] if r["activation"]))
        with patch("sys.stdout", io.StringIO()) as output:
            entry.print_summary(report)
        self.assertEqual(len(output.getvalue().splitlines()), 8)

    def test_new_commit_is_allowed_but_resealed_results_or_configuration_are_not(self):
        original = self.source.read_bytes()
        changed = copy.deepcopy(self.previous)
        changed["git_commit"] = "historical-implementation-commit"
        self.source.write_text(json.dumps(v1.seal(changed, "report_sha256")))
        report = entry.study(self.path, self.campaign, self.source)
        self.assertEqual(report["source_study"]["git_commit"], "historical-implementation-commit")
        mutations = (
            lambda p: p["models"][v3.PRIMARY]["variants"]["consecutive1"]["summary"].update(anticipated=999),
            lambda p: p["models"][v3.PRIMARY]["variants"]["consecutive1"]["policy"].update(threshold=.7),
            lambda p: p.update(promotion_eligible=True),
        )
        for mutate in mutations:
            changed = copy.deepcopy(self.previous)
            mutate(changed)
            self.source.write_text(json.dumps(v1.seal(changed, "report_sha256")))
            with self.assertRaisesRegex(ValueError, "não reproduz"):
                entry.study(self.path, self.campaign, self.source)
        self.source.write_bytes(original)

    def test_cli_new_only_and_official_failure_is_not_changed(self):
        self.assertEqual(self.official["criteria_status"], "NOT_PASSED")
        official_bytes, source_bytes = (self.campaign / "campaign-summary.json").read_bytes(), self.source.read_bytes()
        with patch("sys.stdout", io.StringIO()) as output:
            self.assertEqual(entry.main(self.args()), 0)
        self.assertEqual(len(output.getvalue().splitlines()), 8)
        self.assertEqual((self.campaign / "campaign-summary.json").read_bytes(), official_bytes)
        self.assertEqual(self.source.read_bytes(), source_bytes)
        new_bytes = self.target.read_bytes()
        with patch.object(entry, "study", side_effect=AssertionError("must reject before replay")), \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(entry.main(self.args()), 2)
        self.assertEqual(self.target.read_bytes(), new_bytes)

    def test_existing_source_campaign_old_protocol_and_symlink_targets_are_refused(self):
        link = self.path.parent / "preventive-entry-link.json"
        link.symlink_to(self.source)
        for target in (self.path, self.source, self.campaign / "preventive-entry.json",
                       self.path.parent / "models/preventive-entry.json",
                       self.fixture.v2_path.parent / "preventive-entry.json", link):
            with self.subTest(target=target), patch.object(entry, "study", side_effect=AssertionError("replay")), \
                    patch("sys.stderr", io.StringIO()):
                self.assertEqual(entry.main(self.args(target)), 2)

    def test_modified_source_code_or_data_during_replay_prevents_publication(self):
        real = entry.replay_entry
        touched = False
        contents = self.source.read_bytes()

        def mutate(*args, **kwargs):
            nonlocal touched
            result = real(*args, **kwargs)
            if not touched:
                self.source.write_bytes(contents + b" ")
                touched = True
            return result

        with patch.object(entry, "replay_entry", side_effect=mutate), \
                self.assertRaisesRegex(ValueError, "mudaram durante"):
            entry.study(self.path, self.campaign, self.source)
        self.source.write_bytes(contents)
        snapshot = entry.code_snapshot()
        with patch.object(entry, "code_snapshot", side_effect=[snapshot, {}]), \
                self.assertRaisesRegex(ValueError, "mudaram durante"):
            entry.study(self.path, self.campaign, self.source)
        csv = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        csv.write_bytes(csv.read_bytes() + b"changed")
        with patch("sys.stderr", io.StringIO()):
            self.assertEqual(entry.main(self.args()), 2)
        self.assertFalse(self.target.exists())


if __name__ == "__main__":
    unittest.main()
