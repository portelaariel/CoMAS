import copy
import unittest

import predictive_sla_shadow_control_analysis as analysis
import test_predictive_sla_shadow_ramp as fixtures


class ControlObservationTests(unittest.TestCase):
    def fixture(self, values, **kwargs):
        config, series, journals = fixtures.traces(values, **kwargs)
        # Readiness/warmup precedes the native reference window in the pilot.
        for block in series:
            block["values"] = block["values"][2:]
            block["timestamps_ns"] = block["timestamps_ns"][2:]
        return config, series, journals

    def evaluate(self, values, **kwargs):
        config, series, journals = self.fixture(values, **kwargs)
        return analysis.analyze(config, fixtures.RUN_ID, series, journals)

    def test_complete_quiet_control_is_characterized_not_promoted_or_deadline_passed(self):
        report = self.evaluate([.2] * 35)
        self.assertEqual(report["measurement_status"], "CONTROL_OBSERVED")
        self.assertEqual(report["control_observation"], "NO_PREVENTIVE_SIGNALS_OBSERVED")
        self.assertEqual(report["independent_runs"], 1)
        self.assertEqual(report["correlated_ports"], 2)
        self.assertEqual(report["distinct_joint_agreement_witnesses"], 0)
        self.assertIsNone(report["specificity"])
        self.assertIsNone(report["false_alarm_rate"])
        self.assertIsNone(report["actuation_latency_ms"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["sla_protection_established"])
        self.assertEqual(report["deadline_feasibility"], "UNKNOWN")

    def test_preventive_signals_without_sustained_episode_are_not_hidden(self):
        report = self.evaluate(fixtures.old.WARNING_VALUES + [.2] * 20)
        self.assertEqual(report["measurement_status"], "CONTROL_OBSERVED")
        self.assertEqual(report["control_observation"], "PREVENTIVE_SIGNALS_WITHOUT_SUSTAINED_EPISODE")
        for domain in report["domains"]:
            self.assertEqual(domain["strict_activation_episodes"]["actual_episodes"], 0)
            self.assertGreater(domain["strict_activation_episodes"]["unmatched_activations"], 0)
            self.assertGreater(domain["unsupported_joint_pair_witnesses"], 0)

    def test_one_sample_spike_is_retained_without_inventing_sustained_episode(self):
        report = self.evaluate([.2] * 15 + [1.1] + [.2] * 20)
        for domain in report["domains"]:
            strict = domain["strict_activation_episodes"]
            self.assertEqual(strict["unconfirmed_breach_samples"], 1)
            self.assertEqual(strict["actual_episodes"], 0)

    def test_short_followup_is_censored_not_a_successful_negative(self):
        report = self.evaluate(fixtures.old.WARNING_VALUES)
        self.assertEqual(report["control_observation"], "INCOMPLETE_WARNING_FOLLOWUP")
        for domain in report["domains"]:
            self.assertGreater(domain["strict_activation_episodes"]["censored_activations"], 0)
            self.assertGreater(domain["censored_joint_pair_witnesses"], 0)
            self.assertEqual(domain["unsupported_joint_pair_witnesses"], 0)

    def test_control_label_does_not_override_real_observed_episodes(self):
        report = self.evaluate(fixtures.VALUES)
        self.assertEqual(report["control_observation"], "OBSERVED_SUSTAINED_CROSSING")
        self.assertTrue(all(d["strict_activation_episodes"]["actual_episodes"] == 1 for d in report["domains"]))

    def test_missing_quiet_sample_does_not_become_zero_alarms_with_full_coverage(self):
        config, series, journals = self.fixture([.2] * 35)
        cid = config["subjects"][0]["cid"]
        ts = series[0]["timestamps_ns"][5]
        journals[cid] = [row for row in journals[cid]
            if not (row["kind"] == "LOCAL_EVALUATION" and row["record"]["sample"]["ts_ns"] == ts)]
        report = analysis.analyze(config, fixtures.RUN_ID, series, journals)
        self.assertEqual(report["measurement_status"], "INSUFFICIENT_EVIDENCE")
        self.assertFalse(report["domains"][0]["full_sidecar_reference_coverage"])
        self.assertEqual(report["domains"][0]["native_samples_not_seen_by_sidecar"], 1)
        self.assertEqual(report["domains"][0]["control_observation"], "INSUFFICIENT_EVIDENCE")

    def test_every_reference_evaluation_needs_exact_confirmed_pair_even_without_activation(self):
        config, series, journals = self.fixture([.2] * 35)
        cid = config["subjects"][0]["cid"]
        ts = series[0]["timestamps_ns"][5]
        journals[cid] = [row for row in journals[cid]
            if not (row["kind"] == "PAIR_PUBLICATION" and row["risk"]["observed_ns"] == ts)]
        with self.assertRaisesRegex(ValueError, "par confirmado"):
            analysis.analyze(config, fixtures.RUN_ID, series, journals)

    def test_local_forecast_timestamp_must_equal_published_pair_timestamp(self):
        config, series, journals = self.fixture([.2] * 35)
        cid = config["subjects"][0]["cid"]
        event = next(row for row in journals[cid] if row["kind"] == "LOCAL_EVALUATION"
            and row["record"]["sample"]["ts_ns"] == series[0]["timestamps_ns"][5])
        event["forecast_available_ns"] += 1
        with self.assertRaisesRegex(ValueError, "par confirmado"):
            analysis.analyze(config, fixtures.RUN_ID, series, journals)

    def test_outside_reference_warnings_are_retained_with_unknown_followup(self):
        config, series, journals = self.fixture(fixtures.old.WARNING_VALUES + [.2] * 20)
        for block in series:
            block["values"] = block["values"][:8]
            block["timestamps_ns"] = block["timestamps_ns"][:8]
        report = analysis.analyze(config, fixtures.RUN_ID, series, journals)
        self.assertEqual(report["control_observation"], "INCOMPLETE_WARNING_FOLLOWUP")
        for domain in report["domains"]:
            self.assertGreater(len(domain["local_activations_outside_reference"]), 0)
            self.assertGreater(domain["outside_reference_joint_pair_witnesses"], 0)
            self.assertEqual(domain["observed_joint_pair_witnesses"], 0)

    def test_duplicate_observer_views_do_not_double_joint_pairs_or_independent_trials(self):
        config, series, journals = self.fixture(fixtures.old.WARNING_VALUES + [.2] * 20)
        raw = sum(row["kind"] == "SHADOW_CONSENSUS" and row["assessment"]["status"] == "SHADOW_PREVENT_AGREED"
                  for rows in journals.values() for row in rows)
        report = analysis.analyze(config, fixtures.RUN_ID, series, journals)
        self.assertEqual(raw, 2 * report["distinct_joint_agreement_witnesses"])
        self.assertEqual(report["independent_runs"], 1)
        self.assertTrue(all(d["strict_activation_episodes"]["total_activations"] == 1 for d in report["domains"]))

    def test_late_agreement_is_retained_even_with_pre_onset_input(self):
        report = self.evaluate(fixtures.VALUES, forecast_delay_ns=2_200_000_000)
        for domain in report["domains"]:
            self.assertIn("AT_OR_AFTER_SAMPLED_ONSET", domain["joint_witness_status_counts"])
            self.assertTrue(any(row["sampled_onset_margin_s"] < 0
                for row in domain["joint_witness_observations"] if row["sampled_onset_margin_s"] is not None))

    def test_model_or_unconfirmed_pairs_remain_invalid(self):
        config, series, journals = self.fixture([.2] * 35)
        original = copy.deepcopy(journals)
        cid = config["subjects"][0]["cid"]
        for mode in ("model", "unconfirmed"):
            current = copy.deepcopy(original)
            pair = next(row for row in current[cid] if row["kind"] == "PAIR_PUBLICATION")
            if mode == "model":
                pair["risk"]["model_sha256"] = "other"
            else:
                pair["commit_outcome"] = "UNKNOWN"
            with self.assertRaises(ValueError):
                analysis.analyze(config, fixtures.RUN_ID, series, current)


if __name__ == "__main__":
    unittest.main()
