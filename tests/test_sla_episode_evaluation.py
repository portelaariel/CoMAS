import unittest

from sla_episode_evaluation import evaluate_episodes, summarize_episode_reports


def evaluate(values, alerts=(), *, indexes=None, timestamps=None, **kwargs):
    return evaluate_episodes(
        values=values,
        observations=[{
            "index": index, "persistent_activation": index in alerts,
        } for index in (range(len(values)) if indexes is None else indexes)],
        timestamps_ns=timestamps, series_id="test", cid="domain-0", port_id="2:4",
        comparator=kwargs.pop("comparator", "MAX"), threshold=0.8,
        sample_interval_s=kwargs.pop("sample_interval_s", 2),
        max_horizon_steps=kwargs.pop("max_horizon_steps", 6), **kwargs,
    )


class ObservedSlaEpisodeTests(unittest.TestCase):
    def test_isolated_spikes_remain_unconfirmed_and_one_clear_sample_bridges(self):
        result = evaluate([0.1, 0.9, 0.1, 0.9, 0.9, 0.1, 0.9, 0.1, 0.1])
        self.assertEqual(result["actual_episodes"], 1)
        episode = result["episodes"][0]
        self.assertEqual(episode["onset_index"], 3)
        self.assertEqual(episode["confirmation_index"], 4)
        self.assertEqual(episode["last_breach_index"], 6)
        self.assertEqual(episode["clear_confirmation_index"], 8)
        self.assertEqual(episode["breach_samples"], 3)
        self.assertEqual(result["unconfirmed_breach_runs"], 1)
        self.assertEqual(result["unconfirmed_breach_samples"], 1)

    def test_user_pilot_trace_groups_into_one_episode_per_port(self):
        specs = [
            ([(44, 44), (51, 51), (53, 54), (56, 57), (59, 63),
              (65, 69), (71, 72), (74, 87), (89, 90), (102, 102)], 53, 90, 6),
            ([(39, 39), (46, 46), (51, 51), (54, 55), (57, 87),
              (89, 92)], 54, 92, 8),
        ]
        for runs, onset, last, lead in specs:
            values = [0.1] * 124
            for start, end in runs:
                values[start:end + 1] = [0.9] * (end - start + 1)
            result = evaluate(values, alerts=(45, 50), indexes=range(1, 118))
            with self.subTest(onset=onset):
                self.assertEqual(result["actual_episodes"], 1)
                self.assertEqual(result["episodes"][0]["onset_index"], onset)
                self.assertEqual(result["episodes"][0]["last_breach_index"], last)
                self.assertEqual(result["episodes"][0]["activation_index"], 50)
                self.assertEqual(result["warning_lead_time_s"]["values"], [lead])
                self.assertEqual(result["unmatched_activations"], 1)
                self.assertEqual(result["unconfirmed_breach_runs"], 3)

    def test_single_activation_cannot_detect_two_episodes(self):
        result = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1, 0.9, 0.9,
                           0.1, 0.1], alerts=(1,))
        self.assertEqual(result["eligible_episodes"], 2)
        self.assertEqual(result["detected"], 1)
        self.assertEqual(result["missed"], 1)
        self.assertEqual(result["matched_activations"], 1)
        self.assertIsNone(result["episodes"][1]["activation_index"])

    def test_earliest_unused_activation_is_matched_and_duplicate_is_unmatched(self):
        result = evaluate([0.1, 0.1, 0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1, 2))
        self.assertEqual(result["episodes"][0]["activation_index"], 1)
        self.assertEqual(result["unmatched_activations"], 1)
        self.assertEqual(result["activations"][1]["reason"],
                         "additional_warning_for_matched_episode")

    def test_two_alerts_match_two_episodes_without_reuse(self):
        result = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1, 0.9, 0.9,
                           0.1, 0.1], alerts=(1, 5))
        self.assertEqual([row["activation_index"] for row in result["episodes"]], [1, 5])
        self.assertEqual(result["detected"], 2)

    def test_lead_time_subtracts_integer_csv_timestamps_before_converting(self):
        base = 1_790_000_000_000_000_000
        timestamps = [base + value for value in
                      (0, 1_900_000_000, 4_300_000_001,
                       6_200_000_000, 8_000_000_000, 10_000_000_000)]
        result = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1,),
                          timestamps=timestamps)
        self.assertEqual(result["timing_basis"], "csv_timestamps")
        self.assertEqual(result["warning_lead_time_s"]["values"], [2.400000001])
        self.assertEqual(result["nominal_warning_lead_time_s"]["values"], [2])

    def test_elapsed_horizon_rejects_alert_outside_actual_deadline(self):
        result = evaluate([0.1, 0.9, 0.9, 0.1, 0.1], alerts=(0,),
                          timestamps=[1, 13_000_000_002, 15_000_000_002,
                                      17_000_000_002, 19_000_000_002])
        self.assertEqual(result["detected"], 0)
        self.assertEqual(result["ineligible_episodes"], 1)
        self.assertEqual(result["unmatched_activations"], 1)

    def test_exact_horizon_boundary_is_included(self):
        result = evaluate([0.1] * 6 + [0.9, 0.9, 0.1, 0.1], alerts=(0,))
        self.assertEqual(result["detected"], 1)
        self.assertEqual(result["warning_lead_time_s"]["values"], [12])

    def test_activation_at_onset_is_not_preventive(self):
        result = evaluate([0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1,))
        self.assertEqual(result["detected"], 0)
        self.assertEqual(result["activations"][0]["reason"], "at_or_after_episode_onset")

    def test_incomplete_followup_is_censored_not_unmatched(self):
        result = evaluate([0.1] * 10, alerts=(1, 8))
        self.assertEqual(result["unmatched_activations"], 1)
        self.assertEqual(result["censored_activations"], 1)
        self.assertEqual(result["activation_match_rate"], 0)

    def test_followup_includes_samples_needed_to_confirm_boundary_onset(self):
        result = evaluate([0.1] * 6 + [0.9], alerts=(0,))
        self.assertEqual(result["unconfirmed_breach_samples"], 1)
        self.assertEqual(result["censored_activations"], 1)
        self.assertEqual(result["unmatched_activations"], 0)
        self.assertIsNone(result["activation_match_rate"])

    def test_initial_and_unclosed_episodes_are_marked_censored(self):
        result = evaluate([0.9, 0.9, 0.1, 0.1, 0.9, 0.9])
        self.assertTrue(result["episodes"][0]["left_censored"])
        self.assertFalse(result["episodes"][0]["right_censored"])
        self.assertTrue(result["episodes"][1]["right_censored"])
        self.assertIsNone(result["episodes"][1]["clear_confirmation_index"])

    def test_no_observed_warning_opportunity_is_not_a_missed_episode(self):
        result = evaluate([0.1, 0.9, 0.9, 0.1, 0.1], indexes=())
        self.assertEqual(result["ineligible_episodes"], 1)
        self.assertEqual(result["missed"], 0)
        self.assertIsNone(result["detection_rate"])

    def test_min_comparator_uses_inclusive_threshold(self):
        result = evaluate([1, 1, 0.8, 0.7, 1, 1], alerts=(1,), comparator="MIN")
        self.assertEqual(result["episodes"][0]["onset_index"], 2)
        self.assertEqual(result["detected"], 1)

    def test_aggregate_keeps_series_provenance_and_adds_counts(self):
        result = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1,))
        summary = summarize_episode_reports([result, result])
        self.assertEqual(summary["actual_episodes"], 2)
        self.assertEqual(summary["matched_activations"], 2)
        self.assertEqual(summary["warning_lead_time_s"]["count"], 2)
        self.assertEqual(summary["episodes"][0]["port_id"], "2:4")

    def test_different_episode_policies_cannot_be_pooled(self):
        first = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1,))
        second = evaluate([0.1, 0.1, 0.9, 0.9, 0.1, 0.1], alerts=(1,),
                          min_breach_samples=1)
        with self.assertRaisesRegex(ValueError, "políticas"):
            summarize_episode_reports([first, second])

    def test_invalid_timestamps_and_episode_parameters_are_rejected(self):
        for timestamps in ([1], [1, 1], [2, 1], [True, 2], [0, 2]):
            with self.subTest(timestamps=timestamps), self.assertRaises(ValueError):
                evaluate([0.1, 0.1], timestamps=timestamps)
        for kwargs in ({"min_breach_samples": 0}, {"clear_samples": -1},
                       {"min_breach_samples": True}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                evaluate([0.1, 0.1], **kwargs)


if __name__ == "__main__":
    unittest.main()
