import unittest

from sla_risk import (
    SLA_RISK_EVENT_TYPE,
    SlaRiskPersistence,
    SlaRiskPolicy,
    evaluate_sla_forecast,
)


def evaluate(policy, values):
    return evaluate_sla_forecast(
        policy=policy,
        cid="domain-0",
        subject_type="flow",
        subject_id="10.0.0.1->10.0.0.8",
        observed_value=70.0,
        window_id=100,
        observation_ns=1_000_000_000,
        sample_interval_s=2.0,
        forecasts=[
            {
                "horizon_steps": step,
                "predicted_value": predicted,
                "lower_bound": lower,
                "upper_bound": upper,
            }
            for step, predicted, lower, upper in values
        ],
        model_id="holt-qos:test",
        model_type="holt_multihorizon",
        created_ns=1_100_000_000,
        ttl_s=12.0,
    )


class SlaRiskEvaluationTests(unittest.TestCase):
    def setUp(self):
        self.policy = SlaRiskPolicy(
            metric="utilization_ratio",
            comparator="MAX",
            threshold=0.8,
            horizons_steps=(2, 4, 6),
            required_consecutive_horizons=2,
        )

    def test_clear_forecast_remains_normal(self):
        result = evaluate(self.policy, [
            (2, 0.60, 0.55, 0.65),
            (4, 0.65, 0.60, 0.70),
            (6, 0.70, 0.64, 0.76),
        ])

        self.assertEqual(result["decision"], "NORMAL")
        self.assertEqual(result["risk"]["level"], "CLEAR")
        self.assertFalse(result["risk"]["candidate"])

    def test_uncertainty_touching_sla_is_watch_not_actionable_risk(self):
        result = evaluate(self.policy, [
            (2, 0.70, 0.60, 0.82),
            (4, 0.72, 0.62, 0.84),
            (6, 0.74, 0.64, 0.86),
        ])

        self.assertEqual(result["decision"], "WATCH")
        self.assertEqual(result["risk"]["level"], "POSSIBLE")
        self.assertIsNone(result["risk"]["earliest_likely_crossing_s"])

    def test_two_likely_horizons_create_typed_risk_event(self):
        result = evaluate(self.policy, [
            (2, 0.75, 0.69, 0.81),
            (4, 0.83, 0.76, 0.90),
            (6, 0.88, 0.82, 0.94),
        ])

        self.assertEqual(result["event_type"], SLA_RISK_EVENT_TYPE)
        self.assertEqual(result["decision"], SLA_RISK_EVENT_TYPE)
        self.assertEqual(result["risk"]["confirming_horizon_steps"], [4, 6])
        self.assertEqual(result["risk"]["earliest_likely_crossing_s"], 8.0)
        self.assertEqual(result["risk"]["level"], "HIGH_CONFIDENCE")

    def test_minimum_sla_uses_lower_tail(self):
        policy = SlaRiskPolicy(
            metric="throughput_bps",
            comparator="MIN",
            threshold=50.0,
            horizons_steps=(1, 2),
            required_consecutive_horizons=2,
        )
        result = evaluate(policy, [
            (1, 48.0, 44.0, 52.0),
            (2, 42.0, 38.0, 46.0),
        ])

        self.assertEqual(result["decision"], SLA_RISK_EVENT_TYPE)
        self.assertEqual(result["risk"]["earliest_likely_crossing_s"], 2.0)

    def test_rejects_missing_horizon(self):
        with self.assertRaisesRegex(ValueError, "horizontes recebidos"):
            evaluate(self.policy, [
                (2, 0.75, 0.70, 0.80),
                (4, 0.85, 0.80, 0.90),
            ])

    def test_rejects_interval_that_does_not_contain_prediction(self):
        with self.assertRaisesRegex(ValueError, "intervalo"):
            evaluate(self.policy, [
                (2, 0.75, 0.76, 0.80),
                (4, 0.85, 0.80, 0.90),
                (6, 0.90, 0.85, 0.95),
            ])


class SlaRiskPersistenceTests(unittest.TestCase):
    def setUp(self):
        policy = SlaRiskPolicy(
            metric="utilization_ratio",
            comparator="MAX",
            threshold=0.8,
            horizons_steps=(2, 4),
            required_consecutive_horizons=2,
        )
        self.risk = evaluate(policy, [
            (2, 0.82, 0.75, 0.88),
            (4, 0.86, 0.79, 0.92),
        ])
        self.normal = evaluate(policy, [
            (2, 0.60, 0.55, 0.65),
            (4, 0.65, 0.60, 0.70),
        ])

    def test_requires_consecutive_evaluations_to_activate_and_clear(self):
        tracker = SlaRiskPersistence(activation_windows=2, clear_windows=2)

        first = tracker.update(self.risk)
        second = tracker.update(self.risk)
        first_clear = tracker.update(self.normal)
        second_clear = tracker.update(self.normal)

        self.assertEqual(first["status"], "PENDING_RISK")
        self.assertEqual(second["status"], "ACTIVE_RISK")
        self.assertTrue(second["transitioned"])
        self.assertEqual(first_clear["status"], "ACTIVE_RISK")
        self.assertEqual(second_clear["status"], "CLEARED")
        self.assertTrue(second_clear["transitioned"])


if __name__ == "__main__":
    unittest.main()
