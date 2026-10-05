import copy
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_damping_study as study
import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
from qos_holt import HorizonModel, MultiHorizonHoltForecaster, QosHoltModel
from test_predictive_sla_validation import create_case, create_pilot


def sample_model():
    return QosHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=0.9,
                        priming_samples=2, created_at="2026-10-05T00:00:00Z",
                        horizons=tuple(HorizonModel(horizon_steps=step, alpha=0.2, beta=0.35,
                                                    interval_radius=0.2, calibration_samples=20)
                                       for step in (2, 4, 6)))


class DampedForecasterTests(unittest.TestCase):
    def test_phi_one_reproduces_every_native_point_and_state_exactly(self):
        model = sample_model()
        native = MultiHorizonHoltForecaster(model)
        alternative = study.DampedHoltForecaster(model, 1)
        for observed in [0.1, 0.2, 0.6, 1.4, 0.4, 0, 0, 0.9] * 8:
            expected = native.update(observed)
            actual = alternative.update(observed)
            self.assertEqual([row["predicted_value"] for row in actual],
                             [row["predicted_value"] for row in expected])
            self.assertEqual(alternative.states, native._states)

    def test_amortecimento_changes_state_and_geometric_forecast_not_only_projection(self):
        predictor = study.DampedHoltForecaster(sample_model(), 0.9)
        self.assertEqual(predictor.update(0.5), [])
        predictor.update(0.6)
        predictions = predictor.update(0.7)
        for row in predictions:
            self.assertAlmostEqual(row["level"], 0.56104)
            self.assertAlmostEqual(row["trend"], 0.018459)
            expected = 0.56104 + 0.018459 * sum(0.9 ** i for i in range(1, row["horizon_steps"] + 1))
            self.assertAlmostEqual(row["predicted_value"], expected, places=11)
            self.assertNotIn("upper_bound", row)
            self.assertNotIn("lower_bound", row)

    def test_invalid_phi_or_observations_rejected_without_state_updates(self):
        for phi in (0, -1, 1.01, True, float("nan"), float("inf"), "bad"):
            with self.subTest(phi=phi), self.assertRaises(ValueError):
                study.DampedHoltForecaster(sample_model(), phi)
        predictor = study.DampedHoltForecaster(sample_model(), 0.9)
        before = copy.deepcopy(predictor.states)
        for value in (-0.1, float("nan"), float("inf")):
            with self.assertRaises(ValueError):
                predictor.update(value)
            self.assertEqual(predictor.states, before)

    def test_no_upper_clipping_and_empty_error_metrics_are_not_fabricated_zeroes(self):
        predictor = study.DampedHoltForecaster(sample_model(), 0.9)
        predictor.update(1.4)
        self.assertTrue(all(row["predicted_value"] == 1.4 for row in predictor.update(1.4)))
        self.assertEqual(study.error_metrics([]), dict(samples=0, mae=None, rmse=None, bias=None))
        self.assertEqual(study.error_metrics([-1, 1]), dict(samples=2, mae=1, rmse=1, bias=0))

    def test_future_changes_never_change_past_predictions_or_alerts(self):
        series = dict(series_id="demo", cid="d0", port_id="2:4",
                      values=[0.4 + 0.2 * math.sin(i / 3) for i in range(70)],
                      timestamps_ns=[1_000_000_000 + i * 2_000_000_000 for i in range(70)])
        modified = copy.deepcopy(series)
        modified["values"][40:] = [1.5] * 30
        for phi in study.PHI_GRID:
            _, before, _ = study.replay_series(sample_model(), series, v2.POLICY, phi)
            _, after, _ = study.replay_series(sample_model(), modified, v2.POLICY, phi)
            keys = ("index", "candidate", "active", "activation", "clear_transition", "predictions")
            self.assertEqual([{k: r[k] for k in keys} for r in before if r["index"] < 40],
                             [{k: r[k] for k in keys} for r in after if r["index"] < 40])

    def test_sequence_reset_and_native_scored_scope_are_retained(self):
        series = dict(series_id="demo", cid="d0", port_id="2:4", values=[0.5] * 30,
                      timestamps_ns=[1_000_000_000 + i * 2_000_000_000 for i in range(30)])
        first, rows, errors = study.replay_series(sample_model(), series, v2.POLICY, 0.9)
        second, _, _ = study.replay_series(sample_model(), series, v2.POLICY, 0.9)
        self.assertEqual(first, second)
        self.assertEqual(rows[0]["index"], 1)
        self.assertEqual(rows[-1]["index"], 23)
        self.assertEqual(set(errors), {2, 4, 6})
        self.assertTrue(all(len(e) == len(rows) for e in errors.values()))

    def test_error_pooling_weights_samples_and_uses_squared_rmse(self):
        items = [dict(forecast_errors={"2": study.error_metrics([-1, 1])}),
                 dict(forecast_errors={"2": study.error_metrics([4])})]
        actual = study.pooled_errors(items)["2"]
        expected = study.error_metrics([-1, 1, 4])
        for key in expected:
            self.assertAlmostEqual(actual[key], expected[key])

    def test_native_reference_drift_is_rejected(self):
        series = dict(series_id="demo", cid="d0", port_id="2:4", values=[0.9] * 30,
                      timestamps_ns=[1_000_000_000 + i * 2_000_000_000 for i in range(30)])
        with patch.object(study, "_first_consecutive_run", return_value=None), \
                self.assertRaisesRegex(ValueError, "baseline phi=1"):
            study.replay_series(sample_model(), series, v2.POLICY, 1)


class DampingStudyTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        pilot = self.root / "pilot"
        create_pilot(pilot)
        self.v1_path = self.root / "v1/protocol.json"
        parent = v1.freeze_protocol(pilot, self.v1_path.parent)
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

    def test_report_preserves_all_frozen_sources_and_official_results_without_refit_or_network(self):
        before = self.hashes()
        code = {name: v1.digest_file(v1.ROOT / name) for name in v2.CODE_FILES}
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = study.build_report(self.protocol_path, self.campaign)
        self.assertEqual(before, self.hashes())
        self.assertEqual(code, {name: v1.digest_file(v1.ROOT / name) for name in v2.CODE_FILES})
        self.assertEqual(report["official_v2"]["models"], self.baseline["models"])
        self.assertEqual(report["official_v2"]["criteria_status"], self.baseline["criteria_status"])
        self.assertEqual(report["official_v2"]["checks"], self.baseline["checks"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["deployment_eligible"])
        self.assertIsNone(report["selected_variant"])
        self.assertIn("posthoc", report["scope"])
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(report["study_policy"]["phi_grid"], [1, 0.98, 0.95, 0.9, 0.8])
        self.assertTrue(report["baseline_reference_matches"])
        for variant in report["variants"].values():
            self.assertEqual(len(variant["series"]), 24)
            self.assertEqual(variant["summary"]["workload_runs"], 12)
            self.assertEqual(variant["summary"]["eligible_episodes"],
                             report["variants"]["phi1"]["summary"]["eligible_episodes"])
            self.assertEqual(set(variant["per_profile"]), set(v1.profiles()))
            self.assertEqual(len(variant["per_run"]), 12)
            for step, metrics in variant["summary"]["forecast_errors"].items():
                count = sum(row["forecast_errors"][step]["samples"] for row in variant["per_profile"].values())
                self.assertEqual(count, metrics["samples"])
        self.assertEqual(report["variants"]["phi1"]["versus_baseline"]["lost_anticipated_episodes"], [])
        self.assertIn("NOT_EVALUATED", report["study_policy"]["intervals"])

    def test_paired_changes_keep_episode_identity_and_report_losses_and_gains(self):
        def variant(detected, control, fp):
            return dict(series=[dict(episode_events=dict(episodes=[
                dict(episode_id="demo", onset_index=20, eligible=True, detected=detected)]))],
                        summary=dict(anticipated=int(detected), control_activations=control,
                                     candidate=dict(confusion=dict(FP=fp))))
        baseline, damped = variant(True, 1, 4), variant(False, 0, 2)
        result = study.paired_changes(baseline, damped)
        self.assertEqual(result["lost_anticipated_episodes"], ["demo"])
        self.assertEqual(result["candidate_fp_delta"], -2)
        self.assertEqual(result["control_activation_delta"], -1)
        self.assertEqual(study.paired_changes(damped, baseline)["gained_anticipated_episodes"], ["demo"])
        damped["series"][0]["episode_events"]["episodes"][0]["onset_index"] = 21
        with self.assertRaisesRegex(ValueError, "ground truth"):
            study.paired_changes(baseline, damped)

    def test_model_sources_code_and_summary_tampering_rejected_without_repair(self):
        paths = [self.protocol_path.parent / "models/coverage90.json",
                 self.campaign / "campaign-summary.json",
                 self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"]
        for path in paths:
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            corrupted = self.hashes()
            with self.subTest(path=path), self.assertRaises((ValueError, json.JSONDecodeError)):
                study.build_report(self.protocol_path, self.campaign)
            self.assertEqual(corrupted, self.hashes())
            path.write_bytes(original)
        with patch.object(v2, "CODE_FILES", (*v2.CODE_FILES, "PREDICTIVE_SLA.md")), self.assertRaises(ValueError):
            study.build_report(self.protocol_path, self.campaign)

    def test_incomplete_or_v1_campaign_is_not_accepted(self):
        record_path = self.campaign / self.protocol["cases"][0]["case_id"] / "run.json"
        payload = json.loads(record_path.read_text())
        payload["status"] = "FAILED"
        record_path.write_text(json.dumps(v1.seal(payload, "run_sha256")))
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            study.build_report(self.protocol_path, self.campaign)
        with self.assertRaisesRegex(ValueError, "protocolo v2"):
            study.build_report(self.v1_path, self.campaign)

    def test_changes_during_replay_fail_before_output(self):
        original = study.replay_series
        path = self.campaign / "campaign-summary.json"
        changed = False

        def modify(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                path.write_bytes(path.read_bytes() + b"\n")
                changed = True
            return result

        with patch.object(study, "replay_series", side_effect=modify), self.assertRaisesRegex(ValueError, "mudaram"):
            study.build_report(self.protocol_path, self.campaign)

    def test_output_protection_and_cli_create_only_one_separate_report(self):
        for path in (self.protocol_path, self.campaign / "damping-sensitivity.json",
                     self.root / "damping-sensitivity.json",
                     self.protocol_path.parent / "models/damping-sensitivity.json",
                     self.protocol_path.parent / "damping-sensitivity.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                study.output_path(self.protocol_path, path)
        destination = self.protocol_path.parent / "damping-sensitivity-v1.json"
        before = self.hashes()
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            status = study.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                 "--output", str(destination)])
        self.assertEqual(status, 0)
        self.assertEqual(len(stdout.getvalue().splitlines()), 7)
        self.assertIn("selected_variant=NONE", stdout.getvalue())
        after = self.hashes()
        after.pop(str(destination.relative_to(self.root)))
        self.assertEqual(before, after)
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(study.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                         "--output", str(destination)]), 2)

    def test_frozen_case_and_model_configuration_not_exposed_as_cli_tuning_flags(self):
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as error:
            study.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                        "--output", str(self.protocol_path.parent / "damping-sensitivity-v1.json"), "--phi", "0.5"])
        self.assertEqual(error.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
