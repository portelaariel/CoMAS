import copy
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as v1
import train_qos_damped_holt_model as cli
from qos_damped_holt import (
    DampedHorizonModel, MODEL_TYPE, MultiHorizonDampedHoltForecaster,
    QosDampedHoltModel, balanced_loss, forecast_records, projected_value,
    train_damped_model, updated_state,
)
from qos_holt import HorizonModel, MultiHorizonHoltForecaster, QosHoltModel, conformal_radius
from test_predictive_sla_validation import create_case, create_pilot


def series(run, values, profile="ramp", port="2:4"):
    return dict(run_id=run, profile=profile, series_id=f"{run}/{port}", port_id=port, values=list(values))


def fit(**overrides):
    kwargs = dict(train_series=[series("train", [0.1 + i * .015 for i in range(35)])],
                  calibration_series=[series("cal", [0.2 + i * .01 for i in range(30)])],
                  horizons_steps=(2, 4, 6), sample_interval_s=2, priming_samples=2, coverage=.9,
                  alphas=(.2, .7), betas=(0, .5), phis=(.9, .98, 1),
                  created_at="2026-10-06T00:00:00Z", training_metadata={})
    return train_damped_model(**{**kwargs, **overrides})


class DampedHoltCoreTests(unittest.TestCase):
    def test_phi_one_reproduces_native_online_forecasts_and_bounds_exactly(self):
        native = QosHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=.9,
                             priming_samples=2, created_at="today", horizons=tuple(
                                 HorizonModel(h, .2, .35, .123456789123, 20) for h in (2, 4, 6)))
        damped = QosDampedHoltModel(metric=native.metric, sample_interval_s=2, coverage=.9,
                                   priming_samples=2, created_at="today", horizons=tuple(
                                       DampedHorizonModel(h, .2, .35, .123456789123, 20, phi=1)
                                       for h in (2, 4, 6)))
        a, b = MultiHorizonHoltForecaster(native), MultiHorizonDampedHoltForecaster(damped)
        for value in [0, .08, .2, .7, 1.3, .05] * 12:
            self.assertEqual(a.update(value), b.update(value))

    def test_damped_state_and_geometric_projection_follow_equations(self):
        level, trend = updated_state(.4, .1, .7, .2, .5, .9)
        self.assertAlmostEqual(level, .2 * .7 + .8 * (.4 + .09))
        self.assertAlmostEqual(trend, .5 * (level - .4) + .5 * .09)
        self.assertAlmostEqual(projected_value(level, trend, .9, 4),
                               level + sum(.9 ** h for h in range(1, 5)) * trend)
        self.assertGreater(projected_value(1.2, .1, .95, 6), 1)  # No capacity clipping.
        self.assertEqual(projected_value(0, -1, .9, 6), 0)

    def test_past_only_forecasts_and_reset_at_each_sequence(self):
        model, _ = fit()
        prefix = [.1, .2, .3, .4, .5]
        first, second = MultiHorizonDampedHoltForecaster(model), MultiHorizonDampedHoltForecaster(model)
        for value in prefix:
            self.assertEqual(first.update(value), second.update(value))
        self.assertNotEqual(first.update(.1), second.update(1.5))
        fresh = MultiHorizonDampedHoltForecaster(model)
        self.assertEqual(fresh.update(.9), [])
        records = forecast_records(prefix, alpha=.2, beta=.5, phi=.9, horizon_steps=2, priming_samples=2)
        self.assertEqual(len(records), 2)
        self.assertEqual([row[0] for row in records], [.4, .5])

    def test_training_records_use_identical_inference_points(self):
        model, _ = fit(phis=(.95,), alphas=(.2,), betas=(.5,))
        values = [.1, .2, .4, 1.1, .9, .3] * 6
        emitted = MultiHorizonDampedHoltForecaster(model)
        points = [emitted.update(v) for v in values]
        for h in model.horizons:
            records = forecast_records(values, alpha=h.alpha, beta=h.beta, phi=h.phi,
                                       horizon_steps=h.horizon_steps, priming_samples=model.priming_samples)
            expected = [next(p["predicted_value"] for p in rows if p["horizon_steps"] == h.horizon_steps)
                        for i, rows in enumerate(points) if rows and i + h.horizon_steps < len(values)]
            self.assertEqual([r[1] for r in records], expected)

    def test_calibration_changes_radii_not_parameter_selection(self):
        a, sa = fit()
        b, sb = fit(calibration_series=[series("cal", [.2, 1.3] * 15)])
        self.assertEqual(sa["horizons"][0]["candidates"], sb["horizons"][0]["candidates"])
        self.assertEqual([(h.alpha, h.beta, h.phi) for h in a.horizons],
                         [(h.alpha, h.beta, h.phi) for h in b.horizons])
        self.assertNotEqual([h.interval_radius for h in a.horizons], [h.interval_radius for h in b.horizons])
        self.assertFalse(sa["calibration_used_for_selection"])
        self.assertFalse(sb["independent_test_used"])

    def test_interval_radius_recomputed_from_new_model_calibration_residuals(self):
        values = [.1, .4, .8, .6, .3] * 8
        model, _ = fit(calibration_series=[series("cal", values)], phis=(.95,))
        for h in model.horizons:
            rows = forecast_records(values, alpha=h.alpha, beta=h.beta, phi=h.phi,
                                    horizon_steps=h.horizon_steps, priming_samples=model.priming_samples)
            self.assertEqual(h.interval_radius, conformal_radius([r[2] for r in rows], .9))
            self.assertEqual(h.calibration_samples, len(rows))
            self.assertEqual(h.test_metrics, {})

    def test_profiles_and_runs_have_equal_weight_not_windows_or_ports(self):
        items = [series("a1", [], "a"), series("a1", [], "a", "3:3"),
                 series("a2", [], "a"), series("b1", [], "b")]
        rows = [[(0, 0, 2)] * 100, [(0, 0, 2)] * 100, [(0, 0, 4)], [(0, 0, 10)]]
        self.assertEqual(balanced_loss(items, rows), ((4 + 16) / 2 + 100) / 2)
        with self.assertRaises(ValueError):
            balanced_loss(items, rows[:-1])

    def test_selection_is_grid_minimum_and_exact_ties_prefer_no_damping(self):
        model, selected = fit()
        for entry, h in zip(selected["horizons"], model.horizons):
            winner = min(entry["candidates"], key=lambda c: (c["balanced_train_mse"], -c["phi"], c["alpha"], c["beta"]))
            self.assertEqual((h.alpha, h.beta, h.phi), (winner["alpha"], winner["beta"], winner["phi"]))
            self.assertLessEqual(entry["balanced_train_mse"], entry["train_selected_undamped_reference"]["balanced_train_mse"])
        flat, _ = fit(train_series=[series("t", [.2] * 35)], calibration_series=[series("c", [.2] * 35)],
                      alphas=(.5,), betas=(0, .5))
        self.assertTrue(all(h.phi == 1 and h.beta == 0 for h in flat.horizons))

    def test_artifact_round_trip_and_native_loader_rejects_new_type(self):
        model, _ = fit()
        self.assertEqual(model.model_type, MODEL_TYPE)
        loaded = QosDampedHoltModel.from_dict(model.to_dict())
        self.assertEqual(loaded.to_dict(), model.to_dict())
        with self.assertRaisesRegex(ValueError, "model_type"):
            QosHoltModel.from_dict(model.to_dict())
        for flag in ("promotion_eligible", "deployment_eligible", "test_evaluated"):
            self.assertIs(model.training[flag], False)
        self.assertEqual(model.training["validation_scope"], "posthoc_run_grouped_development_no_holdout")

    def test_tampering_missing_phi_and_test_or_promotion_claims_rejected(self):
        model, _ = fit()
        for mutate in (lambda p: p["horizons"][0].update(phi=.123),
                       lambda p: p["horizons"][0].pop("phi"),
                       lambda p: p["horizons"][0]["metrics"].update(test={"rmse": 0}),
                       lambda p: p["training"].update(promotion_eligible=True),
                       lambda p: p["training"].update(test_evaluated=True)):
            payload = copy.deepcopy(model.to_dict())
            mutate(payload)
            with self.assertRaises(ValueError):
                QosDampedHoltModel.from_dict(payload)

    def test_bad_grids_gaps_in_partition_identity_or_values_rejected(self):
        for override in (dict(phis=(0,)), dict(phis=(1.01,)), dict(phis=(True,)), dict(alphas=()),
                         dict(betas=(-1,)), dict(coverage=1), dict(sample_interval_s=0),
                         dict(horizons_steps=(2, 2)), dict(calibration_series=[]),
                         dict(calibration_series=[series("train", [.3] * 35)]),
                         dict(train_series=[series("t", [.3, float("nan")] * 20)]),
                         dict(train_series=[series("t", [.3, -1] * 20)]),
                         dict(train_series=[series("t", [.3] * 3)]),
                         dict(train_series=[series("t", [.3] * 35, "a"), series("t", [.3] * 35, "b")])):
            with self.subTest(override=override), self.assertRaises(ValueError):
                fit(**override)


class DampedDevelopmentCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        pilot = self.root / "pilot"
        create_pilot(pilot)
        self.protocol_path = self.root / "v1/protocol.json"
        self.protocol = v1.freeze_protocol(pilot, self.protocol_path.parent, 3)
        self.campaign = self.protocol_path.parent / "campaign"
        for ordinal, case in enumerate(self.protocol["cases"]):
            create_case(self.protocol, case, self.campaign, ordinal)
        self.summary_path = self.campaign / "campaign-summary.json"
        v1.write_new_json(self.summary_path, v1.evaluate_campaign(self.protocol_path, self.campaign))
        self.output = self.root / "qos-damped-development-v1"

    def test_offline_cli_grouped_split_provenance_and_unchanged_sources(self):
        before = cli.source_snapshot(self.protocol, self.protocol_path, self.campaign)
        stream = io.StringIO()
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")), \
                patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("native refit")), \
                redirect_stdout(stream):
            status = cli.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                               "--output", str(self.output)])
        self.assertEqual(status, 0)
        self.assertEqual(len(stream.getvalue().splitlines()), 8)
        report = json.loads((self.output / "qos-damped-holt-evaluation.json").read_text())
        spec = json.loads((self.output / "development-spec.json").read_text())
        artifact = QosDampedHoltModel.load(self.output / "qos-damped-holt-model.json")
        self.assertEqual(spec, v1.seal(spec, "development_spec_sha256"))
        self.assertEqual(spec["development_spec_sha256"], artifact.training["development_spec_sha256"])
        self.assertEqual(before, cli.source_snapshot(self.protocol, self.protocol_path, self.campaign))
        self.assertEqual(report["partitions"]["train"]["workload_runs"], 8)
        self.assertEqual(report["partitions"]["train"]["correlated_port_sequences"], 16)
        self.assertEqual(report["partitions"]["calibration"]["workload_runs"], 4)
        self.assertEqual(report["partitions"]["calibration"]["correlated_port_sequences"], 8)
        self.assertTrue(all(r["repetition"] in (1, 2) if r["split"] == "train" else r["repetition"] == 3
                            for r in spec["source_series"]))
        self.assertEqual(len(spec["source_series"]), 24)
        self.assertEqual(report["status"], "DEVELOPMENT_FITTED")
        self.assertFalse(report["v2_used_for_fitting"])
        self.assertFalse(report["test_evaluated"])
        self.assertTrue(all(r["test"] is None for r in report["horizons"]))
        self.assertEqual(set(spec["code_sha256"]), set(cli.CODE_FILES))
        self.assertTrue(all(len(h["candidates"]) == 180 for h in report["selection"]["horizons"]))

    def test_output_overwrite_source_target_and_symlink_rejected_before_fitting(self):
        self.output.mkdir()
        (self.output / "keep.txt").write_text("keep")
        alias = self.root / "qos-damped-development-alias"
        alias.symlink_to(self.output, target_is_directory=True)
        targets = (self.output, self.protocol_path.parent, self.campaign, self.root,
                   self.root / "pilot/qos-damped-development-nested", alias)
        for target in targets:
            with self.subTest(target=target), patch.object(cli, "train_damped_model", side_effect=AssertionError("fit")), \
                    self.assertRaises((ValueError, FileExistsError)):
                cli.fit_campaign(self.protocol_path, self.campaign, target)
        self.assertEqual((self.output / "keep.txt").read_text(), "keep")

    def test_changed_source_csv_or_summary_rejected_without_output(self):
        path = self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv"
        content = path.read_bytes()
        path.write_bytes(content + b"\n")
        with patch.object(cli, "train_damped_model", side_effect=AssertionError("fit")), self.assertRaises(ValueError):
            cli.fit_campaign(self.protocol_path, self.campaign, self.output)
        path.write_bytes(content)
        summary = json.loads(self.summary_path.read_text())
        summary["evaluated_runs"] = 11
        self.summary_path.write_text(json.dumps(summary))
        with self.assertRaisesRegex(ValueError, "relatório"):
            cli.fit_campaign(self.protocol_path, self.campaign, self.output)
        self.assertFalse(self.output.exists())

    def test_sources_changed_during_fit_stop_publication(self):
        snapshot = cli.source_snapshot(self.protocol, self.protocol_path, self.campaign)
        changed = {**snapshot, str(self.protocol_path): "changed"}
        with patch.object(cli, "source_snapshot", side_effect=(snapshot, changed)), \
                patch.object(cli, "ALPHAS", (.2,)), patch.object(cli, "BETAS", (.1,)), \
                patch.object(cli, "PHIS", (.98, 1)), self.assertRaisesRegex(ValueError, "mudaram"):
            cli.fit_campaign(self.protocol_path, self.campaign, self.output)
        self.assertFalse(self.output.exists())

    def test_v2_or_incomplete_v1_refused_not_renamed_as_training(self):
        original = self.protocol_path.read_bytes()
        payload = {**self.protocol, "schema_version": "comas-predictive-sla-prospective/2"}
        self.protocol_path.write_text(json.dumps(v1.seal(payload, "protocol_sha256")))
        with self.assertRaisesRegex(ValueError, "schema"):
            cli.fit_campaign(self.protocol_path, self.campaign, self.output)
        self.protocol_path.write_bytes(original)
        run = self.campaign / self.protocol["cases"][0]["case_id"] / "run.json"
        record = json.loads(run.read_text())
        record["status"] = "FAILED"
        run.write_text(json.dumps(v1.seal(record, "run_sha256")))
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            cli.fit_campaign(self.protocol_path, self.campaign, self.output)
        self.assertFalse(self.output.exists())


if __name__ == "__main__":
    unittest.main()
