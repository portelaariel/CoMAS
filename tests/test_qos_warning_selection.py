import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import qos_warning_selection as selection
import train_qos_warning_model as cli
from qos_damped_holt import QosDampedHoltModel
from qos_holt import QosHoltModel
from test_predictive_sla_validation import create_case, create_pilot


def sequences(prefix="train", scale=1):
    ramp = [.15] * 10 + [.2 + .025 * i for i in range(32)] + [1.0] * 8 + [.2] * 20
    result = []
    for profile in (*selection.CONTROLS, *selection.RAMPS):
        values = ([.3] * len(ramp) if profile in selection.CONTROLS else ramp)
        for port in ("2:4", "3:3"):
            result.append(dict(series_id=f"{prefix}-{profile}/{port}", run_id=f"{prefix}-{profile}",
                               profile=profile, cid=f"d{port}", port_id=port,
                               values=[scale * v for v in values],
                               timestamps_ns=[1_000_000_000 + i * 2_000_000_000 for i in range(len(values))]))
    return result


def choose(**overrides):
    options = dict(train_series=sequences(), priming=2, sample_interval_s=2,
                   alphas=(.2, .7), betas=(0, .35), phis=(.8, 1))
    return selection.choose_parameters(**{**options, **overrides})


class WarningObjectiveTests(unittest.TestCase):
    def test_warning_goal_can_select_trend_over_reactive_zero_beta(self):
        result = choose()
        self.assertEqual(result["candidate_count"], 8)
        self.assertGreater(result["feasible_candidates"], 0)
        self.assertGreater(result["selected"]["parameters"]["beta"], 0)
        self.assertEqual(result["selected"]["score"]["totals"]["control_activations"], 0)
        self.assertFalse(result["calibration_used_for_selection"])
        self.assertFalse(result["v2_used_for_selection"])

    def test_objective_prioritizes_anticipation_then_lateness_not_mse(self):
        candidate = choose()["selected"]
        worse = copy.deepcopy(candidate)
        worse["score"]["anticipated_fraction"] -= .1
        worse["score"]["forecast_mse"] = 0
        self.assertLess(selection.selection_key(candidate), selection.selection_key(worse))
        worse = copy.deepcopy(candidate)
        worse["score"]["late_activation_count"] += 1
        worse["score"]["forecast_mse"] = 0
        self.assertLess(selection.selection_key(candidate), selection.selection_key(worse))
        self.assertNotIn("lead_time", selection.OBJECTIVE["ordered_objectives"])

    def test_remaining_order_is_unmatched_then_window_fp_then_forecast_error(self):
        candidate = choose()["selected"]
        for primary, secondary in (("unmatched_activation_count", "candidate_fp_window_rate"),
                                   ("candidate_fp_window_rate", "forecast_mse")):
            worse = copy.deepcopy(candidate)
            worse["score"][primary] += 1
            worse["score"][secondary] = 0
            self.assertLess(selection.selection_key(candidate), selection.selection_key(worse))
        worse = copy.deepcopy(candidate)
        worse["score"]["forecast_mse"] += 1
        self.assertLess(selection.selection_key(candidate), selection.selection_key(worse))

    def test_macro_average_balances_runs_and_profiles_not_episode_totals(self):
        rows = [dict(profile="slow-ramp", anticipated_fraction=1),
                dict(profile="slow-ramp", anticipated_fraction=0),
                dict(profile="fast-ramp", anticipated_fraction=1)]
        self.assertEqual(selection._profile_mean(rows, "anticipated_fraction", selection.RAMPS), .75)

    def test_no_feasible_model_does_not_silently_choose_mse_or_all_zero_alarms(self):
        result = choose(alphas=(1,), betas=(0,), phis=(1,))
        self.assertEqual(result["feasible_candidates"], 0)
        self.assertIsNone(result["selected"])
        self.assertEqual(result["candidates"][0]["score"]["totals"]["anticipated"], 0)

    def test_control_and_censored_activation_disqualify_candidate(self):
        blocks = selection.run_blocks(selection.candidate_model(dict(alpha=.2, beta=.35, phi=1),
                                                                priming=2, sample_interval_s=2), sequences())
        self.assertTrue(selection.score_blocks(blocks)["feasible"])
        changed = copy.deepcopy(blocks)
        changed[0]["episode_events"]["total_activations"] += 1
        self.assertFalse(selection.score_blocks(changed)["feasible"])
        changed = copy.deepcopy(blocks)
        changed[4]["episode_events"]["activations"].append(dict(status="CENSORED", reason="incomplete_future_followup"))
        changed[4]["episode_events"]["censored_activations"] += 1
        self.assertFalse(selection.score_blocks(changed)["feasible"])

    def test_whole_run_profile_weighting_does_not_count_ports_as_runs(self):
        blocks = selection.run_blocks(selection.candidate_model(dict(alpha=.2, beta=.35, phi=1),
                                                                priming=2, sample_interval_s=2), sequences())
        a = selection.score_blocks(blocks)
        b = selection.score_blocks(blocks + copy.deepcopy(blocks))
        for field in ("anticipated_fraction", "late_activation_count", "unmatched_activation_count",
                      "candidate_fp_window_rate", "forecast_mse"):
            self.assertAlmostEqual(a[field], b[field])
        self.assertEqual(a["totals"]["workload_runs"], b["totals"]["workload_runs"])
        self.assertEqual(a["totals"]["correlated_port_sequences"] * 2, b["totals"]["correlated_port_sequences"])

    def test_calibration_changes_radii_not_selected_parameters_points_or_warnings(self):
        train, chosen = sequences(), choose()["selected"]["parameters"]
        options = dict(parameters=chosen, train_series=train, priming=2, sample_interval_s=2,
                       created_at="test", metadata={})
        a = selection.calibrate_selected(calibration_series=sequences("cal"), **options)
        b = selection.calibrate_selected(calibration_series=sequences("cal", scale=2), **options)
        self.assertEqual([(h.alpha, h.beta, h.phi) for h in a.horizons],
                         [(h.alpha, h.beta, h.phi) for h in b.horizons])
        self.assertNotEqual([h.interval_radius for h in a.horizons], [h.interval_radius for h in b.horizons])
        self.assertEqual(selection.warning_signature(selection.run_blocks(a, train)),
                         selection.warning_signature(selection.run_blocks(b, train)))
        self.assertTrue(all(not h.test_metrics for h in a.horizons))
        with self.assertRaises(ValueError):
            QosHoltModel.from_dict(a.to_dict())

    def test_future_changes_do_not_affect_past_forecasts_or_alerts(self):
        train = sequences()
        changed = copy.deepcopy(train)
        changed[4]["values"][40:] = [1.5] * (len(changed[4]["values"]) - 40)
        model = selection.candidate_model(dict(alpha=.2, beta=.35, phi=.8), priming=2, sample_interval_s=2)
        a, b = (selection.warning_signature(selection.run_blocks(model, items)) for items in (train, changed))
        identity = train[4]["series_id"]
        self.assertEqual([r for r in a[identity]["rows"] if r["index"] < 40],
                         [r for r in b[identity]["rows"] if r["index"] < 40])

    def test_reordered_grid_and_ties_are_deterministic(self):
        a = choose()
        b = choose(alphas=(.7, .2), betas=(.35, 0), phis=(1, .8))
        self.assertEqual(a, b)
        c = a["selected"]
        d = copy.deepcopy(c)
        c["parameters"]["phi"], d["parameters"]["phi"] = 1, .8
        self.assertLess(selection.selection_key(c), selection.selection_key(d))

    def test_invalid_partitions_profiles_grids_and_timestamps_rejected(self):
        for items in ([], sequences() + [sequences()[0]], sequences()[:4]):
            with self.subTest(items=len(items)), self.assertRaises(ValueError):
                choose(train_series=items)
        changed = sequences()
        changed[0]["timestamps_ns"][3] = changed[0]["timestamps_ns"][2]
        with self.assertRaises(ValueError):
            choose(train_series=changed)
        for params in (dict(phis=(0,)), dict(betas=(True,)), dict(alphas=())):
            with self.assertRaises(ValueError):
                choose(**params)
        with self.assertRaises(ValueError):
            selection.calibrate_selected(parameters=dict(alpha=.2, beta=.35, phi=1), train_series=sequences(),
                                         calibration_series=sequences(), priming=2, sample_interval_s=2,
                                         created_at="test", metadata={})


class WarningDevelopmentCliTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
        create_pilot(self.root / "pilot")
        self.protocol_path = self.root / "v1/protocol.json"
        self.protocol = v1.freeze_protocol(self.root / "pilot", self.protocol_path.parent)
        self.campaign = self.protocol_path.parent / "campaign"
        for ordinal, case in enumerate(self.protocol["cases"]):
            create_case(self.protocol, case, self.campaign, ordinal)
        v1.write_new_json(self.campaign / "campaign-summary.json", v1.evaluate_campaign(self.protocol_path, self.campaign))
        self.output = self.root / "qos-warning-development-v1"
        self.patchers = [patch.object(cli, "ALPHAS", (.2, .7)), patch.object(cli, "BETAS", (0, .2)),
                         patch.object(cli, "PHIS", (.8, 1))]
        for p in self.patchers:
            p.start()
            self.addCleanup(p.stop)

    def hashes(self):
        return {str(p): v1.digest_file(p) for p in self.root.rglob("*") if p.is_file()}

    def fit(self):
        return cli.fit_campaign(self.protocol_path, self.campaign, self.output)

    def test_offline_cli_preserves_inputs_seals_outputs_and_never_evaluates_v2(self):
        before = self.hashes()
        with patch("urllib.request.urlopen", side_effect=AssertionError("network")), \
                patch.object(v2, "evaluate_campaign", side_effect=AssertionError("v2 read")), \
                patch("sys.stdout", new=io.StringIO()) as stream:
            status = cli.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                               "--output", str(self.output)])
        self.assertEqual(status, 0)
        self.assertEqual(len(stream.getvalue().splitlines()), 7)
        self.assertIn("independent_test=false", stream.getvalue())
        self.assertEqual(before, {p: v1.digest_file(Path(p)) for p in before})
        spec = json.loads((self.output / "development-spec.json").read_text())
        report = json.loads((self.output / "qos-warning-evaluation.json").read_text())
        self.assertEqual(spec, v1.seal(spec, "development_spec_sha256"))
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(report["status"], "WARNING_DEVELOPMENT_FITTED")
        model = QosDampedHoltModel.load(self.output / "qos-warning-model.json")
        self.assertEqual(model.training["development_spec_sha256"], spec["development_spec_sha256"])
        self.assertEqual(report["model_id"], model.resolved_model_id())
        self.assertEqual(report["partitions"]["train"]["workload_runs"], 8)
        self.assertEqual(report["partitions"]["calibration"]["workload_runs"], 4)
        self.assertTrue(report["paired_changes"]["ground_truth_matches"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["test_evaluated"])
        self.assertEqual(report["warning_policy"], v2.POLICY)

    def test_search_receives_only_train_and_calibration_happens_after_selection(self):
        with patch.object(selection, "choose_parameters", wraps=selection.choose_parameters) as choose_spy, \
                patch.object(selection, "calibrate_selected", wraps=selection.calibrate_selected) as cal_spy:
            self.fit()
        chosen = choose_spy.call_args.kwargs["train_series"]
        self.assertEqual(len({s["run_id"] for s in chosen}), 8)
        self.assertTrue(all(not s["run_id"].startswith("r03-") for s in chosen))
        self.assertNotIn("calibration_series", choose_spy.call_args.kwargs)
        self.assertTrue(all(s["run_id"].startswith("r03-") for s in cal_spy.call_args.kwargs["calibration_series"]))

    def test_none_still_writes_diagnostic_but_no_model_and_no_false_promotion(self):
        with patch.object(cli, "ALPHAS", (1,)), patch.object(cli, "BETAS", (0,)), patch.object(cli, "PHIS", (1,)):
            report = self.fit()
        self.assertEqual(report["status"], "NO_FEASIBLE_CANDIDATE")
        self.assertIsNone(report["model_id"])
        self.assertIsNone(report["selected_training"])
        self.assertFalse((self.output / "qos-warning-model.json").exists())

    def test_existing_outputs_source_targets_and_symlinks_refused_before_selection(self):
        self.output.mkdir()
        (self.output / "keep.txt").write_text("keep")
        alias = self.root / "qos-warning-development-alias"
        alias.symlink_to(self.output, target_is_directory=True)
        for target in (self.output, alias, self.protocol_path.parent, self.campaign,
                       self.root / "pilot/qos-warning-development-nested", self.root):
            with self.subTest(target=target), patch.object(selection, "choose_parameters", side_effect=AssertionError("fit")), \
                    self.assertRaises((ValueError, FileExistsError)):
                cli.fit_campaign(self.protocol_path, self.campaign, target)

    def test_tampering_is_rejected_without_repair_or_new_output(self):
        path = self.campaign / "campaign-summary.json"
        payload = json.loads(path.read_text())
        payload["models"]["coverage90"]["watch_windows"] += 1
        path.write_text(json.dumps(payload))
        before = self.hashes()
        with self.assertRaisesRegex(ValueError, "relatório v1"), \
                patch.object(selection, "choose_parameters", side_effect=AssertionError("fit")):
            self.fit()
        self.assertEqual(before, self.hashes())
        self.assertFalse(self.output.exists())

    def test_input_change_during_search_aborts_before_writing_artifacts(self):
        original_choose = selection.choose_parameters
        summary = self.campaign / "campaign-summary.json"

        def mutate_after_selection(**kwargs):
            result = original_choose(**kwargs)
            summary.write_bytes(summary.read_bytes() + b"\n")
            return result

        with patch.object(selection, "choose_parameters", side_effect=mutate_after_selection), \
                self.assertRaisesRegex(ValueError, "fontes/código mudaram"):
            self.fit()
        self.assertFalse(self.output.exists())

    def test_training_policy_and_objective_have_no_cli_tuning_options(self):
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as raised:
            cli.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                      "--output", str(self.output), "--threshold", ".7"])
        self.assertEqual(raised.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
