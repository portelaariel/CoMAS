import copy
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_damped_replay as replay
import predictive_sla_validation as v1
import predictive_sla_validation_v2 as v2
import train_qos_damped_holt_model as training
from qos_damped_holt import DampedHorizonModel, QosDampedHoltModel
from qos_holt import HorizonModel, QosHoltModel
from test_predictive_sla_validation import create_case, create_pilot


def model(flat=False, damped=True):
    parameters = ((.7, 0, 1), (.7, 0, 1), (.5, .05, .8)) if flat else ((.2, .35, 1),) * 3
    cls = QosDampedHoltModel if damped else QosHoltModel
    horizons = []
    for step, (alpha, beta, phi) in zip((2, 4, 6), parameters):
        if damped:
            horizons.append(DampedHorizonModel(step, alpha, beta, .3, 20, phi=phi))
        else:
            horizons.append(HorizonModel(step, alpha, beta, .3, 20))
    return cls(metric="utilization_ratio", sample_interval_s=2, coverage=.9,
               priming_samples=2, created_at="2026-10-06", horizons=tuple(horizons))


def series(values, timestamps=None, name="demo"):
    return dict(series_id=name, cid="d0", port_id="2:4", values=list(values),
                timestamps_ns=timestamps or [1_000_000_000 + i * 2_000_000_000 for i in range(len(values))])


class DampedReplayCoreTests(unittest.TestCase):
    def test_flat_short_horizons_reproduce_collapsed_point_candidate_rule(self):
        values = [.1 + .01 * i for i in range(65)] + [.9] * 10 + [.3] * 15
        result = replay.replay_series(model(flat=True), series(values), v2.POLICY)
        structural = result["structural_diagnostics"]
        self.assertTrue(structural["short_horizons_flat_identical"])
        self.assertEqual(structural["checked_windows"], result["evaluated_windows"])
        self.assertEqual(structural["candidates_before_first_observed_breach"], 0)
        for row in result["rows"]:
            self.assertEqual(row["predictions"][0]["predicted_value"], row["predictions"][1]["predicted_value"])
            self.assertEqual(row["candidate"], row["predictions"][1]["predicted_value"] >= .8)

    def test_phi_one_replays_identical_native_points_decisions_intervals_and_matches(self):
        values = [.1, .2, .5, .7, .9, 1.3, .4, .1] * 10
        expected = replay.replay_series(model(damped=False), series(values), v2.POLICY)
        actual = replay.replay_series(model(), series(values), v2.POLICY)
        self.assertEqual(expected, actual)
        replay._check_native_reference(model(damped=False), series(values), v2.POLICY, expected)

    def test_future_targets_never_change_past_points_or_persistence(self):
        original = series([.5 + .25 * math.sin(i / 4) for i in range(70)])
        changed = copy.deepcopy(original)
        changed["values"][40:] = [1.3] * 30
        a = replay.replay_series(model(), original, v2.POLICY)
        b = replay.replay_series(model(), changed, v2.POLICY)
        fields = ("index", "predictions", "decision", "candidate", "active", "activation", "clear_transition")
        self.assertEqual([{k: row[k] for k in fields} for row in a["rows"] if row["index"] < 40],
                         [{k: row[k] for k in fields} for row in b["rows"] if row["index"] < 40])

    def test_scored_scope_and_state_reset_match_frozen_replay(self):
        item = series([.5] * 30)
        a = replay.replay_series(model(), item, v2.POLICY)
        b = replay.replay_series(model(), item, v2.POLICY)
        self.assertEqual(a, b)
        self.assertEqual(a["rows"][0]["index"], 1)
        self.assertEqual(a["rows"][-1]["index"], 23)
        self.assertEqual(a["unscored_tail_windows"], 6)
        self.assertFalse(a["structural_diagnostics"]["short_horizons_flat_identical"])

    def test_at_onset_activation_is_late_not_anticipated(self):
        artifact = QosDampedHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=.9,
                                    priming_samples=2, created_at="test", horizons=tuple(
                                        DampedHorizonModel(h, 1, 0, .1, 20, phi=1) for h in (2, 4, 6)))
        result = replay.replay_series(artifact, series([.2] * 10 + [.9] * 10 + [.2] * 20), v2.POLICY)
        self.assertEqual(result["episode_events"]["eligible_episodes"], 1)
        self.assertEqual(result["episode_events"]["detected"], 0)
        self.assertEqual(result["episode_events"]["unmatched_activations"], 1)
        self.assertEqual(len(result["late_activations"]), 1)
        self.assertEqual(result["late_activations"][0]["delay_after_onset_s"], 0)
        self.assertIsNone(result["episode_events"]["warning_lead_time_s"]["mean"])

    def test_late_delay_uses_real_timestamps_not_nominal_sampling(self):
        artifact = QosDampedHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=.9,
                                    priming_samples=2, created_at="test", horizons=tuple(
                                        DampedHorizonModel(h, 1, 0, .1, 20, phi=1) for h in (2, 4, 6)))
        values = [.2] * 10 + [.9] * 10 + [.2] * 20
        timestamps = [1_000_000_000 + i * 2_000_000_000 + max(0, i - 10) * 100_000_000
                      for i in range(len(values))]
        result = replay.replay_series(artifact, series(values, timestamps), {**v2.POLICY, "activation_windows": 2})
        self.assertEqual(result["late_activations"][0]["delay_after_onset_s"], 2.1)

    def test_watch_and_empty_precision_or_lead_are_not_fake_positive_alarms(self):
        result = replay.replay_series(model(flat=True), series([.6] * 40), v2.POLICY)
        result.update(case_id="r01-stable-low", profile="stable-low")
        total = replay.aggregate([result])
        self.assertGreater(total["watch_windows"], 0)
        self.assertEqual(total["control_activations"], 0)
        self.assertEqual(total["late_activations"], 0)
        self.assertEqual(total["eligible_episodes"], 0)
        self.assertIsNone(total["lead_time_s"]["mean"])
        self.assertIsNone(total["candidate"]["metrics"]["precision"])
        self.assertTrue(all(m["interval_coverage"] == 1 for m in total["forecast_errors"].values()))

    def test_error_pooling_and_run_unit_keep_correlated_ports_separate(self):
        a = replay.replay_series(model(), series([.4] * 30), v2.POLICY)
        b = replay.replay_series(model(), series([.2, 1.3] * 25, name="second-port"), v2.POLICY)
        for block in (a, b):
            block.update(case_id="r01-fast-ramp", profile="fast-ramp")
        total = replay.aggregate([a, b])
        errors = [row["actual_horizons"][0] - row["predictions"][0]["predicted_value"] for block in (a, b) for row in block["rows"]]
        self.assertEqual(total["workload_runs"], 1)
        self.assertEqual(total["correlated_port_sequences"], 2)
        self.assertEqual(total["forecast_errors"]["2"]["samples"], len(errors))
        self.assertAlmostEqual(total["forecast_errors"]["2"]["rmse"], math.sqrt(sum(e * e for e in errors) / len(errors)))

    def test_baseline_drift_or_changed_ground_truth_rejected(self):
        item = series([.2] * 10 + [1] * 10 + [.2] * 20)
        original = replay.replay_series(model(damped=False), item, v2.POLICY)
        changed = copy.deepcopy(original)
        changed["rows"][0]["predictions"][0]["predicted_value"] = 9
        with self.assertRaisesRegex(ValueError, "baseline nativo"):
            replay._check_native_reference(model(damped=False), item, v2.POLICY, changed)
        changed = copy.deepcopy(original)
        changed["episode_events"]["episodes"][0]["onset_index"] += 1
        with self.assertRaisesRegex(ValueError, "episódios observados"):
            replay.paired_changes([original], [changed])


class DampedReplayCampaignTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name).resolve()
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
        self.development = self.root / "qos-damped-development-v1"
        with patch.object(training, "ALPHAS", (.2, .7)), patch.object(training, "BETAS", (0, .35)), \
                patch.object(training, "PHIS", (.8, 1)):
            training.fit_campaign(self.v1_path, old_campaign, self.development)
        self.destination = self.development / "replay-v2-v1.json"

    def hashes(self):
        return {str(p.relative_to(self.root)): v1.digest_file(p) for p in self.root.rglob("*") if p.is_file()}

    def test_complete_offline_replay_preserves_originals_without_refit_network_or_promotion(self):
        before = self.hashes()
        with patch.object(training, "train_damped_model", side_effect=AssertionError("fit")), \
                patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("native fit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = replay.build_report(self.protocol_path, self.campaign, self.development)
        self.assertEqual(before, self.hashes())
        self.assertEqual(report, v1.seal(report, "report_sha256"))
        self.assertEqual(report["status"], "REPLAY_COMPLETED")
        self.assertEqual(report["official_v2"]["models"], self.baseline["models"])
        self.assertEqual(report["official_v2"]["criteria_status"], self.baseline["criteria_status"])
        self.assertEqual(report["official_v2"]["checks"], self.baseline["checks"])
        self.assertEqual(report["risk_policy"], v2.POLICY)
        self.assertTrue(report["baseline_exact"])
        self.assertFalse(report["independent_test"])
        self.assertFalse(report["promotion_eligible"])
        self.assertFalse(report["refit"])
        self.assertFalse(report["recalibration"])
        self.assertTrue(report["paired_changes"]["ground_truth_matches"])
        for variant in report["variants"].values():
            self.assertEqual(len(variant["series"]), 24)
            self.assertEqual(variant["summary"]["workload_runs"], 12)
            self.assertEqual(len(variant["per_profile"]), 4)
            self.assertEqual(len(variant["per_run"]), 12)
            for step, score in variant["summary"]["forecast_errors"].items():
                self.assertEqual(score["samples"], sum(p["forecast_errors"][step]["samples"] for p in variant["per_profile"].values()))

    def test_cli_writes_only_new_report_with_seven_console_lines(self):
        before = self.hashes()
        with patch("sys.stdout", new=io.StringIO()) as stdout:
            status = replay.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                  "--development-root", str(self.development), "--output", str(self.destination)])
        self.assertEqual(status, 0)
        self.assertEqual(len(stdout.getvalue().splitlines()), 7)
        self.assertIn("independent_test=false", stdout.getvalue())
        after = self.hashes()
        after.pop(str(self.destination.relative_to(self.root)))
        self.assertEqual(before, after)
        with patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(replay.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                         "--development-root", str(self.development), "--output", str(self.destination)]), 2)

    def test_original_source_paths_existing_output_and_symlink_are_not_targets(self):
        self.destination.write_text("keep")
        alias = self.development / "replay-v2-alias.json"
        alias.symlink_to(self.destination)
        for path in (self.destination, alias, self.protocol_path, self.campaign / "replay-v2.json",
                     self.development / "qos-damped-holt-model.json", self.root / "replay-v2.json",
                     self.development / "models/replay-v2.json", self.development / "replay-v2.txt"):
            with self.subTest(path=path), self.assertRaises(ValueError):
                replay.output_path(self.development, path)
        self.assertEqual(self.destination.read_text(), "keep")

    def test_tampered_model_fit_report_v2_csv_or_summary_rejected_without_repair(self):
        paths = (self.development / "qos-damped-holt-model.json",
                 self.development / "qos-damped-holt-evaluation.json",
                 self.campaign / "campaign-summary.json",
                 self.campaign / self.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv")
        for path in paths:
            original = path.read_bytes()
            path.write_bytes(original + b"changed")
            corrupted = self.hashes()
            with self.subTest(path=path), self.assertRaises((ValueError, json.JSONDecodeError)):
                replay.build_report(self.protocol_path, self.campaign, self.development)
            self.assertEqual(corrupted, self.hashes())
            path.write_bytes(original)
        path = self.development / "qos-damped-holt-evaluation.json"
        payload = json.loads(path.read_text())
        payload["horizons"][0]["alpha"] = .123
        path.write_text(json.dumps(payload))
        with self.assertRaisesRegex(ValueError, "parâmetros/métricas"):
            replay.build_report(self.protocol_path, self.campaign, self.development)
        self.assertFalse(self.destination.exists())

    def test_changed_training_code_or_source_lineage_rejected(self):
        with patch.object(training, "_code_snapshot", return_value={"changed": "hash"}), \
                self.assertRaisesRegex(ValueError, "código/proveniência"):
            replay.build_report(self.protocol_path, self.campaign, self.development)
        spec_path = self.development / "development-spec.json"
        spec = json.loads(spec_path.read_text())
        spec["source_campaign"] = str(self.campaign)
        spec_path.write_text(json.dumps(v1.seal(spec, "development_spec_sha256")))
        with self.assertRaisesRegex(ValueError, "campanha v1 de origem"):
            replay.build_report(self.protocol_path, self.campaign, self.development)

    def test_incomplete_or_v1_campaign_cannot_be_reported_as_complete_replay(self):
        with self.assertRaisesRegex(ValueError, "protocolo v2"):
            replay.build_report(self.v1_path, self.campaign, self.development)
        record_path = self.campaign / self.protocol["cases"][0]["case_id"] / "run.json"
        record = json.loads(record_path.read_text())
        record["status"] = "FAILED"
        record_path.write_text(json.dumps(v1.seal(record, "run_sha256")))
        with self.assertRaisesRegex(ValueError, "12 execuções"):
            replay.build_report(self.protocol_path, self.campaign, self.development)

    def test_change_during_replay_stops_before_any_output(self):
        original = replay.replay_series
        path = self.development / "qos-damped-holt-evaluation.json"
        changed = False

        def modify(*args, **kwargs):
            nonlocal changed
            result = original(*args, **kwargs)
            if not changed:
                path.write_bytes(path.read_bytes() + b"\n")
                changed = True
            return result

        with patch.object(replay, "replay_series", side_effect=modify), patch("sys.stderr", new=io.StringIO()):
            status = replay.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                                  "--development-root", str(self.development), "--output", str(self.destination)])
        self.assertEqual(status, 2)
        self.assertFalse(self.destination.exists())

    def test_rule_tuning_flags_are_not_exposed(self):
        with patch("sys.stderr", new=io.StringIO()), self.assertRaises(SystemExit) as exc:
            replay.main(["--protocol", str(self.protocol_path), "--campaign-root", str(self.campaign),
                         "--development-root", str(self.development), "--output", str(self.destination), "--threshold", ".7"])
        self.assertEqual(exc.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
