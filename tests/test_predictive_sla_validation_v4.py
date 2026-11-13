import copy
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as v1
import predictive_sla_validation_v3 as v3
import predictive_sla_validation_v4 as v4
import predictive_sla_preventive_entry_study as entry
import predictive_sla_damped_replay as replay
import qos_warning_selection as warning
from scripts import collect_qos_validation_campaign as old_collector
from scripts import collect_qos_validation_campaign_v4 as collector
from test_predictive_sla_validation import create_case
import test_predictive_sla_preventive_entry_study as fixtures
from test_predictive_sla_preventive_entry_study import one_horizon, selected_model
from test_predictive_sla_damped_replay import series


class V4CandidateTests(unittest.TestCase):
    def test_exact_inspected_rule_preserves_two_horizon_labels_and_crossings(self):
        values = [.2] * 20 + [1.1] + [.2] * 25
        subject, model = series(values), selected_model()
        expected_raw = one_horizon(model, subject)
        raw, gated = v4.replay_candidate(model, subject)
        self.assertEqual(raw, expected_raw)
        self.assertEqual(gated, entry.replay_entry(subject, expected_raw, v3.POLICY))
        self.assertEqual(raw["candidate"], gated["candidate"])
        self.assertEqual(gated["entry_diagnostic"]["observed_channel"]["threshold_crossing_samples"], 1)
        self.assertEqual(gated["episode_events"]["total_activations"], 0)
        self.assertEqual(v4.POLICY["required_consecutive_horizons"], 1)
        self.assertEqual(v4.SCORING_POLICY["required_consecutive_horizons"], 2)

    def test_blocked_entry_can_reappear_and_existing_alerts_keep_renewal(self):
        subject = series([.2] * 20 + [3] + [.2] * 25)
        raw, gated = v4.replay_candidate(selected_model(), subject)
        self.assertEqual([r["index"] for r in raw["rows"] if r["activation"]], [20])
        self.assertEqual([r["index"] for r in gated["rows"] if r["activation"]], [21])
        self.assertEqual(gated["episode_events"]["unmatched_activations"], 1)
        subject = series([.2] * 15 + [.2 + .025 * i for i in range(35)] + [.2] * 25)
        raw, gated = v4.replay_candidate(selected_model(), subject)
        self.assertEqual(raw["episode_events"], gated["episode_events"])
        self.assertTrue(any(r["active"] and r["observed_state"]["threshold_breach"] for r in gated["rows"]))

    def test_future_values_cannot_change_candidate_or_entry_past(self):
        subject = series([.2] * 15 + [.2 + .015 * i for i in range(35)] + [.2] * 30)
        changed = copy.deepcopy(subject)
        changed["values"][45:] = [1.4] * 35
        fields = ("index", "ts_ns", "predictions", "candidate", "active", "activation", "clear_transition", "observed_state")
        measured = [v4.replay_candidate(selected_model(), s)[1] for s in (subject, changed)]
        self.assertEqual(*[[{k: r[k] for k in fields} for r in b["rows"] if r["index"] < 45] for b in measured])

    def test_operational_timings_are_unknown_not_csv_lead_or_zero(self):
        lead = dict(count=1, minimum=1.99, mean=1.99, maximum=1.99, values=[1.99])
        timing = v4.operational_timing(dict(lead_time_s=lead))
        self.assertEqual(timing["csv_warning_lead_time_s"], lead)
        self.assertEqual(timing["status"], "NOT_MEASURED")
        self.assertEqual(timing["deadline_feasibility"], "UNKNOWN")
        self.assertTrue(all(value is None for key, value in timing.items() if key.endswith("latency_s")))
        self.assertFalse(timing["sla_protection_established"])
        self.assertFalse(timing["execution_boundary"]["predictive_agent_consensus"])


class ProspectiveV4Tests(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.PreventiveEntryCampaignTests(methodName="test_complete_offline_study_preserves_sources_and_exact_raw_baseline")
        self.addCleanup(self.fixture.doCleanups)
        self.fixture.setUp()
        self.source_path, self.source_campaign = self.fixture.path, self.fixture.campaign
        self.study_path = self.fixture.target
        self.study = entry.study(self.source_path, self.source_campaign, self.fixture.source)
        v1.write_new_json(self.study_path, self.study)
        self.root = self.source_path.parent.parent
        self.path = self.root / "qos-prospective-v4/protocol.json"
        self.campaign = self.path.parent / "campaign"
        self.freeze_time = self.fixture.fixture.freeze_time + 15_000_000_000_000

    def freeze(self):
        with patch.object(v4.time, "time_ns", return_value=self.freeze_time):
            return v4.freeze_protocol(self.source_path, self.source_campaign, self.study_path, self.path.parent)

    def cases(self, p, count=12):
        for ordinal, case in enumerate(p["cases"][:count]):
            create_case(p, case, self.campaign, ordinal)

    def record(self, case_id, mutate):
        path = self.campaign / case_id / "run.json"
        payload = json.loads(path.read_text())
        mutate(payload)
        path.write_text(json.dumps(v1.seal(payload, "run_sha256")))

    def args(self, output=None):
        return ["freeze", "--source-protocol", str(self.source_path), "--source-campaign", str(self.source_campaign),
                "--entry-study", str(self.study_path), "--output", str(output or self.path.parent)]

    def test_freeze_exact_copies_no_fit_network_or_source_mutations(self):
        before = self.fixture.fixture.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("search")), \
                patch.object(warning, "calibrate_selected", side_effect=AssertionError("calibration")), \
                patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("fit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            p = self.freeze()
            self.assertEqual(v4.load_protocol(self.path), p)
        self.assertEqual(before, {path: v1.digest_file(Path(path)) for path in before})
        self.assertEqual(p["acceptance_criteria"], v3.CRITERIA)
        self.assertEqual(p["entry_rule"], entry.ENTRY_RULE)
        self.assertEqual(p["scoring_policy"], v3.POLICY)
        self.assertEqual(p["policy"], {**v3.POLICY, "required_consecutive_horizons": 1})
        self.assertEqual(p["source_v3"]["criteria_status"], "NOT_PASSED")
        self.assertFalse(p["independence_guaranteed"])
        self.assertGreaterEqual(len(p["excluded_csv_sha256"]), 72)
        for name, model in p["models"].items():
            self.assertEqual((self.path.parent / model["path"]).read_bytes(),
                             (self.source_path.parent / model["path"]).read_bytes())

    def test_no_overwrite_foreign_or_symlink_freeze_and_sources_must_precede(self):
        with patch.object(v4.time, "time_ns", return_value=self.fixture.protocol["created_ns"]), \
                self.assertRaisesRegex(ValueError, "posterior"):
            v4.freeze_protocol(self.source_path, self.source_campaign, self.study_path, self.path.parent)
        target = self.root / "qos-prospective-v4-link"
        target.symlink_to(self.source_path.parent, target_is_directory=True)
        for output in (self.source_path.parent, self.source_campaign / "qos-prospective-v4", target):
            with self.subTest(output=output), self.assertRaises(ValueError):
                v4.freeze_protocol(self.source_path, self.source_campaign, self.study_path, output)
        self.freeze()
        with self.assertRaises(ValueError):
            self.freeze()

    def test_resealed_study_measurements_fail_reproduction_before_writing(self):
        saved = copy.deepcopy(self.study)
        saved["models"][v3.PRIMARY]["variants"]["preventive_entry_one_horizon"]["summary"]["anticipated"] = 999
        self.study_path.write_text(json.dumps(v1.seal(saved, "report_sha256")))
        with self.assertRaisesRegex(ValueError, "não reproduz"):
            self.freeze()
        self.assertFalse(self.path.parent.exists())

    def test_resealed_policy_criteria_boundary_or_exclusions_are_rejected(self):
        original = self.freeze()
        changes = (
            lambda p: p["policy"].update(required_consecutive_horizons=2),
            lambda p: p["policy"].update(activation_windows=2),
            lambda p: p["policy"].update(threshold=.7),
            lambda p: p["scoring_policy"].update(required_consecutive_horizons=1),
            lambda p: p["entry_rule"].update(already_active="clear_on_observed_breach"),
            lambda p: p["acceptance_criteria"].pop("all_eligible_ramp_episodes_anticipated"),
            lambda p: p["execution_boundary"].update(actuator_request=True),
            lambda p: p.update(independence_guaranteed=True),
            lambda p: p.update(promotion_eligible=True),
            lambda p: p.update(excluded_csv_sha256=[]),
            lambda p: p["selected_parameters"].update(beta=.9),
            lambda p: p["models"][v3.PRIMARY].update(path="../qos-prospective-v3/models/selected_warning90.json"),
        )
        for mutate in changes:
            changed = copy.deepcopy(original)
            mutate(changed)
            self.path.write_text(json.dumps(v1.seal(changed, "protocol_sha256")))
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                v4.load_protocol(self.path)

    def test_old_data_study_model_or_code_changes_invalidate_protocol(self):
        p = self.freeze()
        paths = [self.study_path, self.fixture.source, self.source_campaign / "campaign-summary.json",
                 self.source_campaign / self.fixture.protocol["cases"][0]["case_id"] / "port_utilization_domain0.csv",
                 self.path.parent / p["models"][v3.PRIMARY]["path"]]
        for path in paths:
            content = path.read_bytes()
            path.write_bytes(content + b"changed")
            with self.subTest(path=path), self.assertRaises((OSError, ValueError)):
                v4.load_protocol(self.path)
            path.write_bytes(content)
        with patch.object(v4, "code_snapshot", return_value={}), self.assertRaisesRegex(ValueError, "código"):
            v4.load_protocol(self.path)

    def test_complete_new_campaign_is_paired_shadow_with_unchanged_criteria(self):
        p = self.freeze()
        self.cases(p)
        plan = self.campaign / "campaign-plan.json"
        v1.write_new_json(plan, p)
        before = self.fixture.fixture.hashes()
        with patch.object(warning, "choose_parameters", side_effect=AssertionError("fit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(before, self.fixture.fixture.hashes())
        self.assertEqual(result, v1.seal(result, "report_sha256"))
        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["evaluated_runs"], 12)
        self.assertEqual(set(result["checks"]), set(v3.CRITERIA))
        self.assertEqual(len(result["source_sha256"]), 37)
        self.assertTrue(result["prospective_new_traces"])
        self.assertTrue(result["source_v3_unchanged"])
        self.assertEqual(result["source_v3_criteria_status"], "NOT_PASSED")
        for field in ("promotion_eligible", "deployment_eligible", "refit", "recalibration", "new_data_used_for_fitting",
                      "statistical_superiority_assessed", "independence_guaranteed"):
            self.assertFalse(result[field])
        self.assertEqual(result["operational_timing"]["status"], "NOT_MEASURED")
        for model in result["models"].values():
            self.assertEqual(model["candidate"], model["ungated_one_horizon"]["candidate"])
            self.assertEqual(model["forecast_errors"], model["ungated_one_horizon"]["forecast_errors"])
            self.assertTrue(model["paired_entry_changes"]["ground_truth_matches"])
            self.assertEqual(len(model["per_run"]), 12)
            self.assertEqual(model["operational_timing"]["csv_warning_lead_time_s"], model["lead_time_s"])
        for c in result["cases"]:
            self.assertTrue(c["same_series_paired"] and c["observed_episodes_identical"])
            for name, model in c["models"].items():
                for raw, gated in zip(model["ungated_reference"]["series"], model["series"]):
                    self.assertEqual([r["actual_positive"] for r in raw["rows"]], [r["actual_positive"] for r in gated["rows"]])
                    self.assertTrue(all(r["observed_value"] < .8 for r in gated["rows"] if r["activation"]))
                    self.assertEqual(len(gated["entry_diagnostic"]["observed_channel"]["rows"]), gated["samples"])
        changed_plan = copy.deepcopy(p)
        changed_plan["policy"]["threshold"] = .7
        plan.write_text(json.dumps(v1.seal(changed_plan, "protocol_sha256")))
        with patch.object(v4, "replay_candidate", side_effect=AssertionError("replay")), \
                self.assertRaisesRegex(ValueError, "plano"):
            v4.evaluate_campaign(self.path, self.campaign)

    def test_missing_cleanup_and_old_csv_are_not_successful_negatives(self):
        p = self.freeze()
        self.cases(p, 1)
        result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["status"], "INCOMPLETE_OR_INVALID")
        self.assertEqual(len(result["missing_runs"]), 11)
        case = p["cases"][0]
        self.record(case["case_id"], lambda r: r.update(cleanup_errors=["qdisc"]))
        result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["evaluated_runs"], 0)
        self.assertIn("cleanup", result["invalid_runs"][0]["error"])
        self.record(case["case_id"], lambda r: r.update(cleanup_errors=[]))
        target = self.campaign / case["case_id"] / "port_utilization_domain0.csv"
        source = self.source_campaign / case["case_id"] / target.name
        target.write_bytes(source.read_bytes())
        self.record(case["case_id"], lambda r: r["sources"][0].update(sha256=v1.digest_file(target)))
        result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["evaluated_runs"], 0)

    def test_reused_and_overlapping_fresh_runs_are_rejected(self):
        p = self.freeze()
        self.cases(p, 2)
        real = v1._read_case

        def reused(protocol, case, root):
            subjects, record, hashes = real(protocol, case, root)
            return subjects, record, (["shared0", "shared1"] if root.parent == self.campaign else hashes)

        with patch.object(v1, "_read_case", side_effect=reused):
            result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["evaluated_runs"], 1)
        self.assertIn("reutilizado", result["invalid_runs"][0]["error"])

        def overlap(protocol, case, root):
            subjects, record, hashes = real(protocol, case, root)
            if root.parent == self.campaign:
                record["started_ns"] = p["created_ns"] + 100_000_000_000
                record["ended_ns"] = record["started_ns"] + 150_000_000_000
            return subjects, record, hashes

        with patch.object(v1, "_read_case", side_effect=overlap):
            result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["evaluated_runs"], 1)
        self.assertIn("sobrepostas", result["invalid_runs"][0]["error"])

    def test_pre_freeze_timing_checksum_and_mid_replay_change_are_visible(self):
        p = self.freeze()
        self.cases(p, 1)
        case = p["cases"][0]
        path = self.campaign / case["case_id"] / "run.json"
        saved = path.read_bytes()
        self.record(case["case_id"], lambda r: r.update(started_ns=p["created_ns"] - 1))
        result = v4.evaluate_campaign(self.path, self.campaign)
        self.assertEqual(result["evaluated_runs"], 0)
        self.assertIn("posterior", result["invalid_runs"][0]["error"])
        path.write_bytes(saved)
        real = v4.replay_candidate

        def mutate(*args):
            result = real(*args)
            path.write_bytes(path.read_bytes() + b" ")
            return result

        with patch.object(v4, "replay_candidate", side_effect=mutate), self.assertRaisesRegex(ValueError, "mudaram"):
            v4.evaluate_campaign(self.path, self.campaign)

    def test_cli_compact_no_tuning_and_foreign_or_symlink_campaign_refused(self):
        with patch.object(v4.time, "time_ns", return_value=self.freeze_time), patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(v4.main(self.args()), 0)
        self.assertEqual(len(out.getvalue().splitlines()), 5)
        p = v4.load_protocol(self.path)
        self.cases(p, 1)
        for output in (self.source_campaign, self.path.parent / "models", self.path.parent / "new-runs"):
            with self.assertRaises(ValueError):
                v4.campaign_path(self.path, output)
        link = self.path.parent / "campaign-link"
        link.symlink_to(self.source_campaign, target_is_directory=True)
        with self.assertRaises(ValueError):
            v4.campaign_path(self.path, link)
        args = ["evaluate", "--protocol", str(self.path), "--campaign-root", str(self.campaign),
                "--output", str(self.path.parent / "campaign-review-v1.json")]
        with patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(v4.main(args), 2)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        with patch("sys.stderr", io.StringIO()):
            self.assertEqual(v4.main(args), 2)
            with self.assertRaises(SystemExit):
                v4.main(args + ["--threshold", ".7"])


class CollectorV4Tests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.path = Path(temporary.name) / "protocol.json"
        self.output = self.path.parent / "campaign"
        self.protocol = dict(cases=[dict(case_id="r01"), dict(case_id="r02")])
        load = patch.object(collector, "load_protocol", return_value=self.protocol)
        load.start()
        self.addCleanup(load.stop)
        self.safety = dict(status="READY", safety=[{}, {}])

    def args(self, output=None):
        return ["--protocol", str(self.path), "--output", str(output or self.output), "--allow-lab-traffic"]

    def test_preflight_read_only_and_traffic_requires_opt_in(self):
        with patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case") as traffic, patch("sys.stdout", io.StringIO()) as out:
            self.assertEqual(collector.main(["--protocol", str(self.path), "--preflight-only"]), 0)
        self.assertEqual(len(out.getvalue().splitlines()), 1)
        self.assertIn("actuation=false", out.getvalue())
        self.assertFalse(self.output.exists())
        traffic.assert_not_called()
        with patch("sys.stderr", io.StringIO()), patch.object(old_collector, "preflight") as preflight:
            self.assertEqual(collector.main(["--protocol", str(self.path), "--output", str(self.output)]), 2)
        preflight.assert_not_called()

    def test_non_linux_existing_output_or_unsafe_preflight_never_start_traffic(self):
        with patch.object(collector.sys, "platform", "darwin"), patch("sys.stderr", io.StringIO()):
            self.assertEqual(collector.main(self.args()), 2)
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", side_effect=ValueError("unsafe runtime")), \
                patch.object(old_collector, "collect_case") as traffic, patch("sys.stderr", io.StringIO()):
            self.assertEqual(collector.main(self.args()), 2)
        traffic.assert_not_called()
        self.assertFalse(self.output.exists())
        self.output.mkdir()
        with patch.object(collector.sys, "platform", "linux"), patch.object(old_collector, "preflight") as preflight, \
                patch("sys.stderr", io.StringIO()):
            self.assertEqual(collector.main(self.args()), 2)
        preflight.assert_not_called()

    def test_cross_version_lock_failure_prevents_preflight(self):
        with patch.object(collector.sys, "platform", "linux"), patch("sys.stderr", io.StringIO()), \
                patch.object(collector.fcntl, "flock", side_effect=BlockingIOError("locked")), \
                patch.object(old_collector, "preflight") as preflight:
            self.assertEqual(collector.main(self.args()), 2)
        preflight.assert_not_called()
        self.assertFalse(self.output.exists())

    def test_mock_collection_reports_failure_without_changing_rules_or_runtime(self):
        report = dict(status="COMPLETED", evaluated_runs=12, criteria_status="NOT_PASSED")
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case") as traffic, \
                patch.object(collector, "evaluate_campaign", return_value=report), patch("sys.stdout", io.StringIO()):
            self.assertEqual(collector.main(self.args()), 3)
        self.assertEqual(traffic.call_count, 2)
        self.assertEqual(json.loads((self.output / "campaign-summary.json").read_text()), report)

    def test_interrupt_or_changed_protocol_preserves_partial_artifacts(self):
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(old_collector, "collect_case", side_effect=KeyboardInterrupt), patch("sys.stderr", io.StringIO()):
            self.assertEqual(collector.main(self.args()), 130)
        self.assertTrue((self.output / "campaign-plan.json").exists())
        self.assertFalse((self.output / "campaign-summary.json").exists())
        changed = self.path.parent / "campaign-changed"
        with patch.object(collector.sys, "platform", "linux"), patch.object(collector.fcntl, "flock"), \
                patch.object(old_collector, "preflight", return_value=self.safety), \
                patch.object(collector, "load_protocol", side_effect=[self.protocol, dict(cases=[])]), \
                patch.object(old_collector, "collect_case") as traffic, patch("sys.stderr", io.StringIO()):
            self.assertEqual(collector.main(self.args(changed)), 2)
        traffic.assert_not_called()
        self.assertFalse((changed / "campaign-summary.json").exists())


if __name__ == "__main__":
    unittest.main()
