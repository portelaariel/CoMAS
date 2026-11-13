import copy
import csv
import io
import json
import math
import tempfile
import unittest
from pathlib import Path
from unittest.mock import Mock, patch

import predictive_sla_validation as validation
from qos_holt import HorizonModel, QosHoltModel
from qos_telemetry import QosDatasetExporter
from scripts import collect_qos_validation_campaign as collector
from train_qos_holt_model import MANIFEST_SCHEMA, load_manifest


def create_pilot(root):
    root.mkdir()
    entries = []
    for subject in validation.SUBJECTS:
        path = root / f"pilot-{subject['cid']}.csv"
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "cid", "port_id", "ts_ns", "utilization_ratio", "quality"])
            writer.writeheader()
            for index in range(90):
                writer.writerow(dict(cid=subject["cid"], port_id=subject["port_id"],
                                     ts_ns=1_000_000_000 + index * 2_000_000_000,
                                     utilization_ratio=0.1 + (index % 30) * 0.03,
                                     quality="VALID"))
        for index, split in enumerate(("train", "calibration", "test")):
            entries.append(dict(series_id=f"{subject['cid']}-{split}", split=split,
                                cid=subject["cid"], port_id=subject["port_id"], csv=str(path),
                                start_ns=1_000_000_000 + index * 60_000_000_000,
                                end_ns=1_000_000_000 + (index + 1) * 60_000_000_000))
    manifest = root / "qos-holt-manifest-v1.json"
    manifest.write_text(json.dumps(dict(schema_version=MANIFEST_SCHEMA,
                                       validation_scope="pilot_single_run_temporal_split",
                                       sample_interval_s=2, horizons_steps=[2, 4, 6],
                                       coverage=0.95, priming_samples=2, series=entries)))
    _, _, metadata = load_manifest(manifest)
    for name, coverage, radius in (("model-v1", 0.95, 0.3),
                                   ("model-v1-coverage90", 0.9, 0.1)):
        directory = root / name
        directory.mkdir()
        QosHoltModel(metric="utilization_ratio", sample_interval_s=2, coverage=coverage,
                     priming_samples=2, created_at="2026-09-25T00:00:00Z", training=metadata,
                     horizons=tuple(HorizonModel(horizon_steps=step, alpha=0.5, beta=0.2,
                                                 interval_radius=radius, calibration_samples=20)
                                    for step in (2, 4, 6))).save(directory / "qos-holt-model.json")


def create_case(protocol, case, campaign, ordinal=0):
    root = campaign / case["case_id"]
    root.mkdir(parents=True)
    start = protocol["created_ns"] + (100 + ordinal * 500) * 1_000_000_000
    end = start + case["duration_s"] * 1_000_000_000
    workload = []
    cursor = start
    for stage in case["stages"]:
        finish = cursor + stage["duration_s"] * 1_000_000_000
        workload.append({**stage, "start_ns": cursor, "end_ns": finish})
        cursor = finish
    sources = []
    for number, subject in enumerate(protocol["subjects"]):
        path = root / f"port_utilization_domain{number}.csv"
        with path.open("w", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=[
                "cid", "port_id", "ts_ns", "utilization_ratio", "capacity_bps", "quality"])
            writer.writeheader()
            for seconds in range(1, case["duration_s"], 2):
                timestamp = start + seconds * 1_000_000_000
                stage = next(row for row in workload if row["start_ns"] <= timestamp < row["end_ns"])
                writer.writerow(dict(cid=subject["cid"], port_id=subject["port_id"],
                                     ts_ns=timestamp, capacity_bps=subject["capacity_bps"],
                                     utilization_ratio=stage["rate_mbit"] / 100 + number * 0.001,
                                     quality="VALID"))
        sources.append(dict(cid=subject["cid"], port_id=subject["port_id"], csv=path.name,
                            sha256=validation.digest_file(path)))
    record = dict(schema_version=validation.RUN_SCHEMA, protocol_sha256=protocol["protocol_sha256"],
                  case_id=case["case_id"], status="COMPLETED", started_ns=start, ended_ns=end,
                  workload=workload, sources=sources)
    (root / "run.json").write_text(json.dumps(validation.seal(record, "run_sha256")))
    return root


class ProspectiveValidationTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.pilot = self.root / "pilot"
        create_pilot(self.pilot)
        self.protocol_path = self.root / "frozen/protocol.json"
        self.protocol = validation.freeze_protocol(self.pilot, self.protocol_path.parent, 1)
        self.campaign = self.root / "new-runs"

    def test_freeze_copies_exact_artifacts_without_training_or_network(self):
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            loaded = validation.load_protocol(self.protocol_path)
        self.assertEqual(loaded["policy"], validation.POLICY)
        self.assertFalse(loaded["promotion_eligible"])
        for name, directory in (("coverage90", "model-v1-coverage90"), ("coverage95", "model-v1")):
            self.assertEqual((self.pilot / directory / "qos-holt-model.json").read_bytes(),
                             (self.protocol_path.parent / loaded["models"][name]["path"]).read_bytes())
        with self.assertRaises(FileExistsError):
            validation.freeze_protocol(self.pilot, self.protocol_path.parent)

    def test_rotated_four_profiles_and_three_repetitions_are_fixed(self):
        cases = validation.planned_cases(3)
        self.assertEqual(len(cases), 12)
        self.assertEqual(len({row["case_id"] for row in cases}), 12)
        self.assertEqual([cases[index]["profile"] for index in (0, 4, 8)],
                         ["stable-low", "short-pulses", "slow-ramp"])
        for repetitions in (0, 11, True, 1.5):
            with self.assertRaises(ValueError):
                validation.planned_cases(repetitions)

    def test_protocol_model_and_code_tampering_are_rejected(self):
        with patch.object(validation, "digest_file", return_value="modified"):
            with self.assertRaisesRegex(ValueError, "código"):
                validation.load_protocol(self.protocol_path)
        original = self.protocol_path.read_text()
        for field, value in (("policy", {**validation.POLICY, "threshold": 0.7}),
                             ("collection", {**validation.COLLECTION, "offered_rate_mbit": 999}),
                             ("promotion_eligible", True)):
            payload = {**self.protocol, field: value}
            self.protocol_path.write_text(json.dumps(payload))
            with self.assertRaisesRegex(ValueError, "checksum"):
                validation.load_protocol(self.protocol_path)
            self.protocol_path.write_text(json.dumps(validation.seal(payload, "protocol_sha256")))
            with self.assertRaisesRegex(ValueError, "configuração"):
                validation.load_protocol(self.protocol_path)
        self.protocol_path.write_text(original)
        path = self.protocol_path.parent / "models/coverage90.json"
        path.write_text(path.read_text() + " ")
        with self.assertRaisesRegex(ValueError, "hash do modelo"):
            validation.load_protocol(self.protocol_path)

    def test_complete_fresh_runs_use_frozen_models_not_refitting(self):
        before = {name: validation.digest_file(self.protocol_path.parent / value["path"])
                  for name, value in self.protocol["models"].items()}
        for index, case in enumerate(self.protocol["cases"]):
            create_case(self.protocol, case, self.campaign, index)
        with patch("qos_holt.train_qos_holt_model", side_effect=AssertionError("refit")), \
                patch("urllib.request.urlopen", side_effect=AssertionError("network")):
            report = validation.evaluate_campaign(self.protocol_path, self.campaign)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["evaluated_runs"], 4)
        self.assertFalse(report["promotion_eligible"])
        self.assertTrue(all(row["point_forecasts_identical"] and row["candidate_decisions_identical"]
                            for row in report["cases"]))
        self.assertEqual(report["models"]["coverage90"]["episode_events"]["timing_basis"], "csv_timestamps")
        self.assertEqual(before, {name: validation.digest_file(self.protocol_path.parent / value["path"])
                                 for name, value in self.protocol["models"].items()})
        self.assertEqual(len(report["cases"][0]["delivery_checks"]), 2)

    def test_missing_and_failed_runs_are_not_counted_as_successful_negatives(self):
        case = self.protocol["cases"][0]
        root = create_case(self.protocol, case, self.campaign)
        record = json.loads((root / "run.json").read_text())
        record["status"] = "FAILED"
        (root / "run.json").write_text(json.dumps(validation.seal(record, "run_sha256")))
        result = validation.evaluate_campaign(self.protocol_path, self.campaign)
        self.assertEqual(result["status"], "INCOMPLETE_OR_INVALID")
        self.assertEqual(result["evaluated_runs"], 0)
        self.assertEqual(len(result["invalid_runs"]), 1)
        self.assertEqual(len(result["missing_runs"]), 3)
        self.assertEqual(result["models"]["coverage90"]["pooled_window_candidate"]["confusion"]["TN"], 0)

    def test_bad_timestamps_gaps_capacity_quality_and_flat_traffic_are_rejected(self):
        case = self.protocol["cases"][0]
        root = create_case(self.protocol, case, self.campaign)
        record = json.loads((root / "run.json").read_text())
        path = root / record["sources"][0]["csv"]
        with path.open() as handle:
            rows = list(csv.DictReader(handle))
        variants = []
        for field, value in (("quality", "COUNTER_RESET"), ("capacity_bps", "1"),
                             ("utilization_ratio", "nan"), ("ts_ns", rows[0]["ts_ns"]),
                             ("cid", "wrong-domain")):
            modified = copy.deepcopy(rows)
            modified[1][field] = value
            variants.append(modified)
        variants.append(rows[:10] + rows[13:])  # Eight-second gap.
        variants.append([{**row, "utilization_ratio": "0.000001"} for row in rows])
        for modified in variants:
            with self.subTest(first=modified[1]):
                with path.open("w", newline="") as handle:
                    writer = csv.DictWriter(handle, fieldnames=list(rows[0]))
                    writer.writeheader()
                    writer.writerows(modified)
                record["sources"][0]["sha256"] = validation.digest_file(path)
                (root / "run.json").write_text(json.dumps(validation.seal(record, "run_sha256")))
                with self.assertRaises(ValueError):
                    validation._read_case(self.protocol, case, root)

    def test_csv_hash_and_workload_identity_are_required(self):
        case = self.protocol["cases"][0]
        root = create_case(self.protocol, case, self.campaign)
        record_path = root / "run.json"
        original = json.loads(record_path.read_text())
        for mutate in (lambda row: row.update(started_ns=self.protocol["created_ns"] - 1),
                       lambda row: row["workload"][0].update(rate_mbit=999),
                       lambda row: row["sources"][0].update(csv="../../outside.csv"),
                       lambda row: row["sources"][0].update(sha256="modified")):
            payload = copy.deepcopy(original)
            mutate(payload)
            record_path.write_text(json.dumps(validation.seal(payload, "run_sha256")))
            with self.assertRaises(ValueError):
                validation._read_case(self.protocol, case, root)

    def test_overlapping_workload_runs_are_not_pooled(self):
        for case in self.protocol["cases"][:2]:
            create_case(self.protocol, case, self.campaign, 0)
        report = validation.evaluate_campaign(self.protocol_path, self.campaign)
        self.assertEqual(report["evaluated_runs"], 1)
        self.assertIn("sobrepostas", report["invalid_runs"][0]["error"])

    def test_cli_preserves_existing_outputs(self):
        output = self.root / "summary.json"
        output.write_text("preserve me")
        with patch("sys.stderr", new=io.StringIO()):
            status = validation.main(["evaluate", "--protocol", str(self.protocol_path),
                                      "--campaign-root", str(self.campaign), "--output", str(output)])
        self.assertEqual(status, 2)
        self.assertEqual(output.read_text(), "preserve me")


def safe_status(subject):
    return dict(cid=subject["cid"], config=dict(auto_mitigate=False, dry_run=True,
                agentic_mode="shadow", agentic_live_actuation_opt_in=False,
                poll_interval_s=2, qos_telemetry_enabled=True),
                agentic=dict(actuation_enabled=False, live_executions=0))


class CollectionSafetyTests(unittest.TestCase):
    def test_safety_guard_rejects_missing_unsafe_or_live_settings(self):
        subject = validation.SUBJECTS[0]
        self.assertFalse(collector.guard_status(safe_status(subject), subject)["actuation_enabled"])
        for field, value in (("dry_run", False), ("auto_mitigate", True),
                             ("agentic_mode", "authority-live"),
                             ("agentic_live_actuation_opt_in", True), ("poll_interval_s", 3)):
            payload = safe_status(subject)
            payload["config"][field] = value
            with self.assertRaises(ValueError):
                collector.guard_status(payload, subject)
        for payload in (dict(cid=subject["cid"]),
                        {**safe_status(subject), "agentic": dict(actuation_enabled=False, live_executions=1)},
                        {**safe_status(subject), "cid": "wrong"}):
            with self.assertRaises(ValueError):
                collector.guard_status(payload, subject)

    def test_latest_telemetry_requires_schema_identity_and_freshness(self):
        subject = validation.SUBJECTS[0]
        sample = {field: 0 for field in QosDatasetExporter.HEADER}
        sample.update(cid=subject["cid"], port_id=subject["port_id"], capacity_bps=100_000_000,
                      ts_ns=10_000_000_000, quality="VALID")
        with patch.object(collector.time, "time_ns", return_value=11_000_000_000):
            self.assertEqual(collector.latest_sample(dict(enabled=True, latest=[sample]), subject), sample)
            for changed in ({**sample, "ts_ns": 1}, {**sample, "cid": "wrong"},
                            {**sample, "capacity_bps": 1}, {**sample, "ts_ns": True},
                            {key: value for key, value in sample.items() if key != "quality"}):
                with self.assertRaises(ValueError):
                    collector.latest_sample(dict(enabled=True, latest=[changed]), subject)

    def test_exact_persistent_flows_are_required_and_drops_rejected(self):
        text = ("cookie=0x51534c41, priority=3100,ip,in_port=1,nw_src=10.0.0.1,nw_dst=10.0.0.8 actions=output:3\n"
                "cookie=0x51534c41, priority=3100,ip,in_port=3,nw_src=10.0.0.8,nw_dst=10.0.0.1 actions=output:1")
        collector.check_flows(text, "s1", 1, 3)
        for changed in (text.replace("output:3", "output:2"), text.replace("0x51534c41", "0x0"),
                        text.replace("priority=3100", "idle_timeout=30,priority=3100"),
                        text + "\npriority=999 actions=drop", text + "\npriority=999 actions="):
            with self.assertRaises(ValueError):
                collector.check_flows(changed, "s1", 1, 3)

    def test_no_collection_without_explicit_traffic_opt_in(self):
        with patch.object(collector, "load_protocol", return_value={}), \
                patch.object(collector, "preflight") as check, \
                patch.object(collector.subprocess, "Popen") as spawn, \
                patch("sys.stderr", new=io.StringIO()):
            self.assertEqual(collector.main(["--protocol", "not-used.json"]), 2)
        check.assert_not_called()
        spawn.assert_not_called()

    def test_preflight_cli_never_starts_processes(self):
        with patch.object(collector, "load_protocol", return_value={}), \
                patch.object(collector, "preflight", return_value=dict(status="READY", safety=[{}, {}])), \
                patch.object(collector.subprocess, "Popen") as spawn, \
                patch("sys.stdout", new=io.StringIO()):
            self.assertEqual(collector.main(["--protocol", "unused.json", "--preflight-only"]), 0)
        spawn.assert_not_called()

    def test_cleanup_signals_only_owned_process_group(self):
        process = Mock(pid=12345)
        process.poll.return_value = None
        with patch.object(collector, "command") as run:
            collector.stop_owned_process(process)
        run.assert_called_once_with(["sudo", "-n", "kill", "-INT", "--", "-12345"], allow_absent=True)
        process.wait.assert_called_once_with(timeout=3)

    def test_partial_case_is_preserved_and_cleanup_cannot_delete_changed_qdisc(self):
        snapshot = dict(hosts=dict(h1=dict(pid=1, namespace="net1"), h8=dict(pid=8, namespace="net8")))
        protocol = dict(protocol_sha256="fixture", collection=validation.COLLECTION, subjects=validation.SUBJECTS)
        case = validation.planned_cases(1)[0]
        for current_handle, expected_cleanup in (("7a51:", True), ("other:", False)):
            with self.subTest(handle=current_handle), tempfile.TemporaryDirectory() as directory:
                calls = []

                def host_command(pid, arguments):
                    calls.append(arguments)
                    if arguments[:2] == ["tc", "class"]:
                        raise ValueError("shaper setup failed")
                    return ""

                root = Path(directory) / "partial"
                with patch.object(collector, "preflight", return_value=snapshot), \
                        patch.object(collector, "host_command", side_effect=host_command), \
                        patch.object(collector, "namespace", return_value="net1"), \
                        patch.object(collector, "root_qdisc", return_value=dict(handle=current_handle)):
                    with self.assertRaisesRegex(ValueError, "setup failed"):
                        collector.collect_case(protocol, case, root)
                record = json.loads((root / "run.json").read_text())
                self.assertEqual(record["status"], "FAILED")
                self.assertEqual(record, validation.seal(record, "run_sha256"))
                deletion = [row for row in calls if row[:3] == ["tc", "qdisc", "del"]]
                self.assertEqual(bool(deletion), expected_cleanup)
                if deletion:
                    self.assertEqual(deletion[0][-1], "7a51:")

    def test_mocked_collection_deduplicates_samples_and_cleans_up_after_safety_failure(self):
        # Simulated time, processes and REST only: this test never enters a real namespace.
        for unsafe in (False, True):
            with self.subTest(unsafe=unsafe), tempfile.TemporaryDirectory() as directory:
                clock = dict(ns=1_800_000_000_000_000_000, rate=20, status_calls=0)
                snapshot = dict(hosts=dict(h1=dict(pid=1, namespace="net1"),
                                          h8=dict(pid=8, namespace="net8")))
                protocol = dict(protocol_sha256="fixture", collection=validation.COLLECTION,
                                subjects=validation.SUBJECTS)
                case = dict(case_id="mock", duration_s=12,
                            stages=[dict(rate_mbit=rate, duration_s=4) for rate in (20, 50, 20)])
                processes = []
                commands = []

                def spawn(*args, **kwargs):
                    self.assertTrue(kwargs["start_new_session"])
                    process = Mock(pid=100 + len(processes))
                    process.poll.return_value = None
                    process.wait.side_effect = lambda timeout: setattr(process.poll, "return_value", -2)
                    processes.append(process)
                    return process

                def host_command(pid, arguments):
                    commands.append(arguments)
                    if arguments[:3] == ["tc", "class", "change"]:
                        clock["rate"] = int(arguments[arguments.index("rate") + 1].removesuffix("mbit"))
                    return ""

                def get_json(url):
                    subject = next(row for row in validation.SUBJECTS if url.startswith(row["url"]))
                    if url.endswith("/status"):
                        clock["status_calls"] += 1
                        payload = safe_status(subject)
                        if unsafe and clock["status_calls"] > 2:
                            payload["config"]["auto_mitigate"] = True
                        return payload
                    sample = {field: 0 for field in QosDatasetExporter.HEADER}
                    sample.update(cid=subject["cid"], port_id=subject["port_id"], quality="VALID",
                                  ts_ns=(clock["ns"] // 2_000_000_000) * 2_000_000_000,
                                  utilization_ratio=clock["rate"] / 100, capacity_bps=100_000_000)
                    return dict(enabled=True, latest=[sample])

                def advance(seconds):
                    clock["ns"] += math.ceil(seconds * 1_000_000_000) + 1

                root = Path(directory) / "run"
                with patch.object(collector, "preflight", return_value=snapshot), \
                        patch.object(collector, "host_command", side_effect=host_command), \
                        patch.object(collector, "command") as signal_command, \
                        patch.object(collector, "namespace", side_effect=lambda pid: f"net{pid}"), \
                        patch.object(collector, "root_qdisc", return_value=dict(handle="7a51:")), \
                        patch.object(collector, "get_json", side_effect=get_json), \
                        patch.object(collector.subprocess, "Popen", side_effect=spawn), \
                        patch.object(collector.time, "time_ns", side_effect=lambda: clock["ns"]), \
                        patch.object(collector.time, "monotonic", side_effect=lambda: clock["ns"] / 1e9), \
                        patch.object(collector.time, "sleep", side_effect=advance), \
                        patch("sys.stdout", new=io.StringIO()):
                    if unsafe:
                        with self.assertRaisesRegex(ValueError, "configuração insegura"):
                            collector.collect_case(protocol, case, root)
                    else:
                        collector.collect_case(protocol, case, root)
                record = json.loads((root / "run.json").read_text())
                self.assertEqual(record["status"], "FAILED" if unsafe else "COMPLETED")
                self.assertEqual(record["process_return_codes_after_cleanup"], [-2, -2])
                self.assertEqual(len(record["sources"]), 2)
                self.assertEqual(signal_command.call_count, 2)
                self.assertEqual(commands[-1], ["tc", "qdisc", "del", "dev", "h1-eth0", "root", "handle", "7a51:"])
                for source in record["sources"]:
                    with (root / source["csv"]).open() as handle:
                        rows = list(csv.DictReader(handle))
                    times = [int(row["ts_ns"]) for row in rows]
                    self.assertTrue(times)
                    self.assertEqual(times, sorted(set(times)))
                    self.assertTrue(all(record["started_ns"] <= ts <= record["ended_ns"] for ts in times))


if __name__ == "__main__":
    unittest.main()
