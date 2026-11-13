import copy
from dataclasses import replace
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import predictive_sla_validation as validation
from scripts import recover_qos_runtime as recovery
from test_predictive_sla_validation import create_pilot


class FakeDocker:
    def __init__(self, originals):
        self.originals = copy.deepcopy(originals)
        self.copies = {}
        self.calls = []
        self.fail_start = False
        self.bad_mount = False
        self.occupied = []

    def __call__(self, *args):
        self.calls.append(args)
        if args[0] == "ps":
            return "\n".join([*self.originals, *self.occupied])
        if args[:2] == ("image", "inspect"):
            return json.dumps([{"Config": {"Cmd": ["python3", "flow_predictor_cnsm.py"],
                                          "WorkingDir": "/app"}}])
        if args[0] == "inspect":
            return json.dumps([self.originals.get(name) or self.copies[name] for name in args[1:]])
        if args[0] == "create":
            identity = str(len(self.copies) + 1) * 64
            mounts, env = [], []
            for index, value in enumerate(args[:-1]):
                if value == "--env":
                    env.append(args[index + 1])
                elif value == "--mount":
                    options = dict(part.split("=", 1) if "=" in part else (part, True)
                                   for part in args[index + 1].split(","))
                    mounts.append(dict(Type="bind", Source=options["src"],
                                       Destination=options["dst"], RW="readonly" not in options))
            if self.bad_mount:
                mounts[0]["Source"] = "/unexpected-volume"
            primary = args[args.index("--network") + 1]
            self.copies[identity] = dict(Id=identity, Image=args[-1], Mounts=mounts,
                                         Config={"Env": env}, NetworkSettings={"Networks": {primary: {}}})
            return identity
        if args[:2] == ("network", "connect"):
            self.copies[args[3]]["NetworkSettings"]["Networks"][args[2]] = {}
            return ""
        if args[0] == "start":
            if self.fail_start:
                raise ValueError("simulated Docker failure")
            return "\n".join(args[1:])
        if args[0] == "stop":
            return "\n".join(args[1:])
        raise AssertionError(args)


class QosRuntimeRecoveryTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.pilot = self.root / "pilot"
        create_pilot(self.pilot)
        # Match the real testbed: models reference immutable copies, while
        # Docker binds the separate append-only collection histories.
        frozen = self.pilot / "frozen"
        frozen.mkdir()
        manifest_path = self.pilot / "qos-holt-manifest-v1.json"
        manifest = json.loads(manifest_path.read_text())
        self.training_csvs = []
        for index, subject in enumerate(validation.SUBJECTS):
            path = frozen / f"port_utilization_domain{index}.csv"
            path.write_bytes((self.pilot / f"pilot-{subject['cid']}.csv").read_bytes())
            self.training_csvs.append(path)
            for entry in manifest["series"]:
                if entry["cid"] == subject["cid"]:
                    entry["csv"] = str(path)
        manifest_path.write_text(json.dumps(manifest))
        _, _, metadata = validation.load_manifest(manifest_path)
        for name in ("model-v1", "model-v1-coverage90"):
            path = self.pilot / name / "qos-holt-model.json"
            model = recovery.QosHoltModel.load(path)
            replace(model, training=metadata, model_id="").save(path)
        self.protocol_path = self.root / "frozen/protocol.json"
        self.protocol = validation.freeze_protocol(self.pilot, self.protocol_path.parent, 1)
        self.output = self.protocol_path.parent / "runtime"
        self.originals = {}
        for index, subject in enumerate(validation.SUBJECTS):
            history = self.pilot / f"qos_history_domain{index}"
            history.mkdir()
            content = self.training_csvs[index].read_bytes()
            (history / "port_utilization.csv").write_bytes(content + content.splitlines(keepends=True)[-1])
            prediction = self.pilot / f"prediction_history_domain{index}"
            prediction.mkdir()
            env = dict(AUTO_MITIGATE="false", DRY_RUN="true", AGENTIC_MODE="shadow",
                       AGENTIC_LIVE_ACTUATION="false", QOS_TELEMETRY_ENABLED="true",
                       CONTROLLER_ID=subject["cid"], PORT=str(6060 + index),
                       QOS_DATASET_DIR="/app/qos_history", EXPORT_DIR="/app/prediction_history",
                       POLL_INTERVAL_S="2", QOS_PORT_CAPACITIES_JSON=json.dumps(
                           {subject["port_id"]: subject["capacity_bps"]}),
                       PRIVATE_SETTING="not-for-receipt")
            network = f"ryu-network-{index}"
            name = f"flow-predictor-{index}"
            self.originals[name] = dict(
                Id=f"original-{index}", Name=f"/{name}", Image="sha256:frozen-image",
                State={"Status": "exited", "Running": False},
                Config={"Env": [f"{key}={value}" for key, value in env.items()],
                        "Cmd": ["python3", "flow_predictor_cnsm.py"], "WorkingDir": "/app"},
                HostConfig={"NetworkMode": network, "PidsLimit": -1,
                            "RestartPolicy": {"Name": "no"},
                            "PortBindings": {f"{6060 + index}/tcp": [
                                {"HostIp": "", "HostPort": str(6060 + index)}]}},
                NetworkSettings={"Networks": {network: {}, "etcd-network": {}}},
                Mounts=[dict(Type="bind", Source=str(history), Destination="/app/qos_history", RW=True),
                        dict(Type="bind", Source=str(prediction), Destination="/app/prediction_history", RW=True),
                        dict(Type="bind", Source=str(self.pilot / "model-v1/qos-holt-model.json"),
                             Destination="/app/model.json", RW=False)])
        self.docker = FakeDocker(self.originals)
        patcher = patch.object(recovery, "docker", self.docker)
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_default_plan_is_read_only_and_keeps_protocol_and_environment(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        self.assertEqual(protocol["protocol_sha256"], self.protocol["protocol_sha256"])
        self.assertFalse(self.output.exists())
        self.assertTrue(all(call[0] in ("ps", "inspect", "image") for call in self.docker.calls))
        for index, plan in enumerate(plans):
            self.assertEqual(plan["env"], self.originals[f"flow-predictor-{index}"]["Config"]["Env"])
            self.assertEqual(plan["image"], "sha256:frozen-image")
            self.assertEqual(plan["additional_networks"], ["etcd-network"])
            self.assertNotIn("env", recovery.public_plan(plan))

    def test_apply_remaps_histories_and_starts_only_copies_after_verification(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        before = [validation.digest_file(Path(plan["protected_sources"][0]["path"])) for plan in plans]
        recovery.apply(self.protocol_path, self.output, protocol, plans)
        receipt_text = (self.output / "recovery.json").read_text()
        receipt = json.loads(receipt_text)
        self.assertEqual(receipt["status"], "START_REQUESTED")
        self.assertNotIn("not-for-receipt", receipt_text)
        self.assertEqual(before, [validation.digest_file(Path(plan["protected_sources"][0]["path"]))
                                  for plan in plans])
        starts = [call for call in self.docker.calls if call[0] == "start"]
        self.assertEqual(starts, [("start", *receipt["created_container_ids"])])
        self.assertTrue(all(call[0] not in ("rm", "rename") for call in self.docker.calls))
        for row in self.docker.copies.values():
            for mount in row["Mounts"]:
                if mount["RW"]:
                    self.assertTrue(Path(mount["Source"]).is_relative_to(self.output.resolve()))
                else:
                    self.assertEqual(mount["Destination"], "/app/model.json")
        self.assertEqual(validation.load_protocol(self.protocol_path), protocol)

    def test_unsafe_original_configuration_is_rejected_without_writes(self):
        variants = [
            lambda row: row["State"].update(Status="running", Running=True),
            lambda row: row["Config"]["Env"].append("DRY_RUN=false"),
            lambda row: row["HostConfig"].update(Privileged=True),
            lambda row: row["HostConfig"].update(PidsLimit=12),
            lambda row: row["HostConfig"].update(RestartPolicy={"Name": "always"}),
            lambda row: row["Config"].update(Cmd=["custom-command"]),
            lambda row: row["Mounts"][-1].update(RW=True),
            lambda row: row["Mounts"][0].update(Propagation="rshared"),
        ]
        for modify in variants:
            self.docker.originals = copy.deepcopy(self.originals)
            modify(self.docker.originals["flow-predictor-0"])
            with self.subTest(modify=modify), self.assertRaises(ValueError):
                recovery.prepare(self.protocol_path, self.output)
            self.assertFalse(self.output.exists())
        self.assertTrue(all(call[0] in ("ps", "inspect", "image") for call in self.docker.calls))

    def test_existing_names_outputs_and_overlapping_volumes_are_protected(self):
        self.docker.occupied = ["comas-qos-prospective-0"]
        with self.assertRaisesRegex(ValueError, "já existe"):
            recovery.prepare(self.protocol_path, self.output)
        self.docker.occupied = []
        self.output.mkdir()
        with self.assertRaisesRegex(ValueError, "novo diretório"):
            recovery.prepare(self.protocol_path, self.output)
        with self.assertRaisesRegex(ValueError, "novo diretório"):
            recovery.prepare(self.protocol_path, self.pilot / "runtime")
        self.docker.originals["flow-predictor-0"]["Mounts"][-1]["Source"] = str(self.protocol_path.parent)
        with self.assertRaisesRegex(ValueError, "sobrepõe"):
            recovery.prepare(self.protocol_path, self.protocol_path.parent / "other-runtime")

    def test_separate_growing_histories_are_not_mistaken_for_training_sources(self):
        _, plans = recovery.prepare(self.protocol_path, self.output)
        for index, plan in enumerate(plans):
            sources = {source["role"]: source for source in plan["protected_sources"]}
            self.assertEqual(sources["training_source"]["path"], str(self.training_csvs[index].resolve()))
            self.assertNotEqual(sources["training_source"]["sha256"], sources["collection_history"]["sha256"])
            self.assertNotEqual(sources["training_source"]["path"], sources["collection_history"]["path"])
        self.assertFalse(self.output.exists())

    def test_changed_training_csv_is_rejected(self):
        source = self.training_csvs[0]
        source.write_text(source.read_text() + "modified\n")
        with self.assertRaisesRegex(ValueError, "CSV de treinamento diverge"):
            recovery.prepare(self.protocol_path, self.output)
        self.assertFalse(self.output.exists())

    def test_missing_training_csv_is_rejected(self):
        self.training_csvs[0].rename(self.root / "moved.csv")
        with self.assertRaises(FileNotFoundError):
            recovery.prepare(self.protocol_path, self.output)
        self.assertFalse(self.output.exists())

    def test_both_source_roles_are_rechecked_before_any_creation(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        for source in plans[0]["protected_sources"]:
            path = Path(source["path"])
            original = path.read_bytes()
            path.write_bytes(original + b"modified\n")
            with self.subTest(role=source["role"]), self.assertRaisesRegex(ValueError, source["role"]):
                recovery.apply(self.protocol_path, self.output, protocol, plans)
            self.assertFalse(self.output.exists())
            self.assertFalse(any(call[0] == "create" for call in self.docker.calls))
            path.write_bytes(original)

    def test_replaced_original_is_not_copied(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        self.docker.originals["flow-predictor-0"]["Id"] = "replacement"
        with self.assertRaisesRegex(ValueError, "substituído"):
            recovery.apply(self.protocol_path, self.output, protocol, plans)
        self.assertFalse(any(call[0] in ("create", "start") for call in self.docker.calls))

    def test_bad_new_mount_is_not_started_and_only_new_ids_are_stopped(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        self.docker.bad_mount = True
        with self.assertRaisesRegex(ValueError, "volumes"):
            recovery.apply(self.protocol_path, self.output, protocol, plans)
        self.assertFalse(any(call[0] == "start" for call in self.docker.calls))
        self.assertEqual(self.docker.calls[-1], ("stop", *self.docker.copies))
        self.assertEqual(json.loads((self.output / "recovery.json").read_text())["status"], "FAILED")

    def test_start_failure_preserves_originals_and_records_failure(self):
        protocol, plans = recovery.prepare(self.protocol_path, self.output)
        self.docker.fail_start = True
        with self.assertRaisesRegex(ValueError, "simulated"):
            recovery.apply(self.protocol_path, self.output, protocol, plans)
        self.assertEqual(self.docker.calls[-1], ("stop", *self.docker.copies))
        self.assertEqual(self.docker.originals, self.originals)
        self.assertEqual(json.loads((self.output / "recovery.json").read_text())["status"], "FAILED")

    def test_cli_plan_prints_one_line_without_environment_values(self):
        stream = io.StringIO()
        with patch("sys.stdout", stream):
            status = recovery.main(["--protocol", str(self.protocol_path), "--output", str(self.output)])
        self.assertEqual(status, 0)
        self.assertIn("plan=READY", stream.getvalue())
        self.assertEqual(len(stream.getvalue().splitlines()), 1)
        self.assertNotIn("PRIVATE", stream.getvalue())


if __name__ == "__main__":
    unittest.main()
