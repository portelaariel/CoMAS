"""Offline guard/failure tests. No Docker daemon, ETCD or sudo is invoked."""

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch


SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "recover_etcd2_member.py"
SPEC = importlib.util.spec_from_file_location("recover_etcd2_member", SCRIPT)
recovery = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(recovery)
CLUSTER = 0xAABBCCDDEEFF0011  # Above JSON float's exact-integer range.
IMAGE = "sha256:" + "a" * 64


def originals():
    rows = {}
    for name in recovery.MEMBERS:
        running = name != "etcd2"
        rows[name] = dict(Name="/" + name, Id=name + "-original", Image=IMAGE,
                          RestartCount=0, Mounts=[], Config=dict(Hostname=name, Labels={}),
                          State=dict(Status="running" if running else "exited", Running=running,
                                     StartedAt="2026-10-02T12:27:00Z"),
                          HostConfig=dict(RestartPolicy=dict(Name="no"),
                                          PortBindings={"2379/tcp": [dict(HostIp="", HostPort="2380")],
                                                        "2380/tcp": [dict(HostIp="", HostPort="2480")]}),
                          NetworkSettings=dict(Networks={recovery.NETWORK: {}}))
    return rows


def members():
    return dict(header=dict(cluster_id=CLUSTER), members=[
        dict(ID=int(identity, 16), name=name, peerURLs=[f"http://{ip}:2380"],
             clientURLs=[f"http://{ip}:2379"], isLearner=False)
        for name, (identity, ip) in recovery.MEMBERS.items()])


def status(name, isolated=False):
    return dict(header=dict(cluster_id=CLUSTER, member_id=int(recovery.MEMBERS[name][0], 16)),
                version="3.5.16", leader=0 if isolated else int(recovery.MEMBERS["etcd1"][0], 16),
                raftTerm=8 if isolated else 9, raftIndex=100, raftAppliedIndex=100,
                errors=["etcdserver: no leader"] if isolated else [])


def restart_logs(wrong=False):
    identity = "777" if wrong else recovery.MEMBERS["etcd2"][0]
    return "\n".join(json.dumps(row) for row in [
        dict(level="info", msg="restarting local member", **{
            "cluster-id": f"{CLUSTER:x}", "local-member-id": identity, "commit-index": 10}),
        dict(level="info", msg=f"newRaft {identity} [peers: [], term: 8, commit: 10, applied: 0]"),
        dict(level="info", msg="starting etcd server", **{
            "local-member-id": identity, "local-server-version": "3.5.16"}),
    ])


def archive_bytes(extra=()):
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w") as archive:
        for name, content in [
            (recovery.ETCD_BIN.lstrip("/"), b"binary"),
            (recovery.CTL_BIN.lstrip("/"), b"binary"),
            (recovery.DATA_PREFIX + "/member/snap/db", b"original-db"),
            (recovery.DATA_PREFIX + "/member/wal/0000000000000000-0000000000000000.wal", b"original-wal"),
        ]:
            item = tarfile.TarInfo(name)
            item.mode = 0o755 if "/bin/" in name else 0o600
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
        for item, content in extra:
            archive.addfile(item, io.BytesIO(content) if content is not None else None)
    return output.getvalue()


class FakeDocker:
    def __init__(self, bad_probe=False, fail_start=False):
        self.rows = originals()
        self.calls = []
        self.bad_probe = bad_probe
        self.fail_start = fail_start
        self.data_paths = {}

    def __call__(self, *args, **kwargs):
        self.calls.append(args)
        operation = args[0]
        if operation == "inspect":
            return json.dumps([self.rows[name] for name in args[1:]])
        if args[:2] == ("network", "inspect"):
            return json.dumps([dict(Id="network-id", Driver="bridge", Containers={})])
        if args[:2] == ("image", "inspect"):
            return json.dumps([dict(Id=IMAGE, Config=dict(Env=["PATH=/bin"]))])
        if operation == "exec":
            container = args[3]
            if "-probe-" in container:
                raise AssertionError("isolated member's client API waits for quorum and must not be used")
            if args[-2:] == ("member", "list"):
                return json.dumps(members())
            if args[-2:] == ("endpoint", "status"):
                endpoint = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--endpoints="))
                endpoint_name = next((name for name, (_, ip) in recovery.MEMBERS.items()
                                      if endpoint == f"http://{ip}:2379"), None)
                response = status(endpoint_name or "etcd2")
                return json.dumps([dict(Endpoint="unused", Status=response)])
            if "get" in args:
                if "--count-only" in args and "--write-out=json" in args:
                    raise ValueError("docker exec: Error: --count-only is only for `--write-out=fields`")
                endpoint = next(arg.split("=", 1)[1] for arg in args if arg.startswith("--endpoints="))
                member_name = next((name for name, (_, ip) in recovery.MEMBERS.items()
                                    if endpoint == f"http://{ip}:2379"), "etcd2")
                return json.dumps(dict(header=dict(cluster_id=CLUSTER,
                                                    member_id=int(recovery.MEMBERS[member_name][0], 16),
                                                    revision=100), count=0))
        if operation == "create":
            name = args[args.index("--name") + 1]
            label = args[args.index("--label") + 1].split("=", 1)[1]
            mount = args[args.index("--mount") + 1]
            self.data_paths[name] = Path(mount.split("source=", 1)[1].split(",", 1)[0])
            self.rows[name] = dict(Name="/" + name, Config=dict(Labels={recovery.LABEL: label}),
                                   State=dict(Status="created", Running=False))
            return "new-container-id"
        if operation == "start":
            row = self.rows[args[1]]
            # Model an unknown CLI result: process started but the response failed.
            row["State"].update(Status="running", Running=True)
            if "-probe-" in args[1]:
                (self.data_paths[args[1]] / "member/snap/db").write_bytes(b"modified-by-isolated-probe")
            if self.fail_start and "-recovered-" in args[1]:
                if isinstance(self.fail_start, BaseException):
                    raise self.fail_start
                raise ValueError("start response timed out")
            return args[1]
        if operation == "stop":
            self.rows[args[-1]]["State"].update(Status="exited", Running=False)
            return args[-1]
        if operation == "logs":
            return restart_logs(self.bad_probe) if "-probe-" in args[1] else "preserved ETCD logs"
        raise AssertionError(f"unexpected fake Docker command {args}")


class IdentityTests(unittest.TestCase):
    def test_linearizable_read_uses_json_compatible_keys_only(self):
        docker = FakeDocker()
        revision = recovery.linearizable_read(docker, "etcd1", recovery.MEMBERS["etcd1"][1],
                                              "etcd1", CLUSTER)
        self.assertEqual(revision, 100)
        self.assertEqual(len(docker.calls), 1)
        call = docker.calls[0]
        self.assertIn("--write-out=json", call)
        self.assertEqual(call[call.index("get"):], (
            "get", "/comas/maintenance/etcd2-recovery-read-probe", "--keys-only", "--consistency=l"))
        self.assertNotIn("--count-only", call)

    def test_fake_enforces_etcd_3516_count_only_output_restriction(self):
        with self.assertRaisesRegex(ValueError, "count-only is only for"):
            recovery.ctl(FakeDocker(), "etcd1", "http://192.168.253.11:2379",
                         "get", "/read-only-probe", "--count-only", "--consistency=l")

    def test_insufficient_memory_and_shutdown_fail_closed(self):
        self.assertEqual(recovery.check_memory("MemAvailable:    1048576 kB\n"), 1024**3)
        for text in ("MemAvailable: 123 kB\n", "MemFree: 1048576 kB\n"):
            with self.assertRaises(ValueError):
                recovery.check_memory(text)
        with self.assertRaises(InterruptedError):
            recovery.interrupted(15, None)

    def test_uint64_keeps_integer_precision(self):
        self.assertEqual(recovery.validate_members(json.loads(json.dumps(members()))), CLUSTER)
        for bad in (float(CLUSTER), True, "123", 0, -1):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                recovery.positive_id(bad)

    def test_changed_member_id_peer_or_membership_rejected(self):
        for field, value in (("ID", 123), ("peerURLs", ["http://wrong:2380"]),
                             ("clientURLs", []), ("isLearner", True), ("name", "other")):
            payload = members()
            payload["members"][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                recovery.validate_members(payload)
        payload = members()
        payload["members"].append(copy.deepcopy(payload["members"][0]))
        with self.assertRaises(ValueError):
            recovery.validate_members(payload)

    def test_no_leader_only_allowed_during_isolated_probe(self):
        recovery.validate_status(status("etcd2", True), "etcd2", CLUSTER, isolated=True)
        with self.assertRaises(ValueError):
            recovery.validate_status(status("etcd2", True), "etcd2", CLUSTER)
        response = status("etcd2", True)
        response["errors"].append("NOSPACE")
        with self.assertRaises(ValueError):
            recovery.validate_status(response, "etcd2", CLUSTER, isolated=True)

    def test_wrong_cluster_rejected_even_in_probe(self):
        response = status("etcd2", True)
        response["header"]["cluster_id"] += 1
        with self.assertRaises(ValueError):
            recovery.validate_status(response, "etcd2", CLUSTER, isolated=True)

    def test_original_restart_and_start_forbidden(self):
        saved = originals()
        for mutate in (
            lambda rows: rows["etcd1"]["State"].update(StartedAt="later"),
            lambda rows: rows["etcd3"].update(RestartCount=1),
            lambda rows: rows["etcd2"]["State"].update(Running=True, Status="running"),
            lambda rows: rows["etcd2"]["HostConfig"].update(RestartPolicy=dict(Name="always")),
            lambda rows: rows["etcd2"].update(Mounts=[dict(Source="unknown")]),
            lambda rows: rows["etcd1"]["Config"].update(Env=["ETCD_NAME=changed"]),
        ):
            current = copy.deepcopy(saved)
            mutate(current)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                recovery.assert_originals(saved, current)

    def test_preserves_exact_port_bindings(self):
        self.assertEqual(recovery.publication_options(originals()["etcd2"]),
                         ["--publish", "2380:2379/tcp", "--publish", "2480:2380/tcp"])

    def test_extra_network_or_changed_port_is_not_silently_dropped(self):
        row = originals()["etcd2"]
        row["NetworkSettings"]["Networks"]["other"] = {}
        with self.assertRaises(ValueError):
            recovery.publication_options(row)
        row = originals()["etcd2"]
        row["HostConfig"]["PortBindings"]["2379/tcp"][0]["HostPort"] = "9999"
        with self.assertRaises(ValueError):
            recovery.publication_options(row)

    def test_occupied_ip_rejected(self):
        docker = lambda *args: json.dumps([dict(Id="id", Driver="bridge", Containers={
            "someone": dict(IPv4Address="192.168.253.12/24")})])
        with self.assertRaises(ValueError):
            recovery.check_network(docker)

    def test_cannot_stop_an_unlabelled_container(self):
        docker = FakeDocker()
        with self.assertRaises(ValueError):
            recovery.stop_owned(docker, "etcd1", "test-run")
        self.assertFalse(any(call[0] == "stop" for call in docker.calls))

    def test_wal_identity_from_startup_logs_not_readiness(self):
        identity = recovery.identity_from_logs(restart_logs(), CLUSTER)
        self.assertEqual(identity["member_id"], int(recovery.MEMBERS["etcd2"][0], 16))
        self.assertEqual(identity["raft_term"], 8)
        self.assertEqual(identity["commit_index"], 10)
        self.assertIsNone(recovery.identity_from_logs("", CLUSTER))
        first_only = restart_logs().splitlines()[0]
        self.assertIsNone(recovery.identity_from_logs(first_only, CLUSTER))

    def test_rejects_fresh_bootstrap_fatal_wrong_version_and_wrong_cluster(self):
        for message in ("starting local member", "forcing restart member"):
            with self.subTest(message=message), self.assertRaises(ValueError):
                recovery.identity_from_logs(json.dumps(dict(msg=message)), CLUSTER)
        for logs in (restart_logs() + '\n{"level":"fatal"}',
                     restart_logs().replace("3.5.16", "3.6.0"), restart_logs(True)):
            with self.subTest(logs=logs), self.assertRaises(ValueError):
                recovery.identity_from_logs(logs, CLUSTER)
        with self.assertRaises(ValueError):
            recovery.identity_from_logs(restart_logs(), CLUSTER + 1)

    def test_new_runtime_uses_no_bitnami_init_or_snapshot_restore(self):
        options = recovery.create_options("candidate", IMAGE, Path("/new/data"),
                                          run_id="abc", live=True)
        text = " ".join(options)
        self.assertIn("--initial-cluster-state=existing", options)
        self.assertIn(IMAGE, options)
        self.assertIn("--pull=never", options)
        self.assertIn("--restart=no", options)
        self.assertNotIn("--force-new-cluster", text)
        self.assertNotIn("snapshot", text)
        self.assertNotIn("entrypoint.sh", text)
        probe = recovery.create_options("probe", IMAGE, Path("/new/probe"), run_id="abc", live=False)
        self.assertIn("--network=none", probe)
        self.assertNotIn("--publish", probe)
        self.assertNotIn("--ip", probe)


class ArchiveTests(unittest.TestCase):
    def test_extracts_only_original_data_with_private_owned_files(self):
        with tempfile.TemporaryDirectory() as folder:
            base = Path(folder)
            source = base / "rootfs.tar"
            source.write_bytes(archive_bytes())
            manifest = recovery.extract_seed(source, base / "seed")
            self.assertEqual(set(manifest), {"member/snap/db", "member/wal/0000000000000000-0000000000000000.wal"})
            self.assertEqual(manifest["member/snap/db"], hashlib.sha256(b"original-db").hexdigest())
            self.assertEqual((base / "seed/member/snap/db").stat().st_mode & 0o777, 0o600)
            self.assertFalse((base / "seed/opt").exists())

    def test_rejects_traversal_symlink_hardlink_and_duplicate(self):
        entries = []
        for name in ("/absolute", recovery.DATA_PREFIX + "/../../escape"):
            item = tarfile.TarInfo(name)
            entries.append(item)
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE):
            item = tarfile.TarInfo(recovery.DATA_PREFIX + "/member/link")
            item.type, item.linkname = kind, "/etc/shadow"
            entries.append(item)
        entries.append(tarfile.TarInfo(recovery.DATA_PREFIX + "/member/snap/db"))
        for item in entries:
            with self.subTest(name=item.name), tarfile.open(fileobj=io.BytesIO(archive_bytes([(item, b"")])) ) as archive:
                with self.assertRaises(ValueError):
                    recovery.data_members(archive)

    def test_missing_original_wal_blocks_snapshot_only_input(self):
        with tarfile.open(fileobj=io.BytesIO(archive_bytes())) as archive:
            original = archive.getmembers
            archive.getmembers = lambda: [item for item in original() if "/wal/" not in item.name]
            with self.assertRaises(ValueError):
                recovery.data_members(archive)


class ManifestTests(unittest.TestCase):
    def test_requires_exact_coverage_and_matching_hashes(self):
        with tempfile.TemporaryDirectory() as folder:
            backup = Path(folder)
            export = backup / "export"
            export.mkdir()
            paths = [backup / "cluster.db", backup / "containers.json", backup / "etcd2.log", export / "rootfs.tar"]
            lines = []
            for path in paths:
                path.write_bytes(b"preserved")
                lines.append(f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}")
            manifest = export / "SHA256SUMS"
            manifest.write_text("\n".join(lines) + "\n")

            def fake_hash(command, **kwargs):
                path = Path(command[-1])
                return SimpleNamespace(returncode=0, stdout=f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {path}\n")

            with patch.object(recovery.subprocess, "run", side_effect=fake_hash):
                self.assertEqual(len(recovery.verify_manifest(backup, export)), 4)
                for changed in (lines[:-1], lines + [lines[0]],
                                ["0" * 64 + "  /not/a/protected/source", *lines[1:]]):
                    manifest.write_text("\n".join(changed))
                    with self.assertRaises(ValueError):
                        recovery.verify_manifest(backup, export)
                manifest.write_text("\n".join(lines))
                paths[0].write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    recovery.verify_manifest(backup, export)


class WorkflowTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.backup, self.export, self.drill = base / "backup", base / "backup/export", base / "backup/drill"
        self.export.mkdir(parents=True)
        self.drill.mkdir()
        (self.export / "rootfs.tar").write_bytes(archive_bytes())
        (self.backup / "containers.json").write_text(json.dumps(list(originals().values())))
        (self.drill / "helper.json").write_text(json.dumps([dict(
            State=dict(Status="exited", ExitCode=0), HostConfig=dict(NetworkMode="none"),
            Mounts=[dict(Source=str(self.backup / "cluster.db"), RW=False)])]))
        self.manifest_patch = patch.object(recovery, "verify_manifest", return_value={"verified": "checksum"})
        self.manifest_patch.start()
        self.addCleanup(self.manifest_patch.stop)
        memory_patch = patch.object(recovery, "check_memory", return_value=1024**3)
        memory_patch.start()
        self.addCleanup(memory_patch.stop)

    def test_prepare_issues_only_read_operations(self):
        docker = FakeDocker()
        result = recovery.prepare(docker, self.backup, self.export, self.drill)
        self.assertEqual(result["state"]["cluster_id"], CLUSTER)
        self.assertTrue(all(call[0] in {"inspect", "network", "image", "exec"} for call in docker.calls))
        for call in docker.calls:
            if call[0] == "exec":
                self.assertFalse(any(arg in {"put", "del", "add", "remove", "update", "restore"} for arg in call))

    def test_preflight_read_failure_never_applies_or_creates_output(self):
        docker = FakeDocker()
        with patch.object(recovery, "Docker", return_value=docker), \
                patch.object(recovery, "linearizable_read", side_effect=ValueError("CLI read failed")), \
                patch.object(recovery, "apply") as apply_mock, \
                contextlib.redirect_stderr(io.StringIO()):
            code = recovery.main([
                "--backup-root", str(self.backup.resolve()),
                "--export-root", str(self.export.resolve()),
                "--restore-test-root", str(self.drill.resolve()), "--apply"])
        self.assertEqual(code, 2)
        apply_mock.assert_not_called()
        self.assertFalse(any(call[0] in {"create", "start", "stop"} for call in docker.calls))
        self.assertEqual(list(self.backup.parent.glob("etcd2-recovery-*")), [])

    def test_changed_sources_or_unfinished_drill_block_before_network_calls(self):
        docker = FakeDocker()
        with patch.object(recovery, "verify_manifest", side_effect=ValueError("checksum changed")):
            with self.assertRaises(ValueError):
                recovery.prepare(docker, self.backup, self.export, self.drill)
        self.assertEqual(docker.calls, [])
        metadata = json.loads((self.drill / "helper.json").read_text())
        metadata[0]["State"]["ExitCode"] = 1
        (self.drill / "helper.json").write_text(json.dumps(metadata))
        with self.assertRaises(ValueError):
            recovery.prepare(docker, self.backup, self.export, self.drill)
        self.assertEqual(docker.calls, [])

    def test_rejects_implicit_image_etcd_configuration(self):
        docker = FakeDocker()
        def changed_image(*args, **kwargs):
            if args[:2] == ("image", "inspect"):
                return json.dumps([dict(Id=IMAGE, Config=dict(Env=["ETCD_CONFIG_FILE=/unexpected.yaml"]))])
            return docker(*args, **kwargs)
        with self.assertRaises(ValueError):
            recovery.prepare(changed_image, self.backup, self.export, self.drill)

    def run_apply(self, docker):
        plan = recovery.prepare(docker, self.backup, self.export, self.drill)
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()), \
                patch.object(recovery.time, "sleep", return_value=None):
            code = recovery.apply(docker, plan, self.backup, self.export)
        outputs = list(self.backup.parent.glob("etcd2-recovery-*"))
        self.assertEqual(len(outputs), 1)
        return code, json.loads((outputs[0] / "recovery.json").read_text()), outputs[0]

    def test_success_keeps_new_runtime_running_and_all_originals_unchanged(self):
        docker = FakeDocker()
        saved = copy.deepcopy(docker.rows)
        code, receipt, output = self.run_apply(docker)
        self.assertEqual(code, 0)
        self.assertEqual(receipt["status"], "RECOVERED")
        self.assertEqual(receipt["healthy_observations"], 3)
        self.assertEqual(receipt["recovered_external_status"]["header"]["member_id"],
                         int(recovery.MEMBERS["etcd2"][0], 16))
        self.assertTrue(docker.rows[receipt["runtime"]]["State"]["Running"])
        self.assertFalse(docker.rows[receipt["probe"]]["State"]["Running"])
        for name in recovery.MEMBERS:
            self.assertEqual(docker.rows[name], saved[name])
        self.assertEqual(recovery.tree_hashes(output / "original-member-seed"), recovery.tree_hashes(output / "live-data"))
        self.assertNotEqual(recovery.tree_hashes(output / "probe-data"), recovery.tree_hashes(output / "live-data"))
        self.assertFalse(any(call[0] in {"rm", "restart", "update"} for call in docker.calls))
        self.assertFalse(any(call[0] in {"start", "stop"} and call[-1] in recovery.MEMBERS for call in docker.calls))

    def test_wrong_offline_identity_never_creates_live_container(self):
        docker = FakeDocker(bad_probe=True)
        code, receipt, output = self.run_apply(docker)
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "STOPPED_ERROR")
        self.assertNotIn(receipt["runtime"], docker.rows)
        self.assertFalse(docker.rows[receipt["probe"]]["State"]["Running"])
        self.assertTrue((output / "original-member-seed/member/snap/db").exists())

    def test_unknown_live_start_result_stops_only_owned_candidate(self):
        docker = FakeDocker(fail_start=True)
        code, receipt, _ = self.run_apply(docker)
        self.assertEqual(code, 2)
        self.assertFalse(docker.rows[receipt["runtime"]]["State"]["Running"])
        self.assertTrue(receipt["original_containers_unchanged"])
        self.assertIn("timed out", receipt["error"])

    def test_signal_interrupt_after_start_also_stops_only_new_runtime(self):
        docker = FakeDocker(fail_start=InterruptedError("SIGTERM"))
        code, receipt, _ = self.run_apply(docker)
        self.assertEqual(code, 2)
        self.assertFalse(docker.rows[receipt["runtime"]]["State"]["Running"])
        self.assertEqual(receipt["error"], "SIGTERM")
        self.assertFalse(any(call[0] == "stop" and call[-1] in recovery.MEMBERS for call in docker.calls))

    def test_changed_archive_after_join_stops_candidate_and_is_not_success(self):
        docker = FakeDocker()
        with patch.object(recovery, "verify_manifest", side_effect=[{"verified": "checksum"}, {"verified": "changed"}]):
            code, receipt, _ = self.run_apply(docker)
        self.assertEqual(code, 2)
        self.assertEqual(receipt["status"], "STOPPED_ERROR")
        self.assertFalse(docker.rows[receipt["runtime"]]["State"]["Running"])


if __name__ == "__main__":
    unittest.main()
