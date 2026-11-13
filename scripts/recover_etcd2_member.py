#!/usr/bin/env python3
"""Guarded recovery of the existing laboratory etcd2 member, not a cluster restore.

Default: validate preserved sources and query the two survivors, without writes.
--apply: copy ORIGINAL member files, check WAL identity in a network-none probe,
then start a replacement runtime for that SAME member. Never remove/re-add a
member, start the original etcd2, or restart/change etcd1/etcd3. No dependencies
outside Python 3.10+, Docker and sudo. The offline snapshot drill is a required
backup prerequisite, NEVER the source of this member's data.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
import uuid


MEMBERS = {
    "etcd1": ("e08ab541087f7f86", "192.168.253.11"),
    "etcd2": ("564101fcba11e661", "192.168.253.12"),
    "etcd3": ("8af88e5f5d1326ea", "192.168.253.13"),
}
SURVIVORS = ("etcd1", "etcd3")
NETWORK = "etcd-network"
DATA_PREFIX = "bitnami/etcd/data"
ETCD_BIN = "/opt/bitnami/etcd/bin/etcd"
CTL_BIN = "/opt/bitnami/etcd/bin/etcdctl"
LABEL = "comas.etcd2-recovery"
INITIAL_CLUSTER = ",".join(f"{name}=http://{ip}:2380" for name, (_, ip) in MEMBERS.items())


def require(condition, message):
    if not condition:
        raise ValueError(message)


def check_memory(text=None):
    if text is None:
        text = Path("/proc/meminfo").read_text()
    match = re.search(r"^MemAvailable:\s+(\d+)\s+kB$", text, re.MULTILINE)
    require(match is not None and int(match[1]) >= 512 * 1024,
            "menos de 512 MiB de MemAvailable; não arriscar os sobreviventes")
    return int(match[1]) * 1024


def interrupted(signum, frame):
    raise InterruptedError(f"sinal {signum}; interromper somente os runtimes novos")


def positive_id(value):
    require(type(value) is int and 0 < value < 2**64, "ID uint64 inválido")
    return value


def load_json(path):
    require(path.is_file() and not path.is_symlink(), f"fonte ausente/symlink: {path}")
    return json.loads(path.read_text())


def new_json(path, value):
    with path.open("x") as stream:
        json.dump(value, stream, ensure_ascii=False, sort_keys=True, indent=2)
        stream.write("\n")


class Docker:
    def __call__(self, *args, timeout=30):
        command = (["sudo", "-n"] if os.geteuid() != 0 else []) + ["docker", *args]
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise ValueError(f"docker {args[0]}: {result.stderr.strip()[:1200]}")
        # `docker logs` forwards the container's stderr on our stderr stream.
        return ((result.stdout + result.stderr) if args[0] == "logs" else result.stdout).strip()


def inspect(docker, *names):
    return {row["Name"].lstrip("/"): row for row in json.loads(docker("inspect", *names))}


def ctl(docker, container, endpoint, *args):
    return json.loads(docker("exec", "-e", "ETCDCTL_API=3", container, CTL_BIN,
                             f"--endpoints={endpoint}", "--dial-timeout=2s",
                             "--command-timeout=3s", "--write-out=json", *args, timeout=8))


def endpoint_status(docker, container, ip):
    rows = ctl(docker, container, f"http://{ip}:2379", "endpoint", "status")
    require(isinstance(rows, list) and len(rows) == 1, "resposta de status incompleta")
    return rows[0]["Status"]


def validate_members(payload):
    require(isinstance(payload.get("members"), list) and len(payload["members"]) == 3,
            "membership deve conter exatamente os três membros conhecidos")
    found = {}
    for member in payload["members"]:
        name = member.get("name")
        require(name in MEMBERS and name not in found, "membro desconhecido/duplicado")
        member_id, ip = MEMBERS[name]
        require(positive_id(member.get("ID")) == int(member_id, 16), f"ID de {name} mudou")
        require(member.get("peerURLs") == [f"http://{ip}:2380"], f"peer URL de {name} mudou")
        require(member.get("clientURLs") == [f"http://{ip}:2379"], f"client URL de {name} mudou")
        require(member.get("isLearner", False) is False, "membro learner inesperado")
        found[name] = member
    return positive_id(payload["header"]["cluster_id"])


def validate_status(status, name, cluster_id, *, isolated=False):
    header = status["header"]
    require(positive_id(header["cluster_id"]) == cluster_id, "cluster ID divergente")
    require(positive_id(header["member_id"]) == int(MEMBERS[name][0], 16), "member ID divergente")
    require(status.get("version") == "3.5.16", "versão difere do ETCD preservado (3.5.16)")
    require(status.get("isLearner", False) is False, "learner inesperado")
    require(type(status.get("raftTerm")) is int and status["raftTerm"] > 0, "termo Raft inválido")
    if not isolated:
        require(not status.get("errors"), f"{name}: status reporta erros")
        require(status.get("leader") in {int(row[0], 16) for row in MEMBERS.values()}, "líder ausente/desconhecido")
    else:
        # A network-none member cannot elect a leader alone. Other alarms fail.
        require(all(error == "etcdserver: no leader" for error in status.get("errors", [])),
                "probe isolado reporta erro além da ausência esperada de líder")


def linearizable_read(docker, container, ip, name, cluster_id):
    # ETCD 3.5.16 only supports --count-only with fields output. Keep JSON
    # headers (including exact uint64 IDs) and omit values with --keys-only.
    response = ctl(docker, container, f"http://{ip}:2379", "get",
                   "/comas/maintenance/etcd2-recovery-read-probe", "--keys-only", "--consistency=l")
    require(positive_id(response["header"]["cluster_id"]) == cluster_id, "leitura em outro cluster")
    require(positive_id(response["header"]["member_id"]) == int(MEMBERS[name][0], 16),
            "leitura respondeu por outro membro")
    return response["header"]["revision"]


def assert_originals(saved, current):
    for name in MEMBERS:
        old, now = saved[name], current[name]
        require(now["Id"] == old["Id"] and now["Image"] == old["Image"], f"container original {name} mudou")
        require(now["State"]["StartedAt"] == old["State"]["StartedAt"], f"{name} foi reiniciado")
        require(now.get("RestartCount") == old.get("RestartCount"), f"reinícios de {name} mudaram")
        for key in ("Config", "HostConfig", "Mounts"):
            require(now.get(key) == old.get(key), f"{name}: {key} mudou desde a preservação")
        require(now["NetworkSettings"]["Networks"] == old["NetworkSettings"]["Networks"],
                f"redes do original {name} mudaram")
    target = current["etcd2"]
    require(target["State"]["Status"] == "exited" and target["State"]["Running"] is False,
            "etcd2 original deve permanecer parado")
    require(not target["Mounts"], "etcd2 possui mounts não cobertos pelo rootfs preservado")
    require(target["HostConfig"].get("RestartPolicy", {}).get("Name", "no") in ("", "no"),
            "etcd2 original tem restart automático; exige revisão para impedir partida dupla")
    require(target["Config"].get("Hostname") and not target["HostConfig"].get("Privileged"),
            "configuração original inesperada")
    for name in SURVIVORS:
        require(current[name]["State"]["Running"] is True, f"{name} não está ativo")


def check_network(docker):
    network = json.loads(docker("network", "inspect", NETWORK))[0]
    require(network.get("Driver") == "bridge", "rede ETCD não é bridge padrão")
    for row in (network.get("Containers") or {}).values():
        require(row.get("IPv4Address", "").split("/")[0] != MEMBERS["etcd2"][1],
                "IP .12 já está ocupado; não será desconectado automaticamente")
    return network["Id"]


def publication_options(target):
    require(set(target["NetworkSettings"]["Networks"]) == {NETWORK},
            "redes adicionais do etcd2 exigem plano explícito")
    bindings = target["HostConfig"].get("PortBindings") or {}
    require(set(bindings) == {"2379/tcp", "2380/tcp"}, "port bindings originais inesperados")
    result = []
    for port, host_port in (("2379/tcp", "2380"), ("2380/tcp", "2480")):
        rows = bindings[port]
        require(isinstance(rows, list) and len(rows) == 1, "port binding duplicado")
        binding = rows[0]
        require(binding["HostPort"] == host_port, "porta publicada mudou")
        host_ip = binding.get("HostIp") or ""
        require(host_ip in ("", "0.0.0.0", "127.0.0.1"), "bind de host customizado")
        result += ["--publish", f"{host_ip + ':' if host_ip else ''}{host_port}:{port}"]
    return result


def verify_manifest(backup, export):
    expected_paths = {backup / "cluster.db", backup / "containers.json", backup / "etcd2.log", export / "rootfs.tar"}
    found = {}
    for line in (export / "SHA256SUMS").read_text().splitlines():
        match = re.fullmatch(r"([0-9a-f]{64}) [ *](.+)", line)
        require(match is not None, "manifesto SHA256 inválido")
        path = Path(match[2])
        require(path in expected_paths and path not in found and path.is_file() and not path.is_symlink(),
                "fonte SHA256 desconhecida/duplicada/symlink")
        prefix = ["sudo", "-n"] if os.geteuid() != 0 else []
        result = subprocess.run([*prefix, "sha256sum", str(path)], capture_output=True, text=True, timeout=60)
        require(result.returncode == 0 and result.stdout.split()[0] == match[1], f"checksum mudou: {path.name}")
        found[path] = match[1]
    require(set(found) == expected_paths, "manifesto não cobre as quatro fontes preservadas")
    return {str(path): digest for path, digest in found.items()}


def data_members(archive):
    """Only regular ORIGINAL member files; never extract arbitrary rootfs paths."""
    selected, seen, binaries = [], set(), set()
    for member in archive.getmembers():
        raw = member.name
        parts = PurePosixPath(raw).parts
        require(not raw.startswith("/") and ".." not in parts, "rootfs contém caminho inseguro")
        normalized = str(PurePosixPath(raw))
        if normalized in (ETCD_BIN.lstrip("/"), CTL_BIN.lstrip("/")):
            require(member.isfile() and member.mode & 0o111, "binário ETCD ausente/não regular")
            binaries.add(normalized)
        if normalized == DATA_PREFIX or normalized.startswith(DATA_PREFIX + "/"):
            require(normalized not in seen, "caminho de dados duplicado no rootfs")
            seen.add(normalized)
            require(member.isdir() or member.isfile(), "symlink/hardlink/device nos dados; revisão necessária")
            require(member.size >= 0, "tamanho inválido")
            selected.append(member)
    require(len(binaries) == 2, "binários esperados não encontrados no rootfs")
    require(f"{DATA_PREFIX}/member/snap/db" in seen, "DB original não localizado")
    require(any(re.fullmatch(re.escape(DATA_PREFIX) + r"/member/wal/[0-9a-f]{16}-[0-9a-f]{16}\.wal", name)
                for name in seen), "WAL original não localizado")
    return selected


def extract_seed(rootfs, output):
    require(not output.exists(), "seed deve ser novo")
    with tarfile.open(rootfs, "r:") as archive:
        selected = data_members(archive)
        size = sum(member.size for member in selected if member.isfile())
        require(shutil.disk_usage(output.parent).free >= 3 * size + 512 * 1024**2,
                "espaço insuficiente para seed, probe e cópia live")
        output.mkdir(mode=0o700)
        for member in selected:
            relative = PurePosixPath(member.name).relative_to(DATA_PREFIX)
            destination = output.joinpath(*relative.parts)
            if member.isdir():
                destination.mkdir(mode=0o700, parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
                with archive.extractfile(member) as source, destination.open("xb") as target:
                    shutil.copyfileobj(source, target)
                destination.chmod(0o600)
    return tree_hashes(output)


def tree_hashes(directory):
    result = {}
    for path in sorted(directory.rglob("*")):
        require(not path.is_symlink(), "symlink inesperado na cópia de dados")
        if path.is_file():
            digest = hashlib.sha256()
            with path.open("rb") as stream:
                for chunk in iter(lambda: stream.read(1024**2), b""):
                    digest.update(chunk)
            result[str(path.relative_to(directory))] = digest.hexdigest()
    return result


def create_options(name, image, data, *, run_id, live, bindings=()):
    arguments = ["create", "--name", name, "--pull=never", "--restart=no", "--read-only",
                 "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
                 "--user", f"{os.getuid()}:{os.getgid()}", "--label", f"{LABEL}={run_id}",
                 "--mount", f"type=bind,source={data},target=/comas-etcd-data",
                 "--entrypoint", ETCD_BIN]
    if live:
        arguments += ["--network", NETWORK, "--ip", MEMBERS["etcd2"][1], "--network-alias", "etcd2", *bindings]
    else:
        arguments += ["--network=none"]
    arguments += [image, "--name=etcd2", "--data-dir=/comas-etcd-data",
                  "--listen-peer-urls=http://0.0.0.0:2380", "--listen-client-urls=http://0.0.0.0:2379",
                  "--initial-advertise-peer-urls=http://192.168.253.12:2380",
                  "--advertise-client-urls=http://192.168.253.12:2379",
                  f"--initial-cluster={INITIAL_CLUSTER}", "--initial-cluster-state=existing",
                  "--initial-cluster-token=etcd-cluster-1", "--logger=zap", "--log-level=info"]
    return arguments


def record_container(docker, name, output):
    row = inspect(docker, name)[name]
    new_json(output / f"{name}-inspect.json", row)
    (output / f"{name}.log").write_text(docker("logs", name))


def stop_owned(docker, name, run_id):
    row = inspect(docker, name)[name]
    require(row["Config"].get("Labels", {}).get(LABEL) == run_id, "recusa parar container alheio")
    if row["State"]["Running"]:
        docker("stop", "--time=5", name, timeout=15)


def live_state(docker, saved):
    current = inspect(docker, *MEMBERS)
    assert_originals(saved, current)
    payload = ctl(docker, "etcd1", f"http://{MEMBERS['etcd1'][1]}:2379", "member", "list")
    cluster_id = validate_members(payload)
    states = {}
    for name in SURVIVORS:
        ip = MEMBERS[name][1]
        states[name] = endpoint_status(docker, name, ip)
        validate_status(states[name], name, cluster_id)
        linearizable_read(docker, name, ip, name, cluster_id)
    require(len({row["leader"] for row in states.values()}) == 1, "sobreviventes discordam do líder")
    require(len({row["raftTerm"] for row in states.values()}) == 1, "termo Raft instável; repita o preflight")
    return dict(cluster_id=cluster_id, members=payload, statuses=states)


def prepare(docker, backup, export, drill):
    check_memory()
    for path in (backup, export, drill):
        require(path.is_dir() and not path.is_symlink(), "diretório de evidência ausente/symlink")
    require(export.parent == backup and drill.parent == backup, "evidências devem pertencer ao mesmo backup")
    checksums = verify_manifest(backup, export)
    saved = {row["Name"].lstrip("/"): row for row in load_json(backup / "containers.json")}
    require(set(saved) == set(MEMBERS), "inventário original inesperado")
    restored_rows = load_json(drill / "helper.json")
    require(isinstance(restored_rows, list) and len(restored_rows) == 1,
            "drill deve conter o docker inspect original de um único helper")
    restored = restored_rows[0]
    require(restored["State"]["Status"] == "exited" and restored["State"]["ExitCode"] == 0
            and restored["HostConfig"]["NetworkMode"] == "none", "drill offline não foi concluído")
    require(any(mount.get("Source") == str(backup / "cluster.db") and mount.get("RW") is False
                for mount in restored["Mounts"]), "drill não usou o snapshot preservado em read-only")
    state = live_state(docker, saved)
    network_id = check_network(docker)
    bindings = publication_options(saved["etcd2"])
    image = saved["etcd2"]["Image"]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image) is not None, "imagem deve estar fixada por ID")
    image_row = json.loads(docker("image", "inspect", image))[0]
    require(image_row["Id"] == image, "imagem original indisponível")
    require(not image_row["Config"].get("Volumes") and not image_row["Config"].get("Healthcheck"),
            "imagem cria volumes/healthcheck implícitos; exige revisão")
    require(not any(value.split("=", 1)[0].startswith("ETCD_") for value in image_row["Config"].get("Env", [])),
            "imagem possui ETCD_* implícito; flags/configuração devem ser revisadas")
    with tarfile.open(export / "rootfs.tar", "r:") as archive:
        data_members(archive)
    return dict(saved=saved, state=state, network_id=network_id, image=image,
                bindings=bindings, checksums=checksums)


def identity_from_logs(logs, cluster_id):
    """Read WAL-derived restart identity, without waiting for a quorum-dependent API.

    In ETCD 3.5.16 client serving waits for ReadyNotify, which requires publishing
    attributes through Raft. An isolated member cannot satisfy that requirement.
    Require both the restartNode WAL message and the subsequent server-start
    message, and reject fresh/forced bootstrap and fatal/panic records instead.
    """
    records = []
    for line in logs.splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            require(row.get("level") not in {"fatal", "panic"}, "probe reportou fatal/panic")
            require(row.get("msg") not in {"starting local member", "forcing restart member"},
                    "probe tentou bootstrap novo/forçado em vez de carregar WAL")
            records.append(row)
    restarts = [row for row in records if row.get("msg") == "restarting local member"]
    require(len(restarts) <= 1, "identidade de restart ambígua")
    if not restarts:
        return None
    restart = restarts[0]
    for key in ("cluster-id", "local-member-id"):
        require(isinstance(restart.get(key), str) and re.fullmatch(r"[0-9a-f]{1,16}", restart[key]),
                "ID hexadecimal de WAL inválido")
    require(int(restart["cluster-id"], 16) == cluster_id, "cluster ID do WAL diverge do cluster ativo")
    require(restart["local-member-id"] == MEMBERS["etcd2"][0], "member ID do WAL não é o etcd2 cadastrado")
    starts = [row for row in records if row.get("msg") == "starting etcd server"]
    if not starts:
        return None
    require(all(row.get("local-member-id") == MEMBERS["etcd2"][0]
                and row.get("local-server-version") == "3.5.16" for row in starts),
            "servidor de probe iniciou com identidade/versão incompatível")
    terms = []
    for row in records:
        match = re.match(r"newRaft ([0-9a-f]+) \[.*?\bterm: (\d+),", row.get("msg", ""))
        if match:
            require(match[1] == MEMBERS["etcd2"][0], "Raft inicializou outro membro")
            terms.append(int(match[2]))
    if not terms:
        return None
    require(len(set(terms)) == 1 and terms[0] > 0, "termo inicial do WAL ambíguo/inválido")
    require(type(restart.get("commit-index")) is int and restart["commit-index"] >= 0,
            "commit index do WAL inválido")
    return dict(cluster_id=cluster_id, member_id=int(restart["local-member-id"], 16),
                raft_term=terms[0], commit_index=restart["commit-index"],
                evidence="WAL_restart_and_server_start_logs; not_online_quorum_health")


def wait_identity(docker, container, cluster_id, *, timeout_s=25):
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        require(inspect(docker, container)[container]["State"]["Running"], "processo ETCD encerrou; veja logs")
        result = identity_from_logs(docker("logs", container), cluster_id)
        if result:
            return result
        time.sleep(0.5)
    raise ValueError("identidade não comprovada pelos logs do WAL/servidor; nenhuma partida em rede autorizada")


def apply(docker, plan, backup, export):
    output = Path(tempfile.mkdtemp(prefix="etcd2-recovery-", dir=backup.parent))
    output.chmod(0o700)
    run_id = uuid.uuid4().hex
    probe, runtime = f"comas-etcd2-probe-{run_id[:12]}", f"comas-etcd2-recovered-{run_id[:12]}"
    report = dict(schema_version="comas-etcd2-recovery/1", status="IN_PROGRESS", run_id=run_id,
                  output=str(output), source_checksums=plan["checksums"], original_restarted=False,
                  survivor_restarts_requested=False, membership_changes_requested=False,
                  runtime=runtime, probe=probe, restart_policy="no", error=None, cleanup_errors=[])
    report["tool_sha256"] = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()
    new_json(output / "plan.json", plan)
    print(f"recovery_dir={output}", flush=True)
    owned = []
    try:
        seed = output / "original-member-seed"
        manifest = extract_seed(export / "rootfs.tar", seed)
        new_json(output / "member-files-sha256.json", manifest)
        probe_data = output / "probe-data"
        shutil.copytree(seed, probe_data)
        require(tree_hashes(probe_data) == manifest, "cópia de probe diverge do seed")
        docker(*create_options(probe, plan["image"], probe_data, run_id=run_id, live=False))
        owned.append(probe)
        docker("start", probe)
        status = wait_identity(docker, probe, plan["state"]["cluster_id"])
        require(status["raft_term"] <= plan["state"]["statuses"]["etcd1"]["raftTerm"],
                "WAL possui termo superior ao cluster atual; exige revisão")
        require(status["commit_index"] <= plan["state"]["statuses"]["etcd1"]["raftIndex"],
                "WAL possui commit index superior ao cluster ativo; exige revisão")
        report["offline_identity"] = status
        stop_owned(docker, probe, run_id)
        record_container(docker, probe, output)
        print("offline_identity=VERIFIED original_member=564101fcba11e661", flush=True)

        # Do NOT reuse data modified by the isolated probe or by snapshot restore.
        live_data = output / "live-data"
        shutil.copytree(seed, live_data)
        require(tree_hashes(seed) == manifest == tree_hashes(live_data), "seed/live divergem")
        before_start = live_state(docker, plan["saved"])
        check_memory()
        require(before_start["cluster_id"] == plan["state"]["cluster_id"], "cluster mudou durante preparação")
        require(check_network(docker) == plan["network_id"], "rede ETCD foi recriada")
        docker(*create_options(runtime, plan["image"], live_data, run_id=run_id,
                               live=True, bindings=plan["bindings"]))
        owned.append(runtime)
        # No originals are connected/disconnected/started to resolve an IP conflict.
        assert_originals(plan["saved"], inspect(docker, *MEMBERS))
        docker("start", runtime)
        print(f"member_start=REQUESTED runtime={runtime}", flush=True)
        deadline = time.monotonic() + 75
        latest_error = "catch-up não observado"
        good_rounds = 0
        while time.monotonic() < deadline:
            assert_originals(plan["saved"], inspect(docker, *MEMBERS))
            require(inspect(docker, runtime)[runtime]["State"]["Running"], "runtime recuperado encerrou")
            try:
                after = live_state(docker, plan["saved"])
                require(after["cluster_id"] == plan["state"]["cluster_id"], "cluster ID mudou")
                candidate = endpoint_status(docker, runtime, "127.0.0.1")
                validate_status(candidate, "etcd2", after["cluster_id"])
                reference = after["statuses"]["etcd1"]
                require(candidate["leader"] == reference["leader"] and candidate["raftTerm"] == reference["raftTerm"],
                        "membro ainda não alinhou líder/termo")
                require(candidate["raftAppliedIndex"] >= before_start["statuses"]["etcd1"]["raftIndex"],
                        "catch-up ainda não alcançou o índice anterior à partida")
                revision = linearizable_read(docker, runtime, "127.0.0.1", "etcd2", after["cluster_id"])
                external = endpoint_status(docker, "etcd1", MEMBERS["etcd2"][1])
                validate_status(external, "etcd2", after["cluster_id"])
                external_revision = linearizable_read(docker, "etcd1", MEMBERS["etcd2"][1], "etcd2", after["cluster_id"])
                good_rounds += 1
                if good_rounds >= 3:
                    report.update(status="RECOVERED", final_state=after, recovered_status=candidate,
                                  recovered_read_revision=revision, recovered_external_status=external,
                                  recovered_external_read_revision=external_revision,
                                  healthy_observations=good_rounds)
                    break
                time.sleep(1)
            except (ValueError, subprocess.TimeoutExpired) as exc:
                good_rounds = 0
                latest_error = str(exc)
                time.sleep(0.5)
        require(report["status"] == "RECOVERED", latest_error)
        # Check the archived evidence again; never silently promote changed inputs.
        require(verify_manifest(backup, export) == plan["checksums"], "fontes preservadas mudaram")
    except (Exception, KeyboardInterrupt) as exc:
        report.update(status="STOPPED_ERROR", error=str(exc) or "interrompido")
        for name in reversed(owned):
            try:
                stop_owned(docker, name, run_id)
            except Exception as cleanup_error:
                report["cleanup_errors"].append(f"{name}: {cleanup_error}")
    finally:
        try:
            assert_originals(plan["saved"], inspect(docker, *MEMBERS))
            report["original_containers_unchanged"] = True
        except Exception as original_error:
            report["original_containers_unchanged"] = False
            report["cleanup_errors"].append(str(original_error))
            report.update(status="STOPPED_ERROR", error="estado dos originais mudou durante a recuperação")
            if runtime in owned:
                try:
                    stop_owned(docker, runtime, run_id)
                except Exception as cleanup_error:
                    report["cleanup_errors"].append(f"{runtime}: {cleanup_error}")
        for name in owned:
            if not (output / f"{name}-inspect.json").exists():
                try:
                    record_container(docker, name, output)
                except Exception as log_error:
                    report["cleanup_errors"].append(f"logs {name}: {log_error}")
        new_json(output / "recovery.json", report)
    print(f"status={report['status']} originals_unchanged={report['original_containers_unchanged']} "
          f"cleanup_errors={len(report['cleanup_errors'])}")
    print(f"receipt={output / 'recovery.json'}")
    if report["error"]:
        print(f"erro={report['error']}", file=sys.stderr)
    if report["status"] == "RECOVERED":
        print(f"active_etcd2_runtime={runtime}; original_etcd2_must_remain_stopped=true")
    return 0 if report["status"] == "RECOVERED" and report["original_containers_unchanged"] and not report["cleanup_errors"] else 2


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--backup-root", required=True, type=Path)
    parser.add_argument("--export-root", required=True, type=Path)
    parser.add_argument("--restore-test-root", required=True, type=Path)
    parser.add_argument("--apply", action="store_true", help="autoriza criar/start apenas runtimes novos do membro etcd2")
    args = parser.parse_args(argv)
    previous_signals = {sig: signal.getsignal(sig) for sig in (signal.SIGHUP, signal.SIGTERM)}
    for sig in previous_signals:
        signal.signal(sig, interrupted)
    try:
        backup, export, drill = args.backup_root.absolute(), args.export_root.absolute(), args.restore_test_root.absolute()
        require(all(path == path.resolve() for path in (backup, export, drill)), "caminhos devem ser absolutos sem symlinks")
        plan = prepare(Docker(), backup, export, drill)
        print("preflight=READY survivors=2 originals_stopped_etcd2=true backup_verified=true membership_changes=false", flush=True)
        if not args.apply:
            print("mode=READ_ONLY_PLAN; use --apply para autorizar probe e partida do substituto")
            return 0
        return apply(Docker(), plan, backup, export)
    except (Exception, KeyboardInterrupt) as exc:
        print(f"erro: {str(exc) or 'interrompido'}", file=sys.stderr)
        return 2
    finally:
        for sig, handler in previous_signals.items():
            signal.signal(sig, handler)


if __name__ == "__main__":
    raise SystemExit(main())
