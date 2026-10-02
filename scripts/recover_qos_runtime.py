#!/usr/bin/env python3
"""Recover standard shadow collectors without restarting pilot CSV writers.

The default is a read-only plan. --apply creates new containers, copies the
original image/environment, remaps both history mounts, and starts the copies.
Original containers and files are never started, renamed, removed or rewritten.
This is intentionally limited to the repository's standard Docker deployment.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from predictive_sla_validation import digest_file, load_protocol, write_new_json
from qos_holt import QosHoltModel


HISTORY_TARGETS = {"/app/qos_history": "qos_history_domain",
                   "/app/prediction_history": "prediction_history_domain"}
UNSUPPORTED_HOST_OPTIONS = (
    "Privileged", "ReadonlyRootfs", "CapAdd", "CapDrop", "Devices", "SecurityOpt",
    "ExtraHosts", "Dns", "DnsSearch", "DnsOptions", "Links", "Tmpfs", "Mounts",
    "CpuPeriod", "CpuQuota", "NanoCpus", "CpuShares", "CpusetCpus", "CpusetMems",
    "Memory", "MemorySwap", "MemoryReservation", "ContainerIDFile",
    "VolumesFrom", "AutoRemove", "Init", "PublishAllPorts", "DeviceRequests",
)


def docker(*arguments):
    result = subprocess.run(["sudo", "-n", "docker", *arguments],
                            capture_output=True, text=True, timeout=60)
    if result.returncode:
        # Never print the full command: -e arguments can contain private values.
        raise ValueError(f"docker {arguments[0]} falhou: {result.stderr.strip()}")
    return result.stdout.strip()


def prepare(protocol_path, output):
    protocol = load_protocol(protocol_path)
    output = output.resolve()
    if output.exists() or not output.is_relative_to(protocol_path.parent.resolve()):
        raise ValueError("use um novo diretório dentro do protocolo congelado")
    occupied = set(docker("ps", "-a", "--format", "{{.Names}}").splitlines())
    models = [QosHoltModel.load(protocol_path.parent / row["path"])
              for row in protocol["models"].values()]
    original = json.loads(docker("inspect", "flow-predictor-0", "flow-predictor-1"))
    originals = {row["Name"].lstrip("/"): row for row in original}
    plans = []
    for index, subject in enumerate(protocol["subjects"]):
        old_name = f"flow-predictor-{index}"
        name = f"comas-qos-prospective-{index}"
        row = originals[old_name]
        if row["State"]["Status"] != "exited" or row["State"].get("Running") is not False:
            raise ValueError(f"{old_name} deve permanecer parado")
        if name in occupied:
            raise ValueError(f"{name} já existe; não será substituído")
        config, host = row["Config"], row["HostConfig"]
        env_rows = config["Env"]
        env = dict(value.split("=", 1) for value in env_rows)
        if len(env) != len(env_rows):
            raise ValueError("variáveis duplicadas; recuperação exige configuração explícita")
        expected = dict(AUTO_MITIGATE="false", DRY_RUN="true", AGENTIC_MODE="shadow",
                        AGENTIC_LIVE_ACTUATION="false", QOS_TELEMETRY_ENABLED="true",
                        CONTROLLER_ID=subject["cid"], PORT=str(6060 + index),
                        QOS_DATASET_DIR="/app/qos_history", EXPORT_DIR="/app/prediction_history")
        if any(env.get(key) != value for key, value in expected.items()):
            raise ValueError(f"{old_name}: configuração shadow/identidade/histórico incompatível")
        if float(env.get("POLL_INTERVAL_S", "nan")) != 2:
            raise ValueError("amostragem deve continuar em 2 segundos")
        capacities = json.loads(env["QOS_PORT_CAPACITIES_JSON"])
        if capacities.get(subject["port_id"]) != subject["capacity_bps"]:
            raise ValueError("capacidade da porta diverge do protocolo")
        if any(host.get(key) for key in UNSUPPORTED_HOST_OPTIONS):
            raise ValueError("HostConfig customizado; não será descartado silenciosamente")
        if host.get("PidsLimit") not in (None, 0, -1):
            raise ValueError("limite de processos customizado; exige revisão")
        if host.get("RestartPolicy", {}).get("Name", "no") not in ("", "no"):
            raise ValueError("restart automático não é permitido nesta recuperação")
        image = row["Image"]
        image_config = json.loads(docker("image", "inspect", image))[0]["Config"]
        for key in ("Cmd", "Entrypoint", "User", "WorkingDir", "Healthcheck", "StopSignal"):
            if config.get(key) != image_config.get(key):
                raise ValueError(f"{old_name}: {key} customizado; exige revisão")
        networks = row["NetworkSettings"]["Networks"]
        primary = host["NetworkMode"]
        if primary in ("host", "none", "default", "bridge") or primary not in networks:
            raise ValueError("a rede primária deve ser a rede existente do domínio")
        bindings = host["PortBindings"]
        port = f"{6060 + index}/tcp"
        if set(bindings) != {port} or len(bindings[port]) != 1:
            raise ValueError("mapeamento REST customizado")
        binding = bindings[port][0]
        if binding["HostPort"] != str(6060 + index) or binding.get("HostIp", "") not in ("", "0.0.0.0", "127.0.0.1"):
            raise ValueError("porta REST incompatível")
        publish = f"{binding.get('HostIp') or '0.0.0.0'}:{binding['HostPort']}:{6060 + index}/tcp"
        mounts, sources = [], []
        destinations = set()
        for mount in row["Mounts"]:
            destination = mount["Destination"]
            if mount["Type"] != "bind" or destination in destinations:
                raise ValueError("somente os bind mounts padrão são suportados")
            if mount.get("Propagation", "rprivate") not in ("", "rprivate"):
                raise ValueError("propagação de mount customizada; exige revisão")
            destinations.add(destination)
            source = Path(mount["Source"]).resolve()
            if output.is_relative_to(source) or source.is_relative_to(output):
                raise ValueError("destino novo sobrepõe um volume original")
            if destination in HISTORY_TARGETS:
                new_source = output / f"{HISTORY_TARGETS[destination]}{index}"
                if destination == "/app/qos_history":
                    csv_path = source / "port_utilization.csv"
                    checksum = digest_file(csv_path)
                    for model in models:
                        hashes = {entry["csv_sha256"] for entry in model.training.get("source_series", [])
                                  if entry["cid"] == subject["cid"] and entry["port_id"] == subject["port_id"]}
                        if checksum not in hashes:
                            raise ValueError("CSV do piloto mudou; preserve-o e investigue antes de recuperar")
                    sources.append(dict(path=str(csv_path), sha256=checksum))
                source, readonly = new_source, False
            else:
                if mount["RW"]:
                    raise ValueError("volume adicional gravável não será reutilizado")
                readonly = True
            if "," in str(source) or "," in destination:
                raise ValueError("caminho de mount não suportado")
            mounts.append(dict(source=str(source), destination=destination, readonly=readonly))
        if not set(HISTORY_TARGETS).issubset(destinations):
            raise ValueError("mounts dos dois históricos não foram encontrados")
        plans.append(dict(name=name, original_name=old_name, original_id=row["Id"], image=image, env=env_rows,
                          primary_network=primary, additional_networks=sorted(set(networks) - {primary}),
                          publish=publish, mounts=mounts, protected_sources=sources))
    return protocol, plans


def public_plan(plan):
    return {key: value for key, value in plan.items() if key != "env"}


def apply(protocol_path, output, protocol, plans):
    output.mkdir(parents=True, exist_ok=False)
    receipt = dict(schema_version="comas-qos-runtime-recovery/1", status="PREPARING",
                   protocol_sha256=protocol["protocol_sha256"],
                   plans=[public_plan(plan) for plan in plans], created_container_ids=[])
    created = receipt["created_container_ids"]
    try:
        for plan in plans:
            # Recheck identity/state immediately before creating a copy.
            original = json.loads(docker("inspect", plan["original_name"]))[0]
            state = original["State"]
            if original["Id"] != plan["original_id"]:
                raise ValueError("container original foi substituído; refaça o plano")
            if state["Status"] != "exited" or state["Running"] is not False:
                raise ValueError("container original foi iniciado; interrompa a recuperação")
            arguments = ["create", "--pull", "never", "--name", plan["name"],
                         "--network", plan["primary_network"], "--publish", plan["publish"],
                         "--label", f"comas.qos.protocol={protocol['protocol_sha256']}", "--restart", "no"]
            for value in plan["env"]:
                arguments.extend(["--env", value])
            for mount in plan["mounts"]:
                if not mount["readonly"]:
                    Path(mount["source"]).mkdir(parents=True, exist_ok=False)
                option = f"type=bind,src={mount['source']},dst={mount['destination']}"
                if mount["readonly"]:
                    option += ",readonly"
                arguments.extend(["--mount", option])
            arguments.append(plan["image"])
            identity = docker(*arguments)
            created.append(identity)
            for network in plan["additional_networks"]:
                docker("network", "connect", network, identity)
        # Create and attach both networks before starting either collector.
        for identity, plan in zip(created, plans):
            row = json.loads(docker("inspect", identity))[0]
            actual = {mount["Destination"]: (str(Path(mount["Source"]).resolve()), not mount["RW"])
                      for mount in row["Mounts"] if mount["Type"] == "bind"}
            expected = {mount["destination"]: (mount["source"], mount["readonly"])
                        for mount in plan["mounts"]}
            if actual != expected or len(row["Mounts"]) != len(expected):
                raise ValueError("volumes da nova instância diferem do plano; não será iniciada")
            if row["Image"] != plan["image"] or set(row["Config"]["Env"]) != set(plan["env"]):
                raise ValueError("imagem ou variáveis da nova instância diferem do plano")
            if set(row["NetworkSettings"]["Networks"]) != {plan["primary_network"], *plan["additional_networks"]}:
                raise ValueError("redes da nova instância diferem do plano")
        docker("start", *created)
        for plan in plans:
            for source in plan["protected_sources"]:
                if digest_file(Path(source["path"])) != source["sha256"]:
                    raise ValueError("arquivo protegido mudou durante a recuperação")
        load_protocol(protocol_path)  # No evaluator/model mutation is permitted.
        receipt["status"] = "START_REQUESTED"
    except BaseException as exc:
        receipt["status"] = "FAILED"
        receipt["error"] = str(exc) or type(exc).__name__
        if created:
            try:
                docker("stop", *created)  # Only IDs returned by our own create calls.
            except (OSError, ValueError, subprocess.SubprocessError):
                receipt["cleanup_error"] = "não foi possível parar todas as novas instâncias"
        raise
    finally:
        write_new_json(output / "recovery.json", receipt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)
    try:
        path, output = args.protocol.resolve(), args.output.resolve()
        protocol, plans = prepare(path, output)
        if args.apply:
            apply(path, output, protocol, plans)
            print(f"start_requested=2 originals_preserved=2 pilot_hashes_unchanged=true")
            print(f"receipt={output / 'recovery.json'}")
        else:
            print("plan=READY copies=2 originals_preserved=2 changes=new_names,new_history_mounts,automatic_container_IPs")
        return 0
    except KeyboardInterrupt:
        print("recuperação interrompida; originais preservados", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
