#!/usr/bin/env python3
"""Collect fresh v4 shadow telemetry; no predictive decision or action is enabled."""

from __future__ import annotations

import argparse
import fcntl
import os
import signal
import subprocess
import sys
from pathlib import Path
from typing import Sequence

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts import collect_qos_validation_campaign as collector
from predictive_sla_validation import write_new_json
from predictive_sla_validation_v3 import report_exit_code
from predictive_sla_validation_v4 import campaign_path, evaluate_campaign, load_protocol


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--preflight-only", action="store_true")
    parser.add_argument("--output", type=Path)
    parser.add_argument("--allow-lab-traffic", action="store_true")
    args = parser.parse_args(argv)
    try:
        protocol_path = args.protocol.resolve()
        protocol = load_protocol(protocol_path)
        if args.preflight_only:
            snapshot = collector.preflight(protocol)
            print(f"preflight={snapshot['status']} domains={len(snapshot['safety'])} hosts=2 switches=4 "
                  "models=2 preventive_entry=true actuation=false")
            return 0
        if not args.allow_lab_traffic or args.output is None:
            raise ValueError("coleta v4 exige --allow-lab-traffic e novo --output")
        if sys.platform != "linux":
            raise ValueError("a coleta deve ocorrer no servidor Linux")
        output = campaign_path(protocol_path, args.output, new=True)
        # Same lock as v1-v3: never overlap versions on the laboratory traffic path.
        with Path(f"/tmp/comas-qos-validation-{os.getuid()}.lock").open("a") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            collector.preflight(protocol)
            output.mkdir(exist_ok=False)
            write_new_json(output / "campaign-plan.json", protocol)
            previous_term = signal.signal(signal.SIGTERM, collector.interrupt_collection)
            try:
                for case in protocol["cases"]:
                    if load_protocol(protocol_path) != protocol:
                        raise ValueError("protocolo mudou entre execuções")
                    collector.collect_case(protocol, case, output / case["case_id"])
                    print(f"{case['case_id']}: collected", flush=True)
                report = evaluate_campaign(protocol_path, output)
                write_new_json(output / "campaign-summary.json", report)
                print(f"status={report['status']} runs={report['evaluated_runs']}/12 criteria={report['criteria_status']}")
                return report_exit_code(report)
            finally:
                signal.signal(signal.SIGTERM, previous_term)
    except KeyboardInterrupt:
        print("coleta interrompida; artefatos parciais preservados", file=sys.stderr)
        return 130
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as exc:
        print(f"erro: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
