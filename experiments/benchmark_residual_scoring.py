#!/usr/bin/env python3
"""Compare local residual-scoring CPU time against an explicit Git reference.

This microbenchmark does not measure SDN latency or detection generalization.
The reference class is loaded without importing the service or using the network.
"""

import argparse
import ast
from collections import deque
import hashlib
import json
from operator import is_
from pathlib import Path
import platform
import statistics
import subprocess
import sys
import time
from typing import Optional, Tuple


ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from comas.detection import ResidualAnomalyDetector


def load_reference(ref):
    commit = subprocess.check_output(
        ['git', 'rev-parse', '--verify', '--end-of-options', ref + '^{commit}'],
        cwd=ROOT, text=True, stderr=subprocess.PIPE).strip()
    for name in ('comas/detection/residual.py', 'flow_predictor_cnsm.py'):
        result = subprocess.run(['git', 'show', commit + ':' + name], cwd=ROOT,
                                capture_output=True, text=True, check=False)
        if result.returncode:
            continue
        tree = ast.parse(result.stdout)
        node = next((item for item in tree.body if isinstance(item, ast.ClassDef)
                     and item.name == 'ResidualAnomalyDetector'), None)
        if node is not None:
            namespace = dict(deque=deque, Optional=Optional, Tuple=Tuple, is_=is_)
            exec(compile(ast.Module(body=[node], type_ignores=[]), name, 'exec'), namespace)
            return namespace['ResidualAnomalyDetector'], dict(
                commit=commit, path=name,
                source_sha256=hashlib.sha256(result.stdout.encode()).hexdigest())
    raise ValueError('detector de referência não encontrado')


def prepared(cls, window, fixed=False):
    settings = dict(fixed_center=0.0, fixed_scale=1.0) if fixed else {}
    detector = cls(window, 4.0, window, **settings)
    detector.residuals.extend(float(i % 11 - 5) / 10.0 for i in range(window))
    return detector


def measure(detector, values):
    started = time.perf_counter_ns()
    for value in values:
        detector.score(value)
    return (time.perf_counter_ns() - started) / 1e9


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--reference-ref', default='baseline/pre-refactor-2026-11-12')
    parser.add_argument('--iterations', type=int, default=30000)
    parser.add_argument('--repeats', type=int, default=5)
    parser.add_argument('--window', type=int, default=120)
    args = parser.parse_args(argv)
    if min(args.iterations, args.repeats, args.window) < 1:
        parser.error('iterations, repeats e window devem ser positivos')
    try:
        reference, provenance = load_reference(args.reference_ref)
    except (subprocess.CalledProcessError, ValueError) as error:
        parser.error(str(error))
    cases = {}
    for name in ('adaptive_rejected', 'constant_normal', 'varying_normal', 'fixed'):
        fixed = name == 'fixed'
        if name in ('adaptive_rejected', 'fixed'):
            values = [100.0] * args.iterations
        elif name == 'constant_normal':
            values = [0.0] * args.iterations
        else:
            values = [float(i % 11 - 5) / 10.0 for i in range(args.iterations)]
        old, new = (prepared(cls, args.window, fixed) for cls in (reference, ResidualAnomalyDetector))
        assert [old.score(value) for value in values] == [new.score(value) for value in values]
        assert list(old.residuals) == list(new.residuals)
        timings = [[], []]
        for repeat in range(args.repeats):
            for index in ((0, 1) if repeat % 2 == 0 else (1, 0)):
                cls = (reference, ResidualAnomalyDetector)[index]
                timings[index].append(measure(prepared(cls, args.window, fixed), values))
        before, after = (statistics.median(items) for items in timings)
        cases[name] = dict(outputs_match=True, reference_seconds=timings[0],
                           current_seconds=timings[1], reference_median_seconds=before,
                           current_median_seconds=after, speedup=before / after)
    print(json.dumps(dict(
        schema_version='comas-residual-microbenchmark/1.0',
        scope='Local CPU scoring microbenchmark; not end-to-end SDN latency or independent detection validation.',
        reference=provenance,
        current_source_sha256=hashlib.sha256((ROOT / 'comas/detection/residual.py').read_bytes()).hexdigest(),
        python=sys.version, machine=platform.machine(), platform=platform.platform(),
        iterations=args.iterations, repeats=args.repeats, window=args.window, cases=cases,
    ), indent=2))


if __name__ == '__main__':
    main()
