"""Behavioral replay and passive-import checks for extracted traffic primitives."""

import ast
import json
import math
import os
from pathlib import Path, PurePosixPath
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest

from comas.detection import ResidualAnomalyDetector
from comas.forecasting import HoltPredictor


ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'tests/fixtures/runtime_primitives_baseline_v1.json'


class RuntimePrimitiveTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.reference = json.loads(FIXTURE.read_text())

    def assert_replay_equal(self, actual, expected):
        if isinstance(expected, float):
            self.assertTrue(math.isclose(actual, expected, rel_tol=1e-12, abs_tol=1e-12),
                            (actual, expected))
        elif isinstance(expected, bool):
            self.assertIs(type(actual), bool)
            self.assertEqual(actual, expected)
        elif isinstance(expected, dict):
            self.assertEqual(actual.keys(), expected.keys())
            for key in expected:
                self.assert_replay_equal(actual[key], expected[key])
        elif isinstance(expected, list):
            self.assertEqual(len(actual), len(expected))
            for value, reference in zip(actual, expected):
                self.assert_replay_equal(value, reference)
        else:
            self.assertEqual(actual, expected)

    @staticmethod
    def holt_state(predictor):
        return dict(level=predictor.level, trend=predictor.trend, n=predictor.n,
                    forecasts=[predictor.predict(h) for h in (0, 1, 3)],
                    transformed_forecasts=[predictor.predict_transformed(h) for h in (0, 1, 3)],
                    trend_bps=predictor.trend_bps)

    def test_reference_is_bound_to_the_pre_refactor_runtime(self):
        baseline = json.loads((ROOT / 'docs/reference-baseline.json').read_text())
        self.assertEqual(self.reference['schema_version'], 'comas-runtime-primitives-regression/1.0')
        self.assertEqual(self.reference['reference_commit'], baseline['commit'])
        self.assertEqual(self.reference['reference_source_sha256'],
                         baseline['files']['flow_predictor_cnsm.py']['sha256'])

    def test_holt_replays_recorded_reference_states_and_predictions(self):
        for case in self.reference['holt']:
            with self.subTest(case=case['name']):
                predictor = HoltPredictor(**case['settings'])
                self.assert_replay_equal(self.holt_state(predictor), case['initial'])
                for step, row in enumerate(case['rows']):
                    with self.subTest(step=step):
                        predicted = predictor.predict()
                        self.assert_replay_equal(predicted, row['prediction_before_update'])
                        self.assert_replay_equal(predictor.residual(row['observed'], predicted), row['residual'])
                        predictor.update(row['observed'])
                        self.assert_replay_equal(self.holt_state(predictor), row['after'])

    def test_detector_replays_warmup_asymmetry_adaptation_and_rejected_outliers(self):
        for case in self.reference['detector']:
            with self.subTest(case=case['name']):
                detector = ResidualAnomalyDetector(**case['settings'])
                for step, row in enumerate(case['rows']):
                    with self.subTest(step=step):
                        self.assert_replay_equal(detector.ready, row['ready_before'])
                        z_score, anomaly = detector.score(row['residual'])
                        self.assert_replay_equal(z_score, row['z_score'])
                        self.assert_replay_equal(anomaly, row['anomaly'])
                        self.assert_replay_equal(detector.ready, row['ready_after'])
                        self.assert_replay_equal(list(detector.residuals), row['residual_window'])
                        self.assert_replay_equal(detector.threshold_for(z_score), row['threshold'])

    def test_unsupported_transform_keeps_its_error_contract(self):
        with self.assertRaisesRegex(ValueError, 'transformação não suportada'):
            HoltPredictor(transform='unsupported').update(10.0)

    def test_runtime_exposes_the_same_public_class_names(self):
        tree = ast.parse((ROOT / 'flow_predictor_cnsm.py').read_text())
        names = {'HoltPredictor', 'ResidualAnomalyDetector'}
        selected = [node for node in tree.body if isinstance(node, ast.ImportFrom)
                    and any(alias.name in names for alias in node.names)]
        namespace = {}
        exec(compile(ast.Module(body=selected, type_ignores=[]), 'runtime-exports', 'exec'), namespace)
        self.assertIs(namespace['HoltPredictor'], HoltPredictor)
        self.assertIs(namespace['ResidualAnomalyDetector'], ResidualAnomalyDetector)

    def test_docker_copy_layout_supports_passive_imports_without_service_dependencies(self):
        dockerfile = (ROOT / 'Dockerfile.flow_predictor').read_text().replace('\\\n', ' ')
        lines = dockerfile.splitlines()
        workdir = PurePosixPath(next(shlex.split(line)[1] for line in lines if line.startswith('WORKDIR ')))
        with tempfile.TemporaryDirectory() as directory:
            image_root = Path(directory)
            for line in lines:
                if not line.startswith('COPY '):
                    continue
                sources = shlex.split(line)[1:-1]
                destination = image_root / PurePosixPath(shlex.split(line)[-1]).relative_to(workdir)
                destination.mkdir(parents=True, exist_ok=True)
                for name in sources:
                    source = ROOT / name
                    if source.is_dir():
                        shutil.copytree(source, destination, dirs_exist_ok=True)
                    else:
                        shutil.copy2(source, destination / source.name)
            probe = image_root / 'check_passive_imports.py'
            probe.write_text('''import builtins
import json
import sys
import threading

original_import = builtins.__import__
blocked = {"flask", "requests", "etcd3", "flow_predictor_cnsm"}
def guarded_import(name, *args, **kwargs):
    if name.split(".")[0] in blocked:
        raise AssertionError("service dependency imported: " + name)
    return original_import(name, *args, **kwargs)
builtins.__import__ = guarded_import
before = list(threading.enumerate())
from comas.forecasting import HoltPredictor
from comas.detection import ResidualAnomalyDetector
p = HoltPredictor(alpha=0.5, beta=0.5)
p.update(10.0)
p.update(14.0)
d = ResidualAnomalyDetector(5, 4.0, 0, fixed_center=0.0, fixed_scale=1.0)
assert threading.enumerate() == before
assert not blocked.intersection(sys.modules)
print(json.dumps({"prediction": p.predict(), "score": d.score(5.0)}))
''')
            environment = dict(os.environ)
            environment.pop('PYTHONPATH', None)
            environment.update(ETCD_ENDPOINTS='unreachable.invalid:2379',
                               OFFLINE_MODEL_PATH='/missing/model.json',
                               OFFLINE_MODEL_REQUIRED='true', EXPORT_ENABLED='true')
            result = subprocess.run([sys.executable, '-B', '-S', str(probe)], cwd=image_root,
                                    env=environment, capture_output=True, text=True, timeout=10)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout), {'prediction': 13.0, 'score': [5.0, True]})
            self.assertFalse((image_root / 'prediction_history').exists())


if __name__ == '__main__':
    unittest.main()
