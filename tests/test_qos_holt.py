import csv
import json
import tempfile
import unittest
from pathlib import Path

from qos_holt import (
    MultiHorizonHoltForecaster,
    QosHoltModel,
    conformal_radius,
    forecast_records,
    train_qos_holt_model,
)
from sla_risk import SlaRiskPolicy, evaluate_sla_forecast
from train_qos_holt_model import MANIFEST_SCHEMA, load_manifest


def ramp(length, start=0.05, step=0.01):
    return [start + index * step for index in range(length)]


class QosHoltCoreTests(unittest.TestCase):
    def test_forecasts_never_cross_sequence_boundaries(self):
        records = forecast_records(
            [ramp(10), ramp(12, start=0.4)],
            alpha=0.5,
            beta=0.2,
            horizon_steps=2,
            priming_samples=2,
        )
        self.assertEqual(len(records), 7 + 9)

    def test_conformal_radius_uses_finite_sample_rank(self):
        self.assertEqual(conformal_radius([1, -2, 3, -4], 0.8), 4.0)

    def test_training_calibrates_each_horizon_and_round_trips(self):
        model = train_qos_holt_model(
            train_sequences=[ramp(50), ramp(48, start=0.1, step=0.008)],
            calibration_sequences=[ramp(35, start=0.2, step=0.012)],
            test_sequences=[ramp(36, start=0.15, step=0.011)],
            horizons_steps=(2, 4, 6),
            sample_interval_s=2.0,
            coverage=0.9,
            priming_samples=2,
            alphas=(0.2, 0.5, 0.9),
            betas=(0.0, 0.2, 0.5),
            created_at="2026-09-24T00:00:00Z",
            training_metadata={"validation_scope": "test"},
        )

        self.assertEqual(
            [item.horizon_steps for item in model.horizons], [2, 4, 6]
        )
        self.assertTrue(all(item.interval_radius >= 0 for item in model.horizons))
        self.assertTrue(all(item.test_metrics["samples"] > 0 for item in model.horizons))

        loaded = QosHoltModel.from_dict(model.to_dict())
        self.assertEqual(loaded.resolved_model_id(), model.resolved_model_id())

        tampered = model.to_dict()
        tampered["horizons"][0]["alpha"] = 0.123
        with self.assertRaisesRegex(ValueError, "model_id"):
            QosHoltModel.from_dict(tampered)

    def test_runtime_output_connects_to_sla_risk_contract(self):
        model = train_qos_holt_model(
            train_sequences=[ramp(40)],
            calibration_sequences=[ramp(30, start=0.3)],
            test_sequences=[ramp(30, start=0.4)],
            horizons_steps=(2, 4, 6),
            sample_interval_s=2.0,
            coverage=0.9,
            priming_samples=2,
            alphas=(0.5,),
            betas=(0.2,),
            created_at="2026-09-24T00:00:00Z",
        )
        forecaster = MultiHorizonHoltForecaster(model)
        self.assertEqual(forecaster.update(0.70), [])
        forecasts = forecaster.update(0.75)
        self.assertEqual([row["horizon_steps"] for row in forecasts], [2, 4, 6])

        evaluation = evaluate_sla_forecast(
            policy=SlaRiskPolicy(
                metric="utilization_ratio",
                comparator="MAX",
                threshold=0.8,
                horizons_steps=(2, 4, 6),
            ),
            cid="192.168.10.10",
            subject_type="port",
            subject_id="2:4",
            observed_value=0.75,
            window_id=10,
            observation_ns=1_000_000_000,
            sample_interval_s=2.0,
            forecasts=forecasts,
            model_id=model.resolved_model_id(),
            model_type=model.model_type,
            created_ns=1_100_000_000,
            ttl_s=12,
        )
        self.assertIn(evaluation["decision"], {
            "NORMAL", "WATCH", "PREDICTED_SLA_RISK",
        })


class QosHoltManifestTests(unittest.TestCase):
    FIELDNAMES = [
        "schema_version", "cid", "ts_ns", "timestamp_iso", "dpid",
        "port_no", "port_id", "capacity_bps", "rx_bytes", "tx_bytes",
        "delta_rx_bytes", "delta_tx_bytes", "interval_s", "rx_bps",
        "tx_bps", "aggregate_bps", "utilization_ratio", "quality",
        "valid", "above_capacity",
    ]

    def _write_dataset(self, directory: Path) -> Path:
        path = directory / "port_utilization.csv"
        with path.open("w", encoding="utf-8", newline="") as handle:
            writer = csv.DictWriter(handle, fieldnames=self.FIELDNAMES)
            writer.writeheader()
            for index in range(60):
                timestamp = 1_000_000_000 + index * 2_000_000_000
                writer.writerow({
                    "schema_version": 1,
                    "cid": "domain-0",
                    "ts_ns": timestamp,
                    "port_id": "2:4",
                    "utilization_ratio": 0.05 + index * 0.01,
                    "quality": "VALID",
                    "valid": True,
                })
        return path

    def _manifest(self, csv_path: Path):
        boundaries = [
            1_000_000_000,
            1_000_000_000 + 20 * 2_000_000_000,
            1_000_000_000 + 40 * 2_000_000_000,
            1_000_000_000 + 60 * 2_000_000_000,
        ]
        return {
            "schema_version": MANIFEST_SCHEMA,
            "validation_scope": "pilot_single_run_temporal_split",
            "sample_interval_s": 2,
            "horizons_steps": [2, 4, 6],
            "coverage": 0.9,
            "priming_samples": 2,
            "series": [
                {
                    "series_id": split,
                    "split": split,
                    "cid": "domain-0",
                    "port_id": "2:4",
                    "csv": str(csv_path),
                    "start_ns": boundaries[index],
                    "end_ns": boundaries[index + 1],
                }
                for index, split in enumerate(("train", "calibration", "test"))
            ],
        }

    def test_manifest_keeps_temporal_partitions_disjoint(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = self._write_dataset(root)
            manifest_path = root / "manifest.json"
            manifest_path.write_text(
                json.dumps(self._manifest(dataset)), encoding="utf-8"
            )

            _, partitions, metadata = load_manifest(manifest_path)

            self.assertEqual(
                {key: len(value[0]) for key, value in partitions.items()},
                {"train": 20, "calibration": 20, "test": 20},
            )
            self.assertFalse(metadata["promotion_eligible"])

    def test_manifest_rejects_cross_split_overlap(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dataset = self._write_dataset(root)
            payload = self._manifest(dataset)
            payload["series"][1]["start_ns"] = payload["series"][0]["end_ns"] - 1
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps(payload), encoding="utf-8")

            with self.assertRaisesRegex(ValueError, "sobrepõem"):
                load_manifest(manifest_path)


if __name__ == "__main__":
    unittest.main()
