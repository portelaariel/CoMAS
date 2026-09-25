import csv
import json
import tempfile
import unittest
from pathlib import Path

from backtest_sla_risk import (
    _actual_future_outcome,
    _warning_summary,
    backtest_model,
    build_report,
)
from qos_holt import HorizonModel, QosHoltModel, train_qos_holt_model
from sla_risk import SlaRiskPolicy
from train_qos_holt_model import MANIFEST_SCHEMA, load_manifest


def model(radius):
    return QosHoltModel(
        metric="utilization_ratio",
        sample_interval_s=1.0,
        coverage=0.9,
        priming_samples=2,
        horizons=tuple(
            HorizonModel(
                horizon_steps=step,
                alpha=0.5,
                beta=0.2,
                interval_radius=radius,
                calibration_samples=20,
            )
            for step in (1, 2, 3)
        ),
        created_at="2026-09-25T00:00:00Z",
        training={"validation_scope": "test", "promotion_eligible": False},
    )


class SlaRiskBacktestTests(unittest.TestCase):
    def test_ground_truth_uses_same_consecutive_horizons_as_policy(self):
        policy = SlaRiskPolicy(
            metric="utilization_ratio",
            comparator="MAX",
            threshold=0.8,
            horizons_steps=(1, 2, 3),
            required_consecutive_horizons=2,
        )
        outcome = _actual_future_outcome(
            [0.1, 0.85, 0.7, 0.9], 0, policy
        )
        self.assertFalse(outcome["positive"])

        outcome = _actual_future_outcome(
            [0.1, 0.7, 0.85, 0.9], 0, policy
        )
        self.assertTrue(outcome["positive"])
        self.assertEqual(outcome["confirming_horizon_steps"], [2, 3])

    def test_warning_lead_time_uses_earliest_alert_within_horizon(self):
        summary = _warning_summary(
            sequence=[0.1, 0.2, 0.3, 0.85, 0.9],
            observations=[
                {"index": 0, "candidate": True},
                {"index": 1, "candidate": True},
                {"index": 2, "candidate": False},
            ],
            comparator="MAX",
            threshold=0.8,
            max_horizon_steps=3,
            sample_interval_s=2.0,
            signal="candidate",
        )
        self.assertEqual(summary["detected"], 1)
        self.assertEqual(summary["warning_lead_time_s"]["values"], [6.0])
        self.assertEqual(summary["events"][0]["alert_index"], 0)

    def test_interval_changes_watch_but_not_point_candidate(self):
        series = [{
            "series_id": "test-domain",
            "cid": "domain-0",
            "port_id": "2:4",
            "values": [
                0.10, 0.20, 0.30, 0.45, 0.55, 0.65, 0.75,
                0.85, 0.90, 0.95, 0.70, 0.50, 0.30,
            ],
        }]
        narrow, narrow_points, narrow_candidates = backtest_model(
            model=model(0.05),
            series=series,
            threshold=0.8,
            required_consecutive_horizons=2,
            activation_windows=2,
            clear_windows=2,
        )
        wide, wide_points, wide_candidates = backtest_model(
            model=model(0.40),
            series=series,
            threshold=0.8,
            required_consecutive_horizons=2,
            activation_windows=2,
            clear_windows=2,
        )

        self.assertEqual(narrow_points, wide_points)
        self.assertEqual(narrow_candidates, wide_candidates)
        self.assertGreaterEqual(
            wide["aggregate"]["watch_only"]["windows"],
            narrow["aggregate"]["watch_only"]["windows"],
        )
        self.assertEqual(
            wide["aggregate"]["candidate"]["confusion"],
            narrow["aggregate"]["candidate"]["confusion"],
        )
        self.assertIn(
            "persistent_activation", wide["aggregate"]["crossing_events"]
        )
        self.assertEqual(
            len(wide["series"][0]["candidate_errors"]),
            wide["aggregate"]["candidate"]["confusion"]["FP"]
            + wide["aggregate"]["candidate"]["confusion"]["FN"],
        )

    def test_report_validates_sources_and_compares_two_artifacts(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            csv_path = root / "port_utilization.csv"
            fieldnames = [
                "cid", "ts_ns", "port_id", "utilization_ratio", "quality",
            ]
            with csv_path.open("w", encoding="utf-8", newline="") as handle:
                writer = csv.DictWriter(handle, fieldnames=fieldnames)
                writer.writeheader()
                for index in range(90):
                    writer.writerow({
                        "cid": "domain-0",
                        "ts_ns": 1_000_000_000 + index * 2_000_000_000,
                        "port_id": "2:4",
                        "utilization_ratio": 0.1 + (index % 30) * 0.03,
                        "quality": "VALID",
                    })

            boundaries = [
                1_000_000_000,
                1_000_000_000 + 30 * 2_000_000_000,
                1_000_000_000 + 60 * 2_000_000_000,
                1_000_000_000 + 90 * 2_000_000_000,
            ]
            manifest_path = root / "manifest.json"
            manifest_path.write_text(json.dumps({
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
                    for index, split in enumerate(
                        ("train", "calibration", "test")
                    )
                ],
            }), encoding="utf-8")
            _, partitions, metadata = load_manifest(manifest_path)

            paths = []
            for coverage in (0.9, 0.95):
                trained = train_qos_holt_model(
                    train_sequences=partitions["train"],
                    calibration_sequences=partitions["calibration"],
                    test_sequences=partitions["test"],
                    horizons_steps=(2, 4, 6),
                    sample_interval_s=2.0,
                    coverage=coverage,
                    priming_samples=2,
                    alphas=(0.5,),
                    betas=(0.2,),
                    created_at=f"2026-09-25T00:00:0{int(coverage * 10)}Z",
                    training_metadata=metadata,
                )
                path = root / f"model-{coverage}.json"
                trained.save(path)
                paths.append((f"coverage{coverage}", path))

            report = build_report(
                manifest_path=manifest_path,
                model_specs=paths,
                threshold=0.8,
                required_consecutive_horizons=2,
                activation_windows=2,
                clear_windows=2,
            )

            self.assertTrue(
                report["comparison"]["point_forecasts_identical_across_models"]
            )
            self.assertTrue(
                report["comparison"]["candidate_decisions_identical_across_models"]
            )
            self.assertEqual(set(report["models"]), {"coverage0.9", "coverage0.95"})
            self.assertGreater(
                report["models"]["coverage0.9"]["aggregate"]["evaluated_windows"],
                0,
            )


if __name__ == "__main__":
    unittest.main()
