import csv
import tempfile
import unittest
from pathlib import Path

from qos_telemetry import (
    PortCapacityRegistry,
    PortCounterSeries,
    QosDatasetExporter,
    QosTelemetryManager,
)


class PortCapacityTests(unittest.TestCase):
    def test_requires_explicit_decimal_dpid_and_port(self):
        registry = PortCapacityRegistry.from_json(
            '{"1:2": 100000000, "3:4": 1000000000}'
        )
        self.assertEqual(registry.get(1, 2), 100_000_000.0)
        self.assertIsNone(registry.get(1, 3))

        with self.assertRaisesRegex(ValueError, "dpid:port"):
            PortCapacityRegistry.from_json('{"default": 100000000}')
        with self.assertRaisesRegex(ValueError, "positivo"):
            PortCapacityRegistry.from_json('{"1:2": 0}')


class PortCounterSeriesTests(unittest.TestCase):
    def setUp(self):
        self.series = PortCounterSeries(
            cid="domain-0",
            dpid=1,
            port_no=2,
            capacity_bps=100_000_000,
            max_gap_s=5.0,
        )

    def test_uses_max_direction_for_full_duplex_utilization(self):
        first = self.series.ingest(
            rx_bytes=1_000, tx_bytes=2_000, ts_ns=1_000_000_000
        )
        second = self.series.ingest(
            rx_bytes=11_001_000,
            tx_bytes=7_002_000,
            ts_ns=3_000_000_000,
        )

        self.assertEqual(first["quality"], "PRIMING")
        self.assertFalse(first["valid"])
        self.assertEqual(second["rx_bps"], 44_000_000.0)
        self.assertEqual(second["tx_bps"], 28_000_000.0)
        self.assertEqual(second["aggregate_bps"], 72_000_000.0)
        self.assertEqual(second["utilization_ratio"], 0.44)
        self.assertTrue(second["valid"])

    def test_counter_reset_is_explicit_and_re_primes_baseline(self):
        self.series.ingest(
            rx_bytes=10_000, tx_bytes=20_000, ts_ns=1_000_000_000
        )
        reset = self.series.ingest(
            rx_bytes=100, tx_bytes=200, ts_ns=3_000_000_000
        )
        valid = self.series.ingest(
            rx_bytes=1_100, tx_bytes=2_200, ts_ns=5_000_000_000
        )

        self.assertEqual(reset["quality"], "COUNTER_RESET")
        self.assertIsNone(reset["utilization_ratio"])
        self.assertEqual(valid["quality"], "VALID")
        self.assertEqual(valid["delta_rx_bytes"], 1_000)

    def test_gap_is_not_turned_into_low_average_rate(self):
        self.series.ingest(
            rx_bytes=1_000, tx_bytes=2_000, ts_ns=1_000_000_000
        )
        gap = self.series.ingest(
            rx_bytes=1_001_000, tx_bytes=1_002_000, ts_ns=8_000_000_000
        )

        self.assertEqual(gap["quality"], "MISSING_INTERVAL")
        self.assertFalse(gap["valid"])
        self.assertIsNone(gap["rx_bps"])


class QosDatasetTests(unittest.TestCase):
    def test_manager_skips_unconfigured_ports_and_persists_quality_markers(self):
        with tempfile.TemporaryDirectory() as directory:
            manager = QosTelemetryManager(
                cid="domain-0",
                capacities=PortCapacityRegistry({"1:2": 100_000_000}),
                max_gap_s=5.0,
                exporter=QosDatasetExporter(directory, flush_every=1),
            )

            self.assertIsNone(manager.ingest(
                dpid=1, port_no=3, rx_bytes=0, tx_bytes=0,
                ts_ns=1_000_000_000,
            ))
            manager.ingest(
                dpid=1, port_no=2, rx_bytes=1_000, tx_bytes=2_000,
                ts_ns=1_000_000_000,
            )
            manager.ingest(
                dpid=1, port_no=2, rx_bytes=11_001_000,
                tx_bytes=7_002_000, ts_ns=3_000_000_000,
            )
            status = manager.status()
            manager.close()

            self.assertEqual(status["unconfigured_samples"], 1)
            self.assertEqual(status["invalid_samples"], 1)
            self.assertEqual(status["valid_samples"], 1)
            path = Path(directory) / "port_utilization.csv"
            with path.open(encoding="utf-8", newline="") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual([row["quality"] for row in rows], [
                "PRIMING", "VALID",
            ])
            self.assertEqual(rows[0]["utilization_ratio"], "")
            self.assertEqual(rows[1]["utilization_ratio"], "0.44")


if __name__ == "__main__":
    unittest.main()
