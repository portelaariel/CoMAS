"""CSV persistence contracts independent from the service and its environment."""

import csv
from datetime import datetime
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from comas.telemetry import PredictionHistoryExporter


class PredictionHistoryTests(unittest.TestCase):
    META = dict(dpid=1, nw_src='10.0.0.1', nw_dst='10.0.0.8')
    KEY = 'flow:1:10.0.0.1->10.0.0.8'

    def test_csv_values_warmup_and_append_preserve_one_header(self):
        with tempfile.TemporaryDirectory() as directory:
            exporter = PredictionHistoryExporter(directory, flush_every=2)
            exporter.record(self.KEY, self.META, 1.0, 10.0, 10.0, 0.0, None, False)
            exporter.record(self.KEY, self.META, 2.0, 20.0, 10.0, 10.0, 5.0, True)
            self.assertEqual(exporter.status()['records_written'], 2)
            exporter.close()
            reopened = PredictionHistoryExporter(directory)
            reopened.record(self.KEY, self.META, 3.0, 11.0, 10.0, 1.0, 0.5, False)
            reopened.close()
            path = next(Path(directory).glob('*.csv'))
            with path.open() as handle:
                reader = csv.DictReader(handle)
                rows = list(reader)
                self.assertEqual(reader.fieldnames, PredictionHistoryExporter.HEADER)
            self.assertEqual(len(rows), 3)
            self.assertEqual([row['timestamp'] for row in rows], ['1.000', '2.000', '3.000'])
            self.assertEqual(datetime.fromisoformat(rows[0]['datetime_iso']).timestamp(), 1.0)
            self.assertEqual(rows[0]['z_score'], '')
            self.assertEqual(rows[0]['is_anomaly'], 'False')
            self.assertEqual(rows[1]['z_score'], '5.0000')
            self.assertEqual(rows[1]['prediction_error'], '10.0')
            self.assertEqual(rows[1]['is_anomaly'], 'True')
            self.assertEqual(path.read_text().count(','.join(PredictionHistoryExporter.HEADER)), 1)

    def test_disabled_and_nonmatching_prefixes_produce_no_files(self):
        with tempfile.TemporaryDirectory() as directory:
            disabled_path = Path(directory) / 'disabled'
            disabled = PredictionHistoryExporter(str(disabled_path), enabled=False)
            disabled.record(self.KEY, self.META, 1.0, 1.0, 1.0, 0.0, None, False)
            self.assertFalse(disabled_path.exists())
            exporter = PredictionHistoryExporter(directory)
            exporter.record('port:1:2', {}, 1.0, 1.0, 1.0, 0.0, None, False)
            self.assertEqual(list(Path(directory).iterdir()), [])
            exporter.close()

    def test_failed_writes_are_logged_without_raising(self):
        with tempfile.TemporaryDirectory() as directory:
            exporter = PredictionHistoryExporter(directory)
            with patch('builtins.open', side_effect=OSError('test write failure')):
                with self.assertLogs('FlowPredictor', level='ERROR'):
                    exporter.record(self.KEY, self.META, 1.0, 1.0, 1.0, 0.0, None, False)
            self.assertEqual(exporter.records_written, 0)
            exporter.close()

    def test_unusable_directory_disables_exporter(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'file'
            path.write_text('preserve')
            with self.assertLogs('FlowPredictor', level='ERROR'):
                exporter = PredictionHistoryExporter(str(path))
            self.assertFalse(exporter.enabled)
            self.assertEqual(path.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
