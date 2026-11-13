"""Observable scoring behavior when an adaptive baseline is reused."""

import unittest

from comas.detection import ResidualAnomalyDetector


class ResidualBaselineTests(unittest.TestCase):
    def detector(self):
        detector = ResidualAnomalyDetector(5, 4.0, 3)
        detector.residuals.extend([0.0, 1.0, 2.0, 3.0, 4.0])
        for _ in range(4):
            self.assertEqual(detector.score(100.0), (98.0 / 1.4826, True))
        return detector

    def test_repeated_rejections_preserve_window_and_score(self):
        detector = self.detector()
        for _ in range(50):
            self.assertEqual(detector.score(100.0), (98.0 / 1.4826, True))
        self.assertEqual(list(detector.residuals), [0.0, 1.0, 2.0, 3.0, 4.0])

    def test_public_middle_edit_and_scale_factor_are_observed(self):
        detector = self.detector()
        detector.residuals[2] = 20.0
        self.assertEqual(detector.score(100.0), (97.0 / (2.0 * 1.4826), True))
        detector.MAD_K = 2.0
        self.assertEqual(detector.score(100.0), (24.25, True))

    def test_accepted_samples_update_the_next_baseline(self):
        detector = self.detector()
        self.assertFalse(detector.score(3.5)[1])
        self.assertEqual(list(detector.residuals), [1.0, 2.0, 3.0, 4.0, 3.5])
        self.assertEqual(detector.score(100.0), (97.0 / 1.4826, True))

    def test_equal_valued_replacement_with_different_types_is_observed(self):
        detector = ResidualAnomalyDetector(5, 1e-10, 3)
        values = [10**20 + i * 16384 for i in range(5)]
        detector.residuals.extend(values)
        residual = values[2] + 1
        for _ in range(4):
            self.assertTrue(detector.score(residual)[1])
        detector.residuals.clear()
        detector.residuals.extend(float(value) for value in values)
        self.assertEqual(detector.score(residual), (0.0, False))

    def test_calibration_and_adaptation_switches_remain_live(self):
        detector = ResidualAnomalyDetector(5, 4.0, 10, fixed_center=0.0,
                                           fixed_scale=1.0, online_adaptation=True)
        detector.residuals.extend([1.0, 2.0, 3.0])
        for _ in range(4):
            self.assertEqual(detector.score(100.0), (100.0, True))
        detector.warmup = 3
        for _ in range(4):
            self.assertEqual(detector.score(100.0), (98.0 / 1.4826, True))
        detector.online_adaptation = False
        detector.fixed_center, detector.fixed_scale = 50.0, 10.0
        self.assertEqual(detector.score(100.0), (5.0, True))
        detector.online_adaptation = True
        self.assertEqual(detector.score(100.0), (98.0 / 1.4826, True))

    def test_subclass_adjustments_do_not_accumulate(self):
        class ShiftedDetector(ResidualAnomalyDetector):
            def _center_scale(self):
                center, scale = super()._center_scale()
                return center + 1.0, scale

        detector = ShiftedDetector(5, 4.0, 3)
        detector.residuals.extend([0.0, 1.0, 2.0, 3.0, 4.0])
        for _ in range(10):
            self.assertEqual(detector.score(100.0), (97.0 / 1.4826, True))


if __name__ == '__main__':
    unittest.main()
