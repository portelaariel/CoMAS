"""Robust residual scoring, independent from telemetry and service startup."""

from collections import deque
from operator import is_
from typing import Optional, Tuple


class ResidualAnomalyDetector:
    """
    Mantém janela de resíduos (observado - predito). Usa mediana + MAD
    (Median Absolute Deviation) para robustez contra outliers passados —
    um pico anômalo anterior não "envenena" a estatística como faria com
    média/desvio-padrão simples.
    """

    MAD_K = 1.4826  # fator de consistência para distribuição normal

    def __init__(self, window: int, z_threshold: float, warmup: int,
                 fixed_center: Optional[float] = None,
                 fixed_scale: Optional[float] = None,
                 online_adaptation: bool = False,
                 drop_z_threshold: Optional[float] = None):
        self.residuals: deque = deque(maxlen=window)
        # z_threshold permanece como alias do lado positivo para não quebrar
        # clientes e modelos legados que usavam um único valor simétrico.
        self.z_threshold = z_threshold
        self.drop_z_threshold = (z_threshold if drop_z_threshold is None
                                 else drop_z_threshold)
        self.warmup = warmup
        self.fixed_center = fixed_center
        self.fixed_scale = fixed_scale
        self.online_adaptation = online_adaptation
        self._stable_baseline = None
        self._previous_tail = object()

    @property
    def offline_calibrated(self) -> bool:
        return self.fixed_center is not None and self.fixed_scale is not None

    @property
    def ready(self) -> bool:
        return self.offline_calibrated or len(self.residuals) >= self.warmup

    def _center_scale(self) -> Tuple[float, float]:
        use_offline = (self.offline_calibrated
                       and (not self.online_adaptation
                            or len(self.residuals) < max(3, self.warmup)))
        if use_offline:
            return float(self.fixed_center), max(float(self.fixed_scale), 1e-6)

        cached = self._stable_baseline
        if cached is not None:
            window, factor, baseline = cached
            # Immutable inputs and exact object identities also detect edits
            # through the public deque, including equal-valued replacements.
            if (self.MAD_K is factor and len(window) == len(self.residuals)
                    and all(map(is_, window, self.residuals))):
                return baseline
            self._stable_baseline = None

        data = sorted(self.residuals)
        median = data[len(data) // 2]
        mad = sorted(abs(x - median) for x in data)[len(data) // 2]
        baseline = median, max(self.MAD_K * mad, 1e-6)
        tail = self.residuals[-1]
        # A new tail is the normal streaming path: avoid allocating a snapshot.
        # A repeated tail can signal rejected samples. Recompute once, then
        # retain the complete window for safe reuse on subsequent calls.
        if tail is self._previous_tail:
            window = tuple(self.residuals)
            factor = self.MAD_K
            if (type(factor) in (int, float)
                    and all(type(value) in (int, float) for value in window)):
                self._stable_baseline = window, factor, baseline
        self._previous_tail = tail
        return baseline

    def score(self, residual: float) -> Tuple[float, bool]:
        """Retorna (z_score, is_anomaly) usando calibração offline ou warmup."""
        if not self.ready:
            self.residuals.append(residual)
            return 0.0, False

        median, sigma = self._center_scale()
        z = (residual - median) / sigma

        is_anom = z > self.z_threshold or z < -self.drop_z_threshold
        # Resíduos anômalos NÃO entram na janela (evita mascarar ataques prolongados)
        if not is_anom and (not self.offline_calibrated or self.online_adaptation):
            self.residuals.append(residual)
        return z, is_anom

    def threshold_for(self, z_score: float) -> float:
        return self.z_threshold if z_score >= 0.0 else self.drop_z_threshold
