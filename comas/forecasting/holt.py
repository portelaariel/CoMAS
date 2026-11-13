"""Streaming traffic Holt predictor extracted from the legacy runtime.

The artifact transforms remain in ``offline_model`` so existing model contracts
and the offline calibration path continue to use the same implementation.
Importing this module does not load a model or initialize service dependencies.
"""

from typing import Optional

from offline_model import inverse_transform_value, transform_value


class HoltPredictor:
    """
    Suavização exponencial dupla (Holt). Escolhida por:
      - custo O(1) por amostra (escala para milhares de séries);
      - captura nível E tendência (melhor que EWMA puro em rampas de vazão);
      - sem dependências pesadas (funciona em qualquer topologia/hardware).
    A interface (update/predict) é pluggável: pode ser trocada por ARIMA/LSTM
    sem alterar o restante do módulo.
    """

    def __init__(self, alpha: float = 0.35, beta: float = 0.10,
                 transform: str = "identity"):
        self.alpha = alpha
        self.beta = beta
        self.transform = transform
        self.level: Optional[float] = None
        self.trend: float = 0.0
        self.n = 0

    def update(self, value: float) -> None:
        transformed = transform_value(value, self.transform)
        if self.level is None:
            self.level = transformed
            self.trend = 0.0
        else:
            prev_level = self.level
            self.level = (self.alpha * transformed
                          + (1 - self.alpha) * (self.level + self.trend))
            self.trend = self.beta * (self.level - prev_level) + (1 - self.beta) * self.trend
        self.n += 1

    def predict_transformed(self, horizon: int = 1) -> float:
        if self.level is None:
            return transform_value(0.0, self.transform)
        return self.level + horizon * self.trend

    def predict(self, horizon: int = 1) -> float:
        if self.level is None:
            return 0.0
        return inverse_transform_value(self.predict_transformed(horizon), self.transform)

    def residual(self, observed: float, predicted: float) -> float:
        """Resíduo no espaço em que o modelo offline foi calibrado."""
        return (transform_value(observed, self.transform)
                - transform_value(predicted, self.transform))

    @property
    def trend_bps(self) -> float:
        if self.level is None:
            return 0.0
        return self.predict(1) - self.predict(0)
