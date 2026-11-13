# Runtime primitive regression traces

`runtime_primitives_baseline_v1.json` records outputs from `HoltPredictor` and
`ResidualAnomalyDetector` in the unmodified traffic runtime at commit
`40b60906dfa299309fd423022bb00225666d7ff6`. Its source SHA256 is recorded in
`docs/reference-baseline.json`. The class definitions were evaluated without
importing or starting the service, before the extraction into `comas/`.

The cases cover identity/log1p prediction, initial state, negative projection
clamping, adaptive warmup, MAD windows, fixed asymmetric thresholds, the scale
floor and optional online adaptation. They are regression traces, not training
data or independent evidence of predictive-SLA or network performance.

Tests replay these fixed observations against the extracted classes. Do not
regenerate expected outputs from the current classes to accommodate a behavior
change; review any intended algorithm change separately against the reference.
