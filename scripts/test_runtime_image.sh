#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 || -z "$1" || "$1" == -* ]]; then
  echo "uso: bash scripts/test_runtime_image.sh IMAGEM" >&2
  exit 2
fi

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
IMAGE="$1"

docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --pids-limit 64 --memory 256m --cpus 1 \
  --label org.comas.purpose=runtime-smoke \
  --tmpfs /tmp:rw,noexec,nosuid,size=16m \
  --mount "type=bind,src=$PROJECT_ROOT/tests/runtime_image_smoke.py,dst=/app/_runtime_smoke.py,readonly" \
  --mount "type=bind,src=$PROJECT_ROOT/models/cic2019-drddos-udp-holt.json,dst=/app/_offline_model.json,readonly" \
  -e PYTHONDONTWRITEBYTECODE=1 -e TZ=UTC -e CONTROLLER_ID=validation-controller \
  -e AUTO_MITIGATE=false -e DRY_RUN=true -e ETCD_ENDPOINTS= \
  -e COLLABORATION_ENABLED=false -e AGENTIC_ENABLED=false -e AGENTIC_LIVE_ACTUATION=false \
  -e QOS_TELEMETRY_ENABLED=false -e MIN_RATE_BPS=1 \
  -e OFFLINE_MODEL_PATH=/app/_offline_model.json -e OFFLINE_MODEL_REQUIRED=true \
  -e ONLINE_MODEL_ADAPTATION=false -e EXPORT_ENABLED=true -e EXPORT_PREFIXES=flow: \
  -e EXPORT_DIR=/tmp/history -e EXPORT_FLUSH_EVERY=2 \
  --entrypoint python3 "$IMAGE" -B /app/_runtime_smoke.py
