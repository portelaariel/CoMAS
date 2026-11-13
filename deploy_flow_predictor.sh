#!/usr/bin/env bash
set -euo pipefail
#
# deploy_flow_predictor.sh
# Adiciona o FlowPredictor a domínios já em execução (mesmas convenções do setup_env.sh).
#
# Convenção de endereçamento por domínio i:
#   Ryu-Core       192.168.(10+i).10   API 8080+i
#   SimpleSwitch   192.168.(10+i).20   HTTP 9090+i
#   FlowBlocker    192.168.(10+i).30   HTTP 7070+i
#   FlowPredictor  192.168.(10+i).40   HTTP 6060+i   <── NOVO
#
# Uso:
#   bash ./deploy_flow_predictor.sh <num_dominios> [dry_run:true|false]
# Exemplo:
#   bash ./deploy_flow_predictor.sh 2 true # 2 domínios, modo DRY_RUN (não bloqueia)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="${SDN_RUNTIME_CONFIG:-$SCRIPT_DIR/config/runtime.env}"

if [[ ! -r "$CONFIG_FILE" ]]; then
  echo "Runtime config not found: $CONFIG_FILE" >&2
  exit 1
fi
# shellcheck disable=SC1090
source "$CONFIG_FILE"

C="${1:-${CSETS:-2}}"
DRY_RUN="${2:-$PREDICTOR_DRY_RUN}"
if ! [[ "$C" =~ ^[1-9][0-9]*$ ]]; then
  echo "num_dominios must be a positive integer" >&2
  exit 2
fi
if [[ "$DRY_RUN" != "true" && "$DRY_RUN" != "false" ]]; then
  echo "dry_run must be true or false" >&2
  exit 2
fi
for value in "$PREDICTOR_OFFLINE_MODEL_REQUIRED" "$PREDICTOR_ONLINE_MODEL_ADAPTATION" \
  "$PREDICTOR_COLLABORATION_ENABLED" "$PREDICTOR_AGENTIC_ENABLED" \
  "$PREDICTOR_AGENTIC_SHADOW" "$PREDICTOR_AGENTIC_LIVE_ACTUATION" \
  "$PREDICTOR_QOS_TELEMETRY_ENABLED"; do
  if [[ "$value" != "true" && "$value" != "false" ]]; then
    echo "predictor boolean settings must be true or false" >&2
    exit 2
  fi
done
if [[ "$PREDICTOR_QOS_TELEMETRY_ENABLED" == "true" ]]; then
  if ! python3 - "$PREDICTOR_QOS_PORT_CAPACITIES_JSON" <<'PY'
import json
import math
import sys

try:
    values = json.loads(sys.argv[1])
except (TypeError, ValueError) as exc:
    raise SystemExit(f"invalid PREDICTOR_QOS_PORT_CAPACITIES_JSON: {exc}")
if not isinstance(values, dict) or not values:
    raise SystemExit("QoS telemetry requires explicit dpid:port capacities")
for key, value in values.items():
    parts = key.split(":") if isinstance(key, str) else []
    if len(parts) != 2 or not all(part.isdigit() for part in parts):
        raise SystemExit(f"invalid QoS capacity key: {key!r}")
    try:
        capacity = float(value)
    except (TypeError, ValueError):
        raise SystemExit(f"invalid QoS capacity for {key}")
    if not math.isfinite(capacity) or capacity <= 0:
        raise SystemExit(f"QoS capacity must be positive for {key}")
PY
  then
    exit 2
  fi
fi
if ! [[ "$PREDICTOR_FLOW_IDLE_RESET_SAMPLES" =~ ^[1-9][0-9]*$ ]]; then
  echo "PREDICTOR_FLOW_IDLE_RESET_SAMPLES must be a positive integer" >&2
  exit 2
fi

COLLAB_EXPECTED_DOMAINS="${PREDICTOR_COLLAB_EXPECTED_DOMAINS:-$C}"
for value in "$COLLAB_EXPECTED_DOMAINS" "$PREDICTOR_COLLAB_MIN_DOMAINS" \
  "$PREDICTOR_COLLAB_PERSISTENCE_WINDOWS"; do
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "collaboration domain/persistence settings must be positive integers" >&2
    exit 2
  fi
done
if [[ "$PREDICTOR_COLLABORATION_ENABLED" == "true" ]] \
  && (( PREDICTOR_COLLAB_MIN_DOMAINS > COLLAB_EXPECTED_DOMAINS )); then
  echo "PREDICTOR_COLLAB_MIN_DOMAINS cannot exceed expected domains" >&2
  exit 2
fi
if ! [[ "$PREDICTOR_AGENT_REQUIRED_VOTES" =~ ^[1-9][0-9]*$ ]]; then
  echo "PREDICTOR_AGENT_REQUIRED_VOTES must be a positive integer" >&2
  exit 2
fi
if [[ "$PREDICTOR_AGENTIC_ENABLED" == "true" ]] \
  && [[ "$PREDICTOR_COLLABORATION_ENABLED" != "true" ]]; then
  echo "PREDICTOR_AGENTIC_ENABLED requires collaboration" >&2
  exit 2
fi
case "$PREDICTOR_AGENTIC_MODE" in
  shadow)
    EFFECTIVE_AGENTIC_SHADOW=true
    if [[ "$PREDICTOR_AGENTIC_ENABLED" == "true" \
          && "$PREDICTOR_AGENTIC_SHADOW" != "true" ]]; then
      echo "agentic shadow mode requires PREDICTOR_AGENTIC_SHADOW=true" >&2
      exit 2
    fi
    ;;
  authority-dry-run)
    EFFECTIVE_AGENTIC_SHADOW=false
    if [[ "$PREDICTOR_AGENTIC_ENABLED" == "true" && "$DRY_RUN" != "true" ]]; then
      echo "authority-dry-run requires global dry_run=true" >&2
      exit 2
    fi
    ;;
  authority-live)
    EFFECTIVE_AGENTIC_SHADOW=false
    if [[ "$PREDICTOR_AGENTIC_ENABLED" != "true" ]]; then
      echo "authority-live requires PREDICTOR_AGENTIC_ENABLED=true" >&2
      exit 2
    fi
    if [[ "$PREDICTOR_AGENTIC_LIVE_ACTUATION" != "true" ]]; then
      echo "authority-live requires explicit live actuation opt-in" >&2
      exit 2
    fi
    if [[ "$DRY_RUN" != "false" || "$PREDICTOR_AUTO_MITIGATE" != "true" ]]; then
      echo "authority-live requires dry_run=false and auto mitigation" >&2
      exit 2
    fi
    if [[ "$PREDICTOR_OFFLINE_MODEL_REQUIRED" != "true" \
          || "$PREDICTOR_ONLINE_MODEL_ADAPTATION" != "false" ]]; then
      echo "authority-live requires a mandatory non-adaptive offline model" >&2
      exit 2
    fi
    ;;
  *)
    echo "PREDICTOR_AGENTIC_MODE must be shadow, authority-dry-run or authority-live" >&2
    exit 2
    ;;
esac
if [[ "$PREDICTOR_AGENTIC_ENABLED" == "true" \
      && "$PREDICTOR_AGENTIC_LIVE_ACTUATION" == "true" \
      && "$PREDICTOR_AGENTIC_MODE" != "authority-live" ]]; then
  echo "live actuation opt-in is only valid in authority-live" >&2
  exit 2
fi
if [[ "$PREDICTOR_AGENTIC_ENABLED" == "true" ]] \
  && (( PREDICTOR_AGENT_REQUIRED_VOTES > COLLAB_EXPECTED_DOMAINS )); then
  echo "PREDICTOR_AGENT_REQUIRED_VOTES cannot exceed expected domains" >&2
  exit 2
fi

MODEL_DOCKER_ARGS=(
  -e "OFFLINE_MODEL_REQUIRED=$PREDICTOR_OFFLINE_MODEL_REQUIRED"
  -e "ONLINE_MODEL_ADAPTATION=$PREDICTOR_ONLINE_MODEL_ADAPTATION"
)
MODEL_DESCRIPTION="adaptive fallback (warmup=$PREDICTOR_WARMUP_SAMPLES)"
if [[ -n "$PREDICTOR_OFFLINE_MODEL" ]]; then
  MODEL_HOST_PATH="$PREDICTOR_OFFLINE_MODEL"
  if [[ "$MODEL_HOST_PATH" != /* ]]; then
    MODEL_HOST_PATH="$SCRIPT_DIR/$MODEL_HOST_PATH"
  fi
  if [[ ! -r "$MODEL_HOST_PATH" ]]; then
    echo "offline model not readable: $MODEL_HOST_PATH" >&2
    exit 2
  fi
  MODEL_HOST_DIR="$(cd "$(dirname "$MODEL_HOST_PATH")" && pwd)"
  MODEL_HOST_PATH="$MODEL_HOST_DIR/$(basename "$MODEL_HOST_PATH")"
  MODEL_DOCKER_ARGS+=(
    -v "$MODEL_HOST_PATH:/app/models/offline_model.json:ro"
    -e "OFFLINE_MODEL_PATH=/app/models/offline_model.json"
  )
  MODEL_DESCRIPTION="offline model $MODEL_HOST_PATH"
elif [[ "$PREDICTOR_OFFLINE_MODEL_REQUIRED" == "true" ]]; then
  echo "PREDICTOR_OFFLINE_MODEL_REQUIRED=true requires PREDICTOR_OFFLINE_MODEL" >&2
  exit 2
fi

HISTORY_ROOT="${PREDICTION_HISTORY_ROOT:-$SCRIPT_DIR}"

log() { echo "[$(date +%H:%M:%S)] $*"; }

endpoint_ready() {
  local url="$1" kind="$2"
  curl -fsS "$url" 2>/dev/null | python3 -c '
import json
import sys

try:
    payload = json.load(sys.stdin)
except (TypeError, ValueError):
    raise SystemExit(1)

kind = sys.argv[1]
if kind == "status":
    ready = isinstance(payload, dict) and bool(payload.get("cid"))
elif kind == "collaboration":
    ready = payload.get("requested") is True and payload.get("active") is True
elif kind == "agent":
    expected_mode = sys.argv[2]
    ready = (
        payload.get("requested") is True
        and payload.get("active") is True
        and payload.get("mode") == expected_mode
        and payload.get("authoritative") is (expected_mode != "shadow")
        and payload.get("actuation_enabled") is (expected_mode == "authority-live")
    )
else:
    ready = False
raise SystemExit(0 if ready else 1)
' "$kind" "$PREDICTOR_AGENTIC_MODE" >/dev/null 2>&1
}

# Build da imagem se ausente
if ! sudo docker images --format '{{.Repository}}' | grep -qx "$PRED_IMG"; then
  log "Imagem $PRED_IMG não encontrada; construindo..."
  sudo docker build -t "$PRED_IMG" -f "$SCRIPT_DIR/Dockerfile.flow_predictor" "$SCRIPT_DIR"
fi

for ((i=0; i<C; i++)); do
  SUBNET=$((SUBNET_BASE + i))
  CTRL_IP="192.168.${SUBNET}.10"
  FB_IP="192.168.${SUBNET}.30"
  PRED_IP="192.168.${SUBNET}.40"

  CTRL_API_PORT=$((CTRL_API_PORT_BASE + i))
  FB_HTTP_PORT=$((FB_HTTP_PORT_BASE + i))
  PRED_HTTP_PORT=$((PREDICTOR_PORT_BASE + i))

  # Detecta o nome da rede do domínio (ryu-network compartilhada OU ryu-network-$i)
  if sudo docker network ls --format '{{.Name}}' | grep -qx "${RYU_NETWORK_PREFIX}-$i"; then
    NET="${RYU_NETWORK_PREFIX}-$i"
  else
    NET="$RYU_NETWORK_PREFIX"
  fi

  # Remove instância antiga, se houver
  if sudo docker ps -a --format '{{.Names}}' | grep -qx "flow-predictor-$i"; then
    log "Removendo flow-predictor-$i antigo..."
    sudo docker rm -f "flow-predictor-$i" >/dev/null
  fi

  # Diretório do host para o dataset de predição (1 CSV por fluxo)
  HIST_DIR="$HISTORY_ROOT/prediction_history_domain${i}"
  QOS_DIR="$HISTORY_ROOT/qos_history_domain${i}"
  mkdir -p "$HIST_DIR" "$QOS_DIR"

  log "Iniciando flow-predictor-$i em $PRED_IP:$PRED_HTTP_PORT (rede: $NET, dry_run=$DRY_RUN)"
  log "  Dataset em: $HIST_DIR"
  if [[ "$PREDICTOR_QOS_TELEMETRY_ENABLED" == "true" ]]; then
    log "  Dataset QoS em: $QOS_DIR"
  fi
  log "  Detecção: $MODEL_DESCRIPTION"
  log "  Colaboração: $PREDICTOR_COLLABORATION_ENABLED (quórum=$PREDICTOR_COLLAB_MIN_DOMAINS/$COLLAB_EXPECTED_DOMAINS)"
  log "  Agente: $PREDICTOR_AGENTIC_ENABLED (modo=$PREDICTOR_AGENTIC_MODE, votos=$PREDICTOR_AGENT_REQUIRED_VOTES)"
  CONTAINER="flow-predictor-$i"
  sudo docker create --name "$CONTAINER" --network "$NET" --ip "$PRED_IP" \
    -v "$HIST_DIR:/app/prediction_history" \
    -v "$QOS_DIR:/app/qos_history" \
    "${MODEL_DOCKER_ARGS[@]}" \
    -e EXPORT_ENABLED="$PREDICTOR_EXPORT_ENABLED" \
    -e EXPORT_DIR="/app/prediction_history" \
    -e EXPORT_PREFIXES="$PREDICTOR_EXPORT_PREFIXES" \
    -e EXPORT_FLUSH_EVERY="$PREDICTOR_EXPORT_FLUSH_EVERY" \
    -e QOS_TELEMETRY_ENABLED="$PREDICTOR_QOS_TELEMETRY_ENABLED" \
    -e QOS_PORT_CAPACITIES_JSON="$PREDICTOR_QOS_PORT_CAPACITIES_JSON" \
    -e QOS_DATASET_DIR="/app/qos_history" \
    -e QOS_DATASET_FLUSH_EVERY="$PREDICTOR_QOS_DATASET_FLUSH_EVERY" \
    -e QOS_MAX_GAP_FACTOR="$PREDICTOR_QOS_MAX_GAP_FACTOR" \
    -e RYU_BASE_URL="http://${CTRL_IP}:${CTRL_API_PORT}" \
    -e FLOWBLOCKER_URL="http://${FB_IP}:${FB_HTTP_PORT}" \
    -e CONTROLLER_ID="$CTRL_IP" \
    -e ETCD_ENDPOINTS="$ETCD_ENDPOINTS" \
    -e PORT="$PRED_HTTP_PORT" \
    -e POLL_INTERVAL_S="$PREDICTOR_POLL_INTERVAL_S" \
    -e Z_THRESHOLD="$PREDICTOR_Z_THRESHOLD" \
    -e WARMUP_SAMPLES="$PREDICTOR_WARMUP_SAMPLES" \
    -e FLOW_SURGE_WARMUP_SAMPLES="$PREDICTOR_FLOW_SURGE_WARMUP_SAMPLES" \
    -e MIN_RATE_BPS="$PREDICTOR_MIN_RATE_BPS" \
    -e FLOW_IDLE_RESET_SAMPLES="$PREDICTOR_FLOW_IDLE_RESET_SAMPLES" \
    -e AUTO_MITIGATE="$PREDICTOR_AUTO_MITIGATE" \
    -e DRY_RUN="$DRY_RUN" \
    -e MITIGATION_COOLDOWN_S="$PREDICTOR_COOLDOWN_S" \
    -e ANOMALY_EVENT_COOLDOWN_S="$PREDICTOR_EVENT_COOLDOWN_S" \
    -e WHITELIST_IPS="$PREDICTOR_WHITELIST_IPS" \
    -e COLLABORATION_ENABLED="$PREDICTOR_COLLABORATION_ENABLED" \
    -e COLLAB_EXPECTED_DOMAINS="$COLLAB_EXPECTED_DOMAINS" \
    -e COLLAB_MIN_DOMAINS="$PREDICTOR_COLLAB_MIN_DOMAINS" \
    -e COLLAB_WINDOW_S="$PREDICTOR_COLLAB_WINDOW_S" \
    -e COLLAB_EVIDENCE_TTL_S="$PREDICTOR_COLLAB_EVIDENCE_TTL_S" \
    -e COLLAB_CLAIM_TTL_S="$PREDICTOR_COLLAB_CLAIM_TTL_S" \
    -e COLLAB_EVALUATION_INTERVAL_S="$PREDICTOR_COLLAB_EVALUATION_INTERVAL_S" \
    -e COLLAB_PERSISTENCE_WINDOWS="$PREDICTOR_COLLAB_PERSISTENCE_WINDOWS" \
    -e COLLAB_SUSPECT_THRESHOLD="$PREDICTOR_COLLAB_SUSPECT_THRESHOLD" \
    -e COLLAB_ALERT_THRESHOLD="$PREDICTOR_COLLAB_ALERT_THRESHOLD" \
    -e COLLAB_DECISION_THRESHOLD="$PREDICTOR_COLLAB_DECISION_THRESHOLD" \
    -e COLLAB_RATE_RATIO_MAX="$PREDICTOR_COLLAB_RATE_RATIO_MAX" \
    -e COLLAB_WEIGHTS_JSON="$PREDICTOR_COLLAB_WEIGHTS_JSON" \
    -e AGENTIC_ENABLED="$PREDICTOR_AGENTIC_ENABLED" \
    -e AGENTIC_SHADOW="$EFFECTIVE_AGENTIC_SHADOW" \
    -e AGENTIC_MODE="$PREDICTOR_AGENTIC_MODE" \
    -e AGENT_REQUIRED_VOTES="$PREDICTOR_AGENT_REQUIRED_VOTES" \
    -e AGENT_PROPOSAL_TTL_S="$PREDICTOR_AGENT_PROPOSAL_TTL_S" \
    -e AGENT_NEGOTIATION_WINDOW_S="$PREDICTOR_AGENT_NEGOTIATION_WINDOW_S" \
    -e AGENT_PROPOSAL_THRESHOLD="$PREDICTOR_AGENT_PROPOSAL_THRESHOLD" \
    -e AGENT_TOPOLOGY_CACHE_S="$PREDICTOR_AGENT_TOPOLOGY_CACHE_S" \
    -e AGENT_CLAIM_TTL_S="$PREDICTOR_AGENT_CLAIM_TTL_S" \
    -e AGENTIC_LIVE_ACTUATION="$PREDICTOR_AGENTIC_LIVE_ACTUATION" \
    -p "$PRED_HTTP_PORT:$PRED_HTTP_PORT" \
    "$PRED_IMG" >/dev/null

  # O cliente ETCD é criado na importação do processo Python. Por isso a
  # segunda rede precisa existir antes do primeiro byte do aplicativo rodar.
  if [[ "$ETCD_NET" != "$NET" ]]; then
    if ! sudo docker network connect "$ETCD_NET" "$CONTAINER" 2>/dev/null; then
      if [[ "$PREDICTOR_COLLABORATION_ENABLED" == "true" \
            || "$PREDICTOR_AGENTIC_ENABLED" == "true" ]]; then
        log "❌ não foi possível conectar $CONTAINER à rede $ETCD_NET"
        sudo docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
        exit 1
      fi
      log "⚠️  ETCD indisponível para $CONTAINER; mantendo detector local"
    fi
  fi
  if ! sudo docker start "$CONTAINER" >/dev/null; then
    log "❌ não foi possível iniciar $CONTAINER"
    sudo docker rm -f "$CONTAINER" >/dev/null 2>&1 || true
    exit 1
  fi

  # Readiness funcional: HTTP sozinho não basta quando colaboração/agente
  # dependem do ETCD. O deploy só retorna sucesso quando os modos solicitados
  # aparecem efetivamente ativos na API.
  READY=false
  for retry in {1..30}; do
    STATUS_READY=false
    COLLAB_READY=false
    AGENT_READY=false
    endpoint_ready \
      "http://127.0.0.1:${PRED_HTTP_PORT}/predictor/status" status \
      && STATUS_READY=true
    if [[ "$PREDICTOR_COLLABORATION_ENABLED" != "true" ]]; then
      COLLAB_READY=true
    elif endpoint_ready \
      "http://127.0.0.1:${PRED_HTTP_PORT}/predictor/collaboration" collaboration; then
      COLLAB_READY=true
    fi
    if [[ "$PREDICTOR_AGENTIC_ENABLED" != "true" ]]; then
      AGENT_READY=true
    elif endpoint_ready \
      "http://127.0.0.1:${PRED_HTTP_PORT}/predictor/agent" agent; then
      AGENT_READY=true
    fi
    if [[ "$STATUS_READY" == "true" \
          && ( "$PREDICTOR_COLLABORATION_ENABLED" != "true" || "$COLLAB_READY" == "true" ) \
          && ( "$PREDICTOR_AGENTIC_ENABLED" != "true" || "$AGENT_READY" == "true" ) ]]; then
      log "✅ flow-predictor-$i pronto"
      READY=true
      break
    fi
    sleep 1
  done
  if [[ "$READY" != "true" ]]; then
    log "❌ $CONTAINER não atingiu readiness funcional"
    sudo docker logs --tail 100 "$CONTAINER" >&2 || true
    exit 1
  fi
done

log ""
log "FlowPredictor implantado em $C domínio(s)."
log "Endpoints úteis:"
for ((i=0; i<C; i++)); do
  p=$((PREDICTOR_PORT_BASE + i))
  echo "  Domínio $i:"
  echo "    Status:      curl http://127.0.0.1:$p/predictor/status | jq ."
  echo "    Predições:   curl http://127.0.0.1:$p/predictor/predictions | jq ."
  echo "    Anomalias:   curl http://127.0.0.1:$p/predictor/anomalies | jq ."
  echo "    Colaboração: curl http://127.0.0.1:$p/predictor/collaboration | jq ."
  echo "    Agente:      curl http://127.0.0.1:$p/predictor/agent | jq ."
  echo "    Dataset:     curl http://127.0.0.1:$p/predictor/export/status | jq ."
done
log ""
log "📊 CSVs do dataset (1 por fluxo) em: $HISTORY_ROOT/prediction_history_domain<i>/"
log ""
if [[ "$PREDICTOR_AGENTIC_MODE" == "authority-live" ]]; then
  log "⚠️  authority-live ativo: somente o vencedor do claim agentic pode mitigar."
else
  log "⚠️  DRY_RUN=$DRY_RUN — mantenha true até concluir os gates de segurança."
fi
