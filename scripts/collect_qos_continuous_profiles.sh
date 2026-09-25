#!/usr/bin/env bash
set -Eeuo pipefail

usage() {
  cat <<'EOF'
Uso: scripts/collect_qos_continuous_profiles.sh <diretorio-do-experimento>

Executa um unico fluxo UDP h1 -> h8 e varia continuamente a taxa por HTB.
Os tres perfis, com a mesma duracao, delimitam as particoes train,
calibration e test. A topologia e os coletores QoS devem estar ativos e as
regras OpenFlow de calibracao (cookie 0x51534c41) devem estar instaladas.

Variaveis opcionais:
  QOS_STAGE_DURATION_S  Duracao de cada patamar (padrao: 6)
  QOS_OFFERED_RATE_MBIT Taxa oferecida ao HTB (padrao: 140)
  QOS_UDP_PORT          Porta UDP do iperf (padrao: 5001)
EOF
}

if [[ $# -ne 1 || "$1" == "-h" || "$1" == "--help" ]]; then
  usage
  [[ $# -eq 1 ]] && exit 0
  exit 2
fi

OUTPUT_ROOT="$(realpath -m "$1")"
STAGE_DURATION_S="${QOS_STAGE_DURATION_S:-6}"
OFFERED_RATE_MBIT="${QOS_OFFERED_RATE_MBIT:-140}"
UDP_PORT="${QOS_UDP_PORT:-5001}"
FLOW_COOKIE="0x51534c41"

for value in "$STAGE_DURATION_S" "$OFFERED_RATE_MBIT" "$UDP_PORT"; do
  if ! [[ "$value" =~ ^[1-9][0-9]*$ ]]; then
    echo "duracao, taxa e porta devem ser inteiros positivos" >&2
    exit 2
  fi
done

mkdir -p "$OUTPUT_ROOT"
for path in "$OUTPUT_ROOT/workload.tsv" "$OUTPUT_ROOT/partitions.tsv" \
            "$OUTPUT_ROOT/collection-exit-code.txt"; do
  if [[ -e "$path" ]]; then
    echo "saida ja existe: $path" >&2
    exit 2
  fi
done

if ! sudo -n true 2>/dev/null; then
  echo "sudo sem prompt e necessario para executar dentro do tmux" >&2
  exit 2
fi

H1_PID="$(pgrep -f '[m]ininet:h1' | head -n 1 || true)"
H8_PID="$(pgrep -f '[m]ininet:h8' | head -n 1 || true)"
if [[ -z "$H1_PID" || -z "$H8_PID" ]]; then
  echo "namespaces Mininet h1/h8 nao encontrados" >&2
  exit 2
fi

for switch in s1 s2 s3 s4; do
  count="$(
    sudo -n ovs-ofctl dump-flows "$switch" |
      grep -c "cookie=$FLOW_COOKIE" || true
  )"
  if (( count < 2 )); then
    echo "$switch nao possui as duas regras persistentes de calibracao" >&2
    exit 2
  fi
done

TRAIN_RATES=(
  10 15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100 105 110
  105 100 95 90 85 80 75 70 65 60 55 50 45 40 35 30 25 20 15 10
)
CALIBRATION_RATES=(
  110 105 100 95 90 85 80 75 70 65 60 55 50 45 40 35 30 25 20 15 10
  15 20 25 30 35 40 45 50 55 60 65 70 75 80 85 90 95 100 105 110
)
TEST_RATES=(
  10 10 20 20 30 30 40 40 50 50 60 60 70 70 75 75 80 80 85 85 90
  90 95 95 100 100 110 110 100 90 80 75 70 65 60 55 50 40 30 20 10
)

TOTAL_STAGES=$((${#TRAIN_RATES[@]} + ${#CALIBRATION_RATES[@]} + ${#TEST_RATES[@]}))
CLIENT_DURATION_S=$((TOTAL_STAGES * STAGE_DURATION_S + 20))

printf 'profile\tstage\trate_mbit\tstart_ns\tend_ns\tduration_s\n' \
  >"$OUTPUT_ROOT/workload.tsv"
printf 'split\tstart_ns\tend_ns\tstages\n' >"$OUTPUT_ROOT/partitions.tsv"

cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  sudo -n pkill -INT -x iperf 2>/dev/null
  sleep 1
  sudo -n mnexec -a "$H1_PID" tc qdisc del dev h1-eth0 root 2>/dev/null
  printf '%s\n' "$status" >"$OUTPUT_ROOT/collection-exit-code.txt"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

change_rate() {
  local rate_mbit="$1"
  sudo -n mnexec -a "$H1_PID" \
    tc class change dev h1-eth0 parent 1: classid 1:10 htb \
      rate "${rate_mbit}mbit" ceil "${rate_mbit}mbit" \
      burst 256k cburst 256k
}

run_profile() {
  local split="$1"
  local array_name="$2"
  local -n rates="$array_name"
  local profile_start_ns profile_end_ns stage_start_ns stage_end_ns
  local stage=0

  profile_start_ns="$(date +%s%N)"
  for rate_mbit in "${rates[@]}"; do
    stage=$((stage + 1))
    echo "profile=$split stage=$stage/${#rates[@]} rate=${rate_mbit}M"
    change_rate "$rate_mbit"
    stage_start_ns="$(date +%s%N)"
    sleep "$STAGE_DURATION_S"
    stage_end_ns="$(date +%s%N)"
    printf '%s\t%d\t%d\t%s\t%s\t%d\n' \
      "$split" "$stage" "$rate_mbit" "$stage_start_ns" "$stage_end_ns" \
      "$STAGE_DURATION_S" >>"$OUTPUT_ROOT/workload.tsv"
  done
  profile_end_ns="$(date +%s%N)"
  printf '%s\t%s\t%s\t%d\n' \
    "$split" "$profile_start_ns" "$profile_end_ns" "${#rates[@]}" \
    >>"$OUTPUT_ROOT/partitions.tsv"
}

sudo -n pkill -x iperf 2>/dev/null || true
sudo -n mnexec -a "$H1_PID" \
  tc qdisc replace dev h1-eth0 root handle 1: htb default 10
sudo -n mnexec -a "$H1_PID" \
  tc class replace dev h1-eth0 parent 1: classid 1:10 htb \
    rate 10mbit ceil 10mbit burst 256k cburst 256k

sudo -n mnexec -a "$H8_PID" sh -c \
  "nohup iperf -s -u -p '$UDP_PORT' -i '$STAGE_DURATION_S' \
   >'$OUTPUT_ROOT/iperf-server.log' 2>&1 </dev/null &"
sleep 2
sudo -n mnexec -a "$H1_PID" sh -c \
  "nohup iperf -c 10.0.0.8 -u -p '$UDP_PORT' \
   -b '${OFFERED_RATE_MBIT}M' -t '$CLIENT_DURATION_S' -i '$STAGE_DURATION_S' \
   >'$OUTPUT_ROOT/iperf-client.log' 2>&1 </dev/null &"

# Exclui a inicializacao do iperf dos limites das particoes.
sleep 4
run_profile train TRAIN_RATES
run_profile calibration CALIBRATION_RATES
run_profile test TEST_RATES

printf 'completed_at_ns\t%s\n' "$(date +%s%N)" >"$OUTPUT_ROOT/collection-complete.tsv"
echo "coleta concluida: $OUTPUT_ROOT"
