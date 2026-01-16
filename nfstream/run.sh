#!/bin/sh
set -eu

IFACE="${CAPTURE_INTERFACE:-eth0}"
OUTPUT_MODE="${OUTPUT_MODE:-url}"

# CSV mode settings
OUT="${FLOW_CSV_PATH:-/shared/flows/flows.csv}"

# URL mode settings
FLOW_URL="${FLOW_URL:-http://127.0.0.1:9000/flow}"

# Timeouts (seconds)
IDLE_TIMEOUT="${IDLE_TIMEOUT:-10}"
ACTIVE_TIMEOUT="${ACTIVE_TIMEOUT:-300}"

echo "[NFStream] Start capture on interface=$IFACE"
echo "[NFStream] OUTPUT_MODE=$OUTPUT_MODE"
echo "[NFStream] IDLE_TIMEOUT=$IDLE_TIMEOUT ACTIVE_TIMEOUT=$ACTIVE_TIMEOUT"
echo "[NFStream] (need NET_RAW + NET_ADMIN or privileged)"

case "$OUTPUT_MODE" in
  url)
    echo "[NFStream] Posting flows to: $FLOW_URL"
    exec python -u /app/nfstream_sniffer.py \
      --iface "$IFACE" \
      --mode url \
      --flow-url "$FLOW_URL" \
      --idle-timeout "$IDLE_TIMEOUT" \
      --active-timeout "$ACTIVE_TIMEOUT"
    ;;
  csv|*)
    mkdir -p "$(dirname "$OUT")"
    echo "[NFStream] Output CSV=$OUT"
    exec python -u /app/nfstream_sniffer.py \
      --iface "$IFACE" \
      --mode csv \
      --csv-path "$OUT" \
      --idle-timeout "$IDLE_TIMEOUT" \
      --active-timeout "$ACTIVE_TIMEOUT"
    ;;
esac
