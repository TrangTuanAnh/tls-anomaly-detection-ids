#!/bin/sh
set -eu

# Lay ten Card mang tu bien moi truong, mac dinh la eth0
IFACE="${CAPTURE_INTERFACE:-eth0}"
OUTPUT_MODE="${OUTPUT_MODE:-url}"

# Thiet lap duong dan file CSV neu chay o che do xuat file
OUT="${FLOW_CSV_PATH:-/shared/flows/flows.csv}"

# Thiet lap dia chi URL cua dich vu phan tich thoi gian thuc
FLOW_URL="${FLOW_URL:-http://127.0.0.1:9000/flow}"

# Thoi gian cho (giay) de dong mot luong du lieu (Flow)
IDLE_TIMEOUT="${IDLE_TIMEOUT:-10}"
ACTIVE_TIMEOUT="${ACTIVE_TIMEOUT:-300}"

echo "[NFStream] Bat dau bat goi tin tren interface=$IFACE"
echo "[NFStream] Che do dau ra: $OUTPUT_MODE"
echo "[NFStream] Thoi gian timeout: IDLE=$IDLE_TIMEOUT ACTIVE=$ACTIVE_TIMEOUT"
echo "[NFStream] Yeu cau quyen NET_RAW va NET_ADMIN de truy cap card mang"

# Lua chon che do chay dua tren bien OUTPUT_MODE
case "$OUTPUT_MODE" in
  url)
    # Che do Realtime: Gui du lieu truc tiep den Realtime Service qua HTTP
    echo "[NFStream] Dang gui du lieu flow den: $FLOW_URL"
    exec python -u /app/nfstream_sniffer.py \
      --iface "$IFACE" \
      --mode url \
      --flow-url "$FLOW_URL" \
      --idle-timeout "$IDLE_TIMEOUT" \
      --active-timeout "$ACTIVE_TIMEOUT"
    ;;
  csv|*)
    # Che do Debug: Luu du lieu flow ra file CSV de kiem tra
    mkdir -p "$(dirname "$OUT")"
    echo "[NFStream] Xuat du lieu ra file CSV: $OUT"
    exec python -u /app/nfstream_sniffer.py \
      --iface "$IFACE" \
      --mode csv \
      --csv-path "$OUT" \
      --idle-timeout "$IDLE_TIMEOUT" \
      --active-timeout "$ACTIVE_TIMEOUT"
    ;;
esac