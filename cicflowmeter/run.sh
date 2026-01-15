#!/bin/sh
set -eu

IFACE="${CAPTURE_INTERFACE:-wlo1}"
OUT="${FLOW_CSV_PATH:-/shared/flows/flows.csv}"

mkdir -p "$(dirname "$OUT")"

echo "[CICFlowMeter] Start capture on interface=$IFACE"
echo "[CICFlowMeter] Output CSV=$OUT"
echo "[CICFlowMeter] (need NET_RAW + NET_ADMIN or privileged)"

# The cicflowmeter CLI supports:
#   cicflowmeter -i <iface> -c <csv_output>
exec cicflowmeter -i "$IFACE" -c "$OUT"
