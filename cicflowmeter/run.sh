#!/bin/sh
set -eu

IFACE="${CAPTURE_INTERFACE:-eth0}"
URL="${FLOW_HTTP_URL:-http://127.0.0.1:8080/predict}"

echo "[CICFlowMeter] iface=$IFACE -> POST flows to $URL"

exec cicflowmeter -i "$IFACE" -u "$URL"
