#!/bin/bash
# Example: run firewall-controller on a firewall host (needs iptables capability)

export DB_HOST="192.168.1.50"   # IP của máy sensor (MySQL)
export DB_PORT="3306"
export DB_USER="tls_user"
export DB_PASSWORD="1234"
export DB_NAME="tls_ids"

export IPTABLES_CHAIN="FORWARD"
export FIREWALL_TARGET="DROP"
export POLL_INTERVAL="1.0"

echo "Starting firewall-controller ..."
python3 main.py
