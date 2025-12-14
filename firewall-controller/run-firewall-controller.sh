#!/bin/bash

export DB_HOST="192.168.1.50" # Đổi thành IP máy sensor
export DB_PORT="3306"
export DB_USER="tls_user"
export DB_PASSWORD="tls_pass"
export DB_NAME="tls_ids"
export IPTABLES_CHAIN="FORWARD"

echo "Starting firewall-controller ..."
python3 main.py
