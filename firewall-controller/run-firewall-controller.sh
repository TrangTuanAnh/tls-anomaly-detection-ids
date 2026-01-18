#!/bin/bash
# Script khoi chay Module Firewall Controller tren may chu tuong lua

# Thiet lap dia chi IP cua may Sensor noi cai dat MySQL Database
export DB_HOST="192.168.1.50"
export DB_PORT="3306"
export DB_USER="tls_user"
export DB_PASSWORD="1234"
export DB_NAME="tls_ids"

# (Optional) MySQL TLS 
# export DB_TLS_ENABLED="true"
# export DB_SSL_CA="/path/to/ca.pem"
# export DB_SSL_CERT="/path/to/fw-client.pem"
# export DB_SSL_KEY="/path/to/fw-client.key"
# export DB_SSL_VERIFY_CERT="true"
# export DB_SSL_VERIFY_IDENTITY="false"

# Cau hinh Iptables: Su dung chain FORWARD de chan luu luong di qua firewall
export IPTABLES_CHAIN="FORWARD"

# Hanh dong thuc thi: DROP (loai bo goi tin) khi phat hien xam nhap
export FIREWALL_TARGET="DROP"

# Thoi gian nghi giua cac lan quet Database (don vi: giay)
export POLL_INTERVAL="1.0"

echo "Dang khoi chay firewall-controller..."

# Thuc thi file ma nguon Python voi cac bien moi truong da thiet lap
python3 main.py