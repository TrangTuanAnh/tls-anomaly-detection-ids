#!/usr/bin/env bash
set -euo pipefail

# Generate MySQL TLS assets (CA + server cert with SAN + firewall client cert),
# plus mysql-conf/ssl.cnf. Optionally patch docker-compose.sensor.yml to mount TLS files.
#
# Usage (sensor host, in repo root):
#   chmod +x scripts/gen-mysql-tls.sh
#   ./scripts/gen-mysql-tls.sh --sensor-ip 192.168.1.10 --enable-sensor-compose
#   docker compose -f docker-compose.sensor.yml up -d --force-recreate db
#
# Then copy the firewall bundle:
#   scp -r pki/mysql/fw-bundle <firewall-host>:/path/to/project/pki/mysql/
#
# Optional: create a dedicated DB user that MUST present a client cert (REQUIRE X509):
#   ./scripts/gen-mysql-tls.sh --sensor-ip 192.168.1.10 --enable-sensor-compose --create-fw-user
#
# Notes:
# - The script does NOT store the fw_user password in the repo. It will prompt (hidden) if you use --create-fw-user.
# - For strict identity verification from firewall host, the MySQL server certificate MUST include the SENSOR IP in SAN.

die() { echo "ERROR: $*" >&2; exit 1; }

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# Default params
SENSOR_IP=""
CA_CN="tls-mysql-ca"
SERVER_CN="tls-mysql"
FW_CN="fw-controller"

DAYS_CA=3650
DAYS_SERVER=825
DAYS_CLIENT=30

OUT_DIR="pki/mysql"
CONF_DIR="mysql-conf"
BUNDLE_DIR="pki/mysql/fw-bundle"

PATCH_SENSOR_COMPOSE="false"
CREATE_FW_USER="false"
MYSQL_CONTAINER="tls-mysql"

FW_DB_NAME=""
FW_DB_USER="fw_user"

print_help() {
  cat <<'EOF'
scripts/gen-mysql-tls.sh

Options:
  --sensor-ip <ip>            Sensor host IP that firewall-controller uses to connect to MySQL (SAN will include it)
  --ca-cn <cn>                CA Common Name (default: tls-mysql-ca)
  --server-cn <cn>            MySQL server cert CN (default: tls-mysql)
  --fw-cn <cn>                Firewall client cert CN (default: fw-controller)
  --days-ca <n>               CA validity days (default: 3650)
  --days-server <n>           Server cert validity days (default: 825)
  --days-client <n>           Client cert validity days (default: 30)

  --enable-sensor-compose     Uncomment TLS mounts for db in docker-compose.sensor.yml (safe, in-place edit)
  --create-fw-user            Create/alter MySQL user (REQUIRE X509) via docker exec into the db container
  --mysql-container <name>    MySQL container name (default: tls-mysql)
  --fw-db-name <name>         DB name containing firewall_actions (default: read from .env or tls_ids)
  --fw-db-user <name>         DB user for firewall-controller (default: fw_user)

  -h, --help                  Show help

Examples:
  ./scripts/gen-mysql-tls.sh --sensor-ip 10.0.0.5 --enable-sensor-compose
  ./scripts/gen-mysql-tls.sh --sensor-ip 10.0.0.5 --enable-sensor-compose --create-fw-user

EOF
}

# Parse args
while [[ $# -gt 0 ]]; do
  case "$1" in
    --sensor-ip) SENSOR_IP="${2:-}"; shift 2 ;;
    --ca-cn) CA_CN="${2:-}"; shift 2 ;;
    --server-cn) SERVER_CN="${2:-}"; shift 2 ;;
    --fw-cn) FW_CN="${2:-}"; shift 2 ;;
    --days-ca) DAYS_CA="${2:-}"; shift 2 ;;
    --days-server) DAYS_SERVER="${2:-}"; shift 2 ;;
    --days-client) DAYS_CLIENT="${2:-}"; shift 2 ;;
    --enable-sensor-compose) PATCH_SENSOR_COMPOSE="true"; shift ;;
    --create-fw-user) CREATE_FW_USER="true"; shift ;;
    --mysql-container) MYSQL_CONTAINER="${2:-}"; shift 2 ;;
    --fw-db-name) FW_DB_NAME="${2:-}"; shift 2 ;;
    --fw-db-user) FW_DB_USER="${2:-}"; shift 2 ;;
    -h|--help) print_help; exit 0 ;;
    *) die "Unknown argument: $1 (use --help)" ;;
  esac
done

need_cmd openssl
need_cmd awk
need_cmd sed

# Best-effort sensor ip detection if missing
if [[ -z "${SENSOR_IP}" ]]; then
  if command -v hostname >/dev/null 2>&1; then
    SENSOR_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
fi
[[ -n "${SENSOR_IP}" ]] || die "--sensor-ip is required (could not auto-detect)"

umask 077

mkdir -p "${OUT_DIR}" "${CONF_DIR}" "${BUNDLE_DIR}"

CA_KEY="${OUT_DIR}/ca.key"
CA_PEM="${OUT_DIR}/ca.pem"
SERVER_KEY="${OUT_DIR}/server.key"
SERVER_PEM="${OUT_DIR}/server.pem"
SERVER_CSR="${OUT_DIR}/server.csr"
SERVER_CNF="${OUT_DIR}/server.cnf"

FW_KEY="${OUT_DIR}/fw-client.key"
FW_PEM="${OUT_DIR}/fw-client.pem"
FW_CSR="${OUT_DIR}/fw-client.csr"

echo "[*] Generating/ensuring CA..."
if [[ ! -f "${CA_KEY}" || ! -f "${CA_PEM}" ]]; then
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${DAYS_CA}" \
    -subj "/CN=${CA_CN}" -out "${CA_PEM}"
else
  echo "    CA exists: ${CA_PEM}"
fi

echo "[*] Writing server openssl config with SAN (includes SENSOR_IP=${SENSOR_IP})..."
cat > "${SERVER_CNF}" <<EOF
[req]
prompt = no
distinguished_name = dn
req_extensions = v3_req

[dn]
CN = ${SERVER_CN}

[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
subjectAltName = @alt_names

[alt_names]
DNS.1 = db
DNS.2 = localhost
IP.1  = 127.0.0.1
IP.2  = ${SENSOR_IP}
EOF

echo "[*] Generating MySQL server key/cert..."
if [[ ! -f "${SERVER_KEY}" ]]; then
  openssl genrsa -out "${SERVER_KEY}" 2048
fi
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -config "${SERVER_CNF}"
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_PEM}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SERVER_PEM}" -days "${DAYS_SERVER}" -sha256 -extensions v3_req -extfile "${SERVER_CNF}"

echo "[*] Generating firewall client key/cert..."
if [[ ! -f "${FW_KEY}" ]]; then
  openssl genrsa -out "${FW_KEY}" 2048
fi
openssl req -new -key "${FW_KEY}" -out "${FW_CSR}" -subj "/CN=${FW_CN}"
openssl x509 -req -in "${FW_CSR}" -CA "${CA_PEM}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${FW_PEM}" -days "${DAYS_CLIENT}" -sha256

echo "[*] Writing MySQL ssl config: ${CONF_DIR}/ssl.cnf"
cat > "${CONF_DIR}/ssl.cnf" <<'EOF'
[mysqld]
ssl_ca=/etc/mysql/certs/ca.pem
ssl_cert=/etc/mysql/certs/server.pem
ssl_key=/etc/mysql/certs/server.key
tls_version=TLSv1.2,TLSv1.3

# Uncomment AFTER you confirm every client (backend + firewall-controller) uses TLS:
# require_secure_transport=ON
EOF

# Build firewall bundle for copying
echo "[*] Creating firewall bundle: ${BUNDLE_DIR}"
cp -f "${CA_PEM}" "${BUNDLE_DIR}/ca.pem"
cp -f "${FW_PEM}" "${BUNDLE_DIR}/fw-client.pem"
cp -f "${FW_KEY}" "${BUNDLE_DIR}/fw-client.key"
chmod 600 "${BUNDLE_DIR}/fw-client.key" || true

# Optionally patch docker-compose.sensor.yml
if [[ "${PATCH_SENSOR_COMPOSE}" == "true" ]]; then
  [[ -f "docker-compose.sensor.yml" ]] || die "docker-compose.sensor.yml not found in current directory (run from repo root)"
  echo "[*] Patching docker-compose.sensor.yml: enabling MySQL TLS mounts"
  # uncomment the two TLS mount lines if present
  sed -i.bak \
    -e 's|^[[:space:]]*# - \./pki/mysql:/etc/mysql/certs:ro|      - ./pki/mysql:/etc/mysql/certs:ro|g' \
    -e 's|^[[:space:]]*# - \./mysql-conf/ssl\.cnf:/etc/mysql/conf\.d/ssl\.cnf:ro|      - ./mysql-conf/ssl.cnf:/etc/mysql/conf.d/ssl.cnf:ro|g' \
    docker-compose.sensor.yml
  echo "    Backup saved: docker-compose.sensor.yml.bak"
fi

# Optionally create fw db user (REQUIRE X509)
if [[ "${CREATE_FW_USER}" == "true" ]]; then
  need_cmd docker

  # Read MYSQL_ROOT_PASSWORD and DB name from .env if present
  if [[ -f ".env" ]]; then
    MYSQL_ROOT_PASSWORD="$(grep -E '^MYSQL_ROOT_PASSWORD=' .env | tail -n1 | cut -d= -f2- | sed 's/^"//;s/"$//' || true)"
    DEFAULT_DB="$(grep -E '^MYSQL_DATABASE=' .env | tail -n1 | cut -d= -f2- | sed 's/^"//;s/"$//' || true)"
  else
    MYSQL_ROOT_PASSWORD=""
    DEFAULT_DB=""
  fi

  if [[ -z "${FW_DB_NAME}" ]]; then
    FW_DB_NAME="${DEFAULT_DB:-tls_ids}"
  fi

  if [[ -z "${MYSQL_ROOT_PASSWORD}" ]]; then
    echo "[-] Could not read MYSQL_ROOT_PASSWORD from .env."
    read -r -s -p "Enter MySQL root password for container ${MYSQL_CONTAINER}: " MYSQL_ROOT_PASSWORD
    echo
  fi

  read -r -s -p "Set password for DB user '${FW_DB_USER}' (will NOT be stored in repo): " FW_DB_PASSWORD
  echo
  [[ -n "${FW_DB_PASSWORD}" ]] || die "Empty password is not allowed"

  echo "[*] Creating/updating DB user '${FW_DB_USER}' with REQUIRE X509 on '${FW_DB_NAME}'."
  docker exec -i "${MYSQL_CONTAINER}" mysql -uroot -p"${MYSQL_ROOT_PASSWORD}" <<SQL
CREATE USER IF NOT EXISTS '${FW_DB_USER}'@'%' IDENTIFIED BY '${FW_DB_PASSWORD}';
GRANT SELECT, UPDATE ON ${FW_DB_NAME}.firewall_actions TO '${FW_DB_USER}'@'%';
ALTER USER '${FW_DB_USER}'@'%' REQUIRE X509;
FLUSH PRIVILEGES;
SQL

  echo "[*] Done. Remember to set firewall-controller env:"
  echo "    FW_DB_USER=${FW_DB_USER}"
  echo "    FW_DB_PASSWORD=<the password you just set>"
  echo "    (and enable DB_TLS_ENABLED + mount ${BUNDLE_DIR} on firewall host)"
fi

echo
echo "[✓] Generated:"
echo "    CA:            ${CA_PEM}"
echo "    Server cert:   ${SERVER_PEM} (SAN includes ${SENSOR_IP})"
echo "    Firewall cert: ${FW_PEM}"
echo "    MySQL config:  ${CONF_DIR}/ssl.cnf"
echo "    Firewall bundle directory to copy: ${BUNDLE_DIR}"
echo
echo "Next steps:"
echo "  1) On SENSOR host:"
echo "     - Ensure docker-compose.sensor.yml mounts are enabled for db:"
echo "         - ./pki/mysql:/etc/mysql/certs:ro"
echo "         - ./mysql-conf/ssl.cnf:/etc/mysql/conf.d/ssl.cnf:ro"
echo "     - Restart db: docker compose -f docker-compose.sensor.yml up -d --force-recreate db"
echo
echo "  2) Copy bundle to FIREWALL host, then edit docker-compose.firewall.yml:"
echo "     - Mount ./pki/mysql/fw-bundle to /pki/mysql (or similar)"
echo "     - Set DB_HOST=${SENSOR_IP}"
echo "     - Enable DB_TLS_ENABLED=true and point DB_SSL_* to mounted files"
echo
echo "  3) Verify from firewall host with mysql client (optional):"
echo "     mysql --host=${SENSOR_IP} --user=${FW_DB_USER} --ssl-mode=VERIFY_CA \\"
echo "       --ssl-ca=ca.pem --ssl-cert=fw-client.pem --ssl-key=fw-client.key -e \"status\""
