#!/usr/bin/env bash
set -euo pipefail

# Script tu dong hoa viec khoi tao chung chi TLS bao mat cho MySQL
# Muc tieu: Ma hoa du lieu va xac thuc danh tinh giua Sensor va Firewall

# Ham thong bao loi va dung chuong trinh
die() { echo "ERROR: $*" >&2; exit 1; }

# Kiem tra cac cong cu openssl, awk, sed co san tren he thong hay khong
need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Missing required command: $1"
}

# Thiet lap cac tham so mac dinh cho ten va thoi han chung chi
SENSOR_IP=""
CA_CN="tls-mysql-ca"
SERVER_CN="tls-mysql"
FW_CN="fw-controller"

# Thoi han cua cac loai chung chi (ngay)
DAYS_CA=3650
DAYS_SERVER=825
DAYS_CLIENT=30

# Thu muc luu tru chung chi va cau hinh
OUT_DIR="pki/mysql"
CONF_DIR="mysql-conf"
BUNDLE_DIR="pki/mysql/fw-bundle"

PATCH_SENSOR_COMPOSE="false"
CREATE_FW_USER="false"
MYSQL_CONTAINER="tls-mysql"

FW_DB_NAME=""
FW_DB_USER="fw_user"

# Ham hien thi huong dan su dung script
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

# Xu ly cac tham so dau vao tu dong lenh
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

# Tu dong nhan dien dia chi IP cua Sensor neu nguoi dung khong cung cap
if [[ -z "${SENSOR_IP}" ]]; then
  if command -v hostname >/dev/null 2>&1; then
    SENSOR_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
  fi
fi
[[ -n "${SENSOR_IP}" ]] || die "--sensor-ip is required (could not auto-detect)"

umask 077

# Tao cac thu muc luu tru chung chi va cau hinh
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

# Khoi tao chung chi goc CA neu chua ton tai
echo "[*] Generating/ensuring CA..."
if [[ ! -f "${CA_KEY}" || ! -f "${CA_PEM}" ]]; then
  openssl genrsa -out "${CA_KEY}" 4096
  openssl req -x509 -new -nodes -key "${CA_KEY}" -sha256 -days "${DAYS_CA}" \
    -subj "/CN=${CA_CN}" -out "${CA_PEM}"
else
  echo "    CA exists: ${CA_PEM}"
fi

# Tao file cau hinh SAN de xac thuc dung dia chi IP cua may chu, chong gia mao
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

# Tao khoa va chung chi cho MySQL Server ky xac nhan boi CA
echo "[*] Generating MySQL server key/cert..."
if [[ ! -f "${SERVER_KEY}" ]]; then
  openssl genrsa -out "${SERVER_KEY}" 2048
fi
openssl req -new -key "${SERVER_KEY}" -out "${SERVER_CSR}" -config "${SERVER_CNF}"
openssl x509 -req -in "${SERVER_CSR}" -CA "${CA_PEM}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${SERVER_PEM}" -days "${DAYS_SERVER}" -sha256 -extensions v3_req -extfile "${SERVER_CNF}"

# Tao khoa va chung chi cho Firewall Client dung de ket noi an toan
echo "[*] Generating firewall client key/cert..."
if [[ ! -f "${FW_KEY}" ]]; then
  openssl genrsa -out "${FW_KEY}" 2048
fi
openssl req -new -key "${FW_KEY}" -out "${FW_CSR}" -subj "/CN=${FW_CN}"
openssl x509 -req -in "${FW_CSR}" -CA "${CA_PEM}" -CAkey "${CA_KEY}" -CAcreateserial \
  -out "${FW_PEM}" -days "${DAYS_CLIENT}" -sha256

# Tao file cau hinh SSL cho MySQL thiet lap duong dan chung chi ben trong container
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

# Gom nhom cac file chung chi can thiet vao mot bundle de sao chep sang Firewall host
echo "[*] Creating firewall bundle: ${BUNDLE_DIR}"
cp -f "${CA_PEM}" "${BUNDLE_DIR}/ca.pem"
cp -f "${FW_PEM}" "${BUNDLE_DIR}/fw-client.pem"
cp -f "${FW_KEY}" "${BUNDLE_DIR}/fw-client.key"
chmod 600 "${BUNDLE_DIR}/fw-client.key" || true

# Tu dong mo cac dong chu thich mount TLS trong file docker-compose neu co yeu cau
if [[ "${PATCH_SENSOR_COMPOSE}" == "true" ]]; then
  [[ -f "docker-compose.sensor.yml" ]] || die "docker-compose.sensor.yml not found in current directory (run from repo root)"
  echo "[*] Patching docker-compose.sensor.yml: enabling MySQL TLS mounts"
  # Su dung sed de bo comment cac dong mount volume TLS
  sed -i.bak \
    -e 's|^[[:space:]]*# - \./pki/mysql:/etc/mysql/certs:ro|      - ./pki/mysql:/etc/mysql/certs:ro|g' \
    -e 's|^[[:space:]]*# - \./mysql-conf/ssl\.cnf:/etc/mysql/conf\.d/ssl\.cnf:ro|      - ./mysql-conf/ssl.cnf:/etc/mysql/conf.d/ssl.cnf:ro|g' \
    docker-compose.sensor.yml
  echo "    Backup saved: docker-compose.sensor.yml.bak"
fi

# Tao nguoi dung database bat buoc phai co chung chi X509 (REQUIRE X509)
if [[ "${CREATE_FW_USER}" == "true" ]]; then
  need_cmd docker

  # Doc mat khau root va ten DB tu file .env
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

  # Thuc thi cau lenh SQL de tao user kem rang buoc xac thuc chung chi
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
fi

echo
echo "Generated:"
echo "    CA:            ${CA_PEM}"
echo "    Server cert:   ${SERVER_PEM} (SAN includes ${SENSOR_IP})"
echo "    Firewall cert: ${FW_PEM}"
echo "    MySQL config:  ${CONF_DIR}/ssl.cnf"
echo "    Firewall bundle directory to copy: ${BUNDLE_DIR}"
echo
echo "Next steps:"
echo "  1) On SENSOR host restart db"
echo "  2) Copy bundle to FIREWALL host"
echo "  3) Verify from firewall host with mysql client"