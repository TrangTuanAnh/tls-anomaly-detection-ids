# TLS Anomaly Detection (Suricata + Realtime ML + FastAPI + Firewall Controller)

## Kiến trúc (tóm tắt)

- **Sensor stack (docker network nội bộ)**: `suricata` → `python-realtime` → `backend` → `db`
- **Firewall host**: `firewall-controller` chạy `network_mode: host` và **polling** bảng `tls_ids.firewall_actions` để apply iptables.

> Suricata + backend chạy trong cùng mạng Docker nội bộ nên kênh đó không phải “điểm đau” hiện tại.  
> **Điểm cần bảo mật**: kênh **firewall-controller ↔ MySQL (3306)** đang đi qua mạng thật và hiện đang **không TLS**.

---

## Chạy demo nhanh (không TLS DB)

### 1) Sensor host
```bash
docker compose -f docker-compose.sensor.yml up -d --build
```

### 2) Firewall host
```bash
docker compose -f docker-compose.firewall.yml up -d --build
```


---

## Bảo mật kênh Firewall Controller ↔ MySQL bằng TLS (khuyến nghị)

### Option A: Dùng script (nhanh nhất)

Trên **sensor host** (trong repo root):

```bash
chmod +x scripts/gen-mysql-tls.sh
./scripts/gen-mysql-tls.sh --sensor-ip SENSOR_IP_HERE --enable-sensor-compose
docker compose -f docker-compose.sensor.yml up -d --force-recreate db
```

Nếu bạn muốn script **tạo luôn DB user** riêng cho firewall-controller (bắt buộc X509, không lưu password vào repo):

```bash
./scripts/gen-mysql-tls.sh --sensor-ip SENSOR_IP_HERE --enable-sensor-compose --create-fw-user
```

Sau đó copy bundle sang **firewall host**:

```bash
scp -r pki/mysql/fw-bundle <firewall-host>:/path/to/project/pki/mysql/
```

Trên **firewall host**, chỉnh `docker-compose.firewall.yml`:

- `DB_HOST: "SENSOR_IP_HERE"` → IP của sensor host
- Mount cert bundle:
  - `./pki/mysql/fw-bundle:/pki/mysql:ro`
- Bật TLS env (bỏ comment):
  - `DB_TLS_ENABLED: "true"`
  - `DB_SSL_CA: "/pki/mysql/ca.pem"`
  - `DB_SSL_CERT: "/pki/mysql/fw-client.pem"`
  - `DB_SSL_KEY: "/pki/mysql/fw-client.key"`
- Set user/pass (khuyến nghị đặt trong `.env` ở firewall host):
  - `FW_DB_USER=fw_user`
  - `FW_DB_PASSWORD=...`
  - `FW_DB_NAME=tls_ids` (nếu khác)

Restart firewall-controller:

```bash
docker compose -f docker-compose.firewall.yml up -d --force-recreate
```

### Option B: Làm thủ công (tóm tắt)

1) Tạo CA + server cert (có SAN chứa `SENSOR_IP`) + client cert cho firewall  
2) Mount vào MySQL container (`./pki/mysql` và `./mysql-conf/ssl.cnf`)  
3) Tạo DB user `fw_user` và `ALTER USER ... REQUIRE X509`  
4) Trên firewall host: mount CA+client cert/key và bật `DB_TLS_ENABLED=true`

---

## Verify (từ firewall host)

Nếu có mysql client trên firewall host:

```bash
mysql --host=SENSOR_IP_HERE --user=fw_user --password='FW_DB_PASSWORD_HERE'   --ssl-mode=VERIFY_CA   --ssl-ca=ca.pem --ssl-cert=fw-client.pem --ssl-key=fw-client.key   -e "status"
```

---

## Ghi chú “fail-closed”

- Khi `DB_TLS_ENABLED=true` mà thiếu `DB_SSL_CA/DB_SSL_CERT/DB_SSL_KEY` → firewall-controller sẽ **exit** (không tự fallback plaintext).
