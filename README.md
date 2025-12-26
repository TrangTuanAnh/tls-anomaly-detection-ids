# Hệ thống phát hiện bất thường TLS/SSL (JA3) + Tự động chặn IP

Hệ thống gồm **Sensor -> Backend/DB -> Firewall-controller** để phát hiện TLS bất thường (dựa trên JA3/feature từ log Suricata) và chặn IP bằng firewall.

---

## 1) Kiến trúc vận hành

### 1.1 Thành phần

- **Suricata (Sensor)**: bắt TLS handshake, ghi log JSON (eve.json).
- **python-real-time-service (Sensor)**: đọc eve.json realtime, trích xuất feature, chạy model; nếu bất thường thì gọi API backend.
- **Backend (Core/Sensor)**: nhận event, ghi DB, tạo alert và tạo `firewall_actions` (tự động hoặc thủ công qua UI).
- **MySQL (Core/Sensor)**: lưu `tls_events`, `alerts`, `firewall_actions`.
- **firewall-controller (Firewall)**: poll DB lấy `firewall_actions` trạng thái `PENDING`, chạy iptables và cập nhật `EXECUTED/FAILED`.
- **Frontend (tùy chọn)**: UI quản trị xem dashboard, alerts, và gửi lệnh chặn thủ công.

### 1.2 Luồng dữ liệu

1) Suricata ghi TLS event vào `eve.json`.
2) python-real-time-service đọc log, nếu bất thường → `POST /api/events` lên backend.
3) Backend ghi `tls_events`, tạo `alerts` (nếu cần).
4) Nếu bật auto-block hoặc người dùng chặn tay: backend thêm record vào `firewall_actions` (status `PENDING`).
5) firewall-controller đọc `PENDING` -> chạy iptables (DROP) -> cập nhật status sang `EXECUTED` hoặc `FAILED`.

---

## 2) Cấu trúc thư mục

```
.
├── README.md
├── backend
│   ├── Dockerfile
│   ├── main.py
│   └── requirements.txt
├── docker-compose.yml
├── mysql-init
│   └── schema.sql
├── python-real-time-service
│   ├── Dockerfile
│   ├── config.py
│   ├── feature_extractor.py
│   ├── log_utils.py
│   ├── main.py
│   ├── requirements.txt
│   └── trained_models
│       ├── autoencoder_tls.h5
│       └── scaler.pkl
└── suricata
    ├── Dockerfile
    └── suricata.yaml
```

---

## 3) Chạy DEMO trên 1 máy Ubuntu (khuyến nghị để test nhanh)

### 3.1 Yêu cầu

- Docker + Docker Compose
- Có quyền `sudo` (để kiểm tra iptables khi demo chặn thật)

### 3.2 Start

Tạo file cấu hình môi trường (không commit):

```bash
cp .env.example .env
# sửa các biến quan trọng: MYSQL_ROOT_PASSWORD, MYSQL_PASSWORD, SESSION_HMAC_SECRET,
# FW_ACTION_HMAC_SECRET, ADMIN_PASSWORD, ...
```

```bash
docker compose up -d --build
```

Check backend:

```bash
curl http://localhost:8000/health
```

UI (nếu đã build frontend):

- <http://localhost:8080>

---

## 4) Test nhanh firewall end-to-end (không cần Suricata/ML)

Mục tiêu: chứng minh `firewall_actions` tạo được và controller chuyển `PENDING → EXECUTED`.

### 4.1 Tạo 1 container client để test chặn (an toàn)

```bash
docker network create --subnet 172.28.0.0/16 testnet || true

docker run -d --name test-client --network testnet --ip 172.28.0.10 curlimages/curl:8.5.0 sleep 1d

docker exec -it test-client curl -I https://example.com
```

### 4.2 Tạo lệnh BLOCK qua backend

Lấy session token (HMAC-signed):

```bash
TOKEN=$(curl -sS -X POST http://localhost:8000/api/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Admin@12345"}' | \
  python3 -c 'import sys,json; print(json.load(sys.stdin)["access_token"])')
```

Gọi API tạo firewall action (yêu cầu role=admin):

```bash
curl -X POST http://localhost:8000/api/firewall-actions \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer $TOKEN" \
  -d '{"src_ip":"172.28.0.10","action_type":"BLOCK"}'
```

### 4.3 Kiểm tra DB

```bash
docker exec -it tls-mysql mysql -u tls_user -p tls_ids -e \
"SELECT id,src_ip,action_type,status,executed_at,error_message FROM firewall_actions ORDER BY id DESC LIMIT 10;"
```

### 4.4 Kiểm tra rule iptables (demo Docker nên dùng DOCKER-USER)

```bash
sudo iptables -S DOCKER-USER | grep 172.28.0.10 || true
```

### 4.5 Test bị chặn thật

```bash
docker exec -it test-client curl -I https://example.com
```

Kỳ vọng: timeout / không kết nối.

---

## 5) Troubleshooting

### 5.1 Firewall-controller không connect DB (Unknown MySQL server host)

- Nếu firewall-controller chạy `network_mode: host` thì nó **không dùng DNS nội bộ compose**.
- Khi đó DB_HOST nên là `127.0.0.1` (demo 1 máy) và MySQL phải publish port ra host:

Trong service `db`:

```yaml
ports:
  - "3306:3306"
```

Trong firewall-controller (host network):

- `DB_HOST=127.0.0.1`
- `DB_PORT=3306`

### 5.2 python-real-time-service restart liên tục

Xem log:

```bash
docker logs --tail 200 project_cryptography--python-realtime-1
```

Các lỗi hay gặp:

- sai mount hoặc sai đường dẫn `EVE_PATH`
- thiếu file model/scaler trong `trained_models/`

---

## 6) Triển khai thực tế tách 3 mode (Demo / Sensor / Firewall)

### 6.1 Demo 1 máy

Chạy toàn bộ stack trong một máy để chứng minh hệ thống hoạt động.

### 6.2 Sensor

- Chạy: Suricata + python-real-time-service + backend + MySQL (+ frontend nếu cần)
- Không chạy firewall-controller trên sensor.

### 6.3 Firewall

- Chạy: firewall-controller
- `DB_HOST` phải trỏ về IP của Sensor/Core (không dùng `db` hay `tls-mysql`)
- `IPTABLES_CHAIN` thường dùng `FORWARD` nếu firewall là gateway.

---

## 7) Chạy firewall-controller trên firewall mà không dùng Docker (script)

iptables cần quyền admin, nên chạy bằng `sudo`.

Ví dụ `run_firewall_controller.sh`:

```bash
#!/usr/bin/env bash
set -e

export DB_HOST="<IP_MAY_SENSOR>"
export DB_PORT="3306"
export DB_USER="tls_user"
export DB_PASSWORD="tls_pass"
export DB_NAME="tls_ids"
export IPTABLES_CHAIN="FORWARD"
export FW_DRY_RUN="false"
export FW_POLL_INTERVAL="1.0"

cd firewall-controller
sudo -E python3 main.py
```

---

## 8) Ghi chú an toàn

- Không expose MySQL 3306 ra internet. Chỉ mở trong LAN và giới hạn IP firewall được phép truy cập.
- Auto-block nên bật trong môi trường lab/demo hoặc khi chấp nhận rủi ro false positive.

Khuyến nghị bật các tuỳ chọn tăng cường:

- **Ký HMAC firewall_actions**: đặt `FW_ACTION_HMAC_SECRET` (backend sẽ ký, firewall-controller sẽ verify).
- **Chống replay cho admin request** (tuỳ chọn): `REQUIRE_ADMIN_HMAC=true` + `ADMIN_HMAC_SECRET`.
- **Chống replay/giả mạo đường ingest** (tuỳ chọn): `REQUIRE_INGEST_HMAC=true` + `INGEST_HMAC_SECRET`.
- **Integrity model** (tuỳ chọn): set `AE_MODEL_SHA256` / `SCALER_SHA256`.

**Bổ sung theo checklist**

- UI/API quản trị dùng session token (HMAC-signed) + phân quyền (admin mới tạo được BLOCK/UNBLOCK).
- `firewall_actions` được ký HMAC (backend -> firewall-controller) để phát hiện record giả mạo.
- (Tuỳ chọn) HMAC + nonce + timestamp cho đường ingest (python-realtime -> backend) và đường admin (UI -> backend).
