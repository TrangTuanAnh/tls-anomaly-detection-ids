# Hệ thống phát hiện bất thường TLS/SSL (JA3) + Tự động chặn IP


---

## 1) Kiến trúc vận hành

### 1.1 Thành phần

- **suricata**: bắt lưu lượng và ghi `eve.json`
- **python-real-time-service**: đọc `eve.json`, trích đặc trưng + chạy ML (autoencoder / isolation forest), gửi event sang backend
- **backend (FastAPI)**: lưu `tls_events`, sinh `alerts`, và (nếu bật) **tạo `firewall_actions` PENDING** để auto-block
- **firewall-controller**: poll `firewall_actions`, áp rule `iptables` (DROP), cập nhật trạng thái `EXECUTED/FAILED`
- **frontend**: dashboard read-only (events / alerts / firewall actions)

### 1.2 Luồng dữ liệu (tóm tắt)

1) Suricata → `eve.json`  
2) python-real-time-service → `POST /api/events` (tùy chọn HMAC)  
3) Backend:
   - ghi `tls_events`
   - nếu cần → tạo `alerts`
   - nếu `AUTO_BLOCK_ENABLED=true` và severity HIGH/CRITICAL → tạo `firewall_actions` (HMAC-signed)
4) firewall-controller → apply `iptables` → đánh dấu `EXECUTED`
5) Frontend → chỉ hiển thị dữ liệu (không login)

---

## 2) Cấu trúc thư mục

```
.
├── backend
├── firewall-controller
├── frontend
├── mysql-init
├── python-real-time-service
└── suricata
```

---

## 3) Chạy DEMO trên 1 máy Ubuntu (khuyến nghị để test nhanh)

### 3.1 Yêu cầu

- Docker + Docker Compose plugin
- `iptables` (mặc định có trên Ubuntu)
- Quyền `sudo` (để xem rule iptables khi demo chặn thật)

### 3.2 Cấu hình

Sửa `.env` (không commit). Tối thiểu cần set đúng:

- `MYSQL_ROOT_PASSWORD`, `MYSQL_PASSWORD`
- `FW_ACTION_HMAC_SECRET` (backend và firewall-controller **phải giống nhau**)
- `IPTABLES_CHAIN` (demo Docker nên dùng `DOCKER-USER`)

> Gợi ý: nếu chỉ demo nhanh, để `REQUIRE_INGEST_HMAC=false` là được.

### 3.3 Start

```bash
docker compose up -d --build
```

Kiểm tra backend:

```bash
curl http://localhost:8000/health
```

Mở UI:

- http://localhost:8080

---

## 4) Test nhanh firewall end-to-end (không cần Suricata/ML)

Mục tiêu: chứng minh backend tạo được `firewall_actions` và controller chuyển `PENDING → EXECUTED`.

### 4.1 Tạo 1 container client để test chặn (an toàn)

```bash
docker network create --subnet 172.28.0.0/16 testnet || true

docker run -d --name test-client --network testnet --ip 172.28.0.10 curlimages/curl:8.5.0 sleep 1d

docker exec -it test-client curl -I https://example.com
```

### 4.2 Gửi event “CRITICAL” để kích hoạt auto-block

Backend sẽ auto-block nếu:

- `AUTO_BLOCK_ENABLED=true` **và**
- severity là `HIGH` hoặc `CRITICAL`

Severity được tính như sau:
- `CRITICAL`: `rule_deprecated_version=true` **hoặc** `rule_no_pfs=true`
- `HIGH`: `rule_weak_cipher=true` **hoặc** `rule_cbc_only=true`
- `MEDIUM`: `is_anomaly=true` (nhưng không có các rule ở trên)

Ví dụ gửi event với `rule_no_pfs=true` để chắc chắn tạo auto-block:

```bash
NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

curl -sS -X POST http://localhost:8000/api/events   -H "Content-Type: application/json"   -d '{
    "event_time": "'"$NOW"'",
    "sensor_name": "manual-test",
    "src_ip": "172.28.0.10",
    "src_port": 12345,
    "dst_ip": "93.184.216.34",
    "dst_port": 443,
    "proto": "TCP",
    "tls_version": "TLSv1.2",
    "sni": "example.com",
    "ja3_hash": "deadbeefdeadbeefdeadbeefdeadbeef",
    "rule_no_pfs": true,
    "is_anomaly": true,
    "verdict": "ANOMALY"
  }' | python3 -m json.tool
```

> Nếu bật `REQUIRE_INGEST_HMAC=true` trong `.env`, request ingest phải kèm header `X-Timestamp`, `X-Nonce`, `X-Signature` đúng theo quy ước HMAC của backend.

### 4.3 Kiểm tra DB

```bash
docker exec -it tls-mysql mysql -u tls_user -p tls_ids -e "SELECT id,src_ip,action_type,status,executed_at,error_message FROM firewall_actions ORDER BY id DESC LIMIT 10;"
```

### 4.4 Kiểm tra rule iptables (demo Docker nên dùng DOCKER-USER)

```bash
sudo iptables -S DOCKER-USER | tail -n +1
```

### 4.5 Test bị chặn thật

```bash
docker exec -it test-client curl -I https://example.com
```

Nếu rule đã được áp, request sẽ timeout / bị drop (tùy môi trường mạng).

---

## 5) Troubleshooting

### 5.1 Firewall-controller không connect DB

- Kiểm tra `DB_HOST/DB_PORT/DB_USER/DB_PASSWORD/DB_NAME` trong service firewall-controller
- Với mode demo 1 máy (docker-compose.yml), `DB_HOST` là `127.0.0.1` do controller chạy `network_mode: host`

### 5.2 python-real-time-service restart liên tục

- Kiểm tra `trained_models/` có đủ `autoencoder_tls.h5` và `scaler.pkl`
- Xem log:

```bash
docker logs -f tls-python-realtime
```

---

## 6) Triển khai thực tế tách 3 mode (Demo / Sensor / Firewall)

### 6.1 Demo 1 máy

- Dùng `docker-compose.yml` (đủ tất cả service)

```bash
docker compose up -d --build
```

### 6.2 Sensor (máy đặt gần traffic)

- Dùng `docker-compose.sensor.yml` (không có firewall-controller)

```bash
docker compose -f docker-compose.sensor.yml up -d --build
```

### 6.3 Firewall (máy nằm ở tuyến chặn)

- Dùng `docker-compose.firewall.yml`
- **Bắt buộc** sửa `DB_HOST: SENSOR_IP_HERE` trong file compose này thành IP máy sensor (hoặc DB host)
- Set `IPTABLES_CHAIN` phù hợp:
  - `FORWARD` nếu chặn ở gateway/router
  - `DOCKER-USER` nếu chặn traffic container Docker

```bash
docker compose -f docker-compose.firewall.yml up -d --build
```

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

- `firewall_actions` được ký HMAC (backend → firewall-controller) để hạn chế record giả mạo.
- (Tuỳ chọn) Bật HMAC cho đường ingest: `REQUIRE_INGEST_HMAC=true` + `INGEST_HMAC_SECRET`.
