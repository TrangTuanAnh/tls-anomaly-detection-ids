# Flow IDS/IPS Realtime (NFStream + MLP + FastAPI + MySQL)

Đồ án này triển khai một pipeline **phát hiện bất thường theo network flow** (IDS) và có thể mở rộng thành **IPS** bằng cách tự động sinh lệnh chặn IP (iptables).

- **Sensor/Collector**: NFStream sniff traffic trên interface thật, dựng flow và map về **feature-set kiểu CICFlowMeter**.
- **Realtime Scoring**: Python service load **MLP binary classifier** (0 = benign, 1 = anomaly) để chấm điểm flow theo thời gian thực.
- **Backend API + Storage**: FastAPI + MySQL lưu flow + feature + kết quả ML, đồng thời cung cấp API để truy vấn.
- **Firewall Controller (tuỳ chọn)**: đọc bảng `firewall_actions` và apply iptables (BLOCK/UNBLOCK).

## Kiến trúc tổng thể

```
Linux host / gateway
   |
   |  NFStream sniffer (bắt traffic ở host)
   v
python-real-time-service
   - sắp xếp + chuẩn hoá feature
   - scaler -> MLP -> ra điểm cảnh báo
   - (tuỳ chọn) Isolation Forest
   |
   v  POST /api/events (có thể kèm HMAC)
backend (FastAPI)
   |
   v
MySQL 8
  - flow_events
  - firewall_actions
  - request_nonces

(Tuỳ chọn chặn tự động)
firewall-controller (cần NET_ADMIN)
   |
   v  đọc firewall_actions
iptables

```

> Lưu ý: `docker-compose.sensor.yml` cố ý **không publish port** cho backend/rt ra ngoài Internet. Trên Linux, bạn vẫn có thể truy cập bằng IP nội bộ của Docker bridge (mặc định `172.30.0.0/24`) hoặc dùng `docker exec` để test.

## Feature contract (bắt buộc)

Toàn bộ hệ thống được **khóa** theo đúng **34 features** (tên + thứ tự) kiểu CICFlowMeter. Đây là điểm quan trọng nhất để mô hình chạy ổn định từ train đến realtime.

Nguồn “ground truth” của danh sách feature:
- `python-real-time-service/feature_extractor.py` (`FEATURES`)
- `backend/main.py` (`FEATURE_NAMES`) — backend sẽ **drop key thừa** và **fill thiếu = 0.0**
- `nfstream/nfstream_sniffer.py` (`CIC_FEATURES`) — map NFStream -> CIC-style
- `training-model/README.md` — mô tả train/evaluate

Nếu bạn thay đổi feature-set, bạn phải **re-train** model + scaler và đồng bộ lại toàn bộ các list trên.

## Database schema

MySQL khởi tạo bằng `mysql-init/schema.sql`, gồm 3 bảng chính:
- `flow_events`: metadata + `features_json` (JSON đúng 34 features) + output từ ML
- `firewall_actions`: lệnh BLOCK/UNBLOCK (để firewall-controller thực thi)
- `request_nonces`: chống replay cho cơ chế ingest ký HMAC

## API

### python-real-time-service (realtime ingest)
- `GET /health`
- `POST /flow` — nhận **1 flow** (dict) hoặc **nhiều flow** (list) theo format JSON.

### backend
- `GET /health`
- `POST /api/events` — realtime-service gửi flow + feature + score vào đây
- `GET /api/events?limit=100&only_anomaly=false` — truy vấn event (mới nhất trước)

FastAPI swagger:
- backend: `http://<BACKEND_IP>:8000/docs`
- realtime: `http://<RT_IP>:9000/docs`

(Mặc định `<BACKEND_IP>=172.30.0.20`, `<RT_IP>=172.30.0.30` theo `.env`.)

## Cấu trúc thư mục

```
.
├─ backend/                    # FastAPI + MySQL (lưu event, API query)
├─ python-real-time-service/   # Realtime scoring: scaler + MLP + gửi backend
│  └─ trained_models/          # mlp.h5, scaler.pkl (+ scaler_params.json)
├─ nfstream/                   # Sniffer dựng flow từ packet (host network)
├─ firewall-controller/        # (tuỳ chọn) poll DB -> iptables BLOCK/UNBLOCK
├─ mysql-init/                 # schema.sql
├─ scripts/                    # tiện ích (vd: gen TLS cho MySQL)
├─ training-model/             # train/evaluate MLP (supervised)
└─ docker-compose.*.yml         # chạy sensor stack / firewall stack
```

## Yêu cầu

Khuyến nghị chạy trên **Linux** (Ubuntu/Debian) vì cần sniff traffic và iptables.

- Docker + Docker Compose (v2)
- Quyền để capture traffic:
  - container `nfstream` chạy `network_mode: host` và cần `NET_ADMIN` + `NET_RAW` (hoặc bật `privileged: true` nếu môi trường khắt khe)
- Nếu dùng IPS:
  - `firewall-controller` cần `NET_ADMIN` và chạy host network (iptables)

> Trên macOS/Windows (Docker Desktop) việc sniff interface thật + iptables thường không hoạt động đúng như Linux.

## Quickstart: chạy sensor stack (sniffer + realtime + backend + MySQL)

### 1) Cấu hình môi trường

Sửa file `.env` (ít nhất các phần sau):

- MySQL password:
  - `MYSQL_ROOT_PASSWORD`
  - `MYSQL_PASSWORD`
- Interface bắt gói:
  - `CAPTURE_INTERFACE` (vd: `eth0`, `ens33`, `wlan0`)
- Threshold:
  - `MLP_THRESHOLD` (mặc định 0.5)

> Nếu dải mạng `172.30.0.0/24` bị trùng với network của bạn, đổi `SENSOR_NET_SUBNET` trong `.env`.

### 2) Khởi động

```bash
cd fi_mlp_fixed
docker compose -f docker-compose.sensor.yml up -d --build
```

Kiểm tra container:

```bash
docker compose -f docker-compose.sensor.yml ps
```

Xem log realtime:

```bash
# sniffer
docker logs -f nfstream-sniffer

# realtime scoring
docker logs -f flow-rt

# backend
docker logs -f flow-backend
```

### 3) Kiểm tra health (Linux host)

Mặc định các service không publish port ra ngoài, nhưng trên Linux bạn có thể gọi trực tiếp bằng IP bridge:

```bash
curl -s http://172.30.0.30:9000/health | jq
curl -s http://172.30.0.20:8000/health | jq
```

Nếu máy bạn không route được vào IP bridge, có thể test bằng `docker exec`:

```bash
docker exec -it flow-rt python -c "import requests; print(requests.get('http://localhost:9000/health').text)"
docker exec -it flow-backend python -c "import requests; print(requests.get('http://localhost:8000/health').text)"
```

### 4) Xem dữ liệu đã ghi vào DB

```bash
# 20 events gần nhất
curl -s "http://172.30.0.20:8000/api/events?limit=20" | jq '.[0:3]'

# chỉ lấy anomaly
curl -s "http://172.30.0.20:8000/api/events?limit=20&only_anomaly=true" | jq
```

> Để có dữ liệu, bạn cần tạo traffic thật trên interface đang capture (mở web, ping, tải file, v.v.).

### Dừng hệ thống

```bash
docker compose -f docker-compose.sensor.yml down
```

## Huấn luyện mô hình (MLP supervised)

Tham khảo chi tiết trong `training-model/README.md`. Tóm tắt nhanh:

### Dataset
- `training-model/dataset/supervised_train.csv`
- `training-model/dataset/supervised_test.csv`

Yêu cầu tối thiểu:
- Có cột `y` (0/1)
- Có các cột feature đúng theo **Feature contract** (đúng tên và thứ tự)

### Train

```bash
cd training-model
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt

python scripts/mlp_training.py
```

Output:
- `training-model/models/mlp.h5`
- `training-model/models/scaler.pkl`
- `training-model/models/scaler_params.json` (portable, tránh phụ thuộc pickle)

### Evaluate

```bash
# có thể override threshold bằng env var
MLP_THRESHOLD=0.5 python scripts/evaluate.py
```

Output:
- `training-model/results/metrics.json`
- `training-model/results/plots/` (ROC, confusion matrix, score distribution, ...)

### Deploy model vào realtime-service

Copy các file sau sang `python-real-time-service/trained_models/`:
- `mlp.h5`
- `scaler.pkl` (hoặc giữ kèm `scaler_params.json` để fallback)

Sau đó restart realtime container:

```bash
docker compose -f docker-compose.sensor.yml up -d --force-recreate python-realtime
```

> Realtime-service có cơ chế kiểm tra **feature contract** (scaler feature_names_in_ / model input dim). Nếu mismatch sẽ fail sớm để tránh chạy sai.

## IPS (tuỳ chọn): firewall-controller + AUTO_BLOCK

Mục tiêu: khi backend nhận verdict anomaly, nó có thể tự ghi một action vào DB, rồi **firewall-controller** sẽ thực thi iptables.

### 1) Bật auto-block ở sensor

Trong `.env` trên **sensor host**:

```dotenv
AUTO_BLOCK=true
```

Khi backend ingest event có `is_anomaly=true`, backend sẽ insert vào bảng `firewall_actions` một record `BLOCK`.

### 2) Chạy firewall-controller (có thể chạy trên máy khác)

Trên **firewall host** (máy gateway/router hoặc máy cần apply iptables):

1) Trỏ DB về sensor host (nơi đang publish MySQL):

```dotenv
FW_DB_HOST=<IP_sensor_host>
FW_DB_PASSWORD=<mysql_password>
FW_DB_USER=tls_user
FW_DB_NAME=tls_ids
```

2) Start container:

```bash
docker compose -f docker-compose.firewall.yml up -d --build
```

3) Xem log:

```bash
docker logs -f fw-controller
```

### 3) Tuỳ chỉnh iptables

Biến môi trường quan trọng (trong `docker-compose.firewall.yml` hoặc env của container):

- `IPTABLES_CHAIN` (mặc định `FORWARD`)
  - Nếu firewall host là gateway chuyển tiếp traffic: dùng `FORWARD`.
  - Nếu muốn chặn traffic vào chính máy firewall host: cân nhắc dùng `INPUT`.
- `FIREWALL_TARGET` (`DROP` hoặc `REJECT`, mặc định `DROP`)
- `FW_DRY_RUN=true` để chạy thử (không thật sự sửa iptables)

> `firewall-controller` cũng có cơ chế kiểm tra định kỳ (~30s) để re-add rule nếu bị xoá.

### 4) Thử BLOCK/UNBLOCK thủ công

Bạn có thể insert action trực tiếp vào MySQL để test:

```sql
INSERT INTO firewall_actions (src_ip, action_type, target, description)
VALUES ('1.2.3.4', 'BLOCK', 'iptables', 'manual test');

INSERT INTO firewall_actions (src_ip, action_type, target, description)
VALUES ('1.2.3.4', 'UNBLOCK', 'iptables', 'manual test');
```

## Bảo mật & triển khai

### 1) HMAC ký ingest (python-real-time-service -> backend)

Hệ thống hỗ trợ ký request (chống tamper + chống replay) bằng 3 header:
- `X-Timestamp`: unix epoch (seconds)
- `X-Nonce`: random nonce
- `X-Signature`: HMAC-SHA256 trên chuỗi `ts.nonce.body`

Bật/tắt bằng `.env`:

```dotenv
REQUIRE_INGEST_HMAC=true
INGEST_HMAC_SECRET=<secret>
INGEST_HMAC_MAX_AGE_SEC=120
```

- Nếu `REQUIRE_INGEST_HMAC=true`, backend sẽ từ chối ingest thiếu header/seed.
- Backend lưu nonce vào bảng `request_nonces` (TTL mặc định 300s) để chặn replay.

### 2) MySQL TLS khi firewall-controller connect qua mạng thật

Khi firewall-controller chạy trên **máy khác**, khuyến nghị bật TLS cho MySQL.
Repo có script:

```bash
chmod +x scripts/gen-mysql-tls.sh
./scripts/gen-mysql-tls.sh --sensor-ip <IP_sensor> --enable-sensor-compose
```

Script sẽ tạo:
- `pki/mysql/ca.pem`, `pki/mysql/server.pem`, `pki/mysql/server.key`
- `mysql-conf/ssl.cnf`
- bundle cho firewall: `pki/mysql/fw-bundle/` (copy sang firewall host)

Trên firewall host, bật biến:

```dotenv
DB_TLS_ENABLED=true
DB_SSL_CA=/pki/mysql/ca.pem
DB_SSL_CERT=/pki/mysql/fw-client.pem
DB_SSL_KEY=/pki/mysql/fw-client.key
DB_SSL_VERIFY_CERT=true
```

### 3) Kiểm tra integrity model/scaler (tuỳ chọn)

Realtime-service có thể verify SHA256 trước khi load model:

```dotenv
MLP_MODEL_SHA256=<sha256 của mlp.h5>
SCALER_SHA256=<sha256 của scaler.pkl>
```

## Troubleshooting

- **Không có event nào được ghi**:
  - kiểm tra `CAPTURE_INTERFACE` đúng chưa (vd: `ip link`)
  - kiểm tra quyền capture: `nfstream-sniffer` cần `NET_RAW` + `NET_ADMIN` (hoặc `privileged: true`)
  - xem log: `docker logs -f nfstream-sniffer` và `docker logs -f flow-rt`

- **Không gọi được `172.30.0.20:8000` / `172.30.0.30:9000` từ host**:
  - trên Linux thường route được; nếu không, dùng `docker exec` để test
  - nếu dải `SENSOR_NET_SUBNET` bị trùng, đổi sang subnet khác trong `.env`

- **Realtime-service fail vì mismatch feature/model**:
  - đảm bảo model + scaler được train trên đúng 34 feature và đúng thứ tự
  - kiểm tra `python-real-time-service/feature_extractor.py` (`FEATURES`)

- **Lỗi load scaler do khác phiên bản numpy/sklearn**:
  - repo đã có `scaler_params.json` để fallback portable; giữ file này cùng `scaler.pkl`


