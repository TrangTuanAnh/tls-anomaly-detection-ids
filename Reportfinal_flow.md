# Tóm tắt kiến trúc đồ án: Flow-based IDS/IPS (CICFlowMeter + ML + FastAPI + MySQL)

## 1) Sơ đồ tổng quan (2 chế độ chạy)

### 1.1. Sensor host (chạy demo “tất cả trong 1 máy”)
- `cicflowmeter` (sniff NIC) → ghi `./shared/flows/flows.csv`
- `python-real-time-service` → tail CSV → trích 43 feature → scale → Autoencoder/IsolationForest → POST event → `backend`
- `backend` (FastAPI) → validate + clean feature → lưu DB (flow_events) → (tuỳ chọn) ghi firewall_actions khi anomaly
- `db` (MySQL) → lưu `flow_events`, `firewall_actions`, `request_nonces`

### 1.2. Firewall host (tuỳ chọn, giữ tư duy IPS)
- `firewall-controller` (poll MySQL bảng `firewall_actions`) → apply iptables **BLOCK/UNBLOCK** theo `src_ip`

---

## 2) Layout repo (runtime components theo thư mục)
- `docker-compose.sensor.yml` — compose cho **sensor host**
- `docker-compose.firewall.yml` — compose cho **firewall host**
- `mysql-init/schema.sql` — schema DB (3 bảng)
- `cicflowmeter/` — container sniff NIC, xuất CSV
  - `Dockerfile` cài package `cicflowmeter`
  - `run.sh` chạy: `cicflowmeter -i <iface> -c <csv>`
- `python-real-time-service/` — service realtime: CSV → feature → ML → gửi backend
  - `main.py`, `feature_extractor.py`, `log_utils.py`, `config.py`
  - `trained_models/` — model/scaler (read-only mount)
- `backend/` — FastAPI + SQLAlchemy lưu event & phát action
  - `main.py` (API + HMAC verify + feature clean)
- `firewall-controller/` — poll DB và apply iptables
  - `main.py`
- `scripts/gen-mysql-tls.sh` — sinh CA + cert TLS cho MySQL + bundle client cho firewall host (tuỳ chọn)

---

## 3) Data pipeline chi tiết (từ packet → flow → ML → DB → IPS)

### 3.1. Bước 1: Sniff & sinh flow CSV
**Container**: `cicflowmeter-sniffer`  
**Network**: `network_mode: "host"` (để sniff NIC thật)  
**Caps**: `NET_ADMIN`, `NET_RAW`  
**Command** (bên trong run.sh):
~~~sh
cicflowmeter -i "$CAPTURE_INTERFACE" -c "/shared/flows/flows.csv"
~~~
**Output contract**: file CSV grow dần theo thời gian: `./shared/flows/flows.csv` (mount vào các container khác).

### 3.2. Bước 2: Tail CSV (chịu được rotate/truncate)
**Module**: `python-real-time-service/log_utils.py: follow_csv()`  
- Đọc header 1 lần, normalize tên cột (gộp whitespace).
- Nếu file bị rotate/truncate → reset offset + đọc lại header.
- Poll theo `POLL_INTERVAL` (mặc định 0.2s).

### 3.3. Bước 3: Trích metadata flow + vector feature “khóa cứng”
**Module**: `python-real-time-service/feature_extractor.py`
- `extract_flow_meta()` cố gắng lấy:
  - Timestamp từ: `Timestamp | Flow Start Time | Start Time | time | Time`
  - `Flow ID` (nếu có)
  - `Source IP/Port`, `Destination IP/Port`, `Protocol`
- `build_feature_vector()`:
  - luôn build **vector 1x43** theo đúng thứ tự list `FEATURES`
  - mọi giá trị non-n
