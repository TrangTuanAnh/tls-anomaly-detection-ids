# Flow-based IDS/IPS (CICFlowMeter + ML)

**Mục tiêu mới của đồ án:** bỏ Suricata/JA3, chuyển sang **phân tích luồng (flow)** theo kiểu CIC-IDS (CICFlowMeter),
trích xuất feature từ traffic thật trên card mạng rồi đưa vào mô hình ML của bạn (Autoencoder / IsolationForest…).

## 1) Kiến trúc tổng thể

**(Sensor host)**
1. `cicflowmeter` (sniff NIC) → ghi `shared/flows/flows.csv`
2. `python-real-time-service` → tail `flows.csv` → chuẩn hoá feature → chạy ML → POST `/api/events`
3. `backend` (FastAPI) → lưu MySQL (`flow_events`) + (tuỳ chọn) ghi `firewall_actions` nếu auto-block bật
4. `db` (MySQL)

**(Firewall host – tuỳ chọn)**
- `firewall-controller` poll bảng `firewall_actions` → apply iptables (giữ lại tư duy IPS)

## 2) Feature set (flow) đưa vào ML (CHỐT)

Hệ thống **chỉ dùng đúng các feature trong `dataset_filter.py`** (danh sách có 43 item dù comment ghi “39”).
- `python-real-time-service` luôn build **vector theo đúng thứ tự list này**.
- Backend chỉ nhận **`features_json`** (dict) và sẽ **bỏ mọi key “rác”/ngoài danh sách**, đồng thời **fill thiếu = 0.0**.
- API ingest **không cho phép field top-level lạ** (extra fields bị reject) để tránh “lẫn rác” vào pipeline.

## 3) Chạy demo bằng Docker Compose (Sensor host)

### 3.1. Chuẩn bị
- Linux host (khuyến nghị), có quyền sniff NIC (CAP_NET_RAW).
- Chọn interface để sniff: `eth0` / `ens33` / `wlan0`…

### 3.2. Cấu hình `.env`
Các biến quan trọng:
- `CAPTURE_INTERFACE` (NIC để CICFlowMeter sniff)
- `REQUIRE_INGEST_HMAC`, `INGEST_HMAC_SECRET` (chống giả mạo + replay cho ingest)
- `AE_MODEL_PATH`, `SCALER_PATH` (nếu bạn đổi tên model/scaler)
- `AE_MODEL_SHA256`, `SCALER_SHA256` (pin hash để chống model tampering)

### 3.3. Start
```bash
docker compose -f docker-compose.sensor.yml up --build
```

Sau khi có traffic trên interface, bạn sẽ thấy:
- `shared/flows/flows.csv` được tạo và tăng dần dòng
- backend nhận event ở `GET /api/events`

## 4) Auto-block (giữ hướng IPS)

Trong `backend`:
- bật `AUTO_BLOCK=true` để mỗi event bất thường sẽ ghi một dòng `firewall_actions` (BLOCK theo `src_ip`)

Ở `firewall-controller` (chạy host firewall riêng):
- poll bảng `firewall_actions` và apply iptables (giữ logic cũ của đồ án)

## 5) Ghi chú quan trọng
- CICFlowMeter trong repo này đang dùng bản **python package `cicflowmeter`** (CICFlowMeter-like).
  Nếu bạn muốn dùng bản Java jar gốc, bạn có thể thay container `cicflowmeter` bằng image jar-based (xem README của dự án docker hoá CICFlowMeter).
