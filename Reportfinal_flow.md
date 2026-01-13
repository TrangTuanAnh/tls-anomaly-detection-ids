# Đồ án IDS/IPS dựa trên phân tích luồng (Flow) với CICFlowMeter + ML

## 1. Thay đổi hướng so với phiên bản Suricata/JA3
Phiên bản cũ dựa trên Suricata đọc log `eve.json` và trích xuất đặc trưng TLS/JA3.
Phiên bản mới chuyển hoàn toàn sang **phân tích luồng (flow)** theo phong cách CIC-IDS:

- **Sniff trực tiếp NIC** → CICFlowMeter (hoặc CICFlowMeter-like) sinh flow + feature
- **python-real-time-service** đọc CSV flow → chuẩn hoá feature → chạy ML → gửi backend
- **backend + MySQL** lưu log & (tuỳ chọn) phát lệnh block sang firewall-controller

Tư duy “bảo mật hệ thống” vẫn giữ: ký ingest chống giả mạo + replay, kiểm tra toàn vẹn model, TLS MySQL khi firewall-controller connect qua mạng thật, và cơ chế IPS qua iptables.

---

## 2. Kiến trúc hệ thống (hướng Flow)

### 2.1. Sensor host (máy giám sát)
- **cicflowmeter-sniffer**: sniff interface (eth0/ens33/…) và ghi `shared/flows/flows.csv`
- **python-real-time-service**:
  - tail CSV
  - trích 43 feature (theo danh sách training)
  - chạy Autoencoder (reconstruction error) + (tuỳ chọn) IsolationForest
  - POST `/api/events` lên backend (kèm chữ ký HMAC nếu bật)
- **backend (FastAPI)**: nhận event, lưu DB, ghi `firewall_actions` nếu auto-block bật
- **db (MySQL)**: bảng `flow_events`, `firewall_actions`, `request_nonces`

### 2.2. Firewall host (máy tường lửa – tuỳ chọn)
- **firewall-controller**: poll `firewall_actions` và apply iptables (BLOCK/UNBLOCK).
- Có kiểm tra integrity đơn giản: nếu rule bị xoá thủ công, controller có thể thêm lại.

---

## 3. Dòng dữ liệu (Data pipeline)
1. NIC → `cicflowmeter` → `flows.csv`
2. `python-real-time-service` đọc dòng mới → parse metadata (src/dst/proto/time)
3. Tách feature vector `X` (đúng thứ tự training)
4. Scale → Autoencoder → `ae_error`
5. (Optional) IsolationForest → `iso_score`
6. Kết luận bất thường nếu `ae_error > AE_THRESHOLD` hoặc `iso_score < ISO_THRESHOLD`
7. Gửi payload lên backend, backend lưu DB; nếu `AUTO_BLOCK=true` thì tạo action BLOCK

---

## 4. Feature set dùng cho ML
Danh sách feature được dùng trong code ở:
- `python-real-time-service/feature_extractor.py`

**Lưu ý:** file lọc dataset có comment “39 features” nhưng danh sách thực tế hiện tại là **43** (có thêm TCP flags).  
Mô hình training phải dùng đúng danh sách + đúng thứ tự này để inference khớp.

---

## 5. Bảo mật & hardening (giữ lại)
- **HMAC + timestamp + nonce** cho ingest: chống giả mạo + replay khi gửi event.
- **Model integrity pinning (SHA-256)**: phát hiện thay thế file model/scaler trong container.
- **MySQL TLS (tuỳ chọn)**: nếu firewall-controller connect DB qua mạng thật, bật TLS để chống MITM.
- **IPS**: rule iptables do firewall-controller áp dụng theo `firewall_actions`.

---

## 6. Triển khai
### 6.1. Sensor host
```bash
docker compose -f docker-compose.sensor.yml up --build
```

### 6.2. Firewall host (tuỳ chọn)
- Sửa `docker-compose.firewall.yml`: `DB_HOST` trỏ về IP sensor host
- Chạy:
```bash
docker compose -f docker-compose.firewall.yml up --build
```

---

## 7. Đánh giá / Demo
- Tạo traffic bình thường + traffic bất thường (scan, flood, …) để quan sát:
  - dòng flow được sinh ra
  - backend lưu `flow_events`
  - nếu bật `AUTO_BLOCK=true` thì `firewall_actions` tăng và iptables có rule tương ứng
