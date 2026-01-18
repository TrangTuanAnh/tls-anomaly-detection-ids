# API Document (API.md)

Tài liệu này mô tả các API HTTP trong đồ án **Flow-based Anomaly Detection**.

Kiến trúc dịch vụ (theo `docker-compose.sensor.yml`):

- **python-real-time-service** (FastAPI, cổng `9000` trong Docker network): nhận flow realtime (`/flow`), trích xuất đặc trưng, chạy model (MLP + optional IsolationForest), rồi đẩy sự kiện sang backend.
- **backend** (FastAPI, cổng `8000` trong Docker network): lưu **flow event** + **đặc trưng theo feature contract (đã làm sạch đủ 34 feature)** + **kết quả ML** vào MySQL; (tuỳ chọn) ghi intent chặn IP vào `firewall_actions`.

> Cả hai service đều là FastAPI nên có OpenAPI tại `/docs` và `/openapi.json`.

---

## 1) Base URL

Tuỳ cách deploy:

- **Trong Docker network (mặc định compose):**
  - Realtime service: `http://python-realtime:9000` (service name: `python-realtime` / container: `flow-rt`)
  - Backend: `http://backend:8000` (service name: `backend` / container: `flow-backend`)

- **Nếu publish ra host** (tuỳ cấu hình `ports:`):
  - Ví dụ: `http://localhost:9000`, `http://localhost:8000`

---

## 2) Quy ước chung

### Content-Type
- Request/Response dùng JSON.
- Client nên gửi header: `Content-Type: application/json`.

### Định dạng thời gian
- `event_time` nhận **ISO 8601** (VD: `2026-01-18T07:00:00Z`).
- Nếu không có timezone (`tzinfo`), backend sẽ coi là UTC.

### Lỗi (error response)
FastAPI thường trả:

```json
{ "detail": "..." }
```

Các mã lỗi hay gặp:
- `400`: payload sai định dạng
- `401`: thiếu/sai chữ ký HMAC (nếu bật)
- `500`: cấu hình HMAC lỗi (bật `REQUIRE_INGEST_HMAC=true` nhưng thiếu `INGEST_HMAC_SECRET`)
- `422`: sai schema (thiếu field bắt buộc, kiểu dữ liệu sai, có extra field ở **top-level** đối với backend)
- `503`: realtime service chưa sẵn sàng

---

## 3) Bảo mật ingest (tuỳ chọn): HMAC + anti-replay

Backend hỗ trợ **bảo vệ dữ liệu ingest** qua 3 header:

- `X-Timestamp`: Unix epoch seconds (string)
- `X-Nonce`: chuỗi ngẫu nhiên (string)
- `X-Signature`: HMAC-SHA256 hex digest

### Điều kiện kích hoạt
- Bật xác thực tại backend bằng env: `REQUIRE_INGEST_HMAC=true`
- Cấu hình secret: `INGEST_HMAC_SECRET=<secret>`

Giới hạn thời gian và nonce:
- `INGEST_HMAC_MAX_AGE_SEC` (mặc định `120` giây): timestamp lệch quá mức này sẽ bị từ chối.
- `NONCE_TTL_SEC` (mặc định `300` giây): nonce được lưu vào DB để chống replay.

### Chuỗi ký (string-to-sign)
Backend và realtime service đều dùng cùng chuẩn:

```
string_to_sign = "{ts}.{nonce}.{body_json_canonical}"
HMAC_SHA256(secret, string_to_sign)
```

Trong code hiện tại, `body_json_canonical` là bytes JSON **đã sort keys và không có whitespace** (Python):

```python
body = json.dumps(payload, separators=(",",":"), sort_keys=True, ensure_ascii=False).encode("utf-8")
mac = hmac.new(secret.encode("utf-8"), digestmod=hashlib.sha256)
mac.update(ts.encode("utf-8"))
mac.update(b".")
mac.update(nonce.encode("utf-8"))
mac.update(b".")
mac.update(body)
sig = mac.hexdigest()
```

> Lưu ý: nếu tự build client, hãy đảm bảo JSON canonical giống hệt (sort_keys + separators) để chữ ký khớp.

---

## 4) Feature contract (bắt buộc, cố định)

Hệ thống **khóa cứng** vào đúng tập đặc trưng CIC-style (34 feature) và đúng tên key.

- Backend sẽ **drop key thừa** và **fill key thiếu = 0.0** trong `features_json`.
- Thứ tự feature quan trọng cho model; key name phải đúng.

Danh sách feature (đúng tên):

1. `Packet Length Std`
2. `Total Length of Bwd Packets`
3. `Subflow Bwd Bytes`
4. `Destination Port`
5. `Packet Length Variance`
6. `Bwd Packet Length Mean`
7. `Avg Bwd Segment Size`
8. `Bwd Packet Length Max`
9. `Init_Win_bytes_backward`
10. `Total Length of Fwd Packets`
11. `Subflow Fwd Bytes`
12. `Init_Win_bytes_forward`
13. `Average Packet Size`
14. `Packet Length Mean`
15. `Max Packet Length`
16. `Fwd Packet Length Max`
17. `Flow IAT Max`
18. `Bwd Header Length`
19. `Flow Duration`
20. `Fwd IAT Max`
21. `Fwd Header Length`
22. `Fwd IAT Total`
23. `Fwd IAT Mean`
24. `Flow IAT Mean`
25. `Flow Bytes/s`
26. `Bwd Packet Length Std`
27. `Subflow Bwd Packets`
28. `Total Backward Packets`
29. `Fwd Packet Length Mean`
30. `Avg Fwd Segment Size`
31. `Bwd Packet Length Min`
32. `Flow Packets/s`
33. `Fwd Packets/s`
34. `Bwd Packets/s`

---

## 5) Backend API (Flow IDS Backend)

### 5.1 GET `/health`
Kiểm tra backend còn sống.

**Request**
- Không có body.

**Response 200**
```json
{ "status": "ok" }
```

---

### 5.2 POST `/api/events`
Ingest một flow event đã có kết quả ML (thường được gọi từ realtime service).

**Headers (tuỳ chọn nếu bật HMAC):**
- `X-Timestamp`, `X-Nonce`, `X-Signature`

**Body (JSON) – FlowEventIn**
| Field | Type | Bắt buộc | Mô tả |
|---|---:|:---:|---|
| `event_time` | string (datetime ISO8601) | có | Thời gian flow bắt đầu / timestamp |
| `sensor_name` | string \| null |  | Tên sensor (tuỳ chọn) |
| `flow_id` | integer \| null |  | ID flow (tuỳ chọn) |
| `src_ip` | string | có | IP nguồn |
| `src_port` | integer \| null |  | Port nguồn |
| `dst_ip` | string | có | IP đích |
| `dst_port` | integer \| null |  | Port đích |
| `proto` | string \| null |  | Protocol (vd: `TCP`, `UDP`, `6`, `17`...) |
| `features_json` | object | có | Dict 34 feature theo **feature contract** |
| `mlp_score` | number \| null |  | Sigmoid score (0..1) |
| `mlp_anom` | boolean \| null |  | Kết luận theo MLP threshold |
| `iso_score` | number \| null |  | Decision function score (optional) |
| `iso_anom` | boolean \| null |  | Kết luận theo IsolationForest (optional) |
| `is_anomaly` | boolean \| null |  | Kết luận cuối cùng |
| `verdict` | string \| null |  | Nếu không truyền, backend tự set `normal`/`anomaly` theo `is_anomaly` |

> Lưu ý schema backend đang `extra="forbid"` ở top-level: **không được gửi thêm field lạ** ngoài danh sách trên.

**Response 200 – FlowEventOut**
Trả về object vừa insert, thêm:
- `id`: integer
- `created_at`: datetime

**Ví dụ request**

```bash
curl -X POST "http://localhost:8000/api/events" \
  -H "Content-Type: application/json" \
  -d '
{
  "event_time": "2026-01-18T07:00:00Z",
  "sensor_name": "sensor-1",
  "flow_id": 123,
  "src_ip": "10.0.0.5",
  "src_port": 51512,
  "dst_ip": "10.0.0.10",
  "dst_port": 443,
  "proto": "TCP",
  "mlp_score": 0.87,
  "mlp_anom": true,
  "iso_score": -0.2,
  "iso_anom": true,
  "is_anomaly": true,
  "features_json": {
    "Packet Length Std": 12.3,
    "Total Length of Bwd Packets": 456,
    "Subflow Bwd Bytes": 456,
    "Destination Port": 443,
    "Packet Length Variance": 151.2,
    "Bwd Packet Length Mean": 98.2,
    "Avg Bwd Segment Size": 98.2,
    "Bwd Packet Length Max": 1514,
    "Init_Win_bytes_backward": 1024,
    "Total Length of Fwd Packets": 789,
    "Subflow Fwd Bytes": 789,
    "Init_Win_bytes_forward": 2048,
    "Average Packet Size": 123.4,
    "Packet Length Mean": 111.1,
    "Max Packet Length": 1514,
    "Fwd Packet Length Max": 1514,
    "Flow IAT Max": 100000,
    "Bwd Header Length": 800,
    "Flow Duration": 5000000,
    "Fwd IAT Max": 90000,
    "Fwd Header Length": 600,
    "Fwd IAT Total": 300000,
    "Fwd IAT Mean": 75000,
    "Flow IAT Mean": 80000,
    "Flow Bytes/s": 1200.5,
    "Bwd Packet Length Std": 10.1,
    "Subflow Bwd Packets": 5,
    "Total Backward Packets": 5,
    "Fwd Packet Length Mean": 120.0,
    "Avg Fwd Segment Size": 120.0,
    "Bwd Packet Length Min": 0,
    "Flow Packets/s": 30.0,
    "Fwd Packets/s": 20.0,
    "Bwd Packets/s": 10.0
  }
}
'
```

**Status codes**
- `200`: OK
- `401`: HMAC fail (nếu bật)
- `422`: sai schema / thiếu field

---

### 5.3 GET `/api/events`
Lấy danh sách flow event (mới nhất trước).

**Query params**
| Param | Type | Default | Mô tả |
|---|---:|---:|---|
| `only_anomaly` | boolean | `false` | Lọc chỉ event có `is_anomaly=true` |
| `limit` | integer | `100` | Số bản ghi trả về (1..2000) |

**Response 200**
Danh sách `FlowEventOut[]`.

**Ví dụ**
```bash
curl "http://localhost:8000/api/events?only_anomaly=true&limit=50"
```

---

## 6) Realtime Service API (Flow Realtime Service)

Realtime service nhận flow thô (CICFlowMeter / NFStream-mapped), trích xuất 34 feature chuẩn, chạy model và gửi sang backend.

### 6.1 GET `/health`

**Response 200**
```json
{
  "status": "ok",
  "ingest_mode": "url",
  "queue_size": 12
}
```

- `ingest_mode`: `csv` / `url` / `both`
- `queue_size`: số item đang chờ xử lý (nếu service đã bootstrap)

---

### 6.2 POST `/flow`
Nhận flow realtime.

**Body**
- Có thể là **1 object** hoặc **mảng object**.
- Mỗi object là một “flow record” kiểu CICFlowMeter JSON.

Realtime service sẽ cố gắng đọc các field meta sau (không bắt buộc đủ hết):
- Timestamp: một trong các key: `Timestamp`, `Flow Start Time`, `Start Time`, `time`, `Time`
- IP/Port:
  - Source: `Source IP`/`Src IP`/`src_ip`/`src`, `Source Port`/`Src Port`/`src_port`
  - Destination: `Destination IP`/`Dst IP`/`dest_ip`/`dst`, `Destination Port`/`Dst Port`/`dest_port`
- Protocol: `Protocol`/`proto`
- Feature columns: theo **feature contract** (có một số alias phổ biến như `Dst Port`, `TotLen Fwd Pkts`, ...)

**Response 200**
```json
{ "ok": true, "accepted": 1, "dropped": 0 }
```

- `accepted`: số flow được enqueue thành công
- `dropped`: số flow bị bỏ (payload không phải dict hoặc queue full)

**Status codes**
- `200`: OK
- `400`: payload không phải object/list
- `503`: service chưa sẵn sàng (chưa load model / chưa bootstrap)

**Ví dụ gửi 1 flow**

```bash
curl -X POST "http://localhost:9000/flow" \
  -H "Content-Type: application/json" \
  -d '
{
  "Timestamp": "2026-01-18 07:00:00",
  "Source IP": "10.0.0.5",
  "Source Port": 51512,
  "Destination IP": "10.0.0.10",
  "Destination Port": 443,
  "Protocol": "TCP",

  "Packet Length Std": 12.3,
  "Total Length of Bwd Packets": 456,
  "Subflow Bwd Bytes": 456,
  "Packet Length Variance": 151.2,
  "Bwd Packet Length Mean": 98.2,
  "Avg Bwd Segment Size": 98.2,
  "Bwd Packet Length Max": 1514,
  "Init_Win_bytes_backward": 1024,
  "Total Length of Fwd Packets": 789,
  "Subflow Fwd Bytes": 789,
  "Init_Win_bytes_forward": 2048,
  "Average Packet Size": 123.4,
  "Packet Length Mean": 111.1,
  "Max Packet Length": 1514,
  "Fwd Packet Length Max": 1514,
  "Flow IAT Max": 100000,
  "Bwd Header Length": 800,
  "Flow Duration": 5000000,
  "Fwd IAT Max": 90000,
  "Fwd Header Length": 600,
  "Fwd IAT Total": 300000,
  "Fwd IAT Mean": 75000,
  "Flow IAT Mean": 80000,
  "Flow Bytes/s": 1200.5,
  "Bwd Packet Length Std": 10.1,
  "Subflow Bwd Packets": 5,
  "Total Backward Packets": 5,
  "Fwd Packet Length Mean": 120.0,
  "Avg Fwd Segment Size": 120.0,
  "Bwd Packet Length Min": 0,
  "Flow Packets/s": 30.0,
  "Fwd Packets/s": 20.0,
  "Bwd Packets/s": 10.0
}
'
```

---

## 7) Ghi chú về IPS / Firewall (không có HTTP API)

- Backend có tuỳ chọn `AUTO_BLOCK=true`: nếu event được đánh dấu `is_anomaly=true` thì backend sẽ ghi thêm một dòng vào bảng `firewall_actions` (MySQL).
- `firewall-controller` sẽ **poll** bảng `firewall_actions` và áp rule iptables (`BLOCK`/`UNBLOCK`).

Điều này là luồng nội bộ qua DB, không phải REST API.

---

## 8) Tài liệu tham chiếu trong source

- Backend endpoints + schema: `backend/main.py`
- Realtime endpoints + ML scoring: `python-real-time-service/main.py`
- Feature contract + alias: `python-real-time-service/feature_extractor.py`
- NFStream sniffer (map -> CIC feature): `nfstream/nfstream_sniffer.py`

