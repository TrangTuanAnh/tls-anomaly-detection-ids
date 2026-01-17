<<<<<<< HEAD
# Training (Supervised MLP) for Flow IDS

Thư mục này dùng để **train mô hình MLP phân loại (benign = 0, anomaly = 1)** trên feature-set kiểu CICFlowMeter.

## Feature contract (bắt buộc)
- Dùng **đúng thứ tự 34 features** (khớp với:
  - `python-real-time-service/feature_extractor.py` (`FEATURES`)
  - `backend/main.py` (`FEATURE_NAMES`)
)

## Dataset
- `dataset/supervised_train.csv`
- `dataset/supervised_test.csv`

Yêu cầu:
- Có cột `y` (0/1)
- Có cột `Label` (để thống kê theo loại tấn công – tuỳ dataset)

## Train
```bash
python scripts/mlp_training.py
```
Output:
- `models/mlp.h5`
- `models/scaler.pkl`
- `models/scaler_params.json` (portable – tránh phụ thuộc pickle version)

## Evaluate
```bash
# Có thể override threshold bằng env var
MLP_THRESHOLD=0.5 python scripts/evaluate.py
```
Output:
- `results/metrics.json`
- `results/plots/*` (score distribution, ROC curve, confusion matrix)

## Deploy
Copy 2 file sau sang `python-real-time-service/trained_models/`:
- `mlp.h5`
- `scaler.pkl` (hoặc dùng `scaler_params.json` nếu muốn tránh pickle)
=======
# Anomaly Detection in Network Traffic using MLP (CICIDS-2017)

Phần này tập trung vào việc xây dựng hệ thống phát hiện bất thường trong lưu lượng mạng bằng mô hình **Multi-Layer Perceptron (MLP)**. Hệ thống được huấn luyện và đánh giá trên bộ dữ liệu **CICIDS-2017** với mục tiêu tối ưu hóa khả năng nhận diện các cuộc tấn công đã biết và đánh giá tính bền vững trước các mối đe dọa chưa xác định.

## 1. Cơ sở Nghiên cứu
Dự án được triển khai dựa trên sự kết hợp từ hai nghiên cứu khoa học tiêu biểu:
* **Feature Selection:** Sử dụng phương pháp **Information Gain (IG)** [[1]](#ref1) để xếp hạng và trích xuất các đặc trưng quan trọng nhất. Cụ thể, dự án sử dụng nhóm **35 đặc trưng** có trọng số $> 0.3$ để giảm chiều dữ liệu và tăng tốc độ tính toán.
* **Model Evaluation:** Áp dụng kịch bản huấn luyện và đánh giá **Robust Anomaly Detection** [[2]](#ref2) để so sánh khả năng nhận diện giữa các cuộc tấn công quen thuộc (Known Attacks) và tấn công mới (Unknown Attacks).

---

## 2. Cấu trúc Thư mục (Project Structure)
```text
|- ml_for_tls/
|  |- dataset/           # Chứa file CSV gốc và các tập dữ liệu sau khi xử lý
|  |- models/            # Lưu trữ model (.h5) và bộ chuẩn hóa (.pkl)
|  |- results/           # Lưu kết quả metrics (JSON) và các biểu đồ (Plots)
|  |- scripts/
|  |  |- dataset_filter.py  # Lọc, làm sạch nhãn và xử lý giá trị Inf/NaN
|  |  |- build_set.py      # Chia tập dữ liệu 80/20 & tách Unknown Attacks
|  |  |- mlp_training.py    # Huấn luyện mô hình MLP (100-50-1)
|  |  |- eval.py            # Đánh giá chi tiết (Overall & Per-label)
|- README.md
|- requirements.txt

```
---

## 3. Quy trình triển khai (Pipeline)
Quy trình thực hiện bao gồm 4 giai đoạn chính:

<img width="2258" height="1215" alt="models_nt219" src="https://github.com/user-attachments/assets/0057d029-163a-4dcd-937b-46d30a75610b" />


1. Data Preprocessing: Hợp nhất các file PCAP-CSV, chuẩn hóa tên cột và nhãn. Thực hiện xử lý các giá trị thiếu hoặc vô hạn để đảm bảo tính toàn vẹn dữ liệu. Kết quả thu được benign.csv (2 253 985) và attack.csv (557 646).
2. Dataset building:
- Trích xuất 35 đặc trưng có **IG > 0,3** dựa trên bảng xếp hạng **Information Gain** [[1]](#ref1).
- Chia dataset [[2]](#ref2):
• train.csv: 80% benign + 80% known attack.
• test.csv: 20% benign + 20% known attack + 100% unknown attack (Bot, DoS slowloris, DoS Slowhttptest).
3. Model Training:
- StandardScaler ──> scaler.pkl
- Xây dựng mạng MLP [[2]](#ref2) với:
• Dense(100) + ReLU        
• Dense(50)  + ReLU         
• Dense(1)   + Sigmoid      
• Loss: BCE                 
• Optimizer: Adam 
5. Evaluating: Tính toán các chỉ số TPR (Recall), FPR, ROC-AUC và vẽ Confusion Matrix để phân tích hiệu năng mô hình.
  
---

## Research References:

<a name="ref1"></a>**[1]** Kurniabudi et al. (2020). CICIDS-2017 Dataset Feature Analysis with Information Gain for Anomaly Detection.  
<a name="ref2"></a>**[2]** Xu & Liu (2025). Robust Anomaly Detection in Network Traffic: Evaluating Machine Learning Models on CICIDS2017.
>>>>>>> af9282824f817095d5681a1634a8f084c8b6951e
