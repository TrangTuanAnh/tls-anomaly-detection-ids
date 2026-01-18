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
