# trained_models

Thư mục này phải chứa **artifact inference** đúng với bộ feature flow (CICFlowMeter) trong:
- `python-real-time-service/feature_extractor.py` (34 features, đúng thứ tự)

## Bạn cần đặt vào đây
- `autoencoder.h5`  (Keras model, input_dim = 34)
- `scaler.pkl`      (scikit-learn scaler đã fit trên 34 features theo đúng thứ tự)

Tuỳ chọn:
- `isolation_forest.pkl`

## Lưu ý
Repo cũ có các file TLS legacy (không dùng cho flow):
- `legacy_autoencoder_tls.h5`
- `legacy_scaler_tls.pkl`

Nếu muốn chạy legacy, hãy set env:
- `AE_MODEL_PATH=/app/trained_models/legacy_autoencoder_tls.h5`
- `SCALER_PATH=/app/trained_models/legacy_scaler_tls.pkl`
(Đồng thời phải đổi feature extractor sang TLS features tương ứng.)
