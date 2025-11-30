# ANOMALY DETECTION IN TLS/SSH HANDSHAKES & CERTIFICATES

## MODULE TLS (SENSOR VM)

### Module Structure

```text
|- module-tls 
| |- dataset
| | |- feature_tls.csv -> dataset có được sau khi tiền xử lý feature của tls log 
| |- logs
| | |- eve.json -> log được suricata tách ra từ handshake capture được
| |- models -> lưu các modlel sau khi train
| | |- autoencoder_tls.h5 
| | |- isolation_forest_tls.pkl 
| | |- scaler_tls.pkl
| |- scripts
| | |- feature_engineering.py -> tiền xử lý dữ liệu
| | |- tls_capture.py -> tcpdump để bắt handshake khi duyệt web & suricata để tách log
| | |- train_ae.py -> train if
| | |- train_if.py -> train ae
| |- suricata.yaml -> cấu hình suricata dành cho module

*Note: traffic.pcap (130.6 MB) thu được khi duyệt web lưu ở drive
```
