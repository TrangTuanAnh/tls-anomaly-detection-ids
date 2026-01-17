# ANOMALY DETECTION IN TLS/SSH HANDSHAKES & CERTIFICATES

## MODULE TLS (SENSOR VM)

### Module Structure

```text
|- module-tls 
| |- dataset
| | |- train.csv -> size: (6728, 16)
| | |- test.csv -> size: (176 (0) + 39 (1), 16) 
| |- logs
| | |- anomaly_test_eve.json
| | |- normal_test_eve.json
| | |- train_eve.json
| |- models 
| | |- autoencoder_tls.h5*
| | |- scaler.pkl*
| | - results
| | |- pilots -> picture
| |- scripts-> script tien xu li du lieu
| |- suricata.yaml 
| |- README.MD
| |- requirements.txt

*Note: 
- scaler.pkl: dua data ve dang 0-1 truoc khi dua vao model (bat buoc)
- autoencoder_tls.h5: model AE hoan thien (300 epochs)
```
