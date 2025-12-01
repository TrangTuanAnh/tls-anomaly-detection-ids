# suricata/Dockerfile
FROM jasonish/suricata:latest

# Copy config của bạn vào
COPY suricata.yaml /etc/suricata/suricata.yaml

# Chạy ở chế độ PCAP, interface lấy từ config (pcap:any)
# --pcap: dùng cấu hình pcap trong suricata.yaml
ENV SURICATA_OPTIONS="--pcap"

# Không cần CMD ở đây, dùng ENTRYPOINT gốc
# ENTRYPOINT gốc sẽ gọi:
#   /usr/sbin/suricata -c /etc/suricata/suricata.yaml $SURICATA_OPTIONS "$@"
