FROM jasonish/suricata:latest

COPY suricata.yaml /etc/suricata/suricata.yaml

RUN mkdir -p /var/log/suricata

CMD ["suricata", "-c", "/etc/suricata/suricata.yaml"]
