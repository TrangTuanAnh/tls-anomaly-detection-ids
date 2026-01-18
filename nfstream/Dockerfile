# Su dung Python 3.11 phien ban slim de container nhe va toi uu
FROM python:3.11-slim

# Dam bao log Python duoc in ra ngay lap tuc de de dang theo doi va debug
ENV PYTHONUNBUFFERED=1

# Cai dat libpcap-dev de ho tro bat goi tin mang va cac cong cu ho tro build
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Thiet lap thu muc lam viec cho module sniffer
WORKDIR /app

# Sao chep file requirements va cai dat cac thu vien Python can thiet
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

# Sao chep file script khoi chay va xu ly loi xuong dong neu soan thao tren Windows
COPY run.sh /app/run.sh
RUN sed -i 's/\r$//' /app/run.sh

# Sao chep file ma nguon chinh thuc hien viec thu thap du lieu mang
COPY nfstream_sniffer.py /app/nfstream_sniffer.py

# Cap quyen thuc thi cho file script de co the chay duoc trong Docker
RUN chmod +x /app/run.sh

# Khai bao volume de luu tru hoac chia se file du lieu flow voi container khac
VOLUME ["/shared/flows"]

# Thiet lap file script lam diem bat dau khi container khoi chay
ENTRYPOINT ["/app/run.sh"]