# Chon hinh anh co so la Python 3.11 phien ban rut gon de toi uu dung luong
FROM python:3.11-slim

# Cap nhat he thong va cai dat cac cong cu mang can thiet nhu iptables, conntrack
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        iptables \
        conntrack \
        iproute2 \
    && rm -rf /var/lib/apt/lists/*

# Thiet lap thu muc lam viec mac dinh ben trong container
WORKDIR /app

# Sao chep file danh sach thu vien vao container
COPY requirements.txt .

# Cai dat cac thu vien Python can thiet cho do an
RUN pip install --no-cache-dir -r requirements.txt

# Sao chep file ma nguon chinh cua ung dung vao thu muc lam viec
COPY main.py .

# Lenh de khoi chay ung dung Python khi container bat dau chay
CMD ["python", "main.py"]