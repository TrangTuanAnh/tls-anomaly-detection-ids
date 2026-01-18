FROM python:3.11-slim

# Thiet lap thu muc lam viec mac dinh ben trong container
WORKDIR /app

# Sao chep danh sach thu vien va cai dat cac dependency can thiet cho AI (nhu TensorFlow, Scikit-learn)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Sao chep toan bo ma nguon va cac file mo hinh da huan luyen vao container
COPY . .

# Thiet lap duong dan den file CSV du lieu luu luong mang
ENV FLOW_CSV_PATH=/shared/flows/flows.csv

# Tat GPU de TensorFlow chi su dung CPU, phu hop voi moi truong Docker nhe
ENV CUDA_VISIBLE_DEVICES=-1

# Khai bao dia chi URL cua Backend FastAPI de gui ket qua phan tich
ENV BACKEND_URL=http://backend:8000

# Lenh khoi chay dich vu phan tich thoi gian thuc
CMD ["python", "main.py"]