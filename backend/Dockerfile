# Image Python nhẹ
FROM python:3.11-slim

# Không buffer log
ENV PYTHONUNBUFFERED=1

# Thư mục làm việc
WORKDIR /app

# Cài dependency
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r requirements.txt

# Copy code backend
COPY . .

# Expose port cho FastAPI
EXPOSE 8000

# Chạy Uvicorn để serve FastAPI app "app" trong main.py
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
