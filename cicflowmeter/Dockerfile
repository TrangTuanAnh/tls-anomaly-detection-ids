FROM python:3.12-slim


ENV PYTHONUNBUFFERED=1

# libpcap + build tools (một số bản cicflowmeter cần compile phụ thuộc)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install cicflowmeter (CICFlowMeter-like CLI)
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir cicflowmeter==0.4.2

COPY run.sh /app/run.sh
RUN chmod +x /app/run.sh

VOLUME ["/shared/flows"]

ENTRYPOINT ["/app/run.sh"]
