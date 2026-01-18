FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1

# NFStream needs libpcap (capture) and build deps.
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Keep dependencies minimal and explicit.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir --upgrade pip \
    && pip install --no-cache-dir -r /app/requirements.txt

COPY run.sh /app/run.sh
RUN sed -i 's/\r$//' /app/run.sh

COPY nfstream_sniffer.py /app/nfstream_sniffer.py

RUN chmod +x /app/run.sh

VOLUME ["/shared/flows"]

ENTRYPOINT ["/app/run.sh"]
