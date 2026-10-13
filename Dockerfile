FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY proxmox_canary ./proxmox_canary

RUN useradd --system --uid 10001 canary \
    && mkdir -p /data /config \
    && chown canary /data
USER canary

ENV CANARY_CONFIG=/config/config.yaml \
    PYTHONUNBUFFERED=1

CMD ["python", "-m", "proxmox_canary"]
