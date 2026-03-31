# Varaksha Python Bridge — FastAPI service
# Exposes: /v1/tx, /v1/stream, /v1/open-banking/stream
# Deploy on Railway with root directory: services/open_banking

FROM python:3.12-slim-bookworm

WORKDIR /app

# Install dependencies first (layer cache)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy service source
COPY . .

# Runtime environment (override via Railway dashboard)
ENV PORT=8000
ENV LOG_LEVEL=INFO
ENV RUST_GATEWAY_URL=http://localhost:8080
ENV PLAID_ENV=sandbox

EXPOSE 8000

HEALTHCHECK --interval=20s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import httpx; httpx.get('http://localhost:8000/health', timeout=4).raise_for_status()"

CMD ["python", "feed_bridge.py"]
