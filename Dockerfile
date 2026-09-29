# RDRS - Ransomware Detection and Response System
FROM python:3.12-slim

WORKDIR /rdrs

# System deps: none required beyond what pip installs, but keep curl for
# container healthchecks / debugging.
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Folders RDRS writes to at runtime.
RUN mkdir -p logs data/sandbox data/quarantine data/reports

EXPOSE 8000

HEALTHCHECK --interval=15s --timeout=5s --start-period=5s --retries=3 \
    CMD curl -f http://127.0.0.1:8000/health || exit 1

CMD ["python", "-m", "app.main", "--auto-report"]
