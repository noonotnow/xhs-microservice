FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wget \
    ca-certificates \
    fonts-liberation \
    libasound2 \
    libatk-bridge2.0-0 \
    libatk1.0-0 \
    libcups2 \
    libdbus-1-3 \
    libdrm2 \
    libgbm1 \
    libgtk-3-0 \
    libnspr4 \
    libnss3 \
    libx11-xcb1 \
    libxcomposite1 \
    libxdamage1 \
    libxrandr2 \
    libxshmfence1 \
    xdg-utils \
    libpango-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Chromium only (no install-deps needed, we handled it above)
RUN playwright install chromium

# Download stealth.min.js
RUN wget -q -O /app/stealth.min.js \
    https://raw.githubusercontent.com/nicegram/nicegram-stealthkit/master/nicegram-stealthkit.min.js || \
    echo "// stealth fallback" > /app/stealth.min.js

COPY main.py .
COPY sign_service.py .

RUN mkdir -p /app/data/uploads

EXPOSE 8000

CMD sh -c "uvicorn main:app --host 0.0.0.0 --port ${PORT:-8000}"
