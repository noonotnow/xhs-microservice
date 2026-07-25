FROM python:3.12-slim

# Install system dependencies for Playwright/Chromium
RUN apt-get update && apt-get install -y \
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
    xdg-utils \
    libpango-1.0-0 \
    libcairo2 \
    libglib2.0-0 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Install Playwright browsers (Chromium only)
RUN playwright install chromium
RUN playwright install-deps chromium

# Download stealth.min.js (anti-detection)
RUN wget -O /app/stealth.min.js https://raw.githubusercontent.com/nicegram/nicegram-stealthkit/master/nicegram-stealthkit.min.js || \
    wget -O /app/stealth.min.js https://cdn.jsdelivr.net/gh/nicegram/nicegram-stealthkit@main/nicegram-stealthkit.min.js || \
    echo "// stealth fallback" > /app/stealth.min.js

# Copy application code
COPY main.py .
COPY sign_service.py .

# Create data and upload directories
RUN mkdir -p /app/data/uploads

# Expose port
EXPOSE 8000

# Run with uvicorn
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
