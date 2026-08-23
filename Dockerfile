FROM python:3.11-slim-bookworm

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    wkhtmltopdf \
    nmap \
    git \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.2.0/nuclei_3.2.0_linux_amd64.zip && \
    unzip nuclei_3.2.0_linux_amd64.zip && \
    mv nuclei /usr/local/bin/ && \
    rm nuclei_3.2.0_linux_amd64.zip && \
    nuclei -update-templates

# Install testssl.sh (PCI Req 6.2: SSL/early-TLS auto-fail checks)
RUN git clone --depth 1 https://github.com/testssl/testssl.sh.git /opt/testssl && \
    ln -s /opt/testssl/testssl.sh /usr/local/bin/testssl.sh

# Set working directory
WORKDIR /app

# Copy requirements and install
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Playwright's browser binary is separate from the pip package -- this
# also pulls in the OS-level shared libraries Chromium needs (--with-deps),
# since the base image is slim and won't have them otherwise. Used by
# discovery.py for JS-redirect tracking and shallow crawling (§4.4).
RUN python -m playwright install --with-deps chromium

# Copy application code
COPY . .

# Set environment variables
ENV FLASK_APP=app.py
ENV FLASK_RUN_HOST=0.0.0.0
