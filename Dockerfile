FROM python:3.10-slim

WORKDIR /app

# Install system dependencies for scanning tools
RUN apt-get update && apt-get install -y \
    wget \
    curl \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Install Subfinder
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip

# Install Nuclei
RUN wget https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["python", "-m", "aegis.cli"]
