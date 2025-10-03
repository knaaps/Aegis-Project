FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    git \
    wget \
    && rm -rf /var/lib/apt/lists/*

# Install Go-based security tools
RUN wget https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.tar.gz \
    && tar -xzf subfinder_2.6.3_linux_amd64.tar.gz \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.tar.gz

# Copy application
COPY . .
COPY aegis/ ./aegis/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set Python path
ENV PYTHONPATH=/app

# Expose Streamlit port
EXPOSE 8501

# Default command - can run either CLI or UI
CMD ["python", "-m", "aegis.cli", "interactive"]