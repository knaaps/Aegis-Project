# Aegis-Lite Dockerfile - Simplified Version
# Student-friendly container with essential tools only

FROM python:3.10-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    wget \
    unzip \
    nmap \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install security scanning tools
# Subfinder for subdomain discovery
RUN wget -q https://github.com/projectdiscovery/subfinder/releases/download/v2.6.3/subfinder_2.6.3_linux_amd64.zip \
    && unzip -q subfinder_2.6.3_linux_amd64.zip \
    && mv subfinder /usr/local/bin/ \
    && rm subfinder_2.6.3_linux_amd64.zip \
    && chmod +x /usr/local/bin/subfinder

# Nuclei for vulnerability scanning
RUN wget -q https://github.com/projectdiscovery/nuclei/releases/download/v3.1.0/nuclei_3.1.0_linux_amd64.zip \
    && unzip -q nuclei_3.1.0_linux_amd64.zip \
    && mv nuclei /usr/local/bin/ \
    && rm nuclei_3.1.0_linux_amd64.zip \
    && chmod +x /usr/local/bin/nuclei

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY aegis/ ./aegis/
COPY tests/ ./tests/

# Create necessary directories
RUN mkdir -p /app/data

# Set environment variables
ENV PYTHONPATH=/app
ENV AEGIS_DB_PATH=/app/data/aegis.db

# Expose Streamlit port
EXPOSE 8501

# Create a simple startup script
RUN echo '#!/bin/bash' > /app/start.sh && \
    echo 'echo "Aegis-Lite Container Started"' >> /app/start.sh && \
    echo 'echo "Available commands:"' >> /app/start.sh && \
    echo 'echo "  CLI: python -m aegis.cli --help"' >> /app/start.sh && \
    echo 'echo "  UI:  streamlit run aegis/ui.py --server.port 8501 --server.address 0.0.0.0"' >> /app/start.sh && \
    echo 'echo ""' >> /app/start.sh && \
    echo 'if [ "$1" = "ui" ]; then' >> /app/start.sh && \
    echo '    echo "Starting Streamlit UI..."' >> /app/start.sh && \
    echo '    streamlit run aegis/ui.py --server.port 8501 --server.address 0.0.0.0' >> /app/start.sh && \
    echo 'elif [ "$1" = "cli" ]; then' >> /app/start.sh && \
    echo '    shift' >> /app/start.sh && \
    echo '    python -m aegis.cli "$@"' >> /app/start.sh && \
    echo 'else' >> /app/start.sh && \
    echo '    echo "Usage:"' >> /app/start.sh && \
    echo '    echo "  docker run aegis-lite ui                    # Start web interface"' >> /app/start.sh && \
    echo '    echo "  docker run aegis-lite cli scan example.com # Run CLI scan"' >> /app/start.sh && \
    echo '    echo "  docker run aegis-lite cli --help           # Show CLI help"' >> /app/start.sh && \
    echo 'fi' >> /app/start.sh && \
    chmod +x /app/start.sh

# Default command shows usage
CMD ["/app/start.sh"]

# Build instructions (add to README):
# docker build -t aegis-lite .
# docker run -p 8501:8501 aegis-lite ui
# docker run aegis-lite cli scan example.com --ethical
