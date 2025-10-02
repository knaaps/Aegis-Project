FROM python:3.10-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    nmap \
    && rm -rf /var/lib/apt/lists/*

# Copy application - FIXED PATHS
COPY requirements.txt .
COPY aegis/ ./aegis/
COPY tests/ ./tests/

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Set Python path
ENV PYTHONPATH=/app

# Default command - CLI interactive mode
CMD ["python", "-m", "aegis.cli", "interactive"]