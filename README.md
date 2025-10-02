# Aegis-Lite: Final Release v3.0

## 🚀 Quick Start
```bash
# Development
pip install -e .
streamlit run aegis/ui.py

# Docker 
docker build -t aegis-lite .
docker run -p 8501:8501 aegis-lite

# CLI Usage
python -m aegis.cli scan example.com --ethical