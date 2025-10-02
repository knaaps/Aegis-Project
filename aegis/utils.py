"""
Common utilities for Aegis-Lite
===============================
Shared functions and constants to eliminate redundancy
"""

import re
import json
from typing import Dict, Any

# Risk scoring constants
RISK_THRESHOLDS = {
    'critical': 70,
    'high': 50,
    'medium': 30,
    'low': 1
}

RISK_LABELS = {
    'critical': "🔴 Critical",
    'high': "🟠 High",
    'medium': "🟡 Medium",
    'low': "🟢 Low",
    'none': "⚪ None"
}

def validate_domain(domain: str) -> bool:
    """Single source of truth for domain validation"""
    if not domain or len(domain) > 253:
        return False
    # Improved regex to catch double dots and invalid patterns
    pattern = r'^(?!.*\.\.)([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    return bool(re.match(pattern, domain))

def validate_ip(ip: str) -> bool:
    """Check if IP format is valid"""
    if ip in ["Unknown", "TBD"]:
        return True
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        return all(0 <= int(part) <= 255 for part in parts)
    except (ValueError, AttributeError):
        return False

def get_risk_level(score: int) -> str:
    """Convert risk score to risk level label"""
    if score >= RISK_THRESHOLDS['critical']:
        return RISK_LABELS['critical']
    elif score >= RISK_THRESHOLDS['high']:
        return RISK_LABELS['high']
    elif score >= RISK_THRESHOLDS['medium']:
        return RISK_LABELS['medium']
    elif score >= RISK_THRESHOLDS['low']:
        return RISK_LABELS['low']
    else:
        return RISK_LABELS['none']

def safe_json_parse(json_str: str, default: dict = None) -> dict:
    """Safely parse JSON string with fallback"""
    if default is None:
        default = {}
    try:
        return json.loads(json_str) if json_str else default
    except (json.JSONDecodeError, TypeError):
        return default

def clean_input(user_input: str, max_length: int = 255) -> str:
    """Basic input cleaning and length limiting"""
    if not user_input:
        return ""
    # Remove dangerous characters and limit length
    cleaned = re.sub(r'[;&|`$()\\<>"\']', '', str(user_input)[:max_length])
    return cleaned.strip()
