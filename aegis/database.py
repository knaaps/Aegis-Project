"""
Simplified Database Module for Aegis-Lite
==========================================
Reduced from 400+ lines to ~150 lines while maintaining functionality
"""

import sqlite3
import os
import logging
from typing import List, Dict, Any, Optional
from .utils import validate_domain, validate_ip, RISK_THRESHOLDS

logger = logging.getLogger(__name__)

DB_FILE = "aegis.db"

def init_db() -> None:
    """Initialize database with proper table structure"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            cursor.execute("""
                CREATE TABLE IF NOT EXISTS assets (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    domain TEXT NOT NULL UNIQUE,
                    ip TEXT,
                    ports TEXT,
                    score INTEGER DEFAULT 0,
                    ssl_vulnerabilities TEXT DEFAULT '{}',
                    web_vulnerabilities TEXT DEFAULT '{}',
                    last_scanned TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)

            cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_domain ON assets (domain)")
            conn.commit()
            logger.info("Database initialized successfully")

    except sqlite3.Error as e:
        logger.error(f"Database initialization failed: {e}")
        raise

def save_asset(domain: str, ip: str = "TBD", ports: str = "", score: int = 0,
               ssl_vulnerabilities: str = "{}", web_vulnerabilities: str = "{}") -> bool:
    """Insert or update asset in database"""
    if not validate_domain(domain) or not validate_ip(ip):
        logger.error(f"Invalid input: domain={domain}, ip={ip}")
        return False

    try:
        score = max(0, min(100, int(score)))  # Clamp between 0-100
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO assets
                (domain, ip, ports, score, ssl_vulnerabilities, web_vulnerabilities, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (domain, ip, ports, score, ssl_vulnerabilities, web_vulnerabilities))
            conn.commit()
            logger.info(f"Asset {domain} saved successfully")
            return True

    except Exception as e:
        logger.error(f"Failed to save asset {domain}: {e}")
        return False

def get_assets(limit: int = None, min_score: int = None, max_score: int = None,
               order_by: str = "last_scanned DESC") -> List[Dict[str, Any]]:
    """Flexible asset retrieval with optional filters"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()

            query = "SELECT * FROM assets"
            params = []

            # Add score range filter if specified
            if min_score is not None or max_score is not None:
                min_score = min_score or 0
                max_score = max_score or 100
                query += " WHERE score BETWEEN ? AND ?"
                params.extend([min_score, max_score])

            query += f" ORDER BY {order_by}"

            if limit:
                query += " LIMIT ?"
                params.append(limit)

            cursor.execute(query, params)
            assets = [dict(row) for row in cursor.fetchall()]
            logger.info(f"Retrieved {len(assets)} assets")
            return assets

    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve assets: {e}")
        return []

def get_all_assets() -> List[Dict[str, Any]]:
    """Get all assets for backward compatibility"""
    return get_assets()

def get_asset_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Get specific asset by domain"""
    if not validate_domain(domain):
        return None

    try:
        with sqlite3.connect(DB_FILE) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM assets WHERE domain = ?", (domain,))
            row = cursor.fetchone()
            return dict(row) if row else None

    except sqlite3.Error as e:
        logger.error(f"Failed to get asset {domain}: {e}")
        return None

def get_db_stats() -> Dict[str, Any]:
    """Get database statistics with correct risk categorization"""
    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT
                    COUNT(*) as total_assets,
                    COALESCE(AVG(score), 0) as avg_score,
                    COUNT(CASE WHEN score >= ? THEN 1 END) as critical_risk_assets,
                    COUNT(CASE WHEN score >= ? AND score < ? THEN 1 END) as high_risk_assets,
                    COUNT(CASE WHEN score >= ? AND score < ? THEN 1 END) as medium_risk_assets,
                    COUNT(CASE WHEN score >= ? AND score < ? THEN 1 END) as low_risk_assets
                FROM assets
            """, (
                RISK_THRESHOLDS['critical'],
                RISK_THRESHOLDS['high'], RISK_THRESHOLDS['critical'],
                RISK_THRESHOLDS['medium'], RISK_THRESHOLDS['high'],
                RISK_THRESHOLDS['low'], RISK_THRESHOLDS['medium']
            ))

            row = cursor.fetchone()
            if row:
                return {
                    'total_assets': row[0],
                    'avg_score': round(row[1], 2),
                    'critical_risk_assets': row[2],
                    'high_risk_assets': row[3],
                    'medium_risk_assets': row[4],
                    'low_risk_assets': row[5]
                }
            else:
                return _empty_stats()

    except sqlite3.Error as e:
        logger.error(f"Failed to get stats: {e}")
        return _empty_stats()

def clear_db() -> bool:
    """Delete database file"""
    try:
        if os.path.exists(DB_FILE):
            os.remove(DB_FILE)
            logger.info("Database cleared successfully")
        return True
    except OSError as e:
        logger.error(f"Failed to clear database: {e}")
        return False

def delete_asset(domain: str) -> bool:
    """Delete specific asset"""
    if not validate_domain(domain):
        return False

    try:
        with sqlite3.connect(DB_FILE) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM assets WHERE domain = ?", (domain,))
            success = cursor.rowcount > 0
            conn.commit()
            if success:
                logger.info(f"Deleted asset: {domain}")
            return success

    except sqlite3.Error as e:
        logger.error(f"Failed to delete asset {domain}: {e}")
        return False

# Convenience functions for backward compatibility
def insert_asset(domain: str, **kwargs) -> bool:
    """Backward compatibility wrapper"""
    return save_asset(domain, **kwargs)

def get_recent_assets(limit: int = 10) -> List[Dict[str, Any]]:
    """Get recent assets"""
    return get_assets(limit=limit)

def get_critical_assets() -> List[Dict[str, Any]]:
    """Get critical risk assets"""
    return get_assets(min_score=RISK_THRESHOLDS['critical'])

def get_high_risk_assets() -> List[Dict[str, Any]]:
    """Get high risk assets"""
    return get_assets(min_score=RISK_THRESHOLDS['high'], max_score=RISK_THRESHOLDS['critical']-1)

def _empty_stats() -> Dict[str, Any]:
    """Return empty statistics"""
    return {
        'total_assets': 0, 'avg_score': 0, 'critical_risk_assets': 0,
        'high_risk_assets': 0, 'medium_risk_assets': 0, 'low_risk_assets': 0
    }
