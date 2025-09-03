"""
Enhanced Database Module for Aegis-Lite
========================================

Fixed version with proper error handling, connection management,
and consistent data retrieval including vulnerability data.
"""

import sqlite3
import os
import logging
import re
from typing import List, Dict, Any, Optional
from contextlib import contextmanager

# Set up logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Database configuration
DB_FILE_NAME = "aegis.db"
DB_FILE_PATH = os.path.join(os.getcwd(), DB_FILE_NAME)

def validate_domain(domain: str) -> bool:
    """Check if domain format is valid"""
    if not domain or len(domain) > 255:
        return False
    return bool(re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.-]*[a-zA-Z0-9]$', domain))

def validate_ip(ip: str) -> bool:
    """Check if IP format is valid"""
    if ip in ["Unknown", "TBD"]:
        return True
    try:
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            if not 0 <= int(part) <= 255:
                return False
        return True
    except (ValueError, AttributeError):
        return False

@contextmanager
def get_db_connection():
    """Context manager for database connections with proper cleanup"""
    conn = None
    try:
        conn = sqlite3.connect(DB_FILE_PATH)
        conn.row_factory = sqlite3.Row  # Enable column access by name
        yield conn
    except sqlite3.Error as e:
        if conn:
            conn.rollback()
        logger.error(f"Database error: {e}")
        raise
    finally:
        if conn:
            conn.close()

def init_db() -> None:
    """Initialize database with proper table structure"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Create the main assets table
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

            # Create index for faster lookups
            cursor.execute("""
                CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_domain
                ON assets (domain)
            """)

            conn.commit()
            logger.info("Database initialized successfully")

    except sqlite3.Error as e:
        logger.error(f"Failed to initialize database: {e}")
        raise

def insert_asset(domain: str, ip: str = "TBD", ports: str = "", score: int = 0,
                ssl_vulnerabilities: str = "{}", web_vulnerabilities: str = "{}") -> bool:
    """
    Insert or update asset in database with all vulnerability data
    """
    # Input validation
    if not validate_domain(domain):
        logger.error(f"Invalid domain format: {domain}")
        return False

    if not validate_ip(ip):
        logger.error(f"Invalid IP format: {ip}")
        return False

    # Ensure score is valid
    try:
        score = max(0, int(score))
    except (ValueError, TypeError):
        logger.warning(f"Invalid score: {score}, defaulting to 0")
        score = 0

    # Ensure JSON strings are valid
    if not ssl_vulnerabilities:
        ssl_vulnerabilities = "{}"
    if not web_vulnerabilities:
        web_vulnerabilities = "{}"

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Try insert first, update on conflict
            cursor.execute("""
                INSERT OR REPLACE INTO assets
                (domain, ip, ports, score, ssl_vulnerabilities, web_vulnerabilities, last_scanned)
                VALUES (?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
            """, (domain, ip, ports, score, ssl_vulnerabilities, web_vulnerabilities))

            conn.commit()
            logger.info(f"Asset {domain} saved successfully")
            return True

    except sqlite3.Error as e:
        logger.error(f"Failed to insert asset {domain}: {e}")
        return False

def get_all_assets() -> List[Dict[str, Any]]:
    """
    FIXED: Now retrieves ALL columns including vulnerability data
    """
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Select ALL columns including vulnerability data
            cursor.execute("""
                SELECT id, domain, ip, ports, score,
                       ssl_vulnerabilities, web_vulnerabilities, last_scanned
                FROM assets
                ORDER BY last_scanned DESC
            """)

            assets = [dict(row) for row in cursor.fetchall()]
            logger.info(f"Retrieved {len(assets)} assets from database")
            return assets

    except sqlite3.Error as e:
        logger.error(f"Failed to retrieve assets: {e}")
        return []

def get_asset_by_domain(domain: str) -> Optional[Dict[str, Any]]:
    """Get specific asset by domain with all data"""
    if not validate_domain(domain):
        logger.error(f"Invalid domain: {domain}")
        return None

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, domain, ip, ports, score,
                       ssl_vulnerabilities, web_vulnerabilities, last_scanned
                FROM assets
                WHERE domain = ?
            """, (domain,))

            row = cursor.fetchone()
            if row:
                return dict(row)
            return None

    except sqlite3.Error as e:
        logger.error(f"Failed to get asset {domain}: {e}")
        return None

def get_assets_by_score_range(min_score: int = 0, max_score: int = 100) -> List[Dict[str, Any]]:
    """Get assets within a specific risk score range"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, domain, ip, ports, score,
                       ssl_vulnerabilities, web_vulnerabilities, last_scanned
                FROM assets
                WHERE score BETWEEN ? AND ?
                ORDER BY score DESC, domain ASC
            """, (min_score, max_score))

            return [dict(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error(f"Failed to get assets by score range: {e}")
        return []

def delete_asset(domain: str) -> bool:
    """Delete a specific asset from database"""
    if not validate_domain(domain):
        return False

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("DELETE FROM assets WHERE domain = ?", (domain,))

            if cursor.rowcount > 0:
                conn.commit()
                logger.info(f"Deleted asset: {domain}")
                return True
            else:
                logger.warning(f"Asset not found: {domain}")
                return False

    except sqlite3.Error as e:
        logger.error(f"Failed to delete asset {domain}: {e}")
        return False

def clear_db() -> bool:
    """Delete entire database file"""
    try:
        if os.path.exists(DB_FILE_PATH):
            os.remove(DB_FILE_PATH)
            logger.info("Database file deleted successfully")
        else:
            logger.info("Database file doesn't exist")
        return True

    except OSError as e:
        logger.error(f"Failed to delete database: {e}")
        return False

def get_db_stats() -> Dict[str, Any]:
    """Get comprehensive database statistics"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            # Get basic stats
            cursor.execute("""
                SELECT
                    COUNT(*) as total_assets,
                    COALESCE(AVG(score), 0) as avg_score,
                    COALESCE(MAX(score), 0) as max_score,
                    COALESCE(MIN(score), 0) as min_score,
                    COUNT(CASE WHEN ports != '' AND ports IS NOT NULL THEN 1 END) as assets_with_ports,
                    COUNT(CASE WHEN score > 50 THEN 1 END) as high_risk_assets,
                    COUNT(CASE WHEN score BETWEEN 20 AND 50 THEN 1 END) as medium_risk_assets,
                    COUNT(CASE WHEN score < 20 THEN 1 END) as low_risk_assets
                FROM assets
            """)

            row = cursor.fetchone()
            if row:
                return {
                    'total_assets': row['total_assets'],
                    'avg_score': round(row['avg_score'], 2),
                    'max_score': row['max_score'],
                    'min_score': row['min_score'],
                    'assets_with_ports': row['assets_with_ports'],
                    'high_risk_assets': row['high_risk_assets'],
                    'medium_risk_assets': row['medium_risk_assets'],
                    'low_risk_assets': row['low_risk_assets']
                }
            else:
                return _empty_stats()

    except sqlite3.Error as e:
        logger.error(f"Failed to get database stats: {e}")
        return _empty_stats()

def _empty_stats() -> Dict[str, Any]:
    """Return empty statistics structure"""
    return {
        'total_assets': 0,
        'avg_score': 0,
        'max_score': 0,
        'min_score': 0,
        'assets_with_ports': 0,
        'high_risk_assets': 0,
        'medium_risk_assets': 0,
        'low_risk_assets': 0
    }

def update_asset_score(domain: str, new_score: int) -> bool:
    """Update only the score for an existing asset"""
    if not validate_domain(domain):
        return False

    try:
        new_score = max(0, int(new_score))
    except (ValueError, TypeError):
        return False

    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                UPDATE assets
                SET score = ?, last_scanned = CURRENT_TIMESTAMP
                WHERE domain = ?
            """, (new_score, domain))

            if cursor.rowcount > 0:
                conn.commit()
                return True
            return False

    except sqlite3.Error as e:
        logger.error(f"Failed to update score for {domain}: {e}")
        return False

def get_recent_assets(limit: int = 10) -> List[Dict[str, Any]]:
    """Get most recently scanned assets"""
    try:
        with get_db_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT id, domain, ip, ports, score,
                       ssl_vulnerabilities, web_vulnerabilities, last_scanned
                FROM assets
                ORDER BY last_scanned DESC
                LIMIT ?
            """, (limit,))

            return [dict(row) for row in cursor.fetchall()]

    except sqlite3.Error as e:
        logger.error(f"Failed to get recent assets: {e}")
        return []

def test_database():
    """Test database functionality"""
    print("Testing database functionality...")

    try:
        # Initialize database
        init_db()
        print("✓ Database initialization passed")

        # Test inserting an asset with all data
        success = insert_asset(
            "test.example.com",
            "192.168.1.1",
            "80,443",
            25,
            '{"has_ssl": true, "valid_cert": true}',
            '{"has_admin_panel": false}'
        )
        if success:
            print("✓ Insert test passed")
        else:
            print("✗ Insert test failed")
            return

        # Test retrieving assets
        assets = get_all_assets()
        if assets and len(assets) > 0:
            print(f"✓ Retrieve test passed - found {len(assets)} assets")

            # Check if vulnerability data is included
            asset = assets[0]
            if 'ssl_vulnerabilities' in asset and 'web_vulnerabilities' in asset:
                print("✓ Vulnerability data retrieval passed")
            else:
                print("✗ Vulnerability data missing")
        else:
            print("✗ Retrieve test failed")
            return

        # Test statistics
        stats = get_db_stats()
        print(f"✓ Stats test passed: {stats}")

        # Test specific domain retrieval
        asset = get_asset_by_domain("test.example.com")
        if asset:
            print(f"✓ Domain-specific retrieval passed")
        else:
            print("✗ Domain-specific retrieval failed")

        print("All database tests passed!")

    except Exception as e:
        print(f"✗ Database test failed: {e}")

if __name__ == "__main__":
    test_database()
