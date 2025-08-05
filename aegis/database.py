import sqlite3
import os

# Define the database file name relative to the current working directory
# This ensures it's created in the project root by default when running CLI commands.
DB_FILE_NAME = "aegis.db"
DB_FILE_PATH = os.path.join(os.getcwd(), DB_FILE_NAME)

def connect_db():
    """Establishes a connection to the SQLite database."""
    # This will create the file if it doesn't exist at DB_FILE_PATH
    conn = sqlite3.connect(DB_FILE_PATH)
    conn.row_factory = sqlite3.Row # Allows accessing columns by name
    return conn

def init_db():
    """Initializes the database schema if tables don't exist."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS assets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL UNIQUE,
            ip TEXT,
            ports TEXT,
            score INTEGER DEFAULT 0,
            last_scanned TEXT DEFAULT CURRENT_TIMESTAMP
        )
    """)
    # Add an index for faster lookups on domain
    cursor.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_assets_domain ON assets (domain)")
    conn.commit()
    conn.close()

def insert_asset(domain, ip="TBD", ports=""):
    """Inserts or updates an asset in the database."""
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "INSERT INTO assets (domain, ip, ports) VALUES (?, ?, ?)",
            (domain, ip, ports)
        )
    except sqlite3.IntegrityError:
        # If domain already exists, update it
        cursor.execute(
            "UPDATE assets SET ip = ?, ports = ?, last_scanned = CURRENT_TIMESTAMP WHERE domain = ?",
            (ip, ports, domain)
        )
    conn.commit()
    conn.close()

def get_all_assets():
    """Retrieves all assets from the database."""
    conn = connect_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id, domain, ip, ports, score FROM assets")
    assets = cursor.fetchall()
    conn.close()
    return assets

# Optional: Function to clear the database for testing
def clear_db():
    if os.path.exists(DB_FILE_PATH):
        os.remove(DB_FILE_PATH)
