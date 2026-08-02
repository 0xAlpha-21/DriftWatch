import sqlite3

DB_NAME = "driftwatch.db"

def init_db():
    """Initializes SQLite database tables for snapshots and drift logs."""
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    
    # Table 1: Raw configuration snapshots
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS snapshots (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            resource_type TEXT NOT NULL,
            state_data TEXT NOT NULL
        )
    ''')
    
    # Table 2: Historical drift events
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS drift_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            resource_id TEXT NOT NULL,
            event_type TEXT NOT NULL,
            details TEXT NOT NULL,
            cis_control TEXT,
            iso_control TEXT
        )
    ''')
    
    conn.commit()
    conn.close()
    print("✅ Database initialized successfully: driftwatch.db")

if __name__ == "__main__":
    init_db()