import sqlite3
import os

DB_PATH = 'database.db'

def migrate():
    if not os.path.exists(DB_PATH):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check for username column
    cursor.execute("PRAGMA table_info(users)")
    columns = [row[1] for row in cursor.fetchall()]
    
    if 'username' not in columns:
        print("Adding 'username' column to 'users'...")
        # SQLite doesn't allow adding UNIQUE columns via ALTER TABLE easily
        # We add it as TEXT, then we can enforce uniqueness in app logic or via indices
        cursor.execute("ALTER TABLE users ADD COLUMN username TEXT")
        conn.commit()
        
        # Update existing admin
        cursor.execute("UPDATE users SET username = 'admin' WHERE role = 'admin'")
        conn.commit()
    
    print("Database migration complete.")
    conn.close()

if __name__ == "__main__":
    migrate()
