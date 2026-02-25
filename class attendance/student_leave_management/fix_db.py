import sqlite3
import os

DB_PATH = 'database.db'

def fix_db():
    if not os.path.exists(DB_PATH):
        print("Database not found.")
        return

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    
    # Check schema
    cursor.execute("PRAGMA table_info(leave_requests)")
    columns = [row[1] for row in cursor.fetchall()]
    
    print(f"Current columns in 'leave_requests': {columns}")
    
    if 'category' not in columns:
        print("Adding 'category' column...")
        try:
            cursor.execute("ALTER TABLE leave_requests ADD COLUMN category TEXT")
            conn.commit()
            print("Column added successfully.")
        except Exception as e:
            print(f"Error adding column: {e}")
    else:
        print("'category' column already exists.")
        
    conn.close()

if __name__ == "__main__":
    fix_db()
