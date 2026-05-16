import psycopg2
import os
from dotenv import load_dotenv

load_dotenv()
db_url = os.getenv("DATABASE_URL")

def migrate():
    conn = psycopg2.connect(db_url)
    cur = conn.cursor()
    
    try:
        cur.execute("ALTER TABLE team ADD COLUMN IF NOT EXISTS rotation_order INTEGER DEFAULT 0")
        print("Added rotation_order to team")
    except Exception as e:
        print(f"Error adding rotation_order: {e}")
        conn.rollback()

    try:
        cur.execute("ALTER TABLE system_config ADD COLUMN IF NOT EXISTS scale_rotation_order VARCHAR(255)")
        print("Added scale_rotation_order to system_config")
    except Exception as e:
        print(f"Error adding scale_rotation_order: {e}")
        conn.rollback()

    conn.commit()
    cur.close()
    conn.close()

if __name__ == "__main__":
    migrate()
