import os
import sys
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        try:
            # Check if column exists
            check_sql = text("SELECT column_name FROM information_schema.columns WHERE table_name='training_course' AND column_name='allow_retake'")
            result = db.session.execute(check_sql).fetchone()
            
            if not result:
                print("Adding 'allow_retake' column to 'training_course' table...")
                alter_sql = text("ALTER TABLE training_course ADD COLUMN allow_retake BOOLEAN DEFAULT FALSE")
                db.session.execute(alter_sql)
                db.session.commit()
                print("Column added successfully!")
            else:
                print("Column 'allow_retake' already exists.")
                
        except Exception as e:
            print(f"Error during migration: {e}")
            db.session.rollback()

if __name__ == "__main__":
    migrate()
