import sys
import os
sys.path.append(os.getcwd())
from app import app, db
import sqlalchemy

def migrate():
    with app.app_context():
        columns = [
            ('responsible', 'VARCHAR(200)'),
            ('objective', 'TEXT'),
            ('summary', 'TEXT'),
            ('actions', 'TEXT')
        ]
        
        for col_name, col_type in columns:
            try:
                db.session.execute(sqlalchemy.text(f"ALTER TABLE meeting ADD COLUMN {col_name} {col_type}"))
                print(f"Added column {col_name}")
            except Exception as e:
                print(f"Column {col_name} might already exist or error: {e}")
        
        db.session.commit()
        print("Migration finished.")

if __name__ == "__main__":
    migrate()
