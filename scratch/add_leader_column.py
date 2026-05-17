import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db
with app.app_context():
    try:
        db.session.execute(db.text('ALTER TABLE team ADD COLUMN leader_id INTEGER REFERENCES "user"(id)'))
        db.session.commit()
        print("Successfully added 'leader_id' column to 'team' table referencing 'user'(id).")
    except Exception as e:
        db.session.rollback()
        print(f"Error adding column (it might already exist): {e}")
