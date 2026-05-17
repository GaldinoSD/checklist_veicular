import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db
from sqlalchemy import inspect
with app.app_context():
    inspector = inspect(db.engine)
    cols = inspector.get_columns('team')
    print("Columns in 'team' table:")
    for c in cols:
        print(f"  {c['name']}: {c['type']}")
