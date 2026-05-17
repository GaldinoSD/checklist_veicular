import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db
from sqlalchemy import inspect
with app.app_context():
    inspector = inspect(db.engine)
    t = 'scale'
    if t in inspector.get_table_names():
        print(f"Table: {t}")
        for column in inspector.get_columns(t):
            print(f"  Column: {column['name']} ({column['type']})")
