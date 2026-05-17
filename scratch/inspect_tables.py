import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db
from sqlalchemy import inspect
with app.app_context():
    inspector = inspect(db.engine)
    target_tables = ['activity', 'meeting', 'note', 'daily_closing', 'encerramento', 'patio']
    for t in target_tables:
        if t in inspector.get_table_names():
            print(f"Table: {t}")
            for column in inspector.get_columns(t):
                print(f"  Column: {column['name']} ({column['type']})")
        else:
            print(f"Table: {t} NOT found")
