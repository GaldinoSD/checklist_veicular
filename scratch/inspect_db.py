import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db
from sqlalchemy import inspect
with app.app_context():
    inspector = inspect(db.engine)
    print("ALL TABLES IN DB:")
    for t in sorted(inspector.get_table_names()):
        print(f" - {t}")
