import sys
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db, Team
with app.app_context():
    teams = Team.query.all()
    print(f"Total teams found: {len(teams)}")
    for t in teams:
        print(f"Team ID: {t.id}, Name: {t.name}, Color: {t.color}, Obs: {t.obs}")
        print(f"  Members: {[m.username for m in t.members]}")
