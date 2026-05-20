import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, Team, User, db
with app.app_context():
    teams = Team.query.all()
    for t in teams:
        print(f"Team: {t.name} (ID: {t.id}), Members: {[m.username for m in t.members]}")
