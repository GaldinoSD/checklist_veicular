import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, Scale, db
with app.app_context():
    scales = Scale.query.all()
    for s in scales:
        print(f"ID: {s.id}, Date: {s.date}, Type: {s.type}, Techs: {s.technician_ids}, Teams: {s.team_ids}")
