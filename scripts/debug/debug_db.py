import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, db, User
with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"User {u.username}: permissions={u.permissions}")
