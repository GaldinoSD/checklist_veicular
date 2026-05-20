import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, SystemRule, db
with app.app_context():
    rules = SystemRule.query.all()
    for r in rules:
        print(f"Slug: {r.slug}, Enabled: {r.is_enabled}")
