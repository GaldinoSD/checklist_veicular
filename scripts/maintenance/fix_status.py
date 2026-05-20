import json
import sys
import os

# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, db, Checklist

def fix_checklists():
    with app.app_context():
        checklists = Checklist.query.all()
        count = 0
        for c in checklists:
            if c.raw_json:
                try:
                    data = json.loads(c.raw_json)
                    items = data.get("items", {})
                    has_just = False
                    for key, val in items.items():
                        just = val.get("justificativa", "")
                        if just and str(just).strip() != "":
                            has_just = True
                            break
                    
                    if has_just and c.status == "OK":
                        c.status = "Com Avaria"
                        count += 1
                except Exception as e:
                    print(f"Erro no checklist {c.id}: {e}")
        
        db.session.commit()
        print(f"Status atualizado em {count} checklists.")

if __name__ == '__main__':
    fix_checklists()
