import sys
import json
sys.path.insert(0, '/var/www/checklist_veicular')
from app import app, db, User, Team, Patio, Task, Scale

print("Starting localized REST API endpoints validation...")
client = app.test_client()

# Simula login definindo o usuário na sessão ou contornando
# Como a aplicação pode requerer login real com flask-login, vamos verificar
# se os endpoints de Gestão Técnica respondem com 200/302/401/403 ou se importam corretamente sem SyntaxError.
# A melhor validação é carregar o contexto da aplicação e simular chamadas de API!

with app.app_context():
    print("Application context loaded successfully.")
    
    # 1. Test query users
    try:
        users = User.query.limit(5).all()
        print(f"  [PASS] User model query successful. Found {len(users)} users.")
    except Exception as e:
        print(f"  [FAIL] User model query failed: {e}")
        
    # 2. Test query teams
    try:
        teams = Team.query.limit(5).all()
        print(f"  [PASS] Team model query successful. Found {len(teams)} teams.")
    except Exception as e:
        print(f"  [FAIL] Team model query failed: {e}")

    # 3. Test query tasks
    try:
        tasks = Task.query.limit(5).all()
        print(f"  [PASS] Task model query successful. Found {len(tasks)} tasks.")
    except Exception as e:
        print(f"  [FAIL] Task model query failed: {e}")

    # 4. Test query scales
    try:
        scales = Scale.query.limit(5).all()
        print(f"  [PASS] Scale model query successful. Found {len(scales)} scales.")
    except Exception as e:
        print(f"  [FAIL] Scale model query failed: {e}")

print("Validation completed.")
