import sys
import os
from datetime import datetime

# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, db, Vehicle, Checklist, generate_consolidated_report

with app.app_context():
    # Encontra o último veículo que tenha um checklist
    last_c = Checklist.query.order_by(Checklist.id.desc()).first()
    if not last_c:
        print("Nenhum checklist encontrado no banco.")
        sys.exit(1)
        
    v = Vehicle.query.get(last_c.vehicle_id)
    print(f"Testando para veículo: {v.plate} (ID: {v.id})")
    
    start = datetime(2020, 1, 1)
    end = datetime(2026, 12, 31)
    
    try:
        filename = generate_consolidated_report(v, start, end)
        print(f"Sucesso! Arquivo gerado: {filename}")
    except Exception as e:
        print(f"FALHA: {e}")
        import traceback
        traceback.print_exc()
