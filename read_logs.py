from app import app, Log, Checklist
with app.app_context():
    print("Últimos Logs:")
    logs = Log.query.order_by(Log.id.desc()).limit(10).all()
    for l in logs:
        print(f"{l.data_hora}: {l.usuario} - {l.acao}")
    
    print("\nCheck KM em checklists recentes:")
    checklists = Checklist.query.order_by(Checklist.id.desc()).limit(10).all()
    for c in checklists:
        print(f"ID: {c.id}, KM: {c.km}, Vehicle: {c.vehicle_id}")
