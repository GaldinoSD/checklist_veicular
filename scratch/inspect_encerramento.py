from app import app, db, Encerramento, Patio

with app.app_context():
    rows = Encerramento.query.all()
    print(f"Total Encerramentos: {len(rows)}")
    for r in rows:
        print(f"ID: {r.id}, Date: {r.date}, Patio ID: {r.patio_id}, Closing: {r.closing_time}, Obs: {r.obs}")
        print(f"  Patios JSON: {r.patios_json}")
        print(f"  Techs JSON: {r.technicians_json}")
        print("-" * 50)
