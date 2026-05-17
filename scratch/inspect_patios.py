from app import app, db, Patio

with app.app_context():
    patios = Patio.query.all()
    print(f"Total Patios: {len(patios)}")
    for p in patios:
        print(f"ID: {p.id}, Name: {p.name}, Location: {p.location}")
