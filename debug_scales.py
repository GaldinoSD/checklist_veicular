from app import app, Scale, db
with app.app_context():
    scales = Scale.query.all()
    for s in scales:
        print(f"ID: {s.id}, Date: {s.date}, Type: {s.type}, Techs: {s.technician_ids}, Teams: {s.team_ids}")
