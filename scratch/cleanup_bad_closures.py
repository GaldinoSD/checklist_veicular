from app import app, db, Encerramento

with app.app_context():
    bad_rows = Encerramento.query.filter(Encerramento.date == None).all()
    count = len(bad_rows)
    for r in bad_rows:
        db.session.delete(r)
    db.session.commit()
    print(f"Successfully cleaned up {count} bad daily closures.")
