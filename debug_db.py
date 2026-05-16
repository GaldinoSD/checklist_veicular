from app import app, db, User
with app.app_context():
    users = User.query.all()
    for u in users:
        print(f"User {u.username}: permissions={u.permissions}")
