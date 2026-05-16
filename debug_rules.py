from app import app, SystemRule, db
with app.app_context():
    rules = SystemRule.query.all()
    for r in rules:
        print(f"Slug: {r.slug}, Enabled: {r.is_enabled}")
