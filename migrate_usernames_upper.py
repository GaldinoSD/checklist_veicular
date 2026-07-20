#!/usr/bin/env python3
"""One-time script to convert all existing usernames to UPPERCASE."""
import sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from backend import create_app, db
from backend.models import User

app = create_app()

with app.app_context():
    users = User.query.all()
    updated = 0
    for u in users:
        original = u.username
        uppered = original.upper()
        if original != uppered:
            # Use raw SQL to avoid triggering listener loops
            db.session.execute(
                db.text('UPDATE "user" SET username = :new WHERE id = :uid'),
                {"new": uppered, "uid": u.id}
            )
            updated += 1
            print(f"  ✅ {original} → {uppered}")
    db.session.commit()
    print(f"\n🔄 {updated} username(s) convertido(s) para MAIÚSCULAS de {len(users)} total.")
