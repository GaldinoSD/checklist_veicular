from app import app, db
from sqlalchemy import text

def migrate():
    with app.app_context():
        try:
            db.session.execute(text("ALTER TABLE team ADD COLUMN rotation_order INTEGER DEFAULT 0"))
            db.session.commit()
            print("Added rotation_order to team")
        except Exception as e:
            db.session.rollback()
            print(f"Error adding rotation_order: {e}")

        try:
            db.session.execute(text("ALTER TABLE system_config ADD COLUMN scale_rotation_order VARCHAR(255)"))
            db.session.commit()
            print("Added scale_rotation_order to system_config")
        except Exception as e:
            db.session.rollback()
            print(f"Error adding scale_rotation_order: {e}")

if __name__ == "__main__":
    migrate()
