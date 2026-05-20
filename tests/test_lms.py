from app import app, db, TrainingCourse

with app.app_context():
    courses = TrainingCourse.query.order_by(TrainingCourse.id.desc()).all()
    for c in courses:
        try:
            total_assigned = len(c.assignments)
            approved = sum(1 for a in c.assignments if a.status == 'aprovado')
            res = {
                "id": c.id,
                "title": c.title,
                "deadline": c.deadline.strftime("%Y-%m-%d") if c.deadline else None,
                "created_at": c.created_at.strftime("%d/%m/%Y") if c.created_at else ""
            }
            print(f"Course {c.id} OK")
        except Exception as e:
            print(f"Error on course {c.id}: {e}")
