from app import app, db, TrainingCourse, TrainingAssignment
with app.app_context():
    courses = TrainingCourse.query.all()
    print("Courses count:", len(courses))
    for c in courses:
        print(f"ID: {c.id}, Title: {c.title}, Published: {c.is_published}, Creator: {c.created_by_id}")
