import sys
import os
# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, db, TrainingCourse, TrainingAssignment
with app.app_context():
    courses = TrainingCourse.query.all()
    print("--- COURSES ---")
    for c in courses:
        print(f"Course ID: {c.id}, Title: {c.title}")
    
    print("\n--- ASSIGNMENTS ---")
    assignments = TrainingAssignment.query.all()
    for a in assignments:
        print(f"Assig ID: {a.id}, Course ID: {a.course_id}, User ID: {a.user_id}, Status: {a.status}")
