"""
Script para deletar um treinamento e todas as suas dependências.
Remove: atribuições (assignments), módulos, questões, tentativas e o próprio curso.
Isso faz o treinamento e o selo sumirem para todos os técnicos.

Uso: python delete_training.py [COURSE_ID]
Exemplo: python delete_training.py 1
"""
import sys
import os

# Adiciona o diretório raiz ao path do Python
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

from app import app, db, TrainingCourse, TrainingAssignment, TrainingModule, TrainingQuestion, Notification

def delete_course(course_id):
    with app.app_context():
        course = TrainingCourse.query.get(course_id)
        if not course:
            print(f"❌ Treinamento ID {course_id} não encontrado.")
            return False
        
        print(f"📋 Treinamento encontrado: '{course.title}' (ID: {course.id})")
        print(f"   - Publicado: {course.is_published}")
        print(f"   - Módulos: {len(course.modules)}")
        print(f"   - Questões: {len(course.questions)}")
        print(f"   - Atribuições: {len(course.assignments)}")
        
        # Count notifications
        notifs_count_check = Notification.query.filter_by(ref_type='training', ref_id=course_id).count()
        if notifs_count_check > 0:
            print(f"   - 📣 Comunicados vinculados: {notifs_count_check}")
        
        # Count badges that will be removed
        approved = [a for a in course.assignments if a.status == 'aprovado']
        if approved:
            print(f"   - 🏅 Selos que serão removidos: {len(approved)}")
            for a in approved:
                print(f"     → Usuário ID {a.user_id} (nota: {a.best_score}%)")
        
        # Delete all related data
        assignments_count = TrainingAssignment.query.filter_by(course_id=course_id).delete()
        modules_count = TrainingModule.query.filter_by(course_id=course_id).delete()
        questions_count = TrainingQuestion.query.filter_by(course_id=course_id).delete()
        notifications_count = Notification.query.filter_by(ref_type='training', ref_id=course_id).delete()
        
        db.session.delete(course)
        db.session.commit()
        
        print(f"\n✅ Treinamento '{course.title}' excluído com sucesso!")
        print(f"   - {assignments_count} atribuições removidas")
        print(f"   - {modules_count} módulos removidos")
        print(f"   - {questions_count} questões removidas")
        print(f"   - {notifications_count} comunicados de sistema removidos")
        print(f"   - Selos removidos para todos os técnicos")
        return True

def list_courses():
    with app.app_context():
        courses = TrainingCourse.query.all()
        if not courses:
            print("📭 Nenhum treinamento encontrado no banco de dados.")
            return
        print("📋 Treinamentos cadastrados:")
        for c in courses:
            approved = sum(1 for a in c.assignments if a.status == 'aprovado')
            print(f"   ID: {c.id} | '{c.title}' | Pub: {c.is_published} | Atrib: {len(c.assignments)} | Aprovados: {approved}")

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print("Uso: python delete_training.py [COURSE_ID]")
        print("     python delete_training.py list    → Listar todos\n")
        list_courses()
        sys.exit(0)
    
    arg = sys.argv[1]
    if arg == 'list':
        list_courses()
    else:
        try:
            cid = int(arg)
        except ValueError:
            print("❌ ID deve ser um número inteiro.")
            sys.exit(1)
        
        confirm = input(f"⚠️  Tem certeza que deseja excluir o treinamento ID {cid}? (s/n): ")
        if confirm.lower() in ('s', 'sim', 'y', 'yes'):
            delete_course(cid)
        else:
            print("Operação cancelada.")
