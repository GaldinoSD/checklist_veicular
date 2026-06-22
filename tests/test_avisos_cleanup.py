import unittest
from datetime import timedelta
from app import app, db
from backend.models import Announcement, AnnouncementRead, User
from backend.utils import agora
from backend.blueprints.technical import cleanup_old_announcements

class TestAvisosCleanup(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        
        # Garante que temos um usuário para associar aos avisos, se necessário
        self.user = User.query.filter_by(username="admin").first()
        if not self.user:
            self.user = User(username="admin", password="pbkdf2:sha256:...", role="admin")
            db.session.add(self.user)
            db.session.commit()

        # Limpa avisos existentes para o teste
        AnnouncementRead.query.delete()
        Announcement.query.delete()
        db.session.commit()

    def tearDown(self):
        # Limpa avisos criados
        AnnouncementRead.query.delete()
        Announcement.query.delete()
        db.session.commit()
        self.app_context.pop()

    def test_cleanup_old_announcements(self):
        now = agora()
        
        # 1. Criar um aviso antigo (4 dias atrás)
        old_ann = Announcement(
            title="Aviso Antigo",
            content="Conteúdo Antigo",
            created_at=now - timedelta(days=4)
        )
        db.session.add(old_ann)
        db.session.commit()
        
        # Adicionar registro de leitura para o aviso antigo
        old_read = AnnouncementRead(
            announcement_id=old_ann.id,
            user_id=self.user.id
        )
        db.session.add(old_read)
        db.session.commit()

        # 2. Criar um aviso recente (2 dias atrás)
        recent_ann = Announcement(
            title="Aviso Recente",
            content="Conteúdo Recente",
            created_at=now - timedelta(days=2)
        )
        db.session.add(recent_ann)
        db.session.commit()
        
        # Adicionar registro de leitura para o aviso recente
        recent_read = AnnouncementRead(
            announcement_id=recent_ann.id,
            user_id=self.user.id
        )
        db.session.add(recent_read)
        db.session.commit()

        # Guardar IDs antes que sejam excluídos
        old_ann_id = old_ann.id
        recent_ann_id = recent_ann.id

        # 3. Executar a limpeza
        cleanup_old_announcements()

        # 4. Validar os resultados
        remaining_anns = Announcement.query.all()
        remaining_titles = [a.title for a in remaining_anns]
        
        self.assertNotIn("Aviso Antigo", remaining_titles, "O aviso antigo (4 dias) deveria ter sido excluído!")
        self.assertIn("Aviso Recente", remaining_titles, "O aviso recente (2 dias) deveria ter sido mantido!")

        # Validar que o registro de leitura do aviso antigo também foi removido
        remaining_reads = AnnouncementRead.query.all()
        read_ann_ids = [r.announcement_id for r in remaining_reads]
        self.assertNotIn(old_ann_id, read_ann_ids, "O registro de leitura do aviso antigo deveria ter sido excluído!")
        self.assertIn(recent_ann_id, read_ann_ids, "O registro de leitura do aviso recente deveria ter sido mantido!")

if __name__ == "__main__":
    unittest.main()
