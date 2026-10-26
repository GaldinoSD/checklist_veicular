import unittest
from datetime import datetime, date, timedelta
from app import app, db
from backend.models import User, Announcement, AnnouncementRead, Scale, SystemRule
from backend.utils import user_can_receive_announcement, agora
from backend.blueprints.technical import dispatch_system_rule_alert, execute_system_audit, cleanup_old_announcements


class TestSupervisorAdminNotificationFilter(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

        # Usuário Admin
        self.admin = User.query.filter_by(username="TEST_ADMIN").first()
        if not self.admin:
            self.admin = User(username="TEST_ADMIN", role="admin")
            self.admin.set_password("123456")
            db.session.add(self.admin)

        # Usuário Supervisor
        self.supervisor = User.query.filter_by(username="TEST_SUPERVISOR").first()
        if not self.supervisor:
            self.supervisor = User(username="TEST_SUPERVISOR", role="supervisor")
            self.supervisor.set_password("123456")
            db.session.add(self.supervisor)

        # Usuário Técnico
        self.tech = User.query.filter_by(username="TEST_TECH").first()
        if not self.tech:
            self.tech = User(username="TEST_TECH", role="tech")
            self.tech.set_password("123456")
            db.session.add(self.tech)

        db.session.commit()

    def tearDown(self):
        self.app_context.pop()

    def test_user_properties(self):
        """Valida que as propriedades is_admin, is_supervisor e is_supervisor_or_admin funcionam corretamente."""
        self.assertTrue(self.admin.is_admin)
        self.assertTrue(self.admin.is_supervisor_or_admin)
        self.assertFalse(self.admin.is_tech)

        self.assertTrue(self.supervisor.is_supervisor)
        self.assertTrue(self.supervisor.is_supervisor_or_admin)
        self.assertFalse(self.supervisor.is_tech)

        self.assertFalse(self.tech.is_admin)
        self.assertFalse(self.tech.is_supervisor_or_admin)

    def test_user_can_receive_announcement_filter(self):
        """Valida que user_can_receive_announcement bloqueia avisos operacionais para admin e supervisor."""
        class MockAnnouncement:
            def __init__(self, title, content="", category=""):
                self.title = title
                self.content = content
                self.message = content
                self.category = category

        late_ann = MockAnnouncement(
            title="🔔 Lembrete: Checklist Diário Pendente",
            content="Olá, você está de plantão hoje e ainda não enviou o Checklist Veicular regulamentar.",
            category="late_checklist"
        )
        inactive_ann = MockAnnouncement(
            title="⚠️ Lembrete: Checklist não realizado há +7 dias",
            content="identificamos que você não realiza nenhuma vistoria ou checklist veicular há mais de 7 dias.",
            category="inactive_tech_alert"
        )
        tool_ann = MockAnnouncement(
            title="🛠️ Inspeção de Ferramental Atrasada (+30 dias)",
            content="sua conferência e assinatura de kit de ferramentas está pendente há mais de 30 dias.",
            category="tool_inspection_alert"
        )
        supervisor_issue_ann = MockAnnouncement(
            title="🚨 Checklist Não Conforme: ABC-1234",
            content="O técnico TEST_TECH enviou checklist com itens reprovados.",
            category="checklist_issue_alert"
        )

        # Admin NÃO pode receber pendência de checklist/ferramental próprio
        self.assertFalse(user_can_receive_announcement(self.admin, late_ann))
        self.assertFalse(user_can_receive_announcement(self.admin, inactive_ann))
        self.assertFalse(user_can_receive_announcement(self.admin, tool_ann))

        # Supervisor NÃO pode receber pendência de checklist/ferramental próprio
        self.assertFalse(user_can_receive_announcement(self.supervisor, late_ann))
        self.assertFalse(user_can_receive_announcement(self.supervisor, inactive_ann))
        self.assertFalse(user_can_receive_announcement(self.supervisor, tool_ann))

        # Técnico PODE receber lembretes de pendência do seu próprio checklist
        self.assertTrue(user_can_receive_announcement(self.tech, late_ann))
        self.assertTrue(user_can_receive_announcement(self.tech, inactive_ann))

        # Supervisor e Admin PODEM e DEVEM receber alertas de supervisão de checklist (ex: itens reprovados)
        self.assertTrue(user_can_receive_announcement(self.admin, supervisor_issue_ann))
        self.assertTrue(user_can_receive_announcement(self.supervisor, supervisor_issue_ann))

    def test_dispatch_system_rule_alert_blocks_for_admin_and_supervisor(self):
        """Garante que dispatch_system_rule_alert não despacha late_checklist ou inactive_tech_alert para admin/supervisor."""
        res_admin_late = dispatch_system_rule_alert(
            "late_checklist",
            user_target=self.admin,
            title_default="🔔 Lembrete: Checklist Diário Pendente",
            content_default="Você não fez checklist",
            bypass_silence=True
        )
        self.assertEqual(res_admin_late, 0, "Admin não deveria receber alerta de late_checklist")

        res_sup_inactive = dispatch_system_rule_alert(
            "inactive_tech_alert",
            user_target=self.supervisor,
            title_default="⚠️ Lembrete: Checklist não realizado há +7 dias",
            content_default="Você não fez checklist há 7 dias",
            bypass_silence=True
        )
        self.assertEqual(res_sup_inactive, 0, "Supervisor não deveria receber alerta de inactive_tech_alert")


if __name__ == "__main__":
    unittest.main()
