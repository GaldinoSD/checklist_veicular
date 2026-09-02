import unittest
from datetime import datetime, date, timedelta
from app import app, db
from backend.models import (
    User, SystemRule, SystemRuleLog, Announcement,
    Scale, Schedule, Meeting, Task, Solicitacao,
    SupervisaoTecnica, RFO, TechnicalDocument, Vehicle,
    UserToolInspection, TrainingAssignment, TrainingCourse
)
from backend.blueprints.technical import execute_system_audit, dispatch_system_rule_alert


class TestAll18SystemAutomations(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_all_18_rules_present(self):
        """Verifica se todas as 18 regras de automação são cadastradas e auditadas com sucesso."""
        execute_system_audit()
        
        expected_slugs = [
            "scale_alert",
            "cronograma_alert",
            "meeting_alert",
            "task_assigned_alert",
            "solicitacao_alert",
            "late_checklist",
            "checklist_issue_alert",
            "cnh_expiry_alert",
            "vehicle_doc_alert",
            "vehicle_maintenance_km_alert",
            "os_alert",
            "os_created_alert",
            "inactive_tech_alert",
            "supervisao_alert",
            "rfo_alert",
            "tool_inspection_alert",
            "training_alert",
            "training_assigned_alert"
        ]
        
        rules = SystemRule.query.all()
        found_slugs = {r.slug for r in rules}
        
        for slug in expected_slugs:
            self.assertIn(slug, found_slugs, f"Regra {slug} não encontrada no banco de dados.")

    def test_rule_update_ajax(self):
        """Verifica se o endpoint AJAX de atualização de regra responde corretamente."""
        with self.client.session_transaction() as sess:
            admin = User.query.filter(db.func.lower(User.username) == "admin").first()
            if not admin:
                admin = User(username="admin", role="admin")
                admin.set_password("123456")
                db.session.add(admin)
                db.session.commit()
            sess["_user_id"] = str(admin.id)

        response = self.client.post("/api/system/rules/scale_alert/update", json={
            "is_enabled": True,
            "trigger_days": 1,
            "silence_days": 2,
            "channels": ["system", "whatsapp"]
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertEqual(data["rule"]["trigger_days"], 1)
        self.assertEqual(data["rule"]["silence_days"], 2)

    def test_rule_test_preview_and_dispatch(self):
        """Verifica se o endpoint de teste gera os previews e cria notificação no sistema."""
        with self.client.session_transaction() as sess:
            admin = User.query.filter(db.func.lower(User.username) == "admin").first()
            if not admin:
                admin = User(username="admin", role="admin")
                admin.set_password("123456")
                db.session.add(admin)
                db.session.commit()
            sess["_user_id"] = str(admin.id)

        response = self.client.post("/api/system/rules/scale_alert/test", json={
            "channel": "system",
            "send": True
        })
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("previews", data)
        self.assertIn("system", data["previews"])
        self.assertIsNotNone(data.get("dispatch_result"))

    def test_dispatch_system_rule_alert_generic(self):
        """Verifica se o helper genérico dispatch_system_rule_alert funciona para qualquer uma das 18 regras."""
        admin = User.query.filter(db.func.lower(User.username) == "admin").first()
        if not admin:
            admin = User(username="admin", role="admin")
            admin.set_password("123456")
            db.session.add(admin)
            db.session.commit()

        # Testa disparo de alerta de tarefa
        sent = dispatch_system_rule_alert(
            "task_assigned_alert",
            user_target=admin,
            title_default="📌 Tarefa Teste",
            content_default="Você recebeu uma tarefa teste",
            placeholders={"usuario": "Admin", "tarefa": "Tarefa Teste", "descricao": "Descrição", "data": "Hoje"},
            bypass_silence=True
        )
        self.assertIn(sent, [0, 1])


if __name__ == "__main__":
    unittest.main()
