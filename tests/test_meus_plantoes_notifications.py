# -*- coding: utf-8 -*-
import unittest
from unittest.mock import patch
from datetime import datetime, date, timedelta
from app import app, db
from backend.models import User, Team, Scale, Announcement

class TestMeusPlantoesNotifications(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # 1. Usuário técnico de teste
        self.tech = User.query.filter(db.func.upper(User.username) == "TECH_PLANTAO_TEST").first()
        if not self.tech:
            self.tech = User(
                username="TECH_PLANTAO_TEST",
                role="tech",
                phone="5521988887777"
            )
            self.tech.set_password("123456")
            db.session.add(self.tech)
            db.session.commit()
        else:
            self.tech.phone = "5521988887777"
            db.session.commit()

        # 2. Usuário supervisor/admin de teste
        self.supervisor = User.query.filter(db.func.upper(User.username) == "SUPERVISOR_PLANTAO_TEST").first()
        if not self.supervisor:
            self.supervisor = User(
                username="SUPERVISOR_PLANTAO_TEST",
                role="admin"
            )
            self.supervisor.set_password("123456")
            db.session.add(self.supervisor)
            db.session.commit()

        # 3. Equipe de teste
        self.team = Team.query.filter_by(name="Equipe Teste Plantão").first()
        if not self.team:
            self.team = Team(name="Equipe Teste Plantão", color="#0284c7")
            db.session.add(self.team)
            db.session.commit()

        # Vincula o técnico à equipe se ainda não vinculado
        if self.tech not in self.team.members:
            self.team.members.append(self.tech)
            db.session.commit()

    def tearDown(self):
        # Limpeza dos dados criados nos testes
        Announcement.query.filter(Announcement.user_id.in_([self.tech.id, self.supervisor.id])).delete()
        Announcement.query.filter(Announcement.title.like("%Plantão%")).delete()
        Announcement.query.filter(Announcement.title.like("%Escala%")).delete()
        Scale.query.filter(Scale.obs.like("%Teste Automatizado%")).delete()
        db.session.commit()
        self.app_context.pop()

    def login_as(self, user):
        with self.client.session_transaction() as sess:
            sess["user_id"] = user.id
            sess["_fresh"] = True

    def test_api_tecnico_minhas_escalas_upcoming_and_past(self):
        """Verifica se o técnico visualiza seus plantões futuros e histórico corretamente."""
        today = datetime.now().date()
        future_date = today + timedelta(days=5)
        past_date = today - timedelta(days=5)

        # Cria escala futura com técnico direto
        s_future = Scale(
            type="sabado",
            date=future_date,
            technician_ids=str(self.tech.id),
            obs="Teste Automatizado Futuro",
            status="ATIVO"
        )
        # Cria escala passada vinculada à equipe do técnico
        s_past = Scale(
            type="domingo",
            date=past_date,
            team_id=self.team.id,
            team_ids=str(self.team.id),
            obs="Teste Automatizado Passado",
            status="ATIVO"
        )
        db.session.add_all([s_future, s_past])
        db.session.commit()

        with patch('flask_login.utils._get_user', return_value=self.tech):
            res = self.client.get("/api/tecnico/minhas-escalas")
            self.assertEqual(res.status_code, 200)

            data = res.get_json()
            self.assertTrue(data.get("success"))
            self.assertIn("stats", data)
            self.assertIn("upcoming", data)
            self.assertIn("past", data)

            upcoming_ids = [item["id"] for item in data["upcoming"]]
            past_ids = [item["id"] for item in data["past"]]

            self.assertIn(s_future.id, upcoming_ids)
            self.assertIn(s_past.id, past_ids)

    def test_meus_plantoes_page_render(self):
        """Verifica se a página /meus-plantoes renderiza com sucesso para o técnico."""
        with patch('flask_login.utils._get_user', return_value=self.tech):
            res = self.client.get("/meus-plantoes")
            self.assertEqual(res.status_code, 200)
            self.assertIn(b"Meus", res.data)
            self.assertIn(b"page-plantoes-list-container", res.data)

    @patch("backend.blueprints.technical.send_whatsapp_message")
    def test_notification_on_scale_creation_and_adjustment(self, mock_whatsapp):
        """Verifica emissão de Announcement e disparo de WhatsApp quando uma escala é criada ou ajustada."""
        today = datetime.now().date()
        date_str = (today + timedelta(days=3)).strftime("%Y-%m-%d")

        # 1. Cria nova escala com o técnico
        payload = {
            "type": "sabado",
            "date": date_str,
            "technician_ids": [self.tech.id],
            "obs": "Teste Automatizado Criação",
            "status": "ATIVO"
        }
        with patch('flask_login.utils._get_user', return_value=self.supervisor):
            res = self.client.post("/api/gestao/escalas", json=payload)
            self.assertEqual(res.status_code, 200)
            scale_id = res.get_json().get("id")
            self.assertIsNotNone(scale_id)

        # Verifica Announcement criado para o técnico
        ann = Announcement.query.filter_by(user_id=self.tech.id, category="escala").order_by(Announcement.id.desc()).first()
        self.assertIsNotNone(ann)
        self.assertIn("Novo Plantão Agendado", ann.title)
        self.assertTrue(mock_whatsapp.called)

        # 2. Ajusta a data da escala
        new_date_str = (today + timedelta(days=4)).strftime("%Y-%m-%d")
        payload_update = {
            "id": scale_id,
            "type": "sabado",
            "date": new_date_str,
            "technician_ids": [self.tech.id],
            "obs": "Teste Automatizado Data Alterada",
            "status": "ATIVO"
        }
        mock_whatsapp.reset_mock()
        with patch('flask_login.utils._get_user', return_value=self.supervisor):
            res_up = self.client.put(f"/api/gestao/escalas/{scale_id}", json=payload_update)
            self.assertEqual(res_up.status_code, 200)

        ann_up = Announcement.query.filter_by(user_id=self.tech.id, category="escala").order_by(Announcement.id.desc()).first()
        self.assertIsNotNone(ann_up)
        self.assertIn("Data do Plantão Alterada", ann_up.title)
        self.assertTrue(mock_whatsapp.called)

        # 3. Exclui a escala e verifica aviso de cancelamento
        mock_whatsapp.reset_mock()
        with patch('flask_login.utils._get_user', return_value=self.supervisor):
            res_del = self.client.delete(f"/api/gestao/escalas/{scale_id}")
            self.assertEqual(res_del.status_code, 200)

        ann_del = Announcement.query.filter_by(user_id=self.tech.id, category="escala").order_by(Announcement.id.desc()).first()
        self.assertIsNotNone(ann_del)
        self.assertIn("Plantão Cancelado", ann_del.title)
        self.assertTrue(mock_whatsapp.called)

if __name__ == "__main__":
    unittest.main()
