import unittest
import json
from datetime import date, timedelta
from app import app, db, User, Scale, Team, SystemConfig

class TestGestaoDashboardStats(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

        # Obter ou criar usuário supervisor
        self.supervisor = User.query.filter_by(username="supervisor_test_gt").first()
        if not self.supervisor:
            self.supervisor = User(
                username="supervisor_test_gt",
                role="supervisor"
            )
            self.supervisor.set_password("123456")
            db.session.add(self.supervisor)

        # Criar técnico de teste
        self.tech1 = User.query.filter_by(username="tecnico_test_1").first()
        if not self.tech1:
            self.tech1 = User(
                username="tecnico_test_1",
                role="tech"
            )
            self.tech1.set_password("123456")
            db.session.add(self.tech1)

        # Criar equipe de teste
        self.team1 = Team.query.filter_by(name="Equipe Alfa GT").first()
        if not self.team1:
            self.team1 = Team(name="Equipe Alfa GT", leader_id=self.supervisor.id)
            db.session.add(self.team1)
        
        db.session.commit()

        # Criar uma escala de teste para sábado
        today = date.today()
        # Próximo sábado
        days_ahead = 5 - today.weekday()
        if days_ahead <= 0:
            days_ahead += 7
        next_sat = today + timedelta(days=days_ahead)

        self.scale1 = Scale(
            type="sabado",
            date=next_sat,
            team_id=self.team1.id,
            technician_ids=str(self.tech1.id),
            team_ids=str(self.team1.id),
            obs="Plantão teste sábado",
            status="ATIVO"
        )
        db.session.add(self.scale1)
        db.session.commit()

    def tearDown(self):
        if hasattr(self, 'scale1') and self.scale1.id:
            Scale.query.filter_by(id=self.scale1.id).delete()
            db.session.commit()
        self.ctx.pop()

    def test_gestao_dashboard_stats_endpoint(self):
        # Login como supervisor
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            sess['_fresh'] = True

        res = self.client.get("/api/gestao/dashboard_stats")
        self.assertEqual(res.status_code, 200)

        data = json.loads(res.data.decode('utf-8'))
        self.assertIn("plantao_kpis", data)
        self.assertIn("distribuicao_tipos", data)
        self.assertIn("proximo_plantao", data)
        self.assertIn("proximos_plantoes", data)
        self.assertIn("ranking_tecnicos_plantoes", data)
        self.assertIn("timeline_plantoes", data)

        # Validar dados do próximo plantão
        self.assertIsNotNone(data["proximo_plantao"])
        self.assertEqual(data["proximo_plantao"]["type"], "Sábado")
        tech_names_upper = [t.upper() for t in data["proximo_plantao"]["techs"]]
        self.assertIn("TECNICO_TEST_1", tech_names_upper)

if __name__ == "__main__":
    unittest.main()
