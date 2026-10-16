import unittest
import json
from app import app, db, User, AnnualScaleSchedule

class TestCronogramaAnual(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.ctx = self.app.app_context()
        self.ctx.push()

        # Login supervisor
        self.supervisor = User.query.filter(User.username.ilike("SUPERVISOR_TEST_CRONOGRAMA")).first()
        if not self.supervisor:
            self.supervisor = User(
                username="SUPERVISOR_TEST_CRONOGRAMA",
                role="supervisor"
            )
            self.supervisor.set_password("123456")
            db.session.add(self.supervisor)
            db.session.commit()

        # Auth session
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            sess['_fresh'] = True

    def tearDown(self):
        self.ctx.pop()

    def test_01_page_render(self):
        """Verifica se a página do Cronograma Anual renderiza com sucesso."""
        res = self.client.get("/gestao-tecnica/cronograma-anual")
        self.assertEqual(res.status_code, 200)
        self.assertIn(b"Cronograma de Escalas", res.data)

    def test_02_get_cronograma_default(self):
        """Verifica se o GET retorna a estrutura completa de sábados, domingos e feriados."""
        res = self.client.get("/api/gestao/cronograma-anual/2026")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get("success"))
        self.assertIn("data", data)
        self.assertIn("saturdays", data["data"])
        self.assertIn("sundays", data["data"])
        self.assertIn("holidays", data["data"])
        self.assertEqual(len(data["data"]["saturdays"]), 52)
        self.assertEqual(len(data["data"]["sundays"]), 52)
        self.assertGreater(len(data["data"]["holidays"]), 10)

    def test_03_post_and_save_cronograma(self):
        """Verifica se o POST salva e persiste alterações no banco de dados."""
        payload = {
            "data": {
                "year": 2026,
                "saturdays": [
                    {"date": "2026-01-03", "date_extenso": "sábado, 3 de janeiro de 2026", "team": "EQUIPE ROSA"}
                ],
                "sundays": [
                    {"date": "2026-01-04", "date_extenso": "domingo, 4 de janeiro de 2026", "interno": "Roberth", "externo_1": "Adriano", "externo_2": "Sidney"}
                ],
                "holidays": [
                    {"name": "Carnaval", "date": "2026-02-17", "date_extenso": "Carnaval, terça-feira, 17 de fevereiro de 2026", "interno": "Roberth", "externo_1": "Adriano", "externo_2": "Samuel", "prevalecer_domingo": False}
                ]
            }
        }
        res = self.client.post(
            "/api/gestao/cronograma-anual/2026",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        res_data = res.get_json()
        self.assertTrue(res_data.get("success"))

        # Recuperar e checar se persistiu no AnnualScaleSchedule
        record = AnnualScaleSchedule.query.filter_by(year=2026).first()
        self.assertIsNotNone(record)
        saved_data = json.loads(record.data_json)
        self.assertEqual(saved_data["saturdays"][0]["team"], "EQUIPE ROSA")
        self.assertEqual(saved_data["sundays"][0]["interno"], "Roberth")

        # Verificar se sincronizou na tabela Scale (impactando Escalas e Calendário)
        from datetime import date
        from app import Scale
        sat_scale = Scale.query.filter_by(date=date(2026, 1, 3), type="sabado").first()
        self.assertIsNotNone(sat_scale)
        self.assertIn("EQUIPE ROSA", sat_scale.obs)

        sun_scale = Scale.query.filter_by(date=date(2026, 1, 4), type="domingo").first()
        self.assertIsNotNone(sun_scale)
        self.assertIn("Roberth", sun_scale.obs)

    def test_04_generate_pdf_endpoint(self):
        """Verifica se o endpoint de PDF gera e envia o PDF formatado."""
        res = self.client.get("/api/gestao/cronograma-anual/2026/pdf")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.mimetype, "application/pdf")
        self.assertGreater(len(res.data), 1000)

    def test_05_auto_fill_endpoint(self):
        """Verifica o endpoint de auto-fill com customização de equipes."""
        payload = {
            "teams": ["EQUIPE OURO", "EQUIPE PRATA"]
        }
        res = self.client.post(
            "/api/gestao/cronograma-anual/2027/auto-fill",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)
        res_data = res.get_json()
        self.assertTrue(res_data.get("success"))
        sats = res_data["data"]["saturdays"]
        self.assertEqual(sats[0]["team"], "EQUIPE OURO")
        self.assertEqual(sats[1]["team"], "EQUIPE PRATA")

    def test_06_multi_tech_pdf(self):
        """Verifica se o PDF é gerado corretamente quando há múltiplos técnicos internos (ex: 2) e externos (ex: 4)."""
        payload = {
            "data": {
                "year": 2028,
                "saturdays": [
                    {"date": "2028-01-01", "date_extenso": "sábado, 1 de janeiro de 2028", "team": "EQUIPE VERDE"}
                ],
                "sundays": [
                    {
                        "date": "2028-01-02",
                        "date_extenso": "domingo, 2 de janeiro de 2028",
                        "internos": ["Roberth", "João"],
                        "externos": ["Adriano Mendonça", "Victor Leandro", "Lucas Jr", "Sidney Rodrigues"]
                    }
                ],
                "holidays": [
                    {
                        "name": "Carnaval",
                        "date": "2028-02-29",
                        "date_extenso": "Carnaval, terça-feira, 29 de fevereiro de 2028",
                        "internos": ["Gabriel", "Roberth"],
                        "externos": ["Henrique", "Arthur", "Carlos Eduardo", "Pablo Rafael"],
                        "prevalecer_domingo": False
                    }
                ]
            }
        }
        # Salva o cronograma com múltiplos técnicos
        res_post = self.client.post(
            "/api/gestao/cronograma-anual/2028",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res_post.status_code, 200)

        # Gera o PDF correspondente
        res_pdf = self.client.get("/api/gestao/cronograma-anual/2028/pdf")
        self.assertEqual(res_pdf.status_code, 200)
        self.assertEqual(res_pdf.mimetype, "application/pdf")
        self.assertGreater(len(res_pdf.data), 1000)

    def test_07_three_or_more_techs(self):
        """Verifica se plantão com 3 ou mais técnicos externos persiste todos e sincroniza na Scale."""
        from datetime import date
        from app import Scale
        payload = {
            "data": {
                "year": 2029,
                "saturdays": [],
                "sundays": [
                    {
                        "date": "2029-01-07",
                        "date_extenso": "domingo, 7 de janeiro de 2029",
                        "interno": "Arthur",
                        "externos": ["Eric", "Gabriel", "Henrique"]
                    }
                ],
                "holidays": []
            }
        }
        res = self.client.post(
            "/api/gestao/cronograma-anual/2029",
            data=json.dumps(payload),
            content_type="application/json"
        )
        self.assertEqual(res.status_code, 200)

        # Checar registro Scale criado para o domingo
        scale_rec = Scale.query.filter_by(date=date(2029, 1, 7), type="domingo").first()
        self.assertIsNotNone(scale_rec)
        self.assertIn("Eric", scale_rec.obs)
        self.assertIn("Gabriel", scale_rec.obs)
        self.assertIn("Henrique", scale_rec.obs)

    def test_08_team_change_reflects_in_scales(self):
        """Verifica se ajustes na equipe refletem imediatamente nas escalas associadas."""
        from datetime import date, timedelta
        from app import Team, Scale

        # Criar usuários técnicos de teste
        t1 = User.query.filter_by(username="TECH_ALPHA_TEST").first()
        if not t1:
            t1 = User(username="TECH_ALPHA_TEST", role="tech")
            t1.set_password("123456")
            db.session.add(t1)

        t2 = User.query.filter_by(username="TECH_BETA_TEST").first()
        if not t2:
            t2 = User(username="TECH_BETA_TEST", role="tech")
            t2.set_password("123456")
            db.session.add(t2)
        db.session.commit()

        # Criar Equipe com t1
        team = Team.query.filter_by(name="EQUIPE_REFLECT_TEST").first()
        if not team:
            team = Team(name="EQUIPE_REFLECT_TEST", color="#00ff00")
            db.session.add(team)
            db.session.commit()

        team.members = [t1]
        db.session.commit()

        # Criar Escala de Sábado futura associada a esta equipe
        future_sat = date.today() + timedelta(days=10)
        scale = Scale.query.filter_by(date=future_sat).first()
        if not scale:
            scale = Scale(date=future_sat, type="sabado", team_id=team.id, team_ids=str(team.id))
            db.session.add(scale)
        else:
            scale.team_id = team.id
            scale.team_ids = str(team.id)
            scale.type = "sabado"
        db.session.commit()

        # 1. Checa se view=list retorna TECH_ALPHA_TEST na escala da equipe
        res1 = self.client.get("/api/gestao/escalas?view=list")
        self.assertEqual(res1.status_code, 200)
        items1 = res1.get_json()
        target_s1 = next((item for item in items1 if item["id"] == scale.id), None)
        self.assertIsNotNone(target_s1)
        self.assertIn("TECH_ALPHA_TEST", target_s1["technician_names"])
        self.assertNotIn("TECH_BETA_TEST", target_s1["technician_names"])

        # 2. Agora edita a equipe via API adicionando t2 (TECH_BETA_TEST)
        payload_update = {
            "id": team.id,
            "name": team.name,
            "color": team.color,
            "member_ids": [t1.id, t2.id]
        }
        res_put = self.client.put(
            f"/api/gestao/equipes/{team.id}",
            data=json.dumps(payload_update),
            content_type="application/json"
        )
        self.assertEqual(res_put.status_code, 200)

        # 3. Checa se view=list reflete imediatamente t1 e t2
        res2 = self.client.get("/api/gestao/escalas?view=list")
        self.assertEqual(res2.status_code, 200)
        items2 = res2.get_json()
        target_s2 = next((item for item in items2 if item["id"] == scale.id), None)
        self.assertIsNotNone(target_s2)
        self.assertIn("TECH_ALPHA_TEST", target_s2["technician_names"])
        self.assertIn("TECH_BETA_TEST", target_s2["technician_names"])

        # 4. Agora remove t1 e deixa apenas t2
        payload_update2 = {
            "id": team.id,
            "name": team.name,
            "color": team.color,
            "member_ids": [t2.id]
        }
        res_put2 = self.client.put(
            f"/api/gestao/equipes/{team.id}",
            data=json.dumps(payload_update2),
            content_type="application/json"
        )
        self.assertEqual(res_put2.status_code, 200)

        # 5. Checa se view=list agora tem apenas t2
        res3 = self.client.get("/api/gestao/escalas?view=list")
        self.assertEqual(res3.status_code, 200)
        items3 = res3.get_json()
        target_s3 = next((item for item in items3 if item["id"] == scale.id), None)
        self.assertIsNotNone(target_s3)
        self.assertNotIn("TECH_ALPHA_TEST", target_s3["technician_names"])
        self.assertIn("TECH_BETA_TEST", target_s3["technician_names"])

if __name__ == "__main__":
    unittest.main()

