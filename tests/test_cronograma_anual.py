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

if __name__ == "__main__":
    unittest.main()
