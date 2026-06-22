import unittest
from app import app, db, User

class TestRelatoriosPreview(unittest.TestCase):
    def test_relatorios_preview(self):
        report_types = [
            "lms",
            "supervisao",
            "rfo",
            "vistoria",
            "rota",
            "atas",
            "escalas",
            "geradores",
            "encerramento",
            "anotacoes",
            "tarefas"
        ]
        with app.test_client() as c:
            # Simula autenticação como Admin (ID 1)
            with c.session_transaction() as sess:
                sess['_user_id'] = '1'

            for r_type in report_types:
                url = f"/api/gestao/relatorios/preview?type={r_type}"
                resp = c.get(url)
                self.assertEqual(resp.status_code, 200, f"Falha ao obter dados para {r_type}: {resp.data.decode('utf-8')}")
                
                data = resp.get_json()
                self.assertIn("records", data)
                self.assertIn("metrics", data)
                
                url_filter = f"/api/gestao/relatorios/preview?type={r_type}&user_id=38"
                resp_filter = c.get(url_filter)
                self.assertEqual(resp_filter.status_code, 200, f"Falha ao filtrar {r_type} por colaborador: {resp_filter.data.decode('utf-8')}")

if __name__ == "__main__":
    unittest.main()
