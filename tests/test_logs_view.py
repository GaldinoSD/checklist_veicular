import unittest
from app import app, db, User

class TestLogsView(unittest.TestCase):
    def test_logs_view_elements(self):
        with app.test_client() as client:
            # 1. Simular autenticação como Admin (ID 1)
            with client.session_transaction() as sess:
                sess['_user_id'] = '1'

            # 2. Consultar a rota /logs
            resp = client.get("/logs")
            self.assertEqual(resp.status_code, 200, f"A rota /logs retornou status {resp.status_code}!")
                
            html_content = resp.data.decode('utf-8')
            
            # 3. Testar a presença dos novos componentes de Terminal CLI no HTML gerado
            checks = {
                "Page Title": "Auditoria",
                "Search input field": 'id="filtro"',
                "Date Period input field": 'id="periodo"',
                "Table Body ID": 'id="tbodyLogs"',
                "Total Logs badge": "Total de Logs",
                "Table header cell": "Descrição da Ação"
            }
              
            for name, query in checks.items():
                self.assertIn(query, html_content, f"{name} ausente no template!")

if __name__ == "__main__":
    unittest.main()
