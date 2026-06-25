import unittest
from app import app, db, User

class TestConfigView(unittest.TestCase):
    def test_config_view_elements(self):
        with app.test_client() as client:
            # 1. Simular autenticação como Admin (ID 1)
            with client.session_transaction() as sess:
                sess['_user_id'] = '1'

            # 2. Consultar a rota /config-checklist
            resp = client.get("/config-checklist")
            self.assertEqual(resp.status_code, 200, f"A rota /config-checklist retornou status {resp.status_code}!")
                
            html_content = resp.data.decode('utf-8')
            
            self.assertIn("w-full space-y-6 pb-16", html_content, "Container não ajustado para largura total!")
            
            # 4. Consultar o layout geral para ver o link
            resp_layout = client.get("/dashboard")
            self.assertEqual(resp_layout.status_code, 200)
            layout_content = resp_layout.data.decode('utf-8')
            self.assertIn("Config. Checklist", layout_content, "Link na sidebar não atualizado para 'Config. Checklist'!")

if __name__ == "__main__":
    unittest.main()
