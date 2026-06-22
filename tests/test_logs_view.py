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
                "Fira Code Font Link": "fonts.googleapis.com/css2?family=Fira+Code",
                "Terminal CSS Style classes": "glass-terminal",
                "Windows buttons mockup": "bg-rose-500/80 inline-block",
                "Boot Information mockup": "CHECKLIST-VEICULAR [Version 2.5.0]",
                "CLI Flag label for Period": "--period",
                "CLI Flag label for Search": "--search",
                "Dynamic command line simulator": "cliCmdDisplay",
                "Blinking Shell Cursor": "animate-blink",
                "Grep display output": "grep -i"
            }
              
            for name, query in checks.items():
                self.assertIn(query, html_content, f"{name} ausente no template!")

if __name__ == "__main__":
    unittest.main()
