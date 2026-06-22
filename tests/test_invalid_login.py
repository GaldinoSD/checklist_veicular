import unittest
from app import app, db, User

class TestInvalidLogin(unittest.TestCase):
    def test_invalid_login_does_not_crash(self):
        with app.test_client() as client:
            # Envia dados de login incorretos para a rota /login
            resp = client.post("/login", data={
                "username": "usuario_inexistente_123",
                "password": "senha_incorreta_123"
            })
            
            # Não deve retornar Internal Server Error (500)
            self.assertEqual(resp.status_code, 200, f"A rota /login com credenciais incorretas retornou status {resp.status_code} em vez de 200!")
            
            html_content = resp.data.decode('utf-8')
            # Deve conter a mensagem de erro esperada ou o formulário de login
            self.assertIn("Usuário ou senha inválidos", html_content, "Mensagem de credenciais inválidas ausente no template!")

if __name__ == "__main__":
    unittest.main()
