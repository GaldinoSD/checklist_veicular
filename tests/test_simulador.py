import unittest
from app import app, db, User

class TestRouterSimulator(unittest.TestCase):
    def test_simulator_anonymous_redirect(self):
        """Test that anonymous users are redirected to login when accessing the simulator."""
        with app.test_client() as client:
            resp = client.get("/simulador-roteadores")
            self.assertEqual(resp.status_code, 302, "A rota para anônimos deveria redirecionar (302) para o login!")

    def test_simulator_page_elements(self):
        """Test that logged-in users can load the simulator and find all key brand mockups & elements."""
        with app.test_client() as client:
            # 1. Simular autenticação como Admin (ID 1)
            with client.session_transaction() as sess:
                sess['_user_id'] = '1'

            # 2. Consultar a rota /simulador-roteadores
            resp = client.get("/simulador-roteadores")
            self.assertEqual(resp.status_code, 200, f"A rota retornou status {resp.status_code}!")
                
            html_content = resp.data.decode('utf-8')
            
            # 3. Testar se todos os componentes chaves do painel virtual estão lá
            checks = {
                "Page Header Title": "Simulador de Roteadores",
                "Huawei Brand Switch Button": "btn-db-huawei",
                "TP-Link Brand Switch Button": "btn-db-tplink",
                "Intelbras Brand Switch Button": "btn-db-intelbras",
                "Engine Local Switch Button": "btn-engine-local",
                "Engine Real Switch Button": "btn-engine-real",
                "View Desktop Switch Button": "btn-view-desktop",
                "View Mobile Switch Button": "btn-view-mobile",
                "Virtual LED Panel - Power": 'id="led-power"',
                "Virtual LED Panel - PON": 'id="led-pon"',
                "Virtual LED Panel - LOS": 'id="led-los"',
                "Virtual LED Panel - WAN": 'id="led-wan"',
                "Virtual LED Panel - WLAN": 'id="led-wlan"',
                "Desktop Viewport Simulator": 'id="desktop-viewport"',
                "Mobile Viewport Simulator": 'id="mobile-viewport"',
                "Simulated Desktop GUI": 'id="simulated-gui-desktop"',
                "Simulated Mobile GUI": 'id="simulated-gui-mobile"',
                "Smartphone Mockup Div": 'class="smartphone-mockup"'
            }
              
            for name, query in checks.items():
                self.assertIn(query, html_content, f"Componente do Simulador ausente no HTML: {name} ('{query}')")

if __name__ == '__main__':
    unittest.main()
