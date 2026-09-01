import unittest
from unittest.mock import patch, MagicMock
from app import app, db, User, WhatsAppConfig, TelegramConfig, CloudflareConfig, TraccarConfig, MetabaseConfig, EmailConfig

class TestIntegracoesStatus(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.app_context = app.app_context()
        self.app_context.push()
        self.client = app.test_client()

        # Criar admin para autenticação nos testes
        self.admin = User.query.filter_by(username='test_integ_admin').first()
        if not self.admin:
            self.admin = User(username='test_integ_admin', role='admin')
            self.admin.set_password('admin123')
            db.session.add(self.admin)
            db.session.commit()

    def tearDown(self):
        if self.admin:
            db.session.delete(self.admin)
            db.session.commit()
        self.app_context.pop()

    def login_admin(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)
            sess['_fresh'] = True

    def test_status_all_endpoint(self):
        """Verifica se /api/integracoes/status_all retorna o dicionário com os 6 serviços"""
        self.login_admin()
        response = self.client.get('/api/integracoes/status_all')
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertIn('results', data)
        results = data['results']
        for service in ['whatsapp', 'telegram', 'cloudflare', 'traccar', 'metabase', 'email']:
            self.assertIn(service, results, f"Serviço {service} deve estar presente no health-check")
            self.assertIn('status', results[service])

    @patch('requests.get')
    def test_telegram_test_connection_mock(self, mock_get):
        """Verifica o teste de conexão do Telegram com mock de sucesso"""
        self.login_admin()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"ok": True, "result": {"id": 12345, "first_name": "NocBot", "username": "NocTestBot"}}
        mock_get.return_value = mock_resp

        response = self.client.post('/api/integracoes/telegram/test', data={'bot_token': '123456:ABC-DEF'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertIn('NocTestBot', data.get('message', ''))

    @patch('requests.get')
    def test_traccar_test_connection_mock(self, mock_get):
        """Verifica o teste de conexão do Traccar com mock de sucesso"""
        self.login_admin()
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"version": "5.12"}
        mock_get.return_value = mock_resp

        response = self.client.post('/api/integracoes/traccar/test', data={'server_url': 'http://traccar.local:8082'})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()
        self.assertTrue(data.get('success'))
        self.assertIn('5.12', data.get('message', ''))

    def test_toggle_integrations(self):
        """Testa o toggle instantâneo para todos os serviços"""
        self.login_admin()
        services = ['whatsapp', 'telegram', 'cloudflare', 'traccar', 'metabase', 'email']
        for srv in services:
            # Desativar
            res_off = self.client.post(f'/api/integracoes/{srv}/toggle', json={'is_enabled': False})
            self.assertEqual(res_off.status_code, 200)
            data_off = res_off.get_json()
            self.assertTrue(data_off.get('success'))
            self.assertFalse(data_off.get('is_enabled'))

            # Ativar
            res_on = self.client.post(f'/api/integracoes/{srv}/toggle', json={'is_enabled': True})
            self.assertEqual(res_on.status_code, 200)
            data_on = res_on.get_json()
            self.assertTrue(data_on.get('success'))
            self.assertTrue(data_on.get('is_enabled'))

