import unittest
import json
from app import app, db, User, SystemRule, SystemRuleLog

class TestComunicacaoAvancada(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.app_context = app.app_context()
        self.app_context.push()
        self.client = app.test_client()

        # Limpeza e sementeiras básicas
        self.test_user = User.query.filter_by(username='test_admin_com').first()
        if self.test_user:
            db.session.delete(self.test_user)
            db.session.commit()

        self.test_user = User(username='test_admin_com', role='admin')
        self.test_user.set_password('admin123')
        db.session.add(self.test_user)
        db.session.commit()

    def tearDown(self):
        if self.test_user:
            db.session.delete(self.test_user)
        # Limpar logs de teste
        SystemRuleLog.query.filter_by(rule_slug='test_rule').delete()
        db.session.commit()
        self.app_context.pop()

    def login(self):
        return self.client.post('/login', data={
            'username': 'test_admin_com',
            'password': 'admin123'
        }, follow_redirects=True)

    def test_system_rule_log_model(self):
        """Verifica se o modelo SystemRuleLog grava dados corretamente"""
        log = SystemRuleLog(
            rule_slug='test_rule',
            user_id=self.test_user.id,
            channel='whatsapp',
            recipient='5521999999999',
            message='Mensagem de teste',
            status='SENT'
        )
        db.session.add(log)
        db.session.commit()

        saved = SystemRuleLog.query.filter_by(rule_slug='test_rule').first()
        self.assertIsNotNone(saved)
        self.assertEqual(saved.recipient, '5521999999999')
        self.assertEqual(saved.status, 'SENT')

    def test_system_rule_silence_days_property(self):
        """Verifica se o modelo SystemRule tem a propriedade silence_days"""
        rule = SystemRule.query.filter_by(slug='scale_alert').first()
        if rule:
            self.assertTrue(hasattr(rule, 'silence_days'))
            self.assertIsNotNone(rule.silence_days)

    def test_api_avisos_logs_endpoint(self):
        """Testa o endpoint de listagem de logs /api/avisos/logs"""
        self.login()
        res = self.client.get('/api/avisos/logs')
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertTrue(data.get('success'))
        self.assertIn('logs', data)

    def test_api_test_integration_whatsapp_denied_for_tech(self):
        """Testa se rota de teste de conexão Whatsapp é negada para técnico comum"""
        tech_user = User.query.filter_by(username='test_tech_com').first()
        if tech_user:
            db.session.delete(tech_user)
            db.session.commit()

        tech_user = User(username='test_tech_com', role='tech')
        tech_user.set_password('tech123')
        db.session.add(tech_user)
        db.session.commit()

        self.client.post('/login', data={
            'username': 'test_tech_com',
            'password': 'tech123'
        })

        res = self.client.post('/api/test-integration/whatsapp', data={
            'recipient': '21999999999',
            'api_url': 'http://localhost',
            'apikey': 'key',
            'instance_name': 'test'
        })
        self.assertEqual(res.status_code, 403)

        db.session.delete(tech_user)
        db.session.commit()
