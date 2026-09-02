# -*- coding: utf-8 -*-
import unittest
from app import app, db
from backend.models import User, SystemRule

class TestAutomacoesUiApi(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()
        
        self.user = User.query.filter(db.func.upper(User.username) == 'ADMIN').first()
        if not self.user:
            self.user = User(username='ADMIN', role='admin', email='admin@test.com', phone='5511999999999')
            self.user.set_password('123456')
            db.session.add(self.user)
            db.session.commit()
        else:
            self.user.set_password('123456')
            self.user.email = 'admin@test.com'
            self.user.phone = '5511999999999'
            db.session.commit()

    def tearDown(self):
        db.session.rollback()
        self.app_context.pop()

    def login(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.user.id)
            sess['_fresh'] = True

    def test_avisos_page_renders_automacoes(self):
        self.login()
        resp = self.client.get('/avisos?tab=automacoes')
        self.assertEqual(resp.status_code, 200)
        content = resp.data.decode('utf-8')
        self.assertIn('Automações Ativas', content)
        self.assertIn('scale_alert', content)
        self.assertIn('cronograma_alert', content)
        self.assertIn('late_checklist', content)
        self.assertIn('training_alert', content)
        self.assertIn('os_alert', content)
        self.assertIn('inactive_tech_alert', content)

    def test_update_rule_api(self):
        self.login()
        resp = self.client.post('/api/system/rules/scale_alert/update', json={
            'is_enabled': True,
            'trigger_days': 1,
            'silence_days': 2,
            'channels': ['system', 'whatsapp']
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        
        rule = SystemRule.query.filter_by(slug='scale_alert').first()
        self.assertTrue(rule.is_enabled)
        self.assertEqual(rule.trigger_days, 1)
        self.assertEqual(rule.silence_days, 2)
        self.assertIn('whatsapp', rule.channels)

    def test_test_rule_preview_and_dispatch(self):
        self.login()
        # Test preview
        resp = self.client.post('/api/system/rules/cronograma_alert/test', json={
            'channel': 'system',
            'send': False
        })
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data['success'])
        self.assertIn('system', data['previews'])
        self.assertIn('whatsapp', data['previews'])

        # Test simulated dispatch
        resp_send = self.client.post('/api/system/rules/cronograma_alert/test', json={
            'channel': 'system',
            'send': True
        })
        self.assertEqual(resp_send.status_code, 200)
        data_send = resp_send.get_json()
        self.assertTrue(data_send['success'])
        self.assertIn('Central de Notificações', data_send['dispatch_result'])

if __name__ == '__main__':
    unittest.main()
