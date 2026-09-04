import unittest
from app import app, db, User, MessageTemplate

class TestWhatsAppMessageTemplates(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        self.app_context = app.app_context()
        self.app_context.push()
        self.client = app.test_client()

        # Criar admin para autenticação
        self.admin = User.query.filter_by(username='test_tpl_admin').first()
        if not self.admin:
            self.admin = User(username='test_tpl_admin', role='admin')
            self.admin.set_password('admin123')
            db.session.add(self.admin)
            db.session.commit()

    def tearDown(self):
        MessageTemplate.query.filter_by(created_by=self.admin.id).delete()
        if self.admin:
            db.session.delete(self.admin)
        db.session.commit()
        self.app_context.pop()

    def login_admin(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)
            sess['_fresh'] = True

    def test_create_list_delete_template(self):
        self.login_admin()

        # 1. Create template
        res = self.client.post('/api/whatsapp/message-templates', json={
            'title': 'Template Teste Unitário',
            'content': 'Olá, este é um teste automatizado.',
            'emoji': '⚡'
        })
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertTrue(data.get('success'))
        tpl_id = data['template']['id']
        self.assertEqual(data['template']['title'], 'Template Teste Unitário')
        self.assertEqual(data['template']['emoji'], '⚡')

        # 2. List templates
        res_list = self.client.get('/api/whatsapp/message-templates')
        self.assertEqual(res_list.status_code, 200)
        data_list = res_list.get_json()
        self.assertTrue(data_list.get('success'))
        ids = [t['id'] for t in data_list['templates']]
        self.assertIn(tpl_id, ids)

        # 3. Delete template
        res_del = self.client.delete(f'/api/whatsapp/message-templates/{tpl_id}')
        self.assertEqual(res_del.status_code, 200)
        data_del = res_del.get_json()
        self.assertTrue(data_del.get('success'))

        # 4. Verify deletion
        tpl_check = MessageTemplate.query.get(tpl_id)
        self.assertIsNone(tpl_check)

    def test_validation_empty_fields(self):
        self.login_admin()
        res = self.client.post('/api/whatsapp/message-templates', json={
            'title': '',
            'content': ''
        })
        self.assertEqual(res.status_code, 400)
        data = res.get_json()
        self.assertFalse(data.get('success'))
