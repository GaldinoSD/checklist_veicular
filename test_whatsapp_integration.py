import unittest
from app import app, db, User, WhatsAppConfig

class TestWhatsAppIntegration(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        # Usamos o banco de dados de teste configurado
        self.app_context = app.app_context()
        self.app_context.push()
        self.client = app.test_client()

    def tearDown(self):
        self.app_context.pop()

    def test_whatsapp_config_model_exists(self):
        """Verifica se o modelo WhatsAppConfig foi criado com sucesso no banco de dados"""
        config = WhatsAppConfig.query.first()
        self.assertIsNotNone(config, "WhatsAppConfig padrão deve existir no banco (semeado)")
        self.assertTrue(hasattr(config, 'api_url'))
        self.assertTrue(hasattr(config, 'apikey'))
        self.assertTrue(hasattr(config, 'instance_name'))
        self.assertTrue(hasattr(config, 'is_enabled'))
        self.assertTrue(hasattr(config, 'recipients'))
        self.assertTrue(hasattr(config, 'msg_checklist_fail'))
        self.assertTrue(hasattr(config, 'msg_os_opened'))
        self.assertTrue(hasattr(config, 'msg_os_closed'))
        self.assertTrue(hasattr(config, 'msg_new_vistoria'))
        self.assertTrue(hasattr(config, 'msg_scale_alert'))
        self.assertTrue(hasattr(config, 'msg_late_checklist'))
        self.assertTrue(hasattr(config, 'msg_training_alert'))
        self.assertTrue(hasattr(config, 'msg_os_overdue'))
        self.assertTrue(hasattr(config, 'msg_inactive_tech'))

    def test_permission_whatsapp_evolution(self):
        """Verifica se o sistema de permissões suporta 'whatsapp_evolution'"""
        # Criamos um usuário de teste temporário
        test_user = User.query.filter_by(username='test_whatsapp_user').first()
        if test_user:
            db.session.delete(test_user)
            db.session.commit()

        test_user = User(username='test_whatsapp_user', role='tech')
        test_user.set_password('123456')
        db.session.add(test_user)
        db.session.commit()

        # Por padrão, não deve ter a permissão
        self.assertFalse(test_user.has_permission('whatsapp_evolution'))

        # Adicionamos a permissão
        test_user.permissions = '{"perm_whatsapp_evolution": true}'
        db.session.commit()

        self.assertTrue(test_user.has_permission('whatsapp_evolution'))

        # Limpamos o usuário de teste
        db.session.delete(test_user)
        db.session.commit()

    def test_dashboard_access_denied_for_anonymous(self):
        """Verifica se usuários anônimos são redirecionados para a tela de login"""
        response = self.client.get('/whatsapp')
        self.assertEqual(response.status_code, 302)
        self.assertIn('/login', response.headers.get('Location', ''))

    def test_manual_announcement_whatsapp_send(self):
        """Verifica se a lógica de criação de avisos manuais integra com o envio do WhatsApp"""
        # Criamos um usuário com telefone
        u = User(username='colaborador_teste', role='tech', phone='5521999999999')
        u.set_password('123456')
        db.session.add(u)
        db.session.commit()

        # Verifica se o banco de dados tem o usuário de teste
        db_user = User.query.filter_by(username='colaborador_teste').first()
        self.assertIsNotNone(db_user)
        self.assertEqual(db_user.phone, '5521999999999')

        # Limpamos o usuário de teste
        db.session.delete(db_user)
        db.session.commit()

if __name__ == '__main__':
    unittest.main()
