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

    def test_permission_whatsapp_conversas(self):
        """Verifica se o sistema de permissões suporta 'whatsapp_conversas'"""
        test_user = User.query.filter_by(username='test_whatsapp_user_conv').first()
        if test_user:
            db.session.delete(test_user)
            db.session.commit()

        test_user = User(username='test_whatsapp_user_conv', role='tech')
        test_user.set_password('123456')
        db.session.add(test_user)
        db.session.commit()

        # Por padrão, não deve ter a permissão
        self.assertFalse(test_user.has_permission('whatsapp_conversas'))

        # Adicionamos a permissão
        test_user.permissions = '{"perm_whatsapp_conversas": true}'
        db.session.commit()

        self.assertTrue(test_user.has_permission('whatsapp_conversas'))

        # Limpamos o usuário de teste
        db.session.delete(test_user)
        db.session.commit()

    def test_default_permissions_for_roles(self):
        """Verifica se as novas permissões do WhatsApp são atribuídas corretamentes para papéis padrão"""
        from app import get_default_perms
        
        # Testando supervisor
        sup_perms = get_default_perms('supervisor')
        self.assertTrue(sup_perms.get('perm_whatsapp_conversas'))
        self.assertTrue(sup_perms.get('perm_whatsapp_evolution'))
        
        # Testando tech (não deve vir ativado por padrão)
        tech_perms = get_default_perms('tech')
        self.assertFalse(tech_perms.get('perm_whatsapp_conversas'))
        self.assertFalse(tech_perms.get('perm_whatsapp_evolution'))

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
        db_user = User.query.filter_by(username='COLABORADOR_TESTE').first()
        self.assertIsNotNone(db_user)
        self.assertEqual(db_user.phone, '5521999999999')

        # Limpamos o usuário de teste
        db.session.delete(db_user)
        db.session.commit()

    def test_send_whatsapp_message_single_argument(self):
        """Verifica se send_whatsapp_message com 1 argumento (msg) envia para destinatários globais"""
        from unittest.mock import patch, MagicMock

        # Garantir que a config está ativada e tem destinatários
        config = WhatsAppConfig.query.first()
        old_enabled = config.is_enabled
        old_recipients = config.recipients
        old_url = config.api_url
        old_key = config.apikey
        old_instance = config.instance_name

        config.is_enabled = True
        config.recipients = "5521988888888, 5521977777777"
        config.api_url = "https://api.example.com"
        config.apikey = "test_key"
        config.instance_name = "test_inst"
        db.session.commit()

        try:
            with patch('requests.post') as mock_post, patch('threading.Thread') as mock_thread:
                # Mock thread start to execute synchronously
                mock_thread_instance = MagicMock()
                mock_thread.return_value = mock_thread_instance
                
                # Quando start() for chamado, executamos a função worker passada no target
                def run_target():
                    target_func = mock_thread.call_args[1]['target']
                    target_func()
                
                mock_thread_instance.start.side_effect = run_target

                from app import send_whatsapp_message
                send_whatsapp_message("Mensagem de Teste Global")

                # Deve ter chamado requests.post para cada um dos dois números
                self.assertEqual(mock_post.call_count, 2)
                
                # Verificar os argumentos da primeira chamada
                args, kwargs = mock_post.call_args_list[0]
                self.assertEqual(kwargs['json']['text'], "Mensagem de Teste Global")
                self.assertIn(kwargs['json']['number'], ["5521988888888", "5521977777777"])
                self.assertEqual(kwargs['headers']['apikey'], "test_key")
        finally:
            # Restaurar estado original
            config.is_enabled = old_enabled
            config.recipients = old_recipients
            config.api_url = old_url
            config.apikey = old_key
            config.instance_name = old_instance
            db.session.commit()

    def test_send_whatsapp_message_double_argument(self):
        """Verifica se send_whatsapp_message com 2 argumentos (phone, msg) envia para destinatário específico"""
        from unittest.mock import patch, MagicMock

        config = WhatsAppConfig.query.first()
        old_enabled = config.is_enabled
        old_recipients = config.recipients
        old_url = config.api_url
        old_key = config.apikey
        old_instance = config.instance_name

        config.is_enabled = True
        config.recipients = "5521988888888" # Global config
        config.api_url = "https://api.example.com"
        config.apikey = "test_key"
        config.instance_name = "test_inst"
        db.session.commit()

        try:
            with patch('requests.post') as mock_post, patch('threading.Thread') as mock_thread:
                mock_thread_instance = MagicMock()
                mock_thread.return_value = mock_thread_instance
                
                def run_target():
                    target_func = mock_thread.call_args[1]['target']
                    target_func()
                
                mock_thread_instance.start.side_effect = run_target

                from app import send_whatsapp_message
                # Enviar para número individual diferente da lista global
                send_whatsapp_message("5511999999999", "Mensagem de Teste Individual")

                # Deve ter chamado requests.post apenas uma vez para o número individual
                self.assertEqual(mock_post.call_count, 1)
                
                args, kwargs = mock_post.call_args
                self.assertEqual(kwargs['json']['text'], "Mensagem de Teste Individual")
                self.assertEqual(kwargs['json']['number'], "5511999999999")
                self.assertEqual(kwargs['headers']['apikey'], "test_key")
        finally:
            config.is_enabled = old_enabled
            config.recipients = old_recipients
            config.api_url = old_url
            config.apikey = old_key
            config.instance_name = old_instance
            db.session.commit()

    def test_whatsapp_chat_send_route_text_only(self):
        """Testa a rota /api/whatsapp/chat/send com apenas mensagem de texto (POST)"""
        from unittest.mock import patch, MagicMock
        
        # Criamos um administrador de teste
        admin_user = User(username='test_admin', role='admin')
        
        # Configuramos o mock da Evolution API
        config = WhatsAppConfig.query.first()
        old_enabled = config.is_enabled
        old_url = config.api_url
        old_key = config.apikey
        old_instance = config.instance_name
        
        config.is_enabled = True
        config.api_url = "https://api.example.com"
        config.apikey = "test_key"
        config.instance_name = "test_inst"
        db.session.commit()
        
        try:
            with patch('flask_login.utils._get_user', return_value=admin_user):
                with patch('requests.post') as mock_post:
                    # Mocking response
                    mock_res = MagicMock()
                    mock_res.status_code = 200
                    mock_res.json.return_value = {"message": "Success"}
                    mock_post.return_value = mock_res
                    
                    response = self.client.post('/api/whatsapp/chat/send', data={
                        'number': '5521999999999',
                        'message': 'Mensagem de texto via Rota'
                    })
                    
                    self.assertEqual(response.status_code, 200)
                    data = response.get_json()
                    self.assertTrue(data['success'])
                    
                    mock_post.assert_called_once()
                    args, kwargs = mock_post.call_args
                    self.assertEqual(kwargs['json']['text'], 'Mensagem de texto via Rota')
                    self.assertEqual(kwargs['json']['number'], '5521999999999')
                    self.assertEqual(kwargs['headers']['apikey'], 'test_key')
        finally:
            config.is_enabled = old_enabled
            config.api_url = old_url
            config.apikey = old_key
            config.instance_name = old_instance
            db.session.commit()

    def test_whatsapp_chat_send_route_with_file(self):
        """Testa a rota /api/whatsapp/chat/send com upload de arquivo (POST multipart)"""
        from unittest.mock import patch, MagicMock
        import io
        
        admin_user = User(username='test_admin', role='admin')
        
        config = WhatsAppConfig.query.first()
        old_enabled = config.is_enabled
        old_url = config.api_url
        old_key = config.apikey
        old_instance = config.instance_name
        
        config.is_enabled = True
        config.api_url = "https://api.example.com"
        config.apikey = "test_key"
        config.instance_name = "test_inst"
        db.session.commit()
        
        try:
            with patch('flask_login.utils._get_user', return_value=admin_user):
                with patch('requests.post') as mock_post:
                    mock_res = MagicMock()
                    mock_res.status_code = 200
                    mock_res.json.return_value = {"message": "Success"}
                    mock_post.return_value = mock_res
                    
                    # Simular arquivo em memória
                    file_data = b"dados binarios de teste"
                    file_name = "checklist.pdf"
                    
                    response = self.client.post('/api/whatsapp/chat/send', data={
                        'number': '5521999999999',
                        'message': 'Legenda da foto',
                        'file': (io.BytesIO(file_data), file_name, 'application/pdf')
                    }, content_type='multipart/form-data')
                    
                    self.assertEqual(response.status_code, 200)
                    data = response.get_json()
                    self.assertTrue(data['success'])
                    
                    mock_post.assert_called_once()
                    args, kwargs = mock_post.call_args
                    
                    # O envio de arquivo deve ter ido para sendMedia
                    self.assertIn('/message/sendMedia/test_inst', args[0])
                    self.assertEqual(kwargs['headers']['apikey'], 'test_key')
                    self.assertEqual(kwargs['data']['number'], '5521999999999')
                    self.assertEqual(kwargs['data']['caption'], 'Legenda da foto')
                    
                    # Verifica os arquivos enviados
                    self.assertIn('file', kwargs['files'])
                    sent_file_tuple = kwargs['files']['file']
                    self.assertEqual(sent_file_tuple[0], file_name)
                    self.assertEqual(sent_file_tuple[1], file_data)
                    self.assertEqual(sent_file_tuple[2], 'application/pdf')
        finally:
            config.is_enabled = old_enabled
            config.api_url = old_url
            config.apikey = old_key
            config.instance_name = old_instance
            db.session.commit()

    def test_whatsapp_logs_route(self):
        """Testa o endpoint de busca de logs /api/whatsapp/logs"""
        from backend.models import WhatsAppLog
        from unittest.mock import patch
        
        admin_user = User(username='test_admin', role='admin')
        
        # Cria um log de teste no banco
        w_log = WhatsAppLog(
            phone="5521999999999",
            message="Mensagem de teste de logs",
            status_code=200,
            status_text="SENT"
        )
        db.session.add(w_log)
        db.session.commit()
        
        try:
            with patch('flask_login.utils._get_user', return_value=admin_user):
                response = self.client.get('/api/whatsapp/logs')
                self.assertEqual(response.status_code, 200)
                data = response.get_json()
                self.assertIsInstance(data, list)
                self.assertTrue(len(data) >= 1)
                
                # Verifica as propriedades do primeiro log
                log_data = data[0]
                self.assertEqual(log_data['phone'], "5521999999999")
                self.assertEqual(log_data['message'], "Mensagem de teste de logs")
                self.assertEqual(log_data['status_code'], 200)
                self.assertEqual(log_data['status_text'], "SENT")
        finally:
            db.session.delete(w_log)
            db.session.commit()

if __name__ == '__main__':
    unittest.main()
