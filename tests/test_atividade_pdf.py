import os
import json
import unittest
from io import BytesIO
from backend import create_app, db
from backend.models import User, Activity

class TestAtividadePDF(unittest.TestCase):
    def setUp(self):
        self.app = create_app()
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.client = self.app.test_client()

        with self.app.app_context():
            db.create_all()
            user = User(username="admin_test", role="ADMIN")
            user.set_password("123456")
            db.session.add(user)
            db.session.commit()

    def tearDown(self):
        with self.app.app_context():
            db.session.remove()
            db.drop_all()

    def test_atividade_pdf_generation(self):
        with self.app.app_context():
            with self.client.session_transaction() as sess:
                sess['_user_id'] = '1'
                sess['_fresh'] = True

            # Create test activity
            data = [{
                "tech_responsible": "Técnico Teste",
                "client_name": "Cliente Exemplo",
                "client_code": "CLI-123",
                "type": "Instalação de Fibra",
                "time": "14:30",
                "quality_rating": "Excelente",
                "os_closure": "Sim",
                "client_feedback": "Atendimento rápido",
                "conclusion": "Tudo ok"
            }]

            res = self.client.post('/api/gestao/atividades', data={
                'data': json.dumps(data)
            })
            self.assertEqual(res.status_code, 200)
            res_json = res.get_json()
            act_id = res_json['id']

            # Test PDF generation endpoint
            pdf_res = self.client.get(f'/api/gestao/atividades/{act_id}/pdf')
            self.assertEqual(pdf_res.status_code, 200)
            self.assertEqual(pdf_res.mimetype, 'application/pdf')
            self.assertTrue(len(pdf_res.data) > 0)

if __name__ == '__main__':
    unittest.main()
