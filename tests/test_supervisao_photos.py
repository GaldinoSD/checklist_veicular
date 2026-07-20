import unittest
import io
import json
from PIL import Image
from app import app, db, User, SupervisaoTecnica

class TestSupervisaoPhotos(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        user = User.query.filter_by(username='admin').first()
        if not user:
            user = User(username='admin', role='admin')
            db.session.add(user)
            db.session.commit()

        self.user_id = user.id

    def tearDown(self):
        self.app_context.pop()

    def test_supervisao_per_tech_photos_and_pdf(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.user_id)

        img1 = Image.new('RGB', (100, 100), color='red')
        img_arr1 = io.BytesIO()
        img1.save(img_arr1, format='JPEG')
        img_arr1.seek(0)

        img2 = Image.new('RGB', (100, 100), color='blue')
        img_arr2 = io.BytesIO()
        img2.save(img_arr2, format='JPEG')
        img_arr2.seek(0)

        techs_payload = [
            {'tech_id': self.user_id, 'tech_name': 'Técnico A', 'conclusion': 'Observação Técnico A', 'epi': 'OK'},
            {'tech_id': self.user_id, 'tech_name': 'Técnico B', 'conclusion': 'Observação Técnico B', 'epi': 'OK'}
        ]

        data = {
            'obs': 'Supervisão Geral',
            'techs': json.dumps(techs_payload),
            'tech_photos_0': (img_arr1, 'foto_tech_a.jpg'),
            'tech_photos_1': (img_arr2, 'foto_tech_b.jpg')
        }

        res = self.client.post('/api/gestao/supervisao', data=data, content_type='multipart/form-data')
        self.assertEqual(res.status_code, 200)
        res_json = res.get_json()
        sup_id = res_json.get('id')
        self.assertIsNotNone(sup_id)

        sup = SupervisaoTecnica.query.get(sup_id)
        self.assertIsNotNone(sup.techs_data)
        techs_data = sup.techs_data
        self.assertEqual(len(techs_data), 2)
        self.assertTrue(len(techs_data[0].get('photos', [])) >= 1)
        self.assertTrue(len(techs_data[1].get('photos', [])) >= 1)

        # PDF test
        pdf_res = self.client.get(f'/api/gestao/supervisao/{sup_id}/pdf')
        self.assertEqual(pdf_res.status_code, 200)
        self.assertEqual(pdf_res.mimetype, 'application/pdf')

        # Cleanup
        db.session.delete(sup)
        db.session.commit()

if __name__ == '__main__':
    unittest.main()
