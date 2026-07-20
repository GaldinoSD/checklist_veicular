import unittest
from app import app, db, User, SupervisaoTecnica

class TestSupervisaoAPI(unittest.TestCase):
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

    def test_get_single_supervisao(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.user_id)

        sup = SupervisaoTecnica(
            supervisor_id=self.user_id,
            obs="Teste Observação Supervisor",
            techs_data=[{"tech_id": self.user_id, "tech_name": "Técnico Teste"}]
        )
        db.session.add(sup)
        db.session.commit()

        res = self.client.get(f'/api/gestao/supervisao/{sup.id}')
        self.assertEqual(res.status_code, 200)
        data = res.get_json()
        self.assertEqual(data["id"], sup.id)
        self.assertEqual(data["obs"], "Teste Observação Supervisor")

        # Cleanup
        db.session.delete(sup)
        db.session.commit()

if __name__ == '__main__':
    unittest.main()
