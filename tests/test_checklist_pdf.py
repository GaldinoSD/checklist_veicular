import unittest
import json
from app import app, db, User, Checklist, Vehicle

class TestChecklistPdf(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Setup clean in-memory SQLite engine
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        
        cls.sqlite_engine = create_engine(
            'sqlite:///:memory:',
            poolclass=StaticPool,
            connect_args={'check_same_thread': False}
        )
        
        if 'sqlalchemy' in app.extensions:
            sa = app.extensions['sqlalchemy']
            if app in sa._app_engines:
                cls.original_engine = sa._app_engines[app].get(None)
                sa._app_engines[app][None] = cls.sqlite_engine

    @classmethod
    def tearDownClass(cls):
        if 'sqlalchemy' in app.extensions:
            sa = app.extensions['sqlalchemy']
            if app in sa._app_engines and hasattr(cls, 'original_engine'):
                sa._app_engines[app][None] = cls.original_engine

    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        db.create_all()
        
        # Setup mock user and vehicle
        self.admin = User(username="admin_test", role="admin")
        self.admin.set_password("123")
        db.session.add(self.admin)
        
        self.vehicle = Vehicle(plate="AAA0000", brand="Fiat", model="Uno")
        db.session.add(self.vehicle)
        db.session.commit()
        
        # Setup a checklist
        self.checklist = Checklist(
            technician="admin_test",
            vehicle_id=self.vehicle.id,
            km=12000,
            signature="test_sig.png"
        )
        db.session.add(self.checklist)
        db.session.commit()
        
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_checklist_pdf_download(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)
            
        res = self.client.get(f'/checklists/{self.checklist.id}/pdf')
        self.assertEqual(res.status_code, 200, f"A rota /checklists/<id>/pdf retornou status {res.status_code}!")
        self.assertEqual(res.mimetype, 'application/pdf', "O tipo do retorno do PDF não é application/pdf!")

if __name__ == '__main__':
    unittest.main()
