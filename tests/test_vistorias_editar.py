import unittest
import io
import os
from app import app, db, User, Vehicle, Vistoria, VistoriaFoto

class TestVistoriasEditar(unittest.TestCase):
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
        
        # Setup mock supervisor user and vehicles
        self.supervisor = User(username="supervisor_test", role="supervisor")
        self.supervisor.set_password("123")
        db.session.add(self.supervisor)
        
        # Technician user (to verify restriction)
        self.tech = User(username="tech_test", role="tech")
        self.tech.set_password("123")
        db.session.add(self.tech)
        
        self.vehicle_car = Vehicle(plate="CAR1234", type="carro", brand="Fiat", model="Uno")
        db.session.add(self.vehicle_car)
        
        self.vehicle_moto = Vehicle(plate="MOT5678", type="moto", brand="Honda", model="CG")
        db.session.add(self.vehicle_moto)
        
        db.session.commit()
        
        # Setup a Vistoria
        self.vistoria = Vistoria(
            vehicle_id=self.vehicle_car.id,
            km=10000,
            turno="inicio",
            local="Base",
            status_geral="ok",
            observacoes="Vistoria inicial limpa",
            created_by=self.supervisor.id
        )
        db.session.add(self.vistoria)
        db.session.commit()
        
        # Add a VistoriaFoto
        self.foto = VistoriaFoto(
            vistoria_id=self.vistoria.id,
            filename="test_foto.jpg",
            item_key="pneus"
        )
        db.session.add(self.foto)
        db.session.commit()
        
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def test_unauthorized_access(self):
        # A tech user should be blocked from GET /vistorias/<id>/editar
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.tech.id)
            
        res = self.client.get(f'/vistorias/{self.vistoria.id}/editar')
        # Expect either redirect to login/dashboard or 403 Forbidden
        self.assertTrue(res.status_code in [302, 403])

    def test_vistorias_editar_get(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            
        res = self.client.get(f'/vistorias/{self.vistoria.id}/editar')
        self.assertEqual(res.status_code, 302)
        self.assertIn(f"/vistorias?open_id={self.vistoria.id}&edit=true", res.headers.get("Location", ""))

    def test_vistorias_json_api(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            
        res = self.client.get(f'/vistorias/{self.vistoria.id}?format=json')
        self.assertEqual(res.status_code, 200)
        import json
        data = json.loads(res.data)
        self.assertEqual(data["id"], self.vistoria.id)
        self.assertEqual(data["km"], 10000)
        
        # Verify fotos_info is populated correctly
        items = data["items"]
        pneus_item = next(item for item in items if item["key"] == "pneus")
        self.assertEqual(len(pneus_item["fotos"]), 1)
        self.assertEqual(pneus_item["fotos"][0], "test_foto.jpg")
        
        self.assertEqual(len(pneus_item["fotos_info"]), 1)
        self.assertEqual(pneus_item["fotos_info"][0]["id"], self.foto.id)
        self.assertEqual(pneus_item["fotos_info"][0]["filename"], "test_foto.jpg")

    def test_vistorias_editar_post_updates_and_adds_photo(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            
        # Post data modifying fields and adding a photo to "capo"
        data = {
            'vehicle_id': str(self.vehicle_car.id),
            'km': '11000',
            'turno': 'fim',
            'local': 'Pátio',
            'observacoes': 'Atualizado com nova avaria',
            'capo': 'avaria',
            'obs_capo': 'Arranhado profundo',
            # Include empty fields for the other items
            'para_choque_dianteiro': 'ok',
            'para_choque_traseiro': 'ok',
            'lateral_esquerda': 'ok',
            'lateral_direita': 'ok',
            'teto': 'ok',
            'porta_malas': 'ok',
            'retrovisores': 'ok',
            'farois_lanternas': 'ok',
            'vidros_parabrisa': 'ok',
            'pneus': 'ok',
            'calotas': 'ok'
        }
        
        # Mock file upload
        data['foto_capo[]'] = (io.BytesIO(b"fake image data"), "capo.png")
        
        res = self.client.post(
            f'/vistorias/{self.vistoria.id}/editar',
            data=data,
            content_type='multipart/form-data'
        )
        
        self.assertEqual(res.status_code, 302)  # Should redirect to list
        
        # Verify db updates
        db.session.refresh(self.vistoria)
        self.assertEqual(self.vistoria.km, 11000)
        self.assertEqual(self.vistoria.turno, 'fim')
        self.assertEqual(self.vistoria.local, 'Pátio')
        self.assertEqual(self.vistoria.status_geral, 'avarias')
        self.assertEqual(self.vistoria.capo, 'avaria')
        self.assertEqual(self.vistoria.obs_capo, 'Arranhado profundo')
        
        # Verify the new photo was recorded
        new_foto = VistoriaFoto.query.filter_by(vistoria_id=self.vistoria.id, item_key="capo").first()
        self.assertIsNotNone(new_foto)
        self.assertTrue(new_foto.filename.startswith("vistoria_"))
        
        # Clean up mock file created on disk if any
        from backend.blueprints.fleet import VISTORIAS_UPLOAD_DIR
        filepath = VISTORIAS_UPLOAD_DIR / new_foto.filename
        if filepath.exists():
            filepath.unlink()

    def test_vistorias_editar_post_deletes_photo(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.supervisor.id)
            
        # Verify photo exists first
        photo_id = self.foto.id
        self.assertIsNotNone(VistoriaFoto.query.get(photo_id))
        
        # Create fake file on disk to simulate deletion
        from backend.blueprints.fleet import VISTORIAS_UPLOAD_DIR
        VISTORIAS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        disk_file = VISTORIAS_UPLOAD_DIR / self.foto.filename
        disk_file.write_text("dummy")
        
        data = {
            'vehicle_id': str(self.vehicle_car.id),
            'km': '10000',
            'turno': 'inicio',
            'local': 'Base',
            'observacoes': 'Removido foto',
            'delete_photos[]': [str(photo_id)]
        }
        # Add OK status for all items
        for item in ["para_choque_dianteiro", "para_choque_traseiro", "lateral_esquerda", "lateral_direita", "capo", "teto", "porta_malas", "retrovisores", "farois_lanternas", "vidros_parabrisa", "pneus", "calotas"]:
            data[item] = 'ok'
            
        res = self.client.post(f'/vistorias/{self.vistoria.id}/editar', data=data)
        self.assertEqual(res.status_code, 302)
        
        # Verify db photo deletion
        self.assertIsNone(VistoriaFoto.query.get(photo_id))
        # Verify disk file was deleted
        self.assertFalse(disk_file.exists())

if __name__ == '__main__':
    unittest.main()
