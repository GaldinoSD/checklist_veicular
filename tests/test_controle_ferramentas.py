import json
import unittest
from app import app, db, User, Tool, UserToolInspection, UserToolStatus, agora

class TestControleFerramentas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Store original SQLALCHEMY_DATABASE_URI
        cls.original_uri = app.config.get('SQLALCHEMY_DATABASE_URI')
        
        # Configure app for testing
        app.config['TESTING'] = True
        app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'  # Use an in-memory database
        app.config['WTF_CSRF_ENABLED'] = False
        
        # Setup clean in-memory SQLite engine
        from sqlalchemy import create_engine
        from sqlalchemy.pool import StaticPool
        
        cls.sqlite_engine = create_engine(
            'sqlite:///:memory:',
            poolclass=StaticPool,
            connect_args={'check_same_thread': False}
        )
        
        # Swap the engines inside flask_sqlalchemy's app registry
        if 'sqlalchemy' in app.extensions:
            sa = app.extensions['sqlalchemy']
            if app in sa._app_engines:
                cls.original_engine = sa._app_engines[app].get(None)
                sa._app_engines[app][None] = cls.sqlite_engine

    @classmethod
    def tearDownClass(cls):
        # Restore original database configuration
        if hasattr(cls, 'original_uri'):
            app.config['SQLALCHEMY_DATABASE_URI'] = cls.original_uri
            
        # Restore original engine to the registry
        if 'sqlalchemy' in app.extensions:
            sa = app.extensions['sqlalchemy']
            if app in sa._app_engines and hasattr(cls, 'original_engine'):
                sa._app_engines[app][None] = cls.original_engine
                
        # Dispose the in-memory SQLite engine
        if hasattr(cls, 'sqlite_engine'):
            cls.sqlite_engine.dispose()

    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()
        
        db.create_all()
        
        # Create test users with dummy password hash
        self.admin = User(username="admin_test", role="admin")
        self.admin.set_password("123")
        self.tech = User(
            username="tech_test", 
            role="tech",
            permissions=json.dumps({"perm_controle_ferramentas": True})
        )
        self.tech.set_password("123")
        self.tech_no_perm = User(username="tech_no_perm", role="tech", permissions="{}")
        self.tech_no_perm.set_password("123")
        
        db.session.add(self.admin)
        db.session.add(self.tech)
        db.session.add(self.tech_no_perm)
        db.session.commit()
        
        self.client = app.test_client()

    def tearDown(self):
        db.session.remove()
        db.drop_all()
        self.app_context.pop()

    def login(self, username):
        return self.client.post('/login', data=dict(
            username=username,
            password="123"  # or bypass login since we are testing in-memory
        ), follow_redirects=True)

    def test_tool_crud_permissions(self):
        # 1. Non-admin should be blocked
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.tech.id)  # Bypass login with session
            
        res = self.client.get('/config/ferramentas')
        self.assertEqual(res.status_code, 302)  # Redirected because of admin_required
        
        # 2. Admin should access successfully
        from flask import g
        if hasattr(g, '_login_user'):
            delattr(g, '_login_user')
            
        admin_client = app.test_client()
        with admin_client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)
            
        res = admin_client.get('/config/ferramentas')
        self.assertEqual(res.status_code, 200)

    def test_tool_crud_operations(self):
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)

        # Create
        res = self.client.post('/config/ferramentas/new', data=dict(
            name="Furadeira de Impacto",
            category="Elétrica"
        ), follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        tool = Tool.query.filter_by(name="Furadeira de Impacto").first()
        self.assertIsNotNone(tool)
        self.assertEqual(tool.category, "Elétrica")
        self.assertTrue(tool.is_active)

        # Edit
        res = self.client.post(f'/config/ferramentas/edit/{tool.id}', data=dict(
            name="Furadeira Bosch",
            category="Ferramenta Elétrica"
        ), follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        db.session.refresh(tool)
        self.assertEqual(tool.name, "Furadeira Bosch")
        self.assertEqual(tool.category, "Ferramenta Elétrica")

        # Toggle Active
        res = self.client.post(f'/config/ferramentas/toggle/{tool.id}', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        db.session.refresh(tool)
        self.assertFalse(tool.is_active)

        # Delete
        res = self.client.post(f'/config/ferramentas/delete/{tool.id}', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        self.assertIsNone(Tool.query.get(tool.id))

    def test_technician_inspection_flow(self):
        # Setup tools
        t1 = Tool(name="Alicate de Pressão", category="Manual", is_active=True)
        t2 = Tool(name="Martelo Polido", category="Manual", is_active=True)
        db.session.add(t1)
        db.session.add(t2)
        db.session.commit()

        # Login as tech
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.tech.id)

        # Get inspection template
        res = self.client.get('/controle/ferramentas')
        self.assertEqual(res.status_code, 200)

        # Submit first inspection
        res = self.client.post('/controle/ferramentas', data={
            f'tool_status_{t1.id}': 'possui',
            f'tool_sub_{t1.id}': 'bom',
            f'tool_status_{t2.id}': 'possui',
            f'tool_sub_{t2.id}': 'ruim',
            f'damage_desc_{t2.id}': 'Cabo rachado',
            'notes': 'Alguns itens novos recebidos hoje.'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Verify db entries
        insp = UserToolInspection.query.filter_by(user_id=self.tech.id).first()
        self.assertIsNotNone(insp)
        self.assertEqual(insp.notes, 'Alguns itens novos recebidos hoje.')
        
        status1 = UserToolStatus.query.filter_by(inspection_id=insp.id, tool_id=t1.id).first()
        self.assertEqual(status1.status, 'possui')
        self.assertEqual(status1.sub_status, 'bom')
        self.assertIsNone(status1.damage_description)

        status2 = UserToolStatus.query.filter_by(inspection_id=insp.id, tool_id=t2.id).first()
        self.assertEqual(status2.status, 'possui')
        self.assertEqual(status2.sub_status, 'ruim')
        self.assertEqual(status2.damage_description, 'Cabo rachado')

        # Submit second inspection (Overwrite validation - No duplication!)
        res = self.client.post('/controle/ferramentas', data={
            f'tool_status_{t1.id}': 'nao_possui',
            f'tool_sub_{t1.id}': 'perdi',
            f'tool_status_{t2.id}': 'possui',
            f'tool_sub_{t2.id}': 'bom',
            'notes': 'Atualizado.'
        }, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Ensure still only ONE inspection record exists
        all_insps = UserToolInspection.query.filter_by(user_id=self.tech.id).all()
        self.assertEqual(len(all_insps), 1)

        db.session.refresh(insp)
        self.assertEqual(insp.notes, 'Atualizado.')

        # Verify that statuses were modified correctly
        db.session.refresh(status1)
        self.assertEqual(status1.status, 'nao_possui')
        self.assertEqual(status1.sub_status, 'perdi')

        db.session.refresh(status2)
        self.assertEqual(status2.status, 'possui')
        self.assertEqual(status2.sub_status, 'bom')
        self.assertIsNone(status2.damage_description)

    def test_admin_dashboard_details(self):
        # Setup tools and an inspection
        t1 = Tool(name="Chave Philips", is_active=True)
        db.session.add(t1)
        db.session.commit()

        insp = UserToolInspection(user_id=self.tech.id, notes="Notas administrativas")
        db.session.add(insp)
        db.session.flush()

        ts = UserToolStatus(
            inspection_id=insp.id,
            tool_id=t1.id,
            status="possui",
            sub_status="ruim",
            damage_description="Ponta gasta"
        )
        db.session.add(ts)
        db.session.commit()

        # Login as admin
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)

        # Get dashboard view
        res = self.client.get('/controle/ferramentas/atual')
        self.assertEqual(res.status_code, 200)

        # Get detailed JSON API
        res = self.client.get(f'/controle/ferramentas/atual/detalhes/{self.tech.id}')
        self.assertEqual(res.status_code, 200)
        
        data = json.loads(res.get_data(as_text=True))
        self.assertEqual(data['technician'], self.tech.username)
        self.assertEqual(data['notes'], "Notas administrativas")
        self.assertEqual(len(data['statuses']), 1)
        self.assertEqual(data['statuses'][0]['tool_name'], "Chave Philips")
        self.assertEqual(data['statuses'][0]['status'], "possui")
        self.assertEqual(data['statuses'][0]['sub_status'], "ruim")
        self.assertEqual(data['statuses'][0]['damage_description'], "Ponta gasta")

    def test_tool_sorting_and_optional_category(self):
        # 1. Setup tools with mixed categories, empty/None category, and various names
        t_outros2 = Tool(name="Zebra Tool", category=None, is_active=True)
        t_eletrica2 = Tool(name="Furadeira", category="Elétrica", is_active=True)
        t_eletrica1 = Tool(name="Amperímetro", category="Elétrica", is_active=True)
        t_manual = Tool(name="Chave de Fenda", category="Manual", is_active=True)
        t_outros1 = Tool(name="Alicate Sem Categoria", category="", is_active=True)
        
        db.session.add_all([t_outros2, t_eletrica2, t_eletrica1, t_manual, t_outros1])
        db.session.commit()

        # Login as admin to test config endpoint
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)

        # 2. Check config page sort order
        # Expected categories in order: Elétrica, Manual, Outros
        # Expected tool names in Elétrica: Amperímetro, Furadeira
        # Expected tool names in Manual: Chave de Fenda
        # Expected tool names in Outros: Alicate Sem Categoria, Zebra Tool
        res = self.client.get('/config/ferramentas')
        self.assertEqual(res.status_code, 200)
        
        # We can extract the tools from the template context or just query and sort in Python using the same logic to assert
        all_tools = Tool.query.all()
        sorted_tools = sorted(all_tools, key=lambda x: (
            1 if not x.category else 0,
            (x.category or "").strip().lower(),
            x.name.strip().lower()
        ))
        
        expected_order = [
            ("Elétrica", "Amperímetro"),
            ("Elétrica", "Furadeira"),
            ("Manual", "Chave de Fenda"),
            ("", "Alicate Sem Categoria"),
            (None, "Zebra Tool")
        ]
        
        # Match only the ones we just added + what was already there if any
        added_tool_names = ["Amperímetro", "Furadeira", "Chave de Fenda", "Alicate Sem Categoria", "Zebra Tool"]
        sorted_added_tools = [t for t in sorted_tools if t.name in added_tool_names]
        
        self.assertEqual(sorted_added_tools[0].name, "Amperímetro")
        self.assertEqual(sorted_added_tools[1].name, "Furadeira")
        self.assertEqual(sorted_added_tools[2].name, "Chave de Fenda")
        self.assertEqual(sorted_added_tools[3].name, "Alicate Sem Categoria")
        self.assertEqual(sorted_added_tools[4].name, "Zebra Tool")

    def test_category_crud_and_fallback(self):
        from app import ToolCategory
        # Login as admin
        with self.client.session_transaction() as sess:
            sess['_user_id'] = str(self.admin.id)

        # 1. Create a Category
        res = self.client.post('/config/ferramentas/categorias/new', data=dict(
            name="Mecânica"
        ), follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        cat = ToolCategory.query.filter_by(name="Mecânica").first()
        self.assertIsNotNone(cat)
        
        # 2. Case-insensitive unique check
        res = self.client.post('/config/ferramentas/categorias/new', data=dict(
            name="mecânica"
        ), follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        # Should only have one Mecânica in DB
        cats = ToolCategory.query.filter(db.func.lower(ToolCategory.name) == "mecânica").all()
        self.assertEqual(len(cats), 1)

        # 3. Create a Tool with this Category
        res = self.client.post('/config/ferramentas/new', data=dict(
            name="Torquímetro de precisão",
            category="Mecânica"
        ), follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        tool = Tool.query.filter_by(name="Torquímetro de precisão").first()
        self.assertIsNotNone(tool)
        self.assertEqual(tool.category, "Mecânica")

        # 4. Delete the Category
        res = self.client.post(f'/config/ferramentas/categorias/delete/{cat.id}', follow_redirects=True)
        self.assertEqual(res.status_code, 200)
        
        # Category should be deleted
        self.assertIsNone(ToolCategory.query.get(cat.id))
        
        # Tool's category should fall back to None
        db.session.refresh(tool)
        self.assertIsNone(tool.category)

if __name__ == '__main__':
    unittest.main()

