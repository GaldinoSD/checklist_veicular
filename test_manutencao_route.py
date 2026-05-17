import json
import unittest
from unittest.mock import patch, MagicMock
from app import app, db, User

class TestManutencaoOSRouteAccess(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app_context = app.app_context()
        self.app_context.push()
        self.app.testing = True

    def tearDown(self):
        self.app_context.pop()

    def test_anonymous_redirected_to_login(self):
        response = self.app.get("/manutencao/os")
        self.assertEqual(response.status_code, 302)
        self.assertTrue("/login" in response.headers["Location"])

    def test_admin_allowed_access(self):
        from app import manutencao_only
        
        @manutencao_only
        def dummy_view():
            return "success"
            
        admin = User(username="admin_test", role="admin")
        
        with app.test_request_context():
            with patch('flask_login.utils._get_user', return_value=admin):
                res = dummy_view()
                self.assertEqual(res, "success")

    def test_manutencao_role_allowed_access(self):
        from app import manutencao_only
        
        @manutencao_only
        def dummy_view():
            return "success"
            
        man_user = User(username="mechanic", role="manutencao")
        
        with app.test_request_context():
            with patch('flask_login.utils._get_user', return_value=man_user):
                res = dummy_view()
                self.assertEqual(res, "success")

    def test_tech_blocked_redirected_to_checklist(self):
        from app import manutencao_only
        
        @manutencao_only
        def dummy_view():
            return "success"
            
        tech_user = User(username="tech_guy", role="tech")
        tech_user.permissions = "{}"
        
        with app.test_request_context():
            with patch('flask_login.utils._get_user', return_value=tech_user):
                res = dummy_view()
                self.assertEqual(res.status_code, 302)
                self.assertTrue("/checklist" in res.headers["Location"])

    def test_tech_with_granular_permission_allowed_access(self):
        from app import manutencao_only
        
        @manutencao_only
        def dummy_view():
            return "success"
            
        tech_user = User(
            username="tech_special", 
            role="tech",
            permissions=json.dumps({"perm_manutencao_os": True})
        )
        
        with app.test_request_context():
            with patch('flask_login.utils._get_user', return_value=tech_user):
                res = dummy_view()
                self.assertEqual(res, "success")

if __name__ == "__main__":
    unittest.main()
