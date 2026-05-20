import json
import unittest
from unittest.mock import MagicMock
from app import User, app, db, get_default_perms

class TestUserHasPermission(unittest.TestCase):
    def setUp(self):
        self.app_context = app.app_context()
        self.app_context.push()

    def tearDown(self):
        self.app_context.pop()

    def test_admin_has_all_permissions(self):
        # Admin via role
        admin_user = User(username="superadmin", role="admin")
        self.assertTrue(admin_user.has_permission("any_random_permission"))
        self.assertTrue(admin_user.has_permission("checklist_mobile"))

        # Admin via legacy is_admin_legacy
        legacy_admin = User(username="legacy", role=None, is_admin_legacy=True)
        self.assertTrue(legacy_admin.has_permission("any_random_permission"))

    def test_tech_default_permissions_normalized(self):
        # Technician permissions saved in DB: {"perm_checklist_mobile": True, "perm_treinamentos_mobile": True}
        tech_user = User(
            username="tech_john",
            role="tech",
            permissions=json.dumps({"perm_checklist_mobile": True, "perm_treinamentos_mobile": True})
        )

        # Checking with prefix
        self.assertTrue(tech_user.has_permission("perm_checklist_mobile"))
        self.assertTrue(tech_user.has_permission("perm_treinamentos_mobile"))

        # Checking without prefix (should resolve automatically)
        self.assertTrue(tech_user.has_permission("checklist_mobile"))
        self.assertTrue(tech_user.has_permission("treinamentos_mobile"))

        # Checking permission not granted
        self.assertFalse(tech_user.has_permission("manutencao_os"))
        self.assertFalse(tech_user.has_permission("perm_manutencao_os"))

    def test_manutencao_permissions_normalized(self):
        # Maintenance permissions saved in DB: {"perm_manutencao_os": True}
        man_user = User(
            username="man_bob",
            role="manutencao",
            permissions=json.dumps({"perm_manutencao_os": True})
        )

        self.assertTrue(man_user.has_permission("perm_manutencao_os"))
        self.assertTrue(man_user.has_permission("manutencao_os"))
        self.assertFalse(man_user.has_permission("checklist_mobile"))

    def test_supervisor_has_frota_by_default(self):
        # Supervisor should automatically have "frota" permission
        supervisor = User(username="supervisor_alice", role="supervisor")
        self.assertTrue(supervisor.has_permission("frota"))

        # Supervisor permissions checking with legacy permissions list
        supervisor.permissions = json.dumps({"perm_dashboard": True})
        self.assertTrue(supervisor.has_permission("frota"))
        self.assertTrue(supervisor.has_permission("dashboard"))
        self.assertTrue(supervisor.has_permission("perm_dashboard"))

    def test_implicit_role_defaults_with_empty_permissions(self):
        # Tech role with empty/no permissions
        tech_empty = User(username="tech_empty", role="tech", permissions="{}")
        self.assertTrue(tech_empty.has_permission("checklist_mobile"))
        self.assertTrue(tech_empty.has_permission("treinamentos_mobile"))
        self.assertFalse(tech_empty.has_permission("manutencao_os"))

        # Manutencao role with empty/no permissions
        man_empty = User(username="man_empty", role="manutencao", permissions="{}")
        self.assertTrue(man_empty.has_permission("manutencao_os"))
        self.assertTrue(man_empty.has_permission("perm_manutencao_os"))
        self.assertFalse(man_empty.has_permission("checklist_mobile"))

        # Supervisor role with empty/no permissions
        supervisor_empty = User(username="supervisor_empty", role="supervisor", permissions="{}")
        self.assertTrue(supervisor_empty.has_permission("frota"))
        self.assertFalse(supervisor_empty.has_permission("manutencao_os"))

    def test_get_default_perms(self):
        # Admin gets everything
        admin_perms = get_default_perms("admin")
        self.assertTrue(admin_perms["perm_dashboard"])
        self.assertTrue(admin_perms["perm_usuarios"])
        self.assertTrue(admin_perms["perm_frota"])
        self.assertTrue(admin_perms["perm_monitoramento_aparelhos"])

        # Supervisor gets everything except perm_usuarios
        supervisor_perms = get_default_perms("supervisor")
        self.assertTrue(supervisor_perms["perm_dashboard"])
        self.assertFalse(supervisor_perms["perm_usuarios"])
        self.assertTrue(supervisor_perms["perm_frota"])

        # Tech gets checklist and training mobile
        tech_perms = get_default_perms("tech")
        self.assertTrue(tech_perms["perm_checklist_mobile"])
        self.assertTrue(tech_perms["perm_treinamentos_mobile"])
        self.assertFalse(tech_perms["perm_manutencao_os"])

        # Manutencao gets manutencao_os
        man_perms = get_default_perms("manutencao")
        self.assertTrue(man_perms["perm_manutencao_os"])
        self.assertFalse(man_perms["perm_checklist_mobile"])

if __name__ == "__main__":
    unittest.main()
