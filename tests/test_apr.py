import json
import unittest
from app import app, db, User, APR, APRMembro, APRItemConfig, APRResposta, APRActivityType

class TestAPRModule(unittest.TestCase):
    def setUp(self):
        self.app = app
        self.client = self.app.test_client()
        self.app_context = self.app.app_context()
        self.app_context.push()

        # Configura banco em memória para isolamento de testes
        db.create_all()

        # Cria usuários de teste únicos
        import uuid
        uid = uuid.uuid4().hex[:6].upper()
        self.tech_user = User(username=f"TECH_WELTON_{uid}", full_name="Welton TST", role="tech")
        self.tech_user.set_password("senha123")
        db.session.add(self.tech_user)

        self.helper_tech = User(username=f"TECH_AUX_{uid}", full_name="Carlos Auxiliar", role="tech")
        self.helper_tech.set_password("senha123")
        db.session.add(self.helper_tech)

        self.admin_user = User(username=f"ADMIN_SST_{uid}", full_name="Gestor SST", role="admin")
        self.admin_user.set_password("senha123")
        db.session.add(self.admin_user)

        db.session.commit()

        # Cria ou obtém perguntas de teste
        self.item_geral = APRItemConfig.query.filter_by(category="geral").first()
        if not self.item_geral:
            self.item_geral = APRItemConfig(
                category="geral",
                order=1,
                question_text="EPIs obrigatórios verificados?",
                is_blocking_if_negative=True,
                requires_photo=False,
                is_active=True
            )
            db.session.add(self.item_geral)

        self.item_altura = APRItemConfig.query.filter_by(category="altura_nr35").first()
        if not self.item_altura:
            self.item_altura = APRItemConfig(
                category="altura_nr35",
                order=1,
                question_text="A escada de fibra está íntegra e amarrada no topo?",
                is_blocking_if_negative=True,
                requires_photo=True,
                is_active=True
            )
            db.session.add(self.item_altura)

        db.session.commit()

    def tearDown(self):
        db.session.rollback()
        self.app_context.pop()

    def test_tech_has_apr_mobile_permission_by_default(self):
        """Verifica se o técnico tem a permissão apr_mobile nativamente."""
        self.assertTrue(self.tech_user.has_permission("apr_mobile"))
        self.assertTrue(self.tech_user.has_permission("perm_apr_mobile"))
        self.assertTrue(self.admin_user.has_permission("apr_mobile"))
        self.assertTrue(self.admin_user.has_permission("apr_gerenciamento"))
        self.assertTrue(self.admin_user.has_permission("config_apr"))

    def test_save_apr_without_blocking_condition(self):
        """Salva APR com todas as verificações OK e coordenadas GPS -> status liberada."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.tech_user.id)
            sess["csrf_token"] = "test_token"

        payload = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua das Laranjeiras, 45",
            "latitude": "-22.903200",
            "longitude": "-43.178200",
            "os_number": "OS-12345",
            "risk_factors": json.dumps(["altura"]),
            f"item_{self.item_geral.id}": "sim",
            f"item_{self.item_altura.id}": "sim",
            "general_notes": "Local seguro e sinalizado."
        }

        resp = self.client.post("/api/apr/salvar", data=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "liberada")
        self.assertFalse(data["has_blocking"])

        # Valida no banco
        apr = APR.query.filter_by(protocol=data["protocol"]).first()
        self.assertIsNotNone(apr)
        self.assertEqual(apr.tech_id, self.tech_user.id)
        self.assertAlmostEqual(apr.latitude, -22.9032, places=4)
        self.assertAlmostEqual(apr.longitude, -43.1782, places=4)

    def test_save_apr_with_blocking_condition_no_emergency_measure(self):
        """Salva APR com 'não' em item impeditivo e sem medida -> status bloqueada."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.tech_user.id)
            sess["csrf_token"] = "test_token"

        payload = {
            "csrf_token": "test_token",
            "activity_type": "Manutenção em Poste",
            "local_description": "Av. Brasil, 100",
            "risk_factors": json.dumps(["altura"]),
            f"item_{self.item_geral.id}": "sim",
            f"item_{self.item_altura.id}": "nao",  # Impeditivo!
            "emergency_measure_notes": ""  # Sem medida
        }

        resp = self.client.post("/api/apr/salvar", data=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "bloqueada")
        self.assertTrue(data["has_blocking"])

    def test_save_apr_with_blocking_condition_and_emergency_measure(self):
        """Salva APR com item impeditivo tratado com medida emergencial -> status liberada (Opção B)."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.tech_user.id)
            sess["csrf_token"] = "test_token"

        payload = {
            "csrf_token": "test_token",
            "activity_type": "Manutenção de Rede",
            "local_description": "Rua B, 200",
            "risk_factors": json.dumps(["altura"]),
            f"item_{self.item_geral.id}": "sim",
            f"item_{self.item_altura.id}": "nao",  # Impeditivo
            "emergency_measure_notes": "Realizada amarração secundária e poda preventiva autorizada pela moradora."
        }

        resp = self.client.post("/api/apr/salvar", data=payload)
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertTrue(data["success"])
        self.assertEqual(data["status"], "liberada")
        self.assertTrue(data["has_blocking"])

        apr = APR.query.filter_by(protocol=data["protocol"]).first()
        self.assertEqual(apr.status, "liberada")
        self.assertIn("amarração secundária", apr.emergency_measure_notes)

    def test_api_apr_details_endpoint(self):
        """Testa o endpoint de auditoria JSON da APR."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_user.id)

        apr = APR(
            protocol="APR-TEST-0001",
            tech_id=self.tech_user.id,
            activity_type="Instalação",
            local_description="Rua Teste, 1",
            status="liberada"
        )
        db.session.add(apr)
        db.session.commit()

        resp = self.client.get(f"/api/apr/{apr.id}")
        self.assertEqual(resp.status_code, 200)
        data = resp.get_json()
        self.assertEqual(data["protocol"], "APR-TEST-0001")
        self.assertEqual(data["tech"]["name"], self.tech_user.display_name)

    def test_config_apr_crud(self):
        """Testa a criação, toggle e exclusão de perguntas da APR."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_user.id)
            sess["csrf_token"] = "test_token"

        # 1. Criação
        payload = {
            "csrf_token": "test_token",
            "category": "eletrica_nr10",
            "question_text": "Detector de tensão utilizado nas ferragens?",
            "guidance": "NR-10 Obrigatório",
            "order": 1,
            "is_blocking_if_negative": "on",
            "requires_photo": "on"
        }
        resp = self.client.post("/api/apr/config/item", data=payload)
        self.assertEqual(resp.status_code, 200)

        item = APRItemConfig.query.filter_by(question_text="Detector de tensão utilizado nas ferragens?").first()
        self.assertIsNotNone(item)
        self.assertTrue(item.is_blocking_if_negative)
        self.assertTrue(item.requires_photo)

        # 2. Toggle active
        toggle_resp = self.client.post("/api/apr/config/toggle",
                                       headers={"X-CSRFToken": "test_token"},
                                       json={"item_id": item.id, "field": "is_active"})
        self.assertEqual(toggle_resp.status_code, 200)
        self.assertFalse(toggle_resp.get_json()["is_active"])

        # 3. Exclusão
        del_resp = self.client.post(f"/api/apr/config/delete/{item.id}",
                                    headers={"X-CSRFToken": "test_token"})
        self.assertEqual(del_resp.status_code, 200)
        self.assertIsNone(APRItemConfig.query.get(item.id))

    def test_inicio_tecnico_page(self):
        """Valida que o técnico acessa a página de início personalizada e os redirecionamentos corretos."""
        # Login como técnico
        self.client.post("/login", data={
            "username": self.tech_user.username,
            "password": "senha123"
        })

        # Acessa /inicio diretamente
        resp = self.client.get("/inicio")
        self.assertEqual(resp.status_code, 200)
        html = resp.get_data(as_text=True)
        self.assertIn("Análise Preliminar de Risco", html)
        self.assertIn("Checklist Veicular Semanal", html)
        self.assertIn("Treinamentos", html)
        self.assertIn("Próximo Plantão", html)
        self.assertIn(self.tech_user.display_name, html)

        # Acessa /dashboard como técnico -> deve redirecionar para /inicio
        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 302)
        self.assertTrue(dash_resp.headers["Location"].endswith("/inicio"))

        # Acessa / (index) como técnico -> deve redirecionar para /inicio
        index_resp = self.client.get("/")
        self.assertEqual(index_resp.status_code, 302)
        self.assertTrue(index_resp.headers["Location"].endswith("/inicio"))

    def test_admin_delete_apr_and_deduct_tech_total(self):
        """Valida que a exclusão de uma APR pelo admin deduz automaticamente da contagem do técnico."""
        # 1. Cria uma APR diretamente para o técnico
        apr = APR(
            protocol="APR-TEST-DEDUCT-001",
            tech_id=self.tech_user.id,
            activity_type="Instalação",
            local_description="Rua Teste, 100",
            status="liberada"
        )
        db.session.add(apr)
        db.session.commit()

        # 2. Confirma que a contagem do técnico na tela de início reflete 1 APR
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
        resp = self.client.get("/inicio")
        self.assertEqual(resp.status_code, 200)
        self.assertIn("1", resp.get_data(as_text=True))

        # 3. Técnico comum tenta excluir a APR -> deve ser bloqueado com 403
        del_tech_resp = self.client.post(f"/api/apr/{apr.id}/delete")
        self.assertEqual(del_tech_resp.status_code, 403)

        # 4. Login como Admin e exclui a APR
        self.client.post("/login", data={"username": self.admin_user.username, "password": "senha123"})
        del_admin_resp = self.client.post(f"/api/apr/{apr.id}/delete")
        self.assertEqual(del_admin_resp.status_code, 200)
        json_data = del_admin_resp.get_json()
        self.assertTrue(json_data["success"])
        self.assertEqual(json_data["novo_total_tecnico"], 0)

        # 5. Verifica que o registro não existe mais no banco
        self.assertIsNone(db.session.get(APR, apr.id))

        # 6. Login novamente como técnico -> tela de início agora exibe 0 APRs
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
        resp_after = self.client.get("/inicio")
        self.assertEqual(resp_after.status_code, 200)
        self.assertIn("0", resp_after.get_data(as_text=True))

    def test_config_activity_types(self):
        """Testa o gerenciamento completo de tipos de atividade (criar, editar, duplicidade, toggle, exclusão e exibição na APR)."""
        # 1. Login como Admin
        self.client.post("/login", data={"username": self.admin_user.username, "password": "senha123"})

        # 2. Criar nova atividade
        resp_create = self.client.post("/api/apr/config/activity", data={
            "name": "Manutenção Subterrânea em Galeria",
            "order": 5
        })
        self.assertEqual(resp_create.status_code, 200)
        self.assertTrue(resp_create.get_json()["success"])

        act = APRActivityType.query.filter_by(name="Manutenção Subterrânea em Galeria").first()
        self.assertIsNotNone(act)
        self.assertEqual(act.order, 5)
        self.assertTrue(act.is_active)

        # 3. Tentar criar duplicada -> deve retornar erro 400
        resp_dup = self.client.post("/api/apr/config/activity", data={
            "name": "manutenção subterrânea em galeria",
            "order": 10
        })
        self.assertEqual(resp_dup.status_code, 400)
        self.assertFalse(resp_dup.get_json()["success"])

        # 4. Editar a atividade
        resp_edit = self.client.post("/api/apr/config/activity", data={
            "activity_id": act.id,
            "name": "Manutenção em Galeria Subterrânea",
            "order": 2
        })
        self.assertEqual(resp_edit.status_code, 200)
        db.session.refresh(act)
        self.assertEqual(act.name, "Manutenção em Galeria Subterrânea")
        self.assertEqual(act.order, 2)

        # 5. Verificar que a nova atividade aparece no formulário mobile da APR (/apr)
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
        apr_page = self.client.get("/apr")
        self.assertEqual(apr_page.status_code, 200)
        self.assertIn("Manutenção em Galeria Subterrânea", apr_page.get_data(as_text=True))

        # 6. Desativar a atividade (toggle)
        self.client.post("/login", data={"username": self.admin_user.username, "password": "senha123"})
        resp_toggle = self.client.post("/api/apr/config/activity/toggle", json={"activity_id": act.id})
        self.assertEqual(resp_toggle.status_code, 200)
        self.assertFalse(resp_toggle.get_json()["is_active"])
        db.session.refresh(act)
        self.assertFalse(act.is_active)

        # 7. Desativada não deve aparecer no formulário da APR para o técnico
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
        apr_page_inactive = self.client.get("/apr")
        self.assertNotIn("Manutenção em Galeria Subterrânea", apr_page_inactive.get_data(as_text=True))

        # 8. Excluir a atividade
        self.client.post("/login", data={"username": self.admin_user.username, "password": "senha123"})
        resp_del = self.client.post(f"/api/apr/config/activity/delete/{act.id}")
        self.assertEqual(resp_del.status_code, 200)
        self.assertIsNone(APRActivityType.query.get(act.id))

if __name__ == "__main__":
    unittest.main()

