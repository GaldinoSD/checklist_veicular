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
        """Valida que o técnico é redirecionado diretamente para o checklist mobile ao acessar o sistema."""
        # Login como técnico
        self.client.post("/login", data={
            "username": self.tech_user.username,
            "password": "senha123"
        })

        # Acessa /inicio diretamente -> redireciona para /checklist
        resp = self.client.get("/inicio")
        self.assertEqual(resp.status_code, 302)
        self.assertTrue(resp.headers["Location"].endswith("/checklist"))

        # Acessa /dashboard como técnico -> deve redirecionar para /checklist
        dash_resp = self.client.get("/dashboard")
        self.assertEqual(dash_resp.status_code, 302)
        self.assertTrue(dash_resp.headers["Location"].endswith("/checklist"))

        # Acessa / (index) como técnico -> deve redirecionar para /checklist
        index_resp = self.client.get("/")
        self.assertEqual(index_resp.status_code, 302)
        self.assertTrue(index_resp.headers["Location"].endswith("/checklist"))

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

        # 2. Confirma que o técnico possui 1 APR no banco
        self.assertEqual(APR.query.filter_by(tech_id=self.tech_user.id).count(), 1)

        # 3. Técnico comum tenta excluir a APR -> deve ser bloqueado com 403
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
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

        # 6. Confirma que a contagem do técnico no banco agora é 0 APRs
        self.assertEqual(APR.query.filter_by(tech_id=self.tech_user.id).count(), 0)

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

    def test_fator_pessoal_evaluation_and_blocking(self):
        """Valida a seção de Fator Pessoal de Segurança, justificativa e bloqueio caso 'SIM'."""
        item_pessoal = APRItemConfig.query.filter_by(category="fator_pessoal").first()
        if not item_pessoal:
            item_pessoal = APRItemConfig(
                category="fator_pessoal",
                order=1,
                question_text="Existe algum fator físico ou psicológico que possa comprometer a segurança da atividade?",
                guidance="Avaliação psicofísica.",
                is_blocking_if_negative=True,
                is_active=True
            )
            db.session.add(item_pessoal)
            db.session.commit()

        # 1. Deve aparecer na tela mobile /apr
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})
        apr_page = self.client.get("/apr")
        self.assertEqual(apr_page.status_code, 200)
        self.assertIn("Fator Pessoal de Segurança", apr_page.get_data(as_text=True))
        self.assertIn("fator físico ou psicológico", apr_page.get_data(as_text=True))

        # 2. Deve aparecer na tela de configuração
        self.client.post("/login", data={"username": self.admin_user.username, "password": "senha123"})
        cfg_page = self.client.get("/configuracao/apr")
        self.assertEqual(cfg_page.status_code, 200)
        self.assertIn("Fator Pessoal", cfg_page.get_data(as_text=True))

        # 3. Enviar APR com Fator Pessoal = SIM -> Deve bloquear por critério impeditivo
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.tech_user.id)
            sess["csrf_token"] = "test_token"

        payload_sim = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua Teste, 100",
            f"item_{item_pessoal.id}": "sim",
            f"justif_{item_pessoal.id}": "Técnico relatando tontura e mal-estar."
        }
        resp_sim = self.client.post("/api/apr/salvar", data=payload_sim)
        self.assertEqual(resp_sim.status_code, 200)
        data_sim = resp_sim.get_json()
        self.assertTrue(data_sim["success"])
        self.assertEqual(data_sim["status"], "bloqueada")
        self.assertTrue(data_sim["has_blocking"])

        # 4. Enviar APR com Fator Pessoal = NÃO -> Deve liberar
        payload_nao = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua Teste, 100",
            f"item_{item_pessoal.id}": "nao"
        }
        resp_nao = self.client.post("/api/apr/salvar", data=payload_nao)
        self.assertEqual(resp_nao.status_code, 200)
        data_nao = resp_nao.get_json()
        self.assertTrue(data_nao["success"])
        self.assertEqual(data_nao["status"], "liberada")
        self.assertFalse(data_nao["has_blocking"])

    def test_apr_auxiliary_technician_flow(self):
        """Testa o fluxo completo com técnico auxiliar: seleção, obrigatoriedade de assinatura e laudo PDF."""
        # 1. Login como técnico líder
        self.client.post("/login", data={"username": self.tech_user.username, "password": "senha123"})

        # Simulação de base64 de assinatura PNG válida de 1x1 pixel
        dummy_sig = "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNk+M9QDwADhgGAWjR9awAAAABJRU5ErkJggg=="

        # 2. Tenta salvar com técnico auxiliar MAS sem a assinatura dele -> Deve retornar 400
        payload_sem_aux_sig = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua das Palmeiras, 45",
            "signature_data": dummy_sig,
            "auxiliary_tech_id": self.helper_tech.id
        }
        resp_fail = self.client.post("/api/apr/salvar", data=payload_sem_aux_sig)
        self.assertEqual(resp_fail.status_code, 400)
        self.assertIn("A assinatura do técnico auxiliar é obrigatória", resp_fail.get_json()["message"])

        # 3. Salva com técnico auxiliar E ambas as assinaturas
        payload_completo = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua das Palmeiras, 45",
            "signature_data": dummy_sig,
            "auxiliary_tech_id": self.helper_tech.id,
            "auxiliary_signature_data": dummy_sig
        }
        resp_ok = self.client.post("/api/apr/salvar", data=payload_completo)
        self.assertEqual(resp_ok.status_code, 200)
        data_ok = resp_ok.get_json()
        self.assertTrue(data_ok["success"])

        # 4. Verifica no banco que a APR gravou o auxiliary_tech_id e o membro de equipe
        apr = APR.query.filter_by(protocol=data_ok["protocol"]).first()
        self.assertIsNotNone(apr)
        self.assertEqual(apr.auxiliary_tech_id, self.helper_tech.id)
        self.assertIsNotNone(apr.signature_image)
        self.assertIsNotNone(apr.auxiliary_signature_image)
        
        # 5. Membro da equipe registrado
        self.assertTrue(any(m.user_id == self.helper_tech.id for m in apr.membros))

        # 6. Gera o PDF da APR para verificar que renderiza sem erros com técnico auxiliar
        pdf_resp = self.client.get(f"/apr/{apr.id}/pdf")
        self.assertEqual(pdf_resp.status_code, 200)
        self.assertEqual(pdf_resp.headers["Content-Type"], "application/pdf")

        # 7. Salva APR individual (sem auxiliar) e valida que o PDF também gera perfeitamente
        payload_solo = {
            "csrf_token": "test_token",
            "activity_type": "Instalação Residencial FTTH",
            "local_description": "Rua das Palmeiras, 45",
            "signature_data": dummy_sig
        }
        resp_solo = self.client.post("/api/apr/salvar", data=payload_solo)
        self.assertEqual(resp_solo.status_code, 200)
        apr_solo = APR.query.filter_by(protocol=resp_solo.get_json()["protocol"]).first()
        pdf_solo_resp = self.client.get(f"/apr/{apr_solo.id}/pdf")
        self.assertEqual(pdf_solo_resp.status_code, 200)
        self.assertEqual(pdf_solo_resp.headers["Content-Type"], "application/pdf")

if __name__ == "__main__":
    unittest.main()

