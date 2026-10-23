# -*- coding: utf-8 -*-
import unittest
import json
from app import app, db, User, AccessProfile

class TestPerfisDinamicos(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()
        self.ctx = app.app_context()
        self.ctx.push()

        # Garante um usuário admin autenticado na sessão de teste
        admin_user = User.query.filter_by(username="ADMIN").first()
        if not admin_user:
            admin_user = User(username="admin", role="admin")
            admin_user.set_password("AdminPass123!")
            db.session.add(admin_user)
            db.session.commit()
        self.admin_id = admin_user.id

    def tearDown(self):
        self.ctx.pop()

    def test_01_perfis_padrao_existentes(self):
        """Verifica se os 4 perfis padrão estão cadastrados no banco."""
        perfis = AccessProfile.query.all()
        slugs = {p.slug for p in perfis}
        self.assertIn("admin", slugs)
        self.assertIn("supervisor", slugs)
        self.assertIn("tech", slugs)
        self.assertIn("manutencao", slugs)

    def test_02_criacao_novo_perfil(self):
        """Testa criação de um novo perfil customizado com permissões específicas."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        # Cria perfil "auditor_qualidade"
        data = {
            "name": "Auditor de Qualidade",
            "slug": "auditor_qualidade",
            "description": "Responsável por auditar checklists e vistorias",
            "color": "sky",
            "perm_relatorios": "on",
            "perm_vistorias_list": "on",
            "perm_checklists_view": "on"
        }
        res = self.client.post("/perfis/novo", data=data, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Verifica persistência
        prof = AccessProfile.query.filter_by(slug="auditor_qualidade").first()
        self.assertIsNotNone(prof)
        self.assertEqual(prof.name, "Auditor de Qualidade")
        self.assertTrue(prof.has_permission("relatorios"))
        self.assertTrue(prof.has_permission("vistorias_list"))
        self.assertFalse(prof.has_permission("usuarios"))

    def test_03_sincronizacao_dinamica_usuario_perfil(self):
        """Testa se usuário herda imediatamente permissões do perfil do banco."""
        # Cria perfil temporário
        prof = AccessProfile(
            name="Operador Teste",
            slug="operador_teste",
            description="Teste dinâmico",
            color="emerald",
            permissions=json.dumps({"perm_checklist_mobile": True, "perm_avarias": False})
        )
        db.session.add(prof)

        # Cria usuário associado a esse perfil sem permissões granulares
        u = User(username="USER_TEST_SYNC", role="operador_teste", permissions=json.dumps({}))
        u.set_password("123456")
        db.session.add(u)
        db.session.commit()

        # Inicialmente deve ter checklist_mobile
        self.assertTrue(u.has_permission("checklist_mobile"))
        self.assertFalse(u.has_permission("avarias"))

        # Atualiza o perfil para adicionar permissão 'avarias'
        prof.permissions = json.dumps({"perm_checklist_mobile": True, "perm_avarias": True})
        db.session.commit()

        # O usuário deve ter imediatamente a permissão 'avarias' refletida!
        self.assertTrue(u.has_permission("avarias"))

        # Permissão granular extra no usuário: dar 'perm_frota'
        u.permissions = json.dumps({"perm_frota": True})
        db.session.commit()

        # Agora usuário deve ter checklist_mobile, avarias (do perfil) E frota (granular)!
        self.assertTrue(u.has_permission("checklist_mobile"))
        self.assertTrue(u.has_permission("avarias"))
        self.assertTrue(u.has_permission("frota"))

    def test_04_edicao_perfil_com_migracao_de_slug(self):
        """Testa se renomear o slug migra automaticamente os usuários daquele perfil."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        # Cria perfil "tech_antigo"
        prof = AccessProfile(
            name="Técnico Legado",
            slug="tech_antigo",
            permissions=json.dumps({"perm_checklist_mobile": True})
        )
        db.session.add(prof)

        # Cria 2 usuários com 'tech_antigo'
        u1 = User(username="TECH_MIG_1", role="tech_antigo")
        u1.set_password("123")
        u2 = User(username="TECH_MIG_2", role="tech_antigo")
        u2.set_password("123")
        db.session.add_all([u1, u2])
        db.session.commit()

        # Executa edição renomeando para 'tecnico_novo'
        edit_data = {
            "name": "Técnico Renovado",
            "slug": "tecnico_novo",
            "description": "Novo perfil modernizado",
            "color": "teal",
            "perm_checklist_mobile": "on"
        }
        res = self.client.post(f"/perfis/{prof.id}/editar", data=edit_data, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        # Checa se o perfil mudou
        db.session.refresh(prof)
        self.assertEqual(prof.slug, "tecnico_novo")
        self.assertEqual(prof.name, "Técnico Renovado")

        # Checa se os usuários foram migrados atomicamente para 'tecnico_novo'
        u1_updated = User.query.filter_by(username="TECH_MIG_1").first()
        u2_updated = User.query.filter_by(username="TECH_MIG_2").first()
        self.assertEqual(u1_updated.role, "tecnico_novo")
        self.assertEqual(u2_updated.role, "tecnico_novo")
        self.assertTrue(u1_updated.has_permission("checklist_mobile"))

    def test_05_seguranca_exclusao_perfil(self):
        """Não permite excluir admin ou perfil com colaboradores vinculados."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        # 1. Admin não pode ser excluído
        admin_prof = AccessProfile.query.filter_by(slug="admin").first()
        res_admin = self.client.post(f"/perfis/{admin_prof.id}/excluir", follow_redirects=True)
        self.assertEqual(res_admin.status_code, 200)
        self.assertIsNotNone(AccessProfile.query.filter_by(slug="admin").first())

        # 2. Perfil com usuário vinculado não pode ser excluído
        tech_prof = AccessProfile.query.filter_by(slug="tech").first()
        if not tech_prof:
            tech_prof = AccessProfile(name="Técnico", slug="tech")
            db.session.add(tech_prof)
            db.session.commit()

        u_tech = User(username="TECH_VINCULADO", role="tech")
        u_tech.set_password("123")
        db.session.add(u_tech)
        db.session.commit()

        res_tech = self.client.post(f"/perfis/{tech_prof.id}/excluir", follow_redirects=True)
        self.assertEqual(res_tech.status_code, 200)
        self.assertIsNotNone(AccessProfile.query.filter_by(slug="tech").first())

        # 3. Perfil sem nenhum usuário vinculado pode ser excluído
        avulso = AccessProfile(name="Perfil Temporario", slug="perfil_temp_del")
        db.session.add(avulso)
        db.session.commit()
        avulso_id = avulso.id

        res_del = self.client.post(f"/perfis/{avulso_id}/excluir", follow_redirects=True)
        self.assertEqual(res_del.status_code, 200)
        self.assertIsNone(AccessProfile.query.get(avulso_id))

    def test_06_renderizacao_pagina_usuarios_e_perfis(self):
        """Verifica se as abas e o template carregam com status 200."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        res1 = self.client.get("/usuarios")
        self.assertEqual(res1.status_code, 200)
        self.assertIn("Usuários e Permissões", res1.data.decode("utf-8"))
        self.assertIn("Perfis de Acesso", res1.data.decode("utf-8"))
        self.assertIn("Meus Plantões", res1.data.decode("utf-8"))

        res2 = self.client.get("/usuarios?tab=perfis")
        self.assertEqual(res2.status_code, 200)
        self.assertIn("Como funcionam os Perfis de Acesso?", res2.data.decode("utf-8"))

    def test_07_meus_plantoes_e_marcar_desmarcar(self):
        """Verifica se marcar e desmarcar no granular salva e reflete exatamente."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        # Cria ou obtém usuário de teste
        u_test = User.query.filter_by(username="TEST_MARCAR_DESMARCAR").first()
        if not u_test:
            u_test = User(username="TEST_MARCAR_DESMARCAR", role="tech")
            u_test.set_password("123")
            db.session.add(u_test)
            db.session.commit()

        # 1. Por herança do perfil tech, tem acesso a meus_plantoes
        u_test.permissions = None
        db.session.commit()
        self.assertTrue(u_test.has_permission("meus_plantoes"))
        self.assertTrue(u_test.has_permission("perm_meus_plantoes"))

        # 2. Desmarca "perm_meus_plantoes" explicitamente para esse usuário
        # Ao desmarcar no formulário, a chave não é enviada (ou fica off)
        form_data = {
            "perm_checklist_mobile": "on"
            # perm_meus_plantoes NÃO enviado = desmarcado
        }
        res = self.client.post(f"/usuarios/{u_test.id}/permissions", data=form_data, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        db.session.refresh(u_test)
        self.assertIsNotNone(u_test.permissions)
        # Agora o usuário teve a permissão revogada individualmente
        self.assertFalse(u_test.has_permission("meus_plantoes"))
        self.assertFalse(u_test.has_permission("perm_meus_plantoes"))
        self.assertTrue(u_test.has_permission("checklist_mobile"))

        # 3. Marca novamente "perm_meus_plantoes"
        form_data_2 = {
            "perm_checklist_mobile": "on",
            "perm_meus_plantoes": "on"
        }
        res2 = self.client.post(f"/usuarios/{u_test.id}/permissions", data=form_data_2, follow_redirects=True)
        self.assertEqual(res2.status_code, 200)

        db.session.refresh(u_test)
        self.assertTrue(u_test.has_permission("meus_plantoes"))
        self.assertTrue(u_test.has_permission("perm_meus_plantoes"))

    def test_08_reset_permissions(self):
        """Verifica a restauração de permissões para o padrão do perfil."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        u_test = User.query.filter_by(username="TEST_RESET_PERMS").first()
        if not u_test:
            u_test = User(username="TEST_RESET_PERMS", role="tech")
            u_test.set_password("123")
            u_test.permissions = json.dumps({"perm_checklist_mobile": False})
            db.session.add(u_test)
            db.session.commit()

        self.assertIsNotNone(u_test.permissions)

        res = self.client.post(f"/usuarios/{u_test.id}/reset_permissions", follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        db.session.refresh(u_test)
        self.assertIsNone(u_test.permissions)
        # Volta a herdar dinamicamente do perfil tech
        self.assertTrue(u_test.has_permission("checklist_mobile"))
        self.assertTrue(u_test.has_permission("meus_plantoes"))

    def test_09_redirecionamento_dinamico_landing_page(self):
        """Verifica se perfil sem checklist cai na primeira página liberada."""
        # Cria perfil que só tem 'meus_plantoes'
        prof_plantoes = AccessProfile.query.filter_by(slug="apenas_plantoes").first()
        if not prof_plantoes:
            prof_plantoes = AccessProfile(
                name="Apenas Plantões",
                slug="apenas_plantoes",
                permissions=json.dumps({"perm_meus_plantoes": True})
            )
            db.session.add(prof_plantoes)
            db.session.commit()

        u_plantao = User.query.filter_by(username="USER_PLANTAO").first()
        if not u_plantao:
            u_plantao = User(username="USER_PLANTAO", role="apenas_plantoes")
            u_plantao.set_password("pass123")
            db.session.add(u_plantao)
            db.session.commit()

        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(u_plantao.id)

        # Acessa a raiz '/' -> Deve redirecionar para '/meus-plantoes'
        res_root = self.client.get("/", follow_redirects=False)
        self.assertEqual(res_root.status_code, 302)
        self.assertIn("/meus-plantoes", res_root.headers.get("Location", ""))

    def test_10_bloqueio_paginas_sem_permissao(self):
        """Verifica se usuário sem permissão de checklist é bloqueado ao acessar /checklist."""
        u_plantao = User.query.filter_by(username="USER_PLANTAO").first()
        self.assertIsNotNone(u_plantao)

        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(u_plantao.id)

        # Tenta acessar /checklist diretamente -> Deve ser bloqueado e redirecionado para /meus-plantoes
        res_check = self.client.get("/checklist", follow_redirects=False)
        self.assertEqual(res_check.status_code, 302)
        self.assertIn("/meus-plantoes", res_check.headers.get("Location", ""))

        # Se seguir o redirect, carrega a página liberada com mensagem flash
        res_followed = self.client.get("/checklist", follow_redirects=True)
        self.assertEqual(res_followed.status_code, 200)
        self.assertIn("Acesso não autorizado ao módulo de Checklist", res_followed.data.decode("utf-8"))

    def test_11_trocar_perfil_usuario_com_slug_longo(self):
        """Verifica se editar um usuário e trocar para um perfil com slug longo funciona sem 500."""
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(self.admin_id)

        # Perfil com mais de 20 caracteres no slug
        long_slug = "seguranca_do_trabalho"
        prof = AccessProfile.query.filter_by(slug=long_slug).first()
        if not prof:
            prof = AccessProfile(
                name="Segurança do Trabalho",
                slug=long_slug,
                permissions=json.dumps({"perm_meus_plantoes": True, "perm_apr_mobile": True})
            )
            db.session.add(prof)
            db.session.commit()

        u_edit = User.query.filter_by(username="USER_EDIT_ROLE").first()
        if not u_edit:
            u_edit = User(username="USER_EDIT_ROLE", role="tech")
            u_edit.set_password("pass123")
            db.session.add(u_edit)
            db.session.commit()

        # Envia POST para /usuarios/<uid>/papel trocando para o novo perfil
        post_data = {
            "full_name": "Colaborador Segurança",
            "role": long_slug,
            "email": "seguranca@empresa.com",
            "phone": "21988887777",
            "telegram_chat_id": ""
        }
        res = self.client.post(f"/usuarios/{u_edit.id}/papel", data=post_data, follow_redirects=True)
        self.assertEqual(res.status_code, 200)

        db.session.refresh(u_edit)
        self.assertEqual(u_edit.role, long_slug)
        self.assertEqual(u_edit.full_name, "Colaborador Segurança")
        # Permissões individuais zeradas para herdar dinamicamente
        self.assertIsNone(u_edit.permissions)
        self.assertTrue(u_edit.has_permission("meus_plantoes"))
        self.assertTrue(u_edit.has_permission("apr_mobile"))

    def test_12_notificacoes_filtradas_por_permissao(self):
        """Verifica se notificações são estritamente filtradas conforme as permissões de módulo do usuário."""
        from backend.blueprints.technical import dispatch_system_rule_alert, cleanup_old_announcements
        from backend.models import Announcement

        # Cria perfil com apenas APR liberada
        prof_apr = AccessProfile.query.filter_by(slug="apenas_apr").first()
        if not prof_apr:
            prof_apr = AccessProfile(
                name="Apenas APR",
                slug="apenas_apr",
                permissions=json.dumps({"perm_apr_mobile": True, "perm_apr_gerenciamento": True})
            )
            db.session.add(prof_apr)
            db.session.commit()

        u_apr = User.query.filter_by(username="USER_TEST_APR_NOTIF").first()
        if not u_apr:
            u_apr = User(username="USER_TEST_APR_NOTIF", role="apenas_apr")
            u_apr.set_password("pass123")
            db.session.add(u_apr)
            db.session.commit()

        # Garante que não tem checklist liberado
        self.assertFalse(u_apr.has_permission("checklist_mobile"))
        self.assertTrue(u_apr.has_permission("apr_mobile"))

        # 1. Cria anúncio direcionado de Checklist e anúncio de APR
        Announcement.query.filter_by(user_id=u_apr.id).delete()
        db.session.commit()

        ann_check = Announcement(
            title="⚠️ Lembrete: Checklist não realizado há +7 dias",
            content="Você não realiza checklist veicular há 7 dias.",
            user_id=u_apr.id
        )
        ann_apr = Announcement(
            title="📋 Análise Preliminar de Risco: Nova APR Disponível",
            content="Uma nova APR foi submetida para avaliação.",
            user_id=u_apr.id
        )
        db.session.add_all([ann_check, ann_apr])
        db.session.commit()

        # 2. Chama /api/comunicados/recent como USER_TEST_APR_NOTIF
        with self.client.session_transaction() as sess:
            sess["_user_id"] = str(u_apr.id)

        res = self.client.get("/api/comunicados/recent")
        self.assertEqual(res.status_code, 200)
        data = res.get_json()

        titles = [n["title"] for n in data["notifications"]]
        # O anúncio de checklist NÃO deve chegar/aparecer para o usuário sem permissão de checklist
        self.assertNotIn("⚠️ Lembrete: Checklist não realizado há +7 dias", titles)
        # O anúncio de APR DEVE aparecer normalmente
        self.assertIn("📋 Análise Preliminar de Risco: Nova APR Disponível", titles)

        # 3. Teste do dispatch_system_rule_alert: bloqueio preventivo de disparo
        disp_result = dispatch_system_rule_alert(
            "inactive_tech_alert",
            u_apr,
            "⚠️ Lembrete: Checklist não realizado há +7 dias",
            "Conteúdo checklist",
            bypass_silence=True
        )
        self.assertEqual(disp_result, 0)

        # 4. Limpeza automática de comunicados incompatíveis
        cleanup_old_announcements()
        remaining = Announcement.query.filter_by(user_id=u_apr.id).all()
        remaining_titles = [a.title for a in remaining]
        self.assertNotIn("⚠️ Lembrete: Checklist não realizado há +7 dias", remaining_titles)
        self.assertIn("📋 Análise Preliminar de Risco: Nova APR Disponível", remaining_titles)

if __name__ == "__main__":
    unittest.main()
