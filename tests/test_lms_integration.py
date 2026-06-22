import unittest
import json
from datetime import date
from app import app, db, User, TrainingCourse, TrainingAssignment, TrainingAttempt, TrainingModule, TrainingQuestion

class TestLMSIntegration(unittest.TestCase):
    def test_lms_flow(self):
        with app.test_client() as client:
            # 1. Simular autenticação como Admin/Supervisor (ID 1)
            with client.session_transaction() as sess:
                sess['_user_id'] = '1'

            # 2. Criar um novo treinamento via POST /api/gestao/treinamentos_lms
            course_payload = {
                "title": "Treinamento de Direção Defensiva 2026",
                "description": "Curso completo de direção defensiva e segurança veicular no trabalho de campo.",
                "category": "Segurança",
                "passing_grade": 80,
                "is_mandatory": True,
                "deadline": "2026-12-31",
                "badge_name": "Campeão da Segurança",
                "badge_icon": "fa-shield-halved",
                "badge_color": "#14b8a6",
                "allow_retake": True,
                "modules": [
                    {
                        "title": "Módulo 1: Conceitos Básicos",
                        "content": "Direção defensiva é o ato de conduzir de modo a evitar acidentes, apesar das ações incorretas dos outros e das condições adversas."
                    },
                    {
                        "title": "Módulo 2: Manutenção Preventiva",
                        "content": "Verificar freios, óleo, pneus e água antes de sair de viagem é essencial para a prevenção de acidentes."
                    }
                ],
                "questions": [
                    {
                        "question_text": "O que é direção defensiva?",
                        "option_a": "Dirigir o mais rápido possível",
                        "option_b": "Evitar acidentes apesar de condições adversas e erros de terceiros",
                        "option_c": "Dirigir apenas em rodovias federais",
                        "option_d": "Não usar o cinto de segurança",
                        "correct_option": "b"
                    },
                    {
                        "question_text": "Qual item deve ser verificado diariamente?",
                        "option_a": "Pressão dos pneus e níveis de fluidos",
                        "option_b": "A cor do veículo",
                        "option_c": "O rádio e som",
                        "option_d": "O estofamento dos bancos",
                        "correct_option": "a"
                    }
                ]
            }

            resp = client.post("/api/gestao/treinamentos_lms", json=course_payload)
            self.assertEqual(resp.status_code, 200, f"Erro na criação: {resp.data.decode('utf-8')}")
                
            res_data = resp.get_json()
            course_id = res_data.get("id")
            self.assertIsNotNone(course_id)

            # 3. Listar treinamentos (Admin)
            resp = client.get("/api/gestao/treinamentos_lms")
            self.assertEqual(resp.status_code, 200)
            courses_list = resp.get_json()
            created_course = next((c for c in courses_list if c["id"] == course_id), None)
            self.assertIsNotNone(created_course, "Treinamento recém-criado não foi encontrado na listagem!")

            # 4. Publicar treinamento
            resp = client.post(f"/api/gestao/treinamentos_lms/{course_id}/publicar")
            self.assertEqual(resp.status_code, 200)
            pub_data = resp.get_json()
            self.assertTrue(pub_data.get('is_published'), "Falha ao publicar o treinamento!")

            # 5. Listar treinamentos associados ao usuário (User Mobile)
            resp = client.get("/api/treinamentos/meus")
            self.assertEqual(resp.status_code, 200)
            meus_treinamentos = resp.get_json()
            my_course = next((c for c in meus_treinamentos if c["course_id"] == course_id), None)
            self.assertIsNotNone(my_course, "Treinamento publicado não foi atribuído ao colaborador logado!")

            # 6. Carregar conteúdo do treinamento para estudo
            resp = client.get(f"/api/treinamentos/{course_id}/conteudo")
            self.assertEqual(resp.status_code, 200)
            content_data = resp.get_json()
            
            mod_id_1 = content_data['modules'][0]['id']
            mod_id_2 = content_data['modules'][1]['id']
            q_id_1 = content_data['questions'][0]['id']
            q_id_2 = content_data['questions'][1]['id']

            # 7. Marcar módulos como lidos
            resp = client.post(f"/api/treinamentos/{course_id}/mark_module", json={"module_id": mod_id_1})
            self.assertEqual(resp.status_code, 200)
            
            resp = client.post(f"/api/treinamentos/{course_id}/mark_module", json={"module_id": mod_id_2})
            self.assertEqual(resp.status_code, 200)

            # Verificar progresso de leitura
            resp = client.get("/api/treinamentos/meus")
            my_course = next((c for c in resp.get_json() if c["course_id"] == course_id), None)
            self.assertEqual(my_course['modules_read'], 2, "O progresso de leitura de módulos não foi incrementado corretamente!")

            # 8. Responder avaliação e reprovar de propósito (Errar uma das questões)
            answers_wrong = {
                str(q_id_1): "b", # Certa
                str(q_id_2): "c"  # Errada
            }
            resp = client.post(f"/api/treinamentos/{course_id}/responder", json={"answers": answers_wrong})
            self.assertEqual(resp.status_code, 200)
            wrong_data = resp.get_json()
            self.assertFalse(wrong_data['passed'], "Colaborador deveria ter sido reprovado!")

            # 9. Responder avaliação e ser aprovado com 100% de sucesso
            answers_correct = {
                str(q_id_1): "b", # Certa
                str(q_id_2): "a"  # Certa
            }
            resp = client.post(f"/api/treinamentos/{course_id}/responder", json={"answers": answers_correct})
            self.assertEqual(resp.status_code, 200)
            correct_data = resp.get_json()
            self.assertTrue(correct_data['passed'], "Colaborador deveria ter sido aprovado!")

            # 10. Listar selos do colaborador
            resp = client.get("/api/treinamentos/meus_selos")
            self.assertEqual(resp.status_code, 200)
            badges = resp.get_json()
            safety_badge = next((b for b in badges if b["badge_name"] == "Campeão da Segurança"), None)
            self.assertIsNotNone(safety_badge, "Selo 'Campeão da Segurança' não foi concedido!")

            # 11. Testar o Preview de Relatórios LMS contendo a nova tentativa
            resp = client.get("/api/gestao/relatorios/preview?type=lms")
            self.assertEqual(resp.status_code, 200)
            preview_data = resp.get_json()
            self.assertGreaterEqual(len(preview_data['records']), 2, "O relatório do LMS deveria listar as 2 tentativas!")

            # 12. Limpar banco
            resp = client.delete(f"/api/gestao/treinamentos_lms/{course_id}")
            self.assertEqual(resp.status_code, 200, "Falha ao excluir o treinamento de teste!")

if __name__ == "__main__":
    unittest.main()
