import sys
import json
from datetime import date
from app import app, db, User, TrainingCourse, TrainingAssignment, TrainingAttempt, TrainingModule, TrainingQuestion

print("=== INICIANDO SUÍTE DE TESTES INTEGRADOS DO LMS ===")

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

    print("\n[TEST] Criando novo treinamento...")
    resp = client.post("/api/gestao/treinamentos_lms", json=course_payload)
    print(f"Status: {resp.status_code}")
    if resp.status_code != 200:
        print(f"Erro na criação: {resp.data.decode('utf-8')}")
        sys.exit(1)
        
    res_data = resp.get_json()
    course_id = res_data.get("id")
    print(f"Treinamento criado com ID: {course_id}")

    # 3. Listar treinamentos (Admin)
    print("\n[TEST] Listando treinamentos administrativos...")
    resp = client.get("/api/gestao/treinamentos_lms")
    print(f"Status: {resp.status_code}")
    courses_list = resp.get_json()
    print(f"Total de treinamentos no painel: {len(courses_list)}")
    created_course = next((c for c in courses_list if c["id"] == course_id), None)
    if not created_course:
        print("[ERRO] Treinamento recém-criado não foi encontrado na listagem administrativa!")
        sys.exit(1)
    print(f"Treinamento encontrado! Total de atribuições geradas: {created_course['total_assignments']}")

    # 4. Publicar treinamento
    print("\n[TEST] Publicando o treinamento...")
    resp = client.post(f"/api/gestao/treinamentos_lms/{course_id}/publicar")
    print(f"Status: {resp.status_code}")
    pub_data = resp.get_json()
    print(f"Treinamento publicado? {pub_data.get('is_published')}")
    if not pub_data.get('is_published'):
        print("[ERRO] Falha ao publicar o treinamento!")
        sys.exit(1)

    # 5. Listar treinamentos associados ao usuário (User Mobile)
    print("\n[TEST] Consultando treinamentos atribuídos ao colaborador...")
    resp = client.get("/api/treinamentos/meus")
    print(f"Status: {resp.status_code}")
    meus_treinamentos = resp.get_json()
    print(f"Total de treinamentos ativos para o colaborador: {len(meus_treinamentos)}")
    my_course = next((c for c in meus_treinamentos if c["course_id"] == course_id), None)
    if not my_course:
        print("[ERRO] Treinamento publicado não foi atribuído ao colaborador logado!")
        sys.exit(1)
    print(f"Treinamento atribuído com sucesso! Status atual: {my_course['status']}")

    # 6. Carregar conteúdo do treinamento para estudo
    print("\n[TEST] Carregando conteúdo do curso...")
    resp = client.get(f"/api/treinamentos/{course_id}/conteudo")
    print(f"Status: {resp.status_code}")
    content_data = resp.get_json()
    print(f"Curso: {content_data['title']}")
    print(f"Módulos para leitura: {len(content_data['modules'])}")
    print(f"Questões da avaliação: {len(content_data['questions'])}")
    
    mod_id_1 = content_data['modules'][0]['id']
    mod_id_2 = content_data['modules'][1]['id']
    q_id_1 = content_data['questions'][0]['id']
    q_id_2 = content_data['questions'][1]['id']

    # 7. Marcar módulos como lidos
    print("\n[TEST] Marcando Módulo 1 como lido...")
    resp = client.post(f"/api/treinamentos/{course_id}/mark_module", json={"module_id": mod_id_1})
    print(f"Status: {resp.status_code}")
    
    print("[TEST] Marcando Módulo 2 como lido...")
    resp = client.post(f"/api/treinamentos/{course_id}/mark_module", json={"module_id": mod_id_2})
    print(f"Status: {resp.status_code}")

    # Verificar progresso de leitura
    resp = client.get("/api/treinamentos/meus")
    my_course = next((c for c in resp.get_json() if c["course_id"] == course_id), None)
    print(f"Progresso de leitura após ler módulos: {my_course['modules_read']} / {my_course['modules_total']}")
    if my_course['modules_read'] != 2:
        print("[ERRO] O progresso de leitura de módulos não foi incrementado corretamente!")
        sys.exit(1)

    # 8. Responder avaliação e reprovar de propósito (Errar uma das questões)
    print("\n[TEST] Respondendo avaliação - Errar de propósito para testar reprovação...")
    answers_wrong = {
        str(q_id_1): "b", # Certa (Evitar acidentes)
        str(q_id_2): "c"  # Errada (O rádio e som - correta é 'a')
    }
    resp = client.post(f"/api/treinamentos/{course_id}/responder", json={"answers": answers_wrong})
    print(f"Status: {resp.status_code}")
    wrong_data = resp.get_json()
    print(f"Pontuação obtida: {wrong_data['score']}%")
    print(f"Aprovado? {wrong_data['passed']}")
    if wrong_data['passed']:
        print("[ERRO] Colaborador deveria ter sido reprovado com 50% de acertos!")
        sys.exit(1)

    # 9. Responder avaliação e ser aprovado com 100% de sucesso
    print("\n[TEST] Respondendo avaliação novamente - Gabaritar a prova...")
    answers_correct = {
        str(q_id_1): "b", # Certa
        str(q_id_2): "a"  # Certa
    }
    resp = client.post(f"/api/treinamentos/{course_id}/responder", json={"answers": answers_correct})
    print(f"Status: {resp.status_code}")
    correct_data = resp.get_json()
    print(f"Pontuação obtida: {correct_data['score']}%")
    print(f"Aprovado? {correct_data['passed']}")
    if not correct_data['passed']:
        print("[ERRO] Colaborador deveria ter sido aprovado com 100% de acertos!")
        sys.exit(1)

    # 10. Listar selos do colaborador
    print("\n[TEST] Verificando selos/badges conquistados...")
    resp = client.get("/api/treinamentos/meus_selos")
    print(f"Status: {resp.status_code}")
    badges = resp.get_json()
    print(f"Total de selos ativos: {len(badges)}")
    safety_badge = next((b for b in badges if b["badge_name"] == "Campeão da Segurança"), None)
    if not safety_badge:
        print("[ERRO] Selo 'Campeão da Segurança' não foi concedido ao colaborador!")
        sys.exit(1)
    print(f"Selo conquistado com sucesso: {safety_badge['badge_name']} (Cor: {safety_badge['badge_color']})")

    # 11. Testar o Preview de Relatórios LMS contendo a nova tentativa
    print("\n[TEST] Testando Preview de Relatórios contendo as novas tentativas do LMS...")
    resp = client.get("/api/gestao/relatorios/preview?type=lms")
    print(f"Status: {resp.status_code}")
    preview_data = resp.get_json()
    print(f"Total de registros no relatório de LMS: {len(preview_data['records'])}")
    print(f"Métricas consolidadas do LMS: {preview_data['metrics']}")
    if len(preview_data['records']) < 2:
        print("[ERRO] O relatório de preview do LMS deveria listar as 2 tentativas realizadas!")
        sys.exit(1)

    # 12. Limpar banco (Remover treinamento de teste para não poluir base de dados real)
    print("\n[TEST] Excluindo treinamento de teste...")
    resp = client.delete(f"/api/gestao/treinamentos_lms/{course_id}")
    print(f"Status: {resp.status_code}")
    if resp.status_code != 200:
        print("[ERRO] Falha ao excluir o treinamento de teste!")
        sys.exit(1)
    
    print("\n=== SUÍTE DE TESTES INTEGRADOS DO LMS COMPLETADA COM SUCESSO! 100% PASSOU! ===")
    sys.exit(0)
