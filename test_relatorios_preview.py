import sys
from app import app, db, User

report_types = [
    "lms",
    "supervisao",
    "rfo",
    "vistoria",
    "rota",
    "atas",
    "escalas",
    "geradores",
    "encerramento",
    "anotacoes",
    "tarefas"
]

print("=== INICIANDO TESTES DO ENDPOINT DE RELATÓRIOS (PREVIEW) ===")

with app.test_client() as c:
    # Simula autenticação como Admin (ID 1)
    with c.session_transaction() as sess:
        sess['_user_id'] = '1'

    all_passed = True
    for r_type in report_types:
        # Teste 1: Preview sem filtros adicionais (apenas tipo de relatório)
        url = f"/api/gestao/relatorios/preview?type={r_type}"
        resp = c.get(url)
        print(f"\nTipo: {r_type.upper()}")
        print(f"  URL: {url}")
        print(f"  Status Code: {resp.status_code}")
        
        if resp.status_code != 200:
            print(f"  [ERRO] Falha ao obter dados para {r_type}: {resp.data.decode('utf-8')}")
            all_passed = False
            continue
            
        data = resp.get_json()
        if "records" not in data or "metrics" not in data:
            print(f"  [ERRO] JSON de {r_type} está incompleto. Chaves presentes: {list(data.keys())}")
            all_passed = False
            continue
            
        records = data["records"]
        metrics = data["metrics"]
        print(f"  Registros encontrados: {len(records)}")
        print(f"  Métricas consolidadas: {metrics}")
        
        if len(records) > 0:
            print(f"  Amostra do primeiro registro: {records[0]}")
            
        # Teste 2: Preview filtrando por um técnico específico (Ex: user_id=38 - jonatas)
        url_filter = f"/api/gestao/relatorios/preview?type={r_type}&user_id=38"
        resp_filter = c.get(url_filter)
        print(f"  Status com filtro (user_id=38): {resp_filter.status_code}")
        if resp_filter.status_code != 200:
            print(f"  [ERRO] Falha ao filtrar {r_type} por colaborador: {resp_filter.data.decode('utf-8')}")
            all_passed = False
            continue
            
        data_filter = resp_filter.get_json()
        print(f"  Registros filtrados encontrados: {len(data_filter['records'])}")

    if all_passed:
        print("\n=== TODOS OS TESTES PASSARAM COM SUCESSO! ===")
        sys.exit(0)
    else:
        print("\n=== ALGUMAS VERIFICAÇÕES FALHARAM. CORRIJA OS ERROS. ===")
        sys.exit(1)
