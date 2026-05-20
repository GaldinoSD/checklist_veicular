import sys
from app import app, db, User

print("=== INICIANDO VERIFICAÇÃO VISUAL DA PÁGINA DE CONFIGURAÇÕES ===")

with app.test_client() as client:
    # 1. Simular autenticação como Admin (ID 1)
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'

    # 2. Consultar a rota /config-checklist
    resp = client.get("/config-checklist")
    print(f"Status da consulta base: {resp.status_code}")
    
    if resp.status_code != 200:
        print(f"[ERRO] A rota /config-checklist retornou status {resp.status_code}!")
        sys.exit(1)
        
    html_content = resp.data.decode('utf-8')
    
    # 3. Testar a presença dos novos valores
    width_ok = "max-w-4xl mx-auto space-y-8 pb-12" in html_content
    print(f"  [CHECK] Container ajustado para max-w-4xl? {width_ok}")
    
    # 4. Consultar o layout geral para ver o link
    resp_layout = client.get("/dashboard")
    layout_content = resp_layout.data.decode('utf-8')
    sidebar_ok = "Config. Checklist" in layout_content
    print(f"  [CHECK] Link na sidebar atualizado para 'Config. Checklist'? {sidebar_ok}")
    
    if width_ok and sidebar_ok:
        print("\n=== VERIFICAÇÃO VISUAL DAS CONFIGURAÇÕES COM SUCESSO! 100% OK! ===")
        sys.exit(0)
    else:
        print("\n=== FALHA: VERIFICAÇÃO DE ALGUNS ELEMENTOS VISUAIS FALHOU! ===")
        sys.exit(1)
