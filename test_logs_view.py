import sys
from app import app, db, User

print("=== INICIANDO VERIFICAÇÃO VISUAL E DE SINTAXE DA PÁGINA DE LOGS (CMD/CLI) ===")

with app.test_client() as client:
    # 1. Simular autenticação como Admin (ID 1)
    with client.session_transaction() as sess:
        sess['_user_id'] = '1'

    # 2. Consultar a rota /logs
    resp = client.get("/logs")
    print(f"Status da consulta base: {resp.status_code}")
    
    if resp.status_code != 200:
        print(f"[ERRO] A rota /logs retornou status {resp.status_code}!")
        print(resp.data.decode('utf-8')[:1000])
        sys.exit(1)
        
    html_content = resp.data.decode('utf-8')
    
    # 3. Testar a presença dos novos componentes de Terminal CLI no HTML gerado
    checks = {
        "Fira Code Font Link": "fonts.googleapis.com/css2?family=Fira+Code",
        "Terminal CSS Style classes": "glass-terminal",
        "Windows buttons mockup": "bg-rose-500/80 inline-block",
        "Boot Information mockup": "CHECKLIST-VEICULAR [Version 2.5.0]",
        "CLI Flag label for Period": "--period",
        "CLI Flag label for Search": "--search",
        "Dynamic command line simulator": "cliCmdDisplay",
        "Blinking Shell Cursor": "animate-blink",
        "Grep display output": "grep -i"
      }
      
    all_ok = True
    for name, query in checks.items():
        present = query in html_content
        print(f"  [CHECK] {name} presente? {present}")
        if not present:
            all_ok = False
            
    if all_ok:
        print("\n=== VERIFICAÇÃO VISUAL DA PÁGINA DE LOGS COM SUCESSO! 100% OK! ===")
        sys.exit(0)
    else:
        print("\n=== FALHA: ALGUNS ELEMENTOS DO TERMINAL ESTÃO AUSENTES NO TEMPLATE! ===")
        sys.exit(1)
