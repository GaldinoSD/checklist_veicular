import re
import sys
import os

# Adiciona o diretório raiz ao path do Python (para robustez)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

app_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../../app.py'))

with open(app_path, 'r', encoding='utf-8') as f:
    content = f.read()

# Substituir @admin_required e @supervisor_allowed de acordo com as rotas
def replacer(match):
    route_line = match.group(1)
    
    # Determinar a permissão baseada na rota
    if '/usuarios' in route_line: perm = 'usuarios'
    elif '/config-checklist' in route_line: perm = 'config_checklist'
    elif '/logs' in route_line: perm = 'logs'
    elif '/veiculos' in route_line: perm = 'veiculos'
    elif '/dashboard' in route_line: perm = 'dashboard'
    elif '/controle-veiculos' in route_line: perm = 'controle_veiculos'
    elif '/avarias' in route_line: perm = 'avarias'
    elif '/relatorios' in route_line: perm = 'relatorios'
    elif '/checklists/importar' in route_line or '/checklists' in route_line: perm = 'checklists_view'
    elif '/vistorias' in route_line:
        if '/vistorias/nova' in route_line: perm = 'vistorias_nova'
        else: perm = 'vistorias_list'
    elif '/gestao' in route_line or '/api/gestao' in route_line:
        if 'equipes' in route_line: perm = 'gestao_equipes'
        elif 'calendario' in route_line: perm = 'gestao_calendario'
        elif 'escalas' in route_line: perm = 'gestao_escalas'
        elif 'reunioes' in route_line: perm = 'gestao_reunioes'
        elif 'anotacoes' in route_line: perm = 'gestao_anotacoes'
        elif 'rfo' in route_line: perm = 'gestao_rfo'
        else: perm = None
    else:
        perm = None

    if perm:
        return f"{route_line}\n@require_permission('{perm}')"
    else:
        return f"{route_line}\n@login_required"

content = re.sub(r'(@app\.route[^\n]+)\n\s*(?:@admin_required|@supervisor_allowed)', replacer, content)

with open(app_path, 'w', encoding='utf-8') as f:
    f.write(content)
print("Decorators updated!")
