import re
import sys
import os

# Adiciona o diretório raiz ao path do Python (caso precise de imports futuramente)
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '../..')))

with open('/var/www/checklist_veicular/templates/gestao_tecnica.html', 'r') as f:
    content = f.read()

scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)
for i, script in enumerate(scripts):
    with open(f"/var/www/checklist_veicular/tests/test_script_{i}.js", "w") as out:
        out.write(script)
