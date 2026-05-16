import re
with open('/var/www/checklist_veicular/templates/gestao_tecnica.html', 'r') as f:
    content = f.read()

scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)
for i, script in enumerate(scripts):
    with open(f"test_script_{i}.js", "w") as out:
        out.write(script)
