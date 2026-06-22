import re
import sys
import os

with open('/var/www/checklist_veicular/frontend/templates/gestao_tecnica.html', 'r') as f:
    content = f.read()

# Extract JS between <script> and </script> tags
scripts = re.findall(r'<script>(.*?)</script>', content, re.DOTALL)
print(f"Found {len(scripts)} script blocks")
for i, script in enumerate(scripts):
    lines = script.strip().split('\n')
    print(f"\nScript block {i}: {len(lines)} lines")
    # Replace Jinja2 expressions with valid JS to check syntax
    js = script
    # Replace {{ ... }} with valid JS
    js = re.sub(r'\{\{.*?\}\}', '[]', js)
    js = re.sub(r'\{%.*?%\}', '', js)
    
    fname = f"/var/www/checklist_veicular/scratch/test_script_block_{i}.js"
    with open(fname, 'w') as out:
        out.write(js)
    print(f"Written to {fname}")
