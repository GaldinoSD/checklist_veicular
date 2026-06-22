import re

with open("app.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

route_pattern = re.compile(r'@app\.route\(\"([^\"]+)\"')

routes = []
for idx, line in enumerate(lines):
    match = route_pattern.search(line)
    if match:
        routes.append((idx + 1, match.group(1)))

print(f"Total routes found: {len(routes)}")
categories = {
    "auth": [],
    "whatsapp": [],
    "network": [],
    "fleet": [],
    "technical": [],
    "misc": []
}

for line_num, path in routes:
    if path == "/" or path.startswith("/login") or path.startswith("/logout") or path.startswith("/usuarios") or path == "/dashboard" or path.startswith("/api/frota/dashboard_stats") or path.startswith("/api/gestao/dashboard_stats"):
        categories["auth"].append((line_num, path))
    elif path.startswith("/whatsapp") or "whatsapp" in path:
        categories["whatsapp"].append((line_num, path))
    elif path.startswith("/mapa") or path.startswith("/rede") or "network" in path or "splitter" in path or "node" in path or "edge" in path:
        categories["network"].append((line_num, path))
    elif path.startswith("/veiculo") or path.startswith("/controle-veiculo") or path.startswith("/avaria") or path.startswith("/checklist") or path.startswith("/relatorio") or path.startswith("/vistoria") or path.startswith("/manutencao"):
        categories["fleet"].append((line_num, path))
    elif path.startswith("/api/gestao") or path.startswith("/gestao") or path.startswith("/api/equipe") or path.startswith("/api/patio") or path.startswith("/api/tarefa") or path.startswith("/api/escala") or path.startswith("/api/rfo") or path.startswith("/api/supervisao") or path.startswith("/api/solicitac") or path.startswith("/api/gerador"):
        categories["technical"].append((line_num, path))
    else:
        categories["misc"].append((line_num, path))

for cat, items in categories.items():
    print(f"\nCategory '{cat}': {len(items)} routes")
    for item in items[:10]:
        print(f"  Line {item[0]}: {item[1]}")
    if len(items) > 10:
        print("  ...")
