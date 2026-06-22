import os

blueprint_files = {
    "backend/blueprints/auth.py": "auth_bp",
    "backend/blueprints/whatsapp.py": "whatsapp_bp",
    "backend/blueprints/network.py": "network_bp",
    "backend/blueprints/fleet.py": "fleet_bp",
    "backend/blueprints/technical.py": "technical_bp"
}

for filepath, bp_var in blueprint_files.items():
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
        continue
        
    with open(filepath, "r", encoding="utf-8") as f:
        content = f.read()
        
    # Substituir @app.get, @app.post, @app.put, @app.delete, @app.route
    modified = content
    modified = modified.replace("@app.get", f"@{bp_var}.get")
    modified = modified.replace("@app.post", f"@{bp_var}.post")
    modified = modified.replace("@app.put", f"@{bp_var}.put")
    modified = modified.replace("@app.delete", f"@{bp_var}.delete")
    modified = modified.replace("@app.route", f"@{bp_var}.route")
    
    if modified != content:
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(modified)
        print(f"Corrigido decorators em '{filepath}' usando '{bp_var}'.")
    else:
        print(f"Nenhuma alteração necessária em '{filepath}'.")
