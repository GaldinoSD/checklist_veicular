import re

# Definições das Blueprints e seus arquivos de destino
blueprint_mapping = {
    "auth": "backend/blueprints/auth.py",
    "whatsapp": "backend/blueprints/whatsapp.py",
    "network": "backend/blueprints/network.py",
    "fleet": "backend/blueprints/fleet.py",
    "technical": "backend/blueprints/technical.py"
}

blueprint_headers = {
    "auth": """# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
auth_bp = GlobalBlueprint("auth", __name__)
""",
    "whatsapp": """# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
whatsapp_bp = GlobalBlueprint("whatsapp", __name__)
""",
    "network": """# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
network_bp = GlobalBlueprint("network", __name__)
""",
    "fleet": """# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
fleet_bp = GlobalBlueprint("fleet", __name__)
""",
    "technical": """# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
technical_bp = GlobalBlueprint("technical", __name__)
"""
}

blueprint_bp_names = {
    "auth": "auth_bp",
    "whatsapp": "whatsapp_bp",
    "network": "network_bp",
    "fleet": "fleet_bp",
    "technical": "technical_bp"
}

# Cabeçalho padrão de imports para todos os arquivos
common_imports = """
import os, json, uuid, requests, pytz, holidays
from datetime import datetime, timedelta, date
from pathlib import Path
from collections import defaultdict

from flask import Blueprint, render_template, request, redirect, url_for, flash, send_from_directory, abort, jsonify, session, current_app
from flask_login import login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
from sqlalchemy import text
from sqlalchemy.orm import joinedload
from PIL import Image

# reportlab
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import Table, TableStyle, SimpleDocTemplate, Paragraph, Spacer, Image as RLImage
from reportlab.lib.styles import getSampleStyleSheet

# backend components
from backend import db
from backend.config import (
    TZ, REV_INTERVAL, REV_ALERT_MARGIN, WEEKS_WINDOW, ALLOWED_EXT,
    VISTORIAS_UPLOAD_DIR, AVARIAS_UPLOAD_DIR, TREINAMENTOS_UPLOAD_DIR,
    UPLOAD_DIR, LOGO_PATH, LAYOUT_UPLOAD_DIR, INBOX_DIR, RELATORIOS_DIR
)
from backend.models import (
    User, Vehicle, VehicleInfo, VehicleMov, Checklist, ChecklistItem,
    Announcement, AnnouncementRead, Manual, ToolCategory, Tool, UserToolInspection,
    UserToolStatus, ToolSuggestion, Training, TrainingCourse, TrainingModule,
    TrainingQuestion, TrainingAssignment, TrainingAttempt, Badge, Generator,
    RFO, Solicitacao, SupervisaoTecnica, RotaExata, Team, Task, Patio, Encerramento,
    Scale, Meeting, Note, Activity, SystemRule, Company, Contract, ExternalCollaborator,
    AvariaOS, Log, Vistoria, VistoriaFoto, SystemConfig, WhatsAppConfig,
    NetworkNode, NetworkSplitter, NetworkEdge, GPSDevice, GPSLog
)
from backend.utils import (
    agora, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts
)
"""

with open("app.py", "r", encoding="utf-8") as f:
    lines = f.readlines()

route_pattern = re.compile(r'@app\.route\(\"([^\"]+)\"')

# 1. Encontrar todas as rotas e suas linhas de início
route_indices = []
for idx, line in enumerate(lines):
    if route_pattern.search(line):
        route_indices.append(idx)

print(f"Encontradas {len(route_indices)} rotas no arquivo.")

# 2. Identificar os blocos de rotas com seus respectivos decorators acima
blocks = []
for i, r_idx in enumerate(route_indices):
    # Encontra o início dos decorators
    start_idx = r_idx
    while start_idx > 0:
        prev_line = lines[start_idx - 1].strip()
        if prev_line.startswith("@") or prev_line.startswith("#") or prev_line == "":
            start_idx -= 1
        else:
            break
            
    # O bloco termina onde o próximo bloco começa, ou no final do arquivo
    if i < len(route_indices) - 1:
        # Para a próxima rota, fazemos o mesmo para achar o início dela
        next_r_idx = route_indices[i + 1]
        end_idx = next_r_idx
        while end_idx > 0:
            p_line = lines[end_idx - 1].strip()
            if p_line.startswith("@") or p_line.startswith("#") or p_line == "":
                end_idx -= 1
            else:
                break
    else:
        end_idx = len(lines)
        
    blocks.append((start_idx, end_idx, r_idx))

# 3. Agrupar os blocos por blueprints
blueprint_contents = {k: [] for k in blueprint_mapping.keys()}

def get_category(path):
    if path == "/" or path.startswith("/login") or path.startswith("/logout") or path.startswith("/usuarios") or path == "/dashboard" or path.startswith("/api/frota/dashboard_stats") or path.startswith("/api/gestao/dashboard_stats") or path.startswith("/logs"):
        return "auth"
    elif path.startswith("/whatsapp") or "whatsapp" in path:
        return "whatsapp"
    elif path.startswith("/mapa") or path.startswith("/rede") or "network" in path or "splitter" in path or "node" in path or "edge" in path:
        return "network"
    elif path.startswith("/veiculo") or path.startswith("/controle-veiculo") or path.startswith("/avaria") or path.startswith("/checklist") or path.startswith("/relatorio") or path.startswith("/vistoria") or path.startswith("/manutencao") or path.startswith("/config-checklist") or path.startswith("/configuracoes/layout") or path.startswith("/config-ferramentas") or path.startswith("/controle-ferramentas"):
        return "fleet"
    else:
        return "technical"

for start, end, r_idx in blocks:
    route_line = lines[r_idx]
    path = route_pattern.search(route_line).group(1)
    cat = get_category(path)
    
    # Extrai o conteúdo do bloco
    block_lines = lines[start:end]
    
    # Substitui @app.route por @[bp_name].route
    bp_name = blueprint_bp_names[cat]
    new_block_lines = []
    for bline in block_lines:
        new_line = bline.replace("@app.route", f"@{bp_name}.route")
        new_block_lines.append(new_line)
        
    blueprint_contents[cat].append("".join(new_block_lines))

# 4. Escrever os arquivos de Blueprints
for cat, content_list in blueprint_contents.items():
    filepath = blueprint_mapping[cat]
    header = blueprint_headers[cat] + common_imports
    body = "\n\n".join(content_list)
    
    with open(filepath, "w", encoding="utf-8") as out_f:
        out_f.write(header + "\n\n" + body)
        
    print(f"Escrito blueprint '{cat}' com {len(content_list)} rotas em '{filepath}'.")
