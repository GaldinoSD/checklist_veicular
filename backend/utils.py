# -*- coding: utf-8 -*-
import os
import uuid
import threading
import requests
import time as _time
from functools import wraps
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict
from flask import request, redirect, url_for, flash, current_app, abort, session
from flask_login import current_user
from backend import db
from backend.config import (
    TZ, REV_INTERVAL, REV_ALERT_MARGIN, WEEKS_WINDOW, ALLOWED_EXT,
    VISTORIAS_UPLOAD_DIR, AVARIAS_UPLOAD_DIR, TREINAMENTOS_UPLOAD_DIR,
    UPLOAD_DIR, LOGO_PATH, LAYOUT_UPLOAD_DIR, INBOX_DIR, RELATORIOS_DIR
)
from backend.models import Log, SystemConfig, WhatsAppConfig, Checklist

def agora():
    """Retorna horário real do Brasil sem tzinfo (compatível com SQLite e Postgres)."""
    return datetime.now(TZ).replace(tzinfo=None)

def br_datetime(dt):
    if not dt:
        return "-"
    try:
        if dt.tzinfo is not None:
            return dt.astimezone(TZ).strftime("%d/%m/%Y %H:%M")
        
        diff_h = (dt - agora()).total_seconds() / 3600.0
        if 2 <= diff_h <= 4:
            import pytz
            dt_aware = pytz.utc.localize(dt).astimezone(TZ)
            return dt_aware.strftime("%d/%m/%Y %H:%M")
        return dt.strftime("%d/%m/%Y %H:%M")
    except Exception:
        try:
            return dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            return str(dt)

def haversine_distance(lat1, lon1, lat2, lon2):
    import math
    R = 6371000 # Raio da Terra em metros
    phi1 = math.radians(lat1)
    phi2 = math.radians(lat2)
    delta_phi = math.radians(lat2 - lat1)
    delta_lambda = math.radians(lon2 - lon1)
    a = math.sin(delta_phi/2)**2 + math.cos(phi1)*math.cos(phi2)*math.sin(delta_lambda/2)**2
    c = 2 * math.atan2(math.sqrt(a), math.sqrt(1-a))
    return R * c

def parse_periodo(periodo: str):
    """
    Aceita:
      - "YYYY-MM-DD - YYYY-MM-DD"
      - "YYYY-MM-DD" (vira dia inteiro)
    Retorna (dt_inicio, dt_fim) ou (None, None)
    """
    if not periodo:
        return None, None

    periodo = periodo.strip()

    try:
        if " - " in periodo:
            inicio_str, fim_str = periodo.split(" - ")
            dt_inicio = datetime.strptime(inicio_str.strip(), "%Y-%m-%d")
            dt_fim = datetime.strptime(fim_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            return dt_inicio, dt_fim

        dt_inicio = datetime.strptime(periodo, "%Y-%m-%d")
        dt_fim = dt_inicio.replace(hour=23, minute=59, second=59)
        return dt_inicio, dt_fim

    except Exception as e:
        print("Erro parse_periodo:", e)
        return None, None

def registrar_log(acao):
    try:
        user = current_user.username if current_user.is_authenticated else "Sistema"
        db.session.add(Log(usuario=user, acao=acao))
        db.session.commit()
    except Exception as e:
        print("⚠️ Erro registrar_log:", e)
        db.session.rollback()

def send_whatsapp_message(to_number_or_msg, text_message=None):
    """
    Dispara uma mensagem de texto assíncrona usando a Evolution API.
    Totalmente isolado em uma thread em background para não travar a aplicação principal.
    """
    if text_message is not None:
        target_number = to_number_or_msg
        actual_msg = text_message
    else:
        target_number = None
        actual_msg = to_number_or_msg

    # Importação local para evitar circular imports
    from backend import create_app
    # Precisamos do app_context para acessar a config do banco dentro do worker
    app = current_app._get_current_object()

    def worker():
        try:
            with app.app_context():
                config = WhatsAppConfig.query.first()
                if not config or not config.is_enabled:
                    return
                
                headers = {
                    "Content-Type": "application/json",
                    "apikey": config.apikey
                }
                
                if target_number:
                    numbers = [target_number]
                else:
                    if not config.recipients:
                        return
                    numbers = [n.strip() for n in config.recipients.split(",") if n.strip()]
                
                for number in numbers:
                    sanitized_number = "".join(filter(str.isdigit, number))
                    if not sanitized_number:
                        continue
                    
                    if len(sanitized_number) <= 11 and not sanitized_number.startswith("55"):
                        sanitized_number = "55" + sanitized_number
                    
                    payload = {
                        "number": sanitized_number,
                        "text": actual_msg
                    }
                    
                    url = f"{config.api_url.rstrip('/')}/message/sendText/{config.instance_name}"
                    try:
                        res = requests.post(url, json=payload, headers=headers, timeout=10)
                        print(f"Evolution API status for {sanitized_number}: {res.status_code}")
                    except Exception as err:
                        print(f"⚠️ Erro ao postar na Evolution API para {sanitized_number}: {err}")
        except Exception as e:
            print("⚠️ Erro ao processar worker de envio de WhatsApp:", e)

    threading.Thread(target=worker, daemon=True).start()

# ----------------- HELPERS DE PERMISSÃO -----------------
def admin_required(view):
    """Garante que apenas admins ou colaboradores com permissão específica para o endpoint possam acessar."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        
        endpoint = request.endpoint
        # Remove o blueprint prefix do endpoint para bater com a tabela
        if endpoint and "." in endpoint:
            endpoint_name = endpoint.split(".")[-1]
        else:
            endpoint_name = endpoint

        allowed = False
        
        if current_user.is_admin:
            allowed = True
        elif endpoint_name in {"users", "users_pwd", "users_new", "users_role", "users_permissions", "users_del"}:
            allowed = current_user.has_permission("usuarios")
        elif endpoint_name in {"config_checklist", "config_checklist_mode", "config_checklist_new", "config_checklist_edit", "config_checklist_del", "config_checklist_move", "checklists_import"}:
            allowed = current_user.has_permission("config_checklist")
        elif endpoint_name == "logs":
            allowed = current_user.has_permission("logs")
        elif endpoint_name in {"config_layout", "reset_layout_field", "test_layout_pdf", "preview_layout"}:
            allowed = current_user.has_permission("config_layout")
        elif endpoint_name in {"config_ferramentas", "config_ferramentas_new", "config_ferramentas_edit", "config_ferramentas_del", "config_ferramentas_toggle"}:
            allowed = current_user.has_permission("config_ferramentas")
        elif endpoint_name in {"controle_ferramentas_atual", "controle_ferramentas_detalhes"}:
            allowed = current_user.has_permission("controle_ferramentas_atual")
            
        if allowed:
            return view(*args, **kwargs)
            
        flash("Acesso restrito ao administrador.", "error")
        if current_user.is_supervisor:
            return redirect(url_for("dashboard"))
        if current_user.is_manutencao:
            return redirect(url_for("manutencao_os"))
        return redirect(url_for("checklist_mobile"))
    return wrapper

def supervisor_allowed(view):
    """Admin + Supervisor podem acessar, ou qualquer perfil com permissão explícita para o endpoint."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        
        endpoint = request.endpoint
        if endpoint and "." in endpoint:
            endpoint_name = endpoint.split(".")[-1]
        else:
            endpoint_name = endpoint
            
        if current_user.is_admin or current_user.is_supervisor or (endpoint_name and current_user.has_permission(endpoint_name)):
            return view(*args, **kwargs)
        flash("Acesso restrito a supervisor ou administrador.", "error")
        if current_user.is_manutencao:
            return redirect(url_for("manutencao_os"))
        return redirect(url_for("checklist_mobile"))
    return wrapper

def manutencao_only(view):
    """Permite acesso se for admin, perfil manutencao ou tiver a permissão manutencao_os."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.is_admin or current_user.is_manutencao or current_user.has_permission("manutencao_os"):
            return view(*args, **kwargs)
        flash("Página exclusiva da equipe de manutenção.", "info")
        if current_user.is_admin or current_user.is_supervisor:
            return redirect(url_for("dashboard"))
        return redirect(url_for("checklist_mobile"))
    return wrapper

def count_files(directory: Path):
    try:
        return len([f for f in directory.iterdir() if f.is_file()])
    except FileNotFoundError:
        return 0

def list_reports():
    RELATORIOS_DIR.mkdir(exist_ok=True)
    items = []
    for p in RELATORIOS_DIR.iterdir():
        if p.is_file():
            items.append({
                "name": p.name,
                "size": p.stat().st_size,
                "mtime": datetime.fromtimestamp(p.stat().st_mtime)
            })
    items.sort(key=lambda x: x["mtime"], reverse=True)
    return items

def km_alert(vehicle_km: int):
    if vehicle_km is None:
        return False, REV_INTERVAL, None
    next_rev = ((vehicle_km // REV_INTERVAL) + 1) * REV_INTERVAL
    remaining = next_rev - vehicle_km
    return remaining <= REV_ALERT_MARGIN, next_rev, remaining

def iso_week(dt: datetime):
    y, w, _ = dt.isocalendar()
    return f"{y}-W{w:02d}"

def weekly_km_series(weeks_back=WEEKS_WINDOW):
    end = datetime.utcnow()
    start = end - timedelta(weeks=weeks_back)

    rows = (Checklist.query
            .filter(Checklist.date >= start, Checklist.date <= end)
            .order_by(Checklist.vehicle_id.asc(), Checklist.date.asc())
            .all())

    weekly_km = defaultdict(int)
    last_km_per_vehicle = {}

    for c in rows:
        vid = c.vehicle_id
        km = c.km or 0
        wk = iso_week(c.date)

        if vid in last_km_per_vehicle:
            diff = km - last_km_per_vehicle[vid]
            if diff > 0:
                weekly_km[wk] += diff

        last_km_per_vehicle[vid] = km

    weeks = []
    for i in range(weeks_back - 1, -1, -1):
        dt = end - timedelta(weeks=i)
        monday = dt - timedelta(days=dt.weekday())
        weeks.append(iso_week(monday + timedelta(days=3)))

    labels = weeks
    values = [weekly_km.get(wk, 0) for wk in weeks]

    return labels, values

def save_photos(files):
    UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
    saved = []
    for f in files:
        if not f or f.filename == "":
            continue
        ext = os.path.splitext(f.filename)[1].lower()
        if ext not in ALLOWED_EXT:
            continue
        fname = f"{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}_{uuid.uuid4().hex[:8]}{ext}"
        path = UPLOAD_DIR / fname
        f.save(path)
        saved.append(f"/static/checklist_fotos/{fname}")
    return saved

# ----------------- RATE LIMITING -----------------
_login_attempts = defaultdict(list)
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_WINDOW_SECONDS = 60
_LOGIN_LOCKOUT_SECONDS = 300

def _check_rate_limit(ip):
    now = _time.time()
    attempts = _login_attempts[ip]
    _login_attempts[ip] = [t for t in attempts if now - t < _LOGIN_LOCKOUT_SECONDS]
    attempts = _login_attempts[ip]
    recent = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
    if len(recent) >= _LOGIN_MAX_ATTEMPTS:
        oldest = min(recent)
        remaining = int(_LOGIN_LOCKOUT_SECONDS - (now - oldest))
        return False, max(remaining, 1)
    return True, 0

def get_remaining_attempts(ip):
    now = _time.time()
    attempts = _login_attempts[ip]
    recent = [t for t in attempts if now - t < _LOGIN_WINDOW_SECONDS]
    return max(0, _LOGIN_MAX_ATTEMPTS - len(recent))

def _record_attempt(ip):
    _login_attempts[ip].append(_time.time())

def _clear_attempts(ip):
    _login_attempts.pop(ip, None)

_login_request_count = 0

def _cleanup_old_attempts():
    global _login_request_count
    _login_request_count += 1
    if _login_request_count % 100 != 0:
        return
    now = _time.time()
    stale_ips = [ip for ip, times in _login_attempts.items() 
                 if not times or now - max(times) > _LOGIN_LOCKOUT_SECONDS]
    for ip in stale_ips:
        del _login_attempts[ip]

# ----------------- GLOBAL BLUEPRINT -----------------
from flask import Blueprint

class GlobalBlueprint(Blueprint):
    """
    Subclasse de Blueprint que registra todas as rotas no escopo global do Flask (sem prefixar com o nome do blueprint).
    Isso preserva retrocompatibilidade com url_for('route_name') nos templates e testes do monolito.
    """
    def register(self, app, options):
        original_add_url_rule = app.add_url_rule
        
        def custom_add_url_rule(rule, endpoint=None, view_func=None, **options):
            if endpoint and "." in endpoint:
                endpoint = endpoint.split(".")[-1]
            original_add_url_rule(rule, endpoint, view_func, **options)
            
        app.add_url_rule = custom_add_url_rule
        try:
            super().register(app, options)
        finally:
            app.add_url_rule = original_add_url_rule


# ==========================================
# 🔥 GERADORES DE RELATÓRIO PDF PREMIUM 🔥
# ==========================================
from reportlab.lib.styles import ParagraphStyle

def make_premium_pdf(buffer, title, metadata, content_table_data, image_paths=None, signature_path=None):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    import os
    from html import escape

    def format_html_text(text):
        if not text:
            return ""
        text_str = str(text)
        import re
        # Split by allowed ReportLab XML/HTML tags (case-insensitive)
        allowed_tags_pattern = r'(</?(?:b|i|u|strong|em|font(?:\s+color=(?:\'[^\']*\'|"[^\"]*")|\s+face=(?:\'[^\']*\'|"[^\"]*")|\s+size=(?:\'[^\']*\'|"[^\"]*"))*|br\s*/?)>)'
        parts = re.split(allowed_tags_pattern, text_str, flags=re.IGNORECASE)
        for i in range(len(parts)):
            if i % 2 == 0:
                parts[i] = escape(parts[i])
                parts[i] = parts[i].replace('\n', '<br/>')
        return "".join(parts)

    # Dynamic layout configuration from SystemConfig
    config = SystemConfig.query.first()
    
    logo_path_custom = None
    if config and config.pdf_logo:
        custom_p = LAYOUT_UPLOAD_DIR / config.pdf_logo
        if custom_p.exists():
            logo_path_custom = str(custom_p)
            
    logo_path = logo_path_custom if logo_path_custom else "logo.png"
    if not logo_path_custom and not os.path.exists(logo_path):
        logo_path = "/var/www/checklist_veicular/logo.png"

    custom_rodape_linhas = None
    if config and config.pdf_footer:
        custom_rodape_linhas = [linha.strip() for linha in config.pdf_footer.splitlines() if linha.strip()]
        
    RODAPE_LINHAS = custom_rodape_linhas if custom_rodape_linhas is not None else [
        "ADAPT LINK SERVIÇOS EM COMUNICAÇÃO MULTIMÍDIA EIRELI",
        "CNPJ: 08.980.148/0001-41       Inscr. Est.: 78.342.480",
        "Rua Waldir Pedro de Medeiros, 253 – São Miguel – Seropédica – RJ",
        "CEP: 23.893-725",
        "Tel.: (21) 3812-5900 / (21) 2682-7822",
        "WWW.ADAPTLINK.COM.BR",
    ]

    def draw_background(c, doc):
        width, height = A4
        
        # 1. Cabeçalho / Logotipo
        if logo_path and os.path.exists(logo_path):
            try:
                from reportlab.lib.utils import ImageReader
                logo = ImageReader(logo_path)
                c.drawImage(logo, 20, height - 60, width=90, height=37.5, preserveAspectRatio=True, mask="auto")
            except Exception as e:
                print("⚠️ Erro ao carregar logo no header:", e)

        # 2. Título e Subtítulo dinâmicos com Paragraph para evitar estouro
        title_len = len(title)
        if title_len > 60:
            font_size = 10
            leading = 12
        elif title_len > 40:
            font_size = 11
            leading = 13
        else:
            font_size = 13
            leading = 15
            
        header_title_style = ParagraphStyle(
            name="HeaderTitle",
            fontName="Helvetica-Bold",
            fontSize=font_size,
            leading=leading,
            textColor=colors.HexColor("#0F172A")
        )
        
        p_title = Paragraph(title.upper(), header_title_style)
        avail_width = width - 145  # width - logo_width(90) - margin_left(20) - margin_right(20) - gap(15)
        _, h_title = p_title.wrap(avail_width, 40)
        
        y_pos = height - 22.5 - h_title
        p_title.drawOn(c, 125, y_pos)
        
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#475569"))
        c.drawString(125, y_pos - 10, "Registro Formal – AdaptLink")

        # 3. Linha Azul Divisória Premium
        offset = 12 if h_title > 18 else 0
        divider_y = height - 65 - offset
        
        c.setStrokeColor(colors.HexColor("#1F3C78"))
        c.setLineWidth(2)
        c.line(20, divider_y, width - 20, divider_y)

        # 4. Metadados do topo
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#475569"))
        now_str = agora().strftime("%d/%m/%Y %H:%M")
        c.drawString(25, divider_y - 10, f"Emitido em: {now_str}")
        
        ref_id = metadata.get("ID") or metadata.get("Código") or metadata.get("Placa") or metadata.get("Nº") or "N/A"
        c.drawRightString(width - 25, divider_y - 10, f"Doc Ref: {ref_id}")

        # 5. Rodapé Institucional AdaptLink
        c.setStrokeColor(colors.HexColor("#E2E8F0"))
        c.setLineWidth(0.8)
        c.line(25, 90, width - 25, 90)
        
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#475569"))
        y_footer = 75
        for linha in RODAPE_LINHAS:
            c.drawCentredString(width / 2, y_footer, linha)
            y_footer -= 9
        
        # Paginação
        c.setFont("Helvetica-Oblique", 8)
        c.drawRightString(width - 25, 30, f"Página {c.getPageNumber()}")

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=20*mm, leftMargin=20*mm,
        topMargin=45*mm, bottomMargin=40*mm
    )

    styles = getSampleStyleSheet()
    
    label_style = ParagraphStyle(
        name="PremiumLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=colors.HexColor("#475569")
    )
    
    value_style = ParagraphStyle(
        name="PremiumValue",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#1E293B")
    )

    story = []

    story.append(Paragraph("<b>Metadados do Registro</b>", styles["Heading3"]))
    story.append(Spacer(1, 3*mm))

    meta_table_data = []
    keys = list(metadata.keys())
    for i in range(0, len(keys), 2):
        k1 = keys[i]
        v1 = metadata[k1]
        row = [
            Paragraph(f"<b>{k1}:</b>", label_style),
            Paragraph(format_html_text(v1), value_style)
        ]
        if i + 1 < len(keys):
            k2 = keys[i+1]
            v2 = metadata[k2]
            row.extend([
                Paragraph(f"<b>{k2}:</b>", label_style),
                Paragraph(format_html_text(v2), value_style)
            ])
        else:
            row.extend(["", ""])
        meta_table_data.append(row)

    meta_table = Table(meta_table_data, colWidths=[35*mm, 50*mm, 35*mm, 50*mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
        ('TOPPADDING', (0, 0), (-1, -1), 6),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    story.append(Paragraph("<b>Detalhamento do Registro</b>", styles["Heading3"]))
    story.append(Spacer(1, 3*mm))

    content_rows = []
    for k, v in content_table_data:
        content_rows.append([
            Paragraph(f"<b>{format_html_text(k)}</b>", label_style),
            Paragraph(format_html_text(v), value_style)
        ])

    content_table = Table(content_rows, colWidths=[45*mm, 125*mm])
    content_table.setStyle(TableStyle([
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
    ]))
    story.append(content_table)

    if image_paths:
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph("<b>Registros Fotográficos</b>", styles["Heading3"]))
        story.append(Spacer(1, 3*mm))
        
        photo_elements = []
        for img_path in image_paths:
            try:
                from PIL import Image as PILImage
                with PILImage.open(img_path) as test_img:
                    test_img.verify()
                
                img = RLImage(str(img_path), width=80*mm, height=60*mm)
                img.hAlign = 'LEFT'
                photo_elements.append(img)
            except Exception as ex:
                print(f"⚠️ Erro ao renderizar foto no PDF ({img_path}):", ex)
        
        if photo_elements:
            table_data = []
            for i in range(0, len(photo_elements), 2):
                row = [photo_elements[i]]
                if i + 1 < len(photo_elements):
                    row.append(photo_elements[i+1])
                else:
                    row.append("")
                table_data.append(row)
            
            photos_table = Table(table_data, colWidths=[85*mm, 85*mm])
            photos_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(photos_table)

    if signature_path and os.path.exists(signature_path):
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph("<b>Assinatura Digital de Validação</b>", styles["Heading3"]))
        story.append(Spacer(1, 3*mm))
        try:
            sig_img = RLImage(signature_path, width=60*mm, height=18*mm)
            sig_img.hAlign = 'LEFT'
            
            tech_name = metadata.get("Técnico Responsável") or metadata.get("Técnico") or "N/A"
            date_time_str = metadata.get("Última Atualização") or metadata.get("Data") or metadata.get("Data/Hora") or agora().strftime("%d/%m/%Y %H:%M")
            
            sig_table_data = [
                [sig_img],
                [Paragraph("____________________________________________", value_style)],
                [Paragraph(f"<b>Técnico:</b> {tech_name}", label_style)],
                [Paragraph(f"<b>Data/Hora:</b> {date_time_str}", label_style)]
            ]
            sig_table = Table(sig_table_data, colWidths=[170*mm])
            sig_table.setStyle(TableStyle([
                ('ALIGN', (0,0), (-1,-1), 'LEFT'),
                ('VALIGN', (0,0), (-1,-1), 'MIDDLE'),
                ('BOTTOMPADDING', (0,0), (-1,-1), 1),
                ('TOPPADDING', (0,0), (-1,-1), 1),
            ]))
            story.append(sig_table)
        except Exception as e:
            print("⚠️ Erro ao renderizar assinatura no PDF:", e)

    doc.build(story, onFirstPage=draw_background, onLaterPages=draw_background)


def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXT
