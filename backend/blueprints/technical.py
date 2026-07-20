# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
technical_bp = GlobalBlueprint("technical", __name__)

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
    RFO, Solicitacao, SupervisaoTecnica, RotaExata, Team, Task, CompletedActivity, Patio, Encerramento,
    Scale, Meeting, Note, Activity, SystemRule, Company, Contract, ExternalCollaborator, SystemRuleLog,
    AvariaOS, Log, Vistoria, VistoriaFoto, SystemConfig, WhatsAppConfig, TelegramConfig, EmailConfig,
    NetworkNode, NetworkSplitter, NetworkEdge, GPSDevice, GPSLog, GPSGeofence, GPSAlert,
    DocCategory, TechnicalDocument, DocumentFile, DocumentHistory
)
from backend.utils import (
    agora, br_datetime, haversine_distance, registrar_log, send_whatsapp_message, send_telegram_message, send_email_notification, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts, make_premium_pdf,
    allowed_file
)
import io



# ===============================
# 🏗️ MÓDULO: GESTÃO TÉCNICA
# ===============================
@technical_bp.route("/gestao-tecnica")
@supervisor_allowed
def gestao_tecnica():
    # Reconhecer todos os colaboradores para gestão técnica
    tecnicos = User.query.filter(User.username != 'admin').all()
    tecnicos_js_data = [{"id": t.id, "username": t.username} for t in tecnicos]
    config = SystemConfig.query.first()
    powerbi_url = None
    if config:
        powerbi_url = config.powerbi_url
        
    if not powerbi_url:
        import os
        powerbi_url = os.environ.get("POWERBI_URL", "https://app.powerbi.com/view?r=eyJrIjoiNDNlNWFiYTgtMjFiNC00OTI5LTk5MGItNDg4OTFlNjBhMjg5IiwidCI6IjU3NGMzZTU2LTQ5MjQtNDAwNC1hZDFhLWQ4NDI3ZTdkYjI0MSJ9")
    return render_template("gestao_tecnica.html", tecnicos=tecnicos, tecnicos_js_data=tecnicos_js_data, powerbi_url=powerbi_url)




# --- AUXILIARES E USUÁRIOS ---
@technical_bp.route("/api/gestao/users", methods=["GET"])
@login_required
def api_gestao_users():
    users = User.query.order_by(User.username.asc()).all()
    return jsonify([{"id": u.id, "username": u.username} for u in users])



# --- CONFIGURAÇÃO GLOBAL DE ESCALAS ---
@technical_bp.route("/api/gestao/config", methods=["GET", "POST"])
@supervisor_allowed
def api_gestao_config():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig()
        db.session.add(config)
        db.session.commit()
    
    if request.method == "POST":
        data = request.json or {}
        scale_start_date_str = data.get("scale_start_date")
        if scale_start_date_str:
            config.scale_start_date = datetime.strptime(scale_start_date_str, "%Y-%m-%d").date()
        config.scale_rotation_order = data.get("scale_rotation_order")
        db.session.commit()
        
        # Gera escalas de sábado automaticamente para as próximas 52 semanas
        if config.scale_start_date and config.scale_rotation_order:
            rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
            if rotation_order:
                from datetime import timedelta
                curr_date = config.scale_start_date
                # Encontra o primeiro sábado a partir da data de início
                while curr_date.weekday() != 5:
                    curr_date += timedelta(days=1)
                
                for _ in range(52):
                    existing = Scale.query.filter_by(date=curr_date).first()
                    weeks = (curr_date - config.scale_start_date).days // 7
                    team_idx = weeks % len(rotation_order)
                    team_id = rotation_order[team_idx]
                    
                    team = Team.query.get(team_id)
                    if team:
                        if existing:
                            existing.type = "sabado"
                            existing.team_ids = str(team_id)
                            existing.technician_ids = ",".join([str(m.id) for m in team.members])
                            existing.obs = "Escala automática por rodízio de equipes"
                        else:
                            s = Scale()
                            s.type = "sabado"
                            s.date = curr_date
                            s.obs = "Escala automática por rodízio de equipes"
                            s.team_ids = str(team_id)
                            s.technician_ids = ",".join([str(m.id) for m in team.members])
                            db.session.add(s)
                    curr_date += timedelta(days=7)
                db.session.commit()
                
        return jsonify({"status": "ok"})
    
    return jsonify({
        "scale_start_date": str(config.scale_start_date) if config.scale_start_date else "",
        "scale_rotation_order": config.scale_rotation_order or ""
    })





# --- GERADORES ---
@technical_bp.route("/api/gestao/geradores", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/geradores/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_geradores(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        # Suporta delete por POST ou DELETE
        target_id = id or request.json.get("id")
        g = Generator.query.get_or_404(target_id)
        db.session.delete(g)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        gid = id or data.get("id")
        if gid:
            g = Generator.query.get(gid)
            if not g:
                return jsonify({"error": "Gerador não encontrado"}), 404
        else:
            g = Generator()
            db.session.add(g)
        
        if "name" in data:
            g.name = data.get("name")
        if "location" in data:
            g.location = data.get("location")
        if "capacity_total" in data:
            g.capacity_total = float(data.get("capacity_total")) if data.get("capacity_total") else None
        if "current_qty" in data:
            g.current_qty = float(data.get("current_qty")) if data.get("current_qty") else None
        if "fuel_type" in data:
            g.fuel_type = data.get("fuel_type")
        if "last_refill_date" in data:
            refill_date = data.get("last_refill_date")
            if refill_date:
                g.last_refill_date = datetime.strptime(refill_date, "%Y-%m-%d").date()
            else:
                g.last_refill_date = None
        if "responsible_id" in data:
            g.responsible_id = int(data.get("responsible_id")) if data.get("responsible_id") else None
        if "status" in data:
            g.status = data.get("status", "OPERACIONAL")
        if "obs" in data:
            g.obs = data.get("obs")
        if "reserve_cans" in data:
            g.reserve_cans = int(data.get("reserve_cans")) if data.get("reserve_cans") else None
        if "reserve_liters" in data:
            g.reserve_liters = float(data.get("reserve_liters")) if data.get("reserve_liters") else None
        
        db.session.commit()
        return jsonify({"status": "ok", "id": g.id})

    gs = Generator.query.all()
    res = []
    for g in gs:
        res.append({
            "id": g.id,
            "name": g.name,
            "location": g.location,
            "capacity_total": g.capacity_total,
            "current_qty": g.current_qty,
            "fuel_type": g.fuel_type,
            "last_refill_date": str(g.last_refill_date) if g.last_refill_date else "",
            "responsible_id": g.responsible_id,
            "responsible_name": g.responsible.username if g.responsible else "N/A",
            "status": g.status,
            "obs": g.obs,
            "reserve_cans": g.reserve_cans,
            "reserve_liters": g.reserve_liters
        })
    return jsonify(res)





# --- RFO (RELATÓRIOS DE OCORRÊNCIA) ---
@technical_bp.route("/api/gestao/rfo", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/rfo/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_rfo(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        r = RFO.query.get_or_404(target_id)
        db.session.delete(r)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        # RFO pode enviar fotos, então suporta multipart form data e JSON
        if request.is_json:
            data = request.json or {}
        else:
            data = request.form or {}

        rid = id or data.get("id")
        if rid:
            r = RFO.query.get(rid)
            if not r:
                return jsonify({"error": "RFO não encontrado"}), 404
        else:
            r = RFO()
            db.session.add(r)
        
        # Mapeamentos robustos de campos do HTML para o banco de dados
        r.number = data.get("protocol") or data.get("number")
        r.problem_type = data.get("problem_type")
        r.tech_responsible = data.get("tech_responsible")
        r.root_cause = data.get("root_cause")
        
        # Ações para solução: "solution_actions" (HTML) ou "action" (DB)
        r.action = data.get("solution_actions") or data.get("action")
        
        # Localização: "lng" (HTML) ou "lon" (DB)
        r.city = data.get("city")
        r.neighborhood = data.get("neighborhood")
        r.lat = data.get("lat")
        r.lon = data.get("lng") or data.get("lon")
        
        # Tempos: "maintenance_start" (HTML) ou "start_time" (DB)
        r.start_time = data.get("maintenance_start") or data.get("start_time")
        r.end_time = data.get("resolution_time") or data.get("end_time")
        
        # Observações adicionais mapeadas para "description" (DB)
        r.description = data.get("observations") or data.get("description")
        
        # Outros metadados
        r.impact = data.get("impact", "Não informado")
        r.status = data.get("status", "ABERTO")
        
        # Título dinâmico premium
        r.title = f"RFO: {r.problem_type or 'Ocorrência'} - {r.city or 'Local'}"
        
        # Equipe vinculada (opcional)
        r.team_id = int(data.get("team_id")) if data.get("team_id") else None
        
        # Tratamento de Data inteligente
        date_str = data.get("date")
        if date_str:
            try:
                r.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except Exception:
                r.date = agora().date()
        elif r.start_time:
            try:
                r.date = datetime.strptime(r.start_time.split("T")[0], "%Y-%m-%d").date()
            except Exception:
                r.date = agora().date()
        else:
            r.date = agora().date()
        
        # Upload de fotos
        photos = request.files.getlist("photos") or request.files.getlist("photos[]")
        filenames = json.loads(r.photos_json) if r.photos_json else []
        for p in photos:
            if p and allowed_file(p.filename):
                ext = os.path.splitext(p.filename.lower())[1]
                fn = f"rfo_{uuid.uuid4().hex}{ext}"
                p.save(VISTORIAS_UPLOAD_DIR / fn)
                filenames.append(fn)
        if filenames:
            r.photos_json = json.dumps(filenames)
            
        db.session.commit()
        return jsonify({"status": "ok", "id": r.id})

    rfos = RFO.query.order_by(RFO.date.desc().nullslast()).all()
    res = []
    for r in rfos:
        res.append({
            "id": r.id,
            "number": r.number,
            "title": r.title,
            "date": str(r.date) if r.date else "",
            "start_time": r.start_time,
            "end_time": r.end_time,
            "city": r.city,
            "neighborhood": r.neighborhood,
            "lat": r.lat,
            "lon": r.lon,
            # Chaves extras de compatibilidade para frontend legível
            "lng": r.lon,
            "tech": r.tech_responsible,
            "observations": r.description,
            
            "description": r.description,
            "root_cause": r.root_cause,
            "impact": r.impact,
            "action": r.action,
            "team_id": r.team_id,
            "team_name": r.team.name if r.team else "N/A",
            "technicians_json": r.technicians_json,
            "photos_json": r.photos_json,
            "status": r.status,
            "problem_type": r.problem_type,
            "tech_responsible": r.tech_responsible
        })
    return jsonify(res)





# --- SUPERVISÃO DE CAMPO ---
@technical_bp.route("/api/gestao/supervisao", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/supervisao/<int:id>", methods=["GET", "PUT", "DELETE"])
@supervisor_allowed
def api_supervisao(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        s = SupervisaoTecnica.query.get_or_404(target_id)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"status": "ok", "success": True})

    if id and request.method == "GET":
        i = SupervisaoTecnica.query.get_or_404(id)
        return jsonify({
            "id": i.id,
            "supervisor_id": i.supervisor_id,
            "supervisor_name": i.supervisor.username if i.supervisor else "N/A",
            "date": str(i.date) if i.date else "",
            "time": i.time,
            "irregularities": i.irregularities,
            "action": i.action,
            "obs": i.obs,
            "checklist_json": i.checklist_json,
            "techs_data": i.techs_data,
            "photos_json": i.photos_json
        })

    if request.method in ["POST", "PUT"]:
        if request.is_json:
            data = request.json or {}
        else:
            data = request.form or {}

        sid = id or data.get("id")
        if sid:
            s = SupervisaoTecnica.query.get(sid)
            if not s:
                return jsonify({"error": "Supervisão não encontrada"}), 404
        else:
            s = SupervisaoTecnica(supervisor_id=current_user.id)
            db.session.add(s)

        # Suporta tanto objeto quanto string serializada para techs_data
        techs = data.get("techs_data") or data.get("techs")
        if isinstance(techs, (list, dict)):
            s.techs_data = techs
        elif isinstance(techs, str):
            try:
                s.techs_data = json.loads(techs)
            except Exception:
                s.techs_data = []

        date_str = data.get("date")
        if date_str:
            try:
                s.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except Exception:
                pass
        else:
            if isinstance(s.techs_data, list) and len(s.techs_data) > 0:
                first_date = s.techs_data[0].get("supervision_date")
                if first_date:
                    try:
                        s.date = datetime.strptime(first_date, "%Y-%m-%d").date()
                    except Exception:
                        pass
            if not s.date:
                s.date = datetime.utcnow().date()

        s.time = data.get("time") or (s.techs_data[0].get("supervision_time") if (isinstance(s.techs_data, list) and len(s.techs_data) > 0) else None)
        s.irregularities = data.get("irregularities") or (s.techs_data[0].get("activity") if (isinstance(s.techs_data, list) and len(s.techs_data) > 0) else None)
        s.action = data.get("action") or (s.techs_data[0].get("conclusion") if (isinstance(s.techs_data, list) and len(s.techs_data) > 0) else None)
        s.obs = data.get("obs")
        s.checklist_json = json.dumps(data.get("checklist", {})) if isinstance(data.get("checklist"), dict) else (data.get("checklist") if isinstance(data.get("checklist"), str) else "{}")

        # Processar upload de fotos por técnico
        if isinstance(s.techs_data, list):
            for idx, t in enumerate(s.techs_data):
                if not isinstance(t, dict):
                    continue
                t_photos = []
                ex_photos = t.get("existing_photos") or t.get("photos")
                if ex_photos:
                    if isinstance(ex_photos, list):
                        t_photos = ex_photos
                    elif isinstance(ex_photos, str):
                        try:
                            t_photos = json.loads(ex_photos)
                        except Exception:
                            t_photos = [ex_photos]
                
                # Fotos enviadas via upload para este técnico específico (key tech_photos_0, tech_photos_1, etc.)
                files = request.files.getlist(f"tech_photos_{idx}") or request.files.getlist(f"tech_photos_row_{idx}")
                for p in files:
                    if p and allowed_file(p.filename):
                        ext = os.path.splitext(p.filename.lower())[1]
                        fn = f"sup_t{idx}_{uuid.uuid4().hex}{ext}"
                        p.save(VISTORIAS_UPLOAD_DIR / fn)
                        t_photos.append(fn)
                
                t["photos"] = t_photos

        # Processar fotos gerais recebidas (raiz)
        existing_photos_raw = data.get("existing_photos")
        filenames = []
        if existing_photos_raw:
            if isinstance(existing_photos_raw, str):
                try:
                    filenames = json.loads(existing_photos_raw)
                except Exception:
                    filenames = [existing_photos_raw]
            elif isinstance(existing_photos_raw, list):
                filenames = existing_photos_raw
        elif s.photos_json:
            try:
                filenames = json.loads(s.photos_json)
            except Exception:
                filenames = []

        photos = request.files.getlist("photos") or request.files.getlist("photos[]")
        for p in photos:
            if p and allowed_file(p.filename):
                ext = os.path.splitext(p.filename.lower())[1]
                fn = f"sup_{uuid.uuid4().hex}{ext}"
                p.save(VISTORIAS_UPLOAD_DIR / fn)
                filenames.append(fn)

        if filenames:
            s.photos_json = json.dumps(filenames)
        else:
            s.photos_json = None

        db.session.commit()
        return jsonify({"status": "ok", "success": True, "id": s.id})

    items = SupervisaoTecnica.query.order_by(SupervisaoTecnica.date.desc()).all()
    res = []
    for i in items:
        res.append({
            "id": i.id,
            "supervisor_id": i.supervisor_id,
            "supervisor_name": i.supervisor.username if i.supervisor else "N/A",
            "date": str(i.date) if i.date else "",
            "time": i.time,
            "irregularities": i.irregularities,
            "action": i.action,
            "obs": i.obs,
            "checklist_json": i.checklist_json,
            "techs_data": i.techs_data,
            "photos_json": i.photos_json
        })
    return jsonify(res)







# --- SOLICITAÇÕES OPERACIONAIS ---
@technical_bp.route("/api/gestao/solicitacoes", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/solicitacoes/<int:id>", methods=["DELETE"])
@technical_bp.route("/api/gestao/solicitacoes/<int:id>/respond", methods=["POST"])
@login_required
def api_solicitacoes(id=None):
    if request.method == "DELETE":
        s = Solicitacao.query.get_or_404(id)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"status": "ok", "success": True})

    if id and request.path.endswith("/respond"):
        if not current_user.is_supervisor and not current_user.is_admin:
            return jsonify({"error": "Não autorizado"}), 403
        data = request.json or {}
        s = Solicitacao.query.get_or_404(id)
        s.status = data.get("status", "APROVADA")
        
        response_text = data.get("management_response") or data.get("response")
        from datetime import datetime
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        
        if response_text:
            s.management_response = f"{response_text} (Por: {current_user.username} em {now_str})"
        else:
            s.management_response = f"Sem justificativa adicional (Por: {current_user.username} em {now_str})"
            
        db.session.commit()
        return jsonify({"status": "ok", "success": True})

    if request.method == "POST":
        data = request.json or {}
        s = Solicitacao(user_id=current_user.id)
        db.session.add(s)
        s.type = data.get("type", "TROCA_PLANTAO")
        s.description = data.get("description")
        s.obs = data.get("obs")
        s.status = "PENDENTE"
        db.session.commit()
        return jsonify({"status": "ok", "success": True, "id": s.id})

    items = Solicitacao.query.order_by(Solicitacao.date.desc()).all()
    res = []
    for i in items:
        res.append({
            "id": i.id,
            "type": i.type,
            "user_id": i.user_id,
            "user_name": i.user.username if i.user else "N/A",
            "date": i.date.isoformat() if i.date else "",
            "description": i.description,
            "status": i.status,
            "management_response": i.management_response,
            "obs": i.obs
        })
    return jsonify(res)





# --- EQUIPES ---
@technical_bp.route("/api/gestao/equipes", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/equipes/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_equipes(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        t = Team.query.get_or_404(target_id)
        db.session.delete(t)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        tid = id or data.get("id")
        if tid:
            t = Team.query.get(tid)
            if not t:
                return jsonify({"error": "Equipe não encontrada"}), 404
        else:
            t = Team()
            db.session.add(t)
        
        t.name = data.get("name")
        t.color = data.get("color")
        t.obs = data.get("obs")
        t.rotation_order = int(data.get("rotation_order")) if data.get("rotation_order") else 0
        t.leader_id = int(data.get("leader_id")) if data.get("leader_id") else None
        
        # Vincular técnicos N:N
        member_ids = data.get("member_ids") or []
        t.members = []
        for mid in member_ids:
            u = User.query.get(int(mid))
            if u:
                t.members.append(u)
                
        db.session.commit()
        return jsonify({"status": "ok", "id": t.id})

    teams = Team.query.order_by(Team.name.asc()).all()
    res = []
    for t in teams:
        res.append({
            "id": t.id,
            "name": t.name,
            "color": t.color,
            "obs": t.obs,
            "rotation_order": t.rotation_order,
            "leader_id": t.leader_id,
            "leader_name": t.leader.username if t.leader else None,
            "member_ids": [m.id for m in t.members],
            "member_names": ", ".join([m.username for m in t.members]),
            "members": [{"id": m.id, "username": m.username} for m in t.members]
        })
    return jsonify(res)





# --- PÁTIOS ---
@technical_bp.route("/api/gestao/patios", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/patios/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_patios(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        p = Patio.query.get_or_404(target_id)
        db.session.delete(p)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        pid = id or data.get("id")
        if pid:
            p = Patio.query.get(pid)
            if not p:
                return jsonify({"error": "Pátio não encontrado"}), 404
        else:
            p = Patio()
            db.session.add(p)
        
        p.name = data.get("name")
        p.location = data.get("location")
        db.session.commit()
        return jsonify({"status": "ok", "id": p.id})

    items = Patio.query.order_by(Patio.name.asc()).all()
    return jsonify([{"id": i.id, "name": i.name, "location": i.location} for i in items])





# --- ENCERRAMENTO DE PÁTIO ---
@technical_bp.route("/api/gestao/encerramento", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/encerramento/<int:id>", methods=["DELETE"])
@supervisor_allowed
def api_encerramento(id=None):
    if request.method == "DELETE":
        e = Encerramento.query.get_or_404(id)
        db.session.delete(e)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method == "POST":
        data = request.json or {}
        eid = data.get("id")
        if eid:
            e = Encerramento.query.get(eid)
            if not e:
                return jsonify({"error": "Registro não encontrado"}), 404
        else:
            e = Encerramento()
            db.session.add(e)
            
        # Pega a lista de pátios e técnicos da requisição
        patios_js = data.get("patios") or data.get("patios_json")
        techs = data.get("technicians") or data.get("technicians_json")

        # Salva em formato JSON string
        if isinstance(patios_js, (list, dict)):
            e.patios_json = json.dumps(patios_js)
        else:
            e.patios_json = patios_js

        if isinstance(techs, (list, dict)):
            e.technicians_json = json.dumps(techs)
        else:
            e.technicians_json = techs

        # Extrai patio_id e closing_time do primeiro pátio para retrocompatibilidade
        if isinstance(patios_js, list) and len(patios_js) > 0:
            try:
                first_patio = patios_js[0]
                e.patio_id = int(first_patio.get("patio_id"))
                e.closing_time = first_patio.get("closing_time")
            except Exception as ex:
                print("⚠️ Erro parsing first patio in post:", ex)
        else:
            e.patio_id = int(data.get("patio_id")) if data.get("patio_id") else None
            e.closing_time = data.get("closing_time")

        # Define a data do encerramento (hoje se não fornecida)
        date_str = data.get("date")
        if date_str:
            e.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        elif not e.date:
            e.date = agora().date()

        e.obs = data.get("obs")
        db.session.commit()
        return jsonify({"status": "ok", "id": e.id})

    items = Encerramento.query.order_by(Encerramento.date.desc()).all()
    res = []
    for i in items:
        # Decodifica pátios e técnicos para retornar em formato array
        try:
            patios_list = json.loads(i.patios_json) if i.patios_json else []
        except Exception:
            patios_list = []

        try:
            techs_list = json.loads(i.technicians_json) if i.technicians_json else []
        except Exception:
            techs_list = []

        # Junta nomes dos pátios fechados no dia para exibir no badge
        patios_names = [p.get("patio_name") or p.get("name") for p in patios_list if p.get("patio_name") or p.get("name")]
        patio_name = ", ".join(patios_names) if patios_names else (i.patio.name if i.patio else "N/A")

        res.append({
            "id": i.id,
            "patio_id": i.patio_id,
            "patio_name": patio_name,
            "date": str(i.date) if i.date else "",
            "closing_time": i.closing_time,
            "obs": i.obs,
            "patios_json": i.patios_json,
            "technicians_json": i.technicians_json,
            "patios": patios_list,
            "techs": techs_list
        })
    return jsonify(res)





# --- TAREFAS ---
@technical_bp.route("/api/gestao/tarefas", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/tarefas/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_tarefas(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        t = Task.query.get_or_404(target_id)
        db.session.delete(t)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        tid = id or data.get("id")
        if tid:
            t = Task.query.get(tid)
            if not t:
                return jsonify({"error": "Tarefa não encontrada"}), 404
        else:
            t = Task()
            t.title = data.get("title", "")
            t.priority = data.get("priority", "Média")
            t.status = data.get("status", "Pendente")
            db.session.add(t)
        
        if "title" in data:
            t.title = data.get("title")
        if "description" in data:
            t.description = data.get("description")
        if "responsible_id" in data:
            t.responsible_id = int(data.get("responsible_id")) if data.get("responsible_id") else None
        if "priority" in data:
            t.priority = data.get("priority")
            
        if "deadline" in data:
            deadline_str = data.get("deadline")
            if deadline_str:
                try:
                    t.deadline = datetime.strptime(deadline_str, "%Y-%m-%d").date()
                except Exception:
                    pass
            else:
                t.deadline = None
                
        if "status" in data:
            t.status = data.get("status")
        if "obs" in data:
            t.obs = data.get("obs")
        if "show_on_calendar" in data:
            t.show_on_calendar = data.get("show_on_calendar") in [True, "true", "True", 1, "1"]
            
        db.session.commit()
        return jsonify({"status": "ok", "id": t.id})

    items = Task.query.order_by(Task.deadline.asc().nullslast()).all()
    res = []
    for i in items:
        res.append({
            "id": i.id,
            "title": i.title,
            "description": i.description,
            "responsible_id": i.responsible_id,
            "responsible_name": i.responsible.username if i.responsible else "Sem responsável",
            "responsible": i.responsible.username if i.responsible else "Sem responsável",
            "priority": i.priority,
            "deadline": str(i.deadline) if i.deadline else "",
            "status": i.status,
            "obs": i.obs,
            "show_on_calendar": i.show_on_calendar or False
        })
    return jsonify(res)





# --- ATIVIDADES REALIZADAS (CAMPOS DINÂMICOS) ---
@technical_bp.route("/api/gestao/atividades-realizadas", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/atividades-realizadas/<int:id>", methods=["DELETE"])
@supervisor_allowed
def api_atividades_realizadas(id=None):
    if request.method == "DELETE":
        a = CompletedActivity.query.get_or_404(id)
        db.session.delete(a)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method == "POST":
        data = request.json or {}
        aid = data.get("id")
        if aid:
            a = CompletedActivity.query.get(aid)
            if not a:
                return jsonify({"error": "Atividade não encontrada"}), 404
        else:
            a = CompletedActivity()
            db.session.add(a)

        a.title = data.get("title", "Sem título")
        a.responsible_id = int(data.get("responsible_id")) if data.get("responsible_id") else None
        a.obs = data.get("obs")

        date_str = data.get("date")
        if date_str:
            try:
                a.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except Exception:
                a.date = agora().date()
        else:
            a.date = agora().date()

        fields = data.get("fields")
        if isinstance(fields, list):
            a.fields_json = json.dumps(fields, ensure_ascii=False)
        elif isinstance(fields, str):
            a.fields_json = fields

        db.session.commit()
        return jsonify({"status": "ok", "id": a.id})

    items = CompletedActivity.query.order_by(CompletedActivity.date.desc().nullslast()).all()
    res = []
    for i in items:
        try:
            fields = json.loads(i.fields_json) if i.fields_json else []
        except Exception:
            fields = []
        res.append({
            "id": i.id,
            "title": i.title,
            "responsible_id": i.responsible_id,
            "responsible_name": i.responsible.username if i.responsible else "N/A",
            "date": str(i.date) if i.date else "",
            "fields": fields,
            "obs": i.obs,
            "created_at": i.created_at.strftime("%d/%m/%Y %H:%M") if i.created_at else ""
        })
    return jsonify(res)


@technical_bp.route("/api/gestao/atividades-realizadas/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def atividade_realizada_pdf(id):
    import io
    from flask import send_file

    a = CompletedActivity.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "__ref_id__": f"AR-{a.id}",
        "Título": a.title or "N/A",
        "Data": a.date.strftime("%d/%m/%Y") if a.date else "N/A",
        "Responsável": (a.responsible.username if a.responsible else "N/A").upper(),
        "Emissão": agora().strftime("%d/%m/%Y %H:%M")
    }

    try:
        fields = json.loads(a.fields_json) if a.fields_json else []
    except Exception:
        fields = []

    content = []
    for f in fields:
        label = f.get("label", "Campo")
        value = f.get("value", "")
        content.append((label, value))

    if a.obs:
        content.append(("Observações Gerais", a.obs))

    if not content:
        content.append(("Informação", "Nenhum campo registrado"))

    make_premium_pdf(buffer, f"Relatório de Atividade Realizada: {a.title}", metadata, content)
    buffer.seek(0)

    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"atividade_realizada_{id}.pdf"
    )



# --- ESCALAS DE PLANTÃO (MANUAIS E AUTOMÁTICAS) ---
@technical_bp.route("/api/gestao/escalas", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/escalas/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_escalas(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        s = Scale.query.get_or_404(target_id)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        sid = id or data.get("id")
        if sid:
            s = Scale.query.get(sid)
            if not s:
                return jsonify({"error": "Escala não encontrada"}), 404
        else:
            s = Scale()
            db.session.add(s)
            
        s.type = data.get("type", "plantao")
        date_str = data.get("date")
        if date_str:
            s.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        s.obs = data.get("obs")
        s.status = data.get("status", "ATIVO")
        
        # Suporta serialização de técnicos e equipes de forma compatível
        tech_ids = data.get("technician_ids")
        if isinstance(tech_ids, list):
            s.technician_ids = ",".join(map(str, tech_ids))
        else:
            s.technician_ids = tech_ids

        team_ids = data.get("team_ids")
        if isinstance(team_ids, list):
            s.team_ids = ",".join(map(str, team_ids))
        else:
            s.team_ids = team_ids
            
        db.session.commit()
        return jsonify({"status": "ok", "id": s.id})

    # Tratamento de GET
    view_list = request.args.get("view") == "list"
    
    if view_list:
        today_date = datetime.now().date()
        items = Scale.query.filter(Scale.date >= today_date).order_by(Scale.date.asc()).all()
        res = []
        for s in items:
            tech_names = ""
            if s.technician_ids:
                try:
                    ids = [int(x) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                    tech_names = ", ".join([u.username for u in User.query.filter(User.id.in_(ids))])
                except Exception:
                    tech_names = s.technician_ids
            t_ids = s.team_ids
            if not t_ids and s.team_id:
                t_ids = str(s.team_id)
            res.append({
                "id": s.id,
                "type": s.type,
                "date": str(s.date),
                "obs": s.obs,
                "status": s.status,
                "technician_ids": s.technician_ids,
                "technician_names": tech_names,
                "team_ids": t_ids
            })
        return jsonify(res)

    # FullCalendar request (has start and end date)
    start_str = request.args.get("start")
    end_str = request.args.get("end")
    
    events = []
    
    # 1. Carrega Escalas Manuais
    query = Scale.query
    if start_str and end_str:
        start_date = datetime.fromisoformat(start_str.replace("Z", "")).date()
        end_date = datetime.fromisoformat(end_str.replace("Z", "")).date()
        query = query.filter(Scale.date >= start_date, Scale.date <= end_date)
        
    items = query.all()
    manual_dates = set()
    today_date = agora().date()
    
    for s in items:
        manual_dates.add(s.date)
        tech_names = ""
        if s.technician_ids:
            try:
                ids = [int(x) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                tech_names = ", ".join([u.username.upper() for u in User.query.filter(User.id.in_(ids))])
            except Exception:
                tech_names = "TÉCNICOS"
                
        is_past = s.date < today_date
        prefix = "✔ REALIZADO: " if is_past else ""
        
        # Define cores premium específicas para cada tipo de escala manual
        m_color = "#10B981"  # Padrão: Emerald para Sábado
        if s.type == "domingo":
            m_color = "#6366F1"  # Indigo para Domingo
        elif s.type == "feriado":
            m_color = "#F59E0B"  # Amber/Orange para Feriado
            
        if is_past:
            m_color = "#64748B"  # Slate elegante para plantões já realizados
            
        events.append({
            "id": f"m_{s.id}",
            "title": f"{prefix}{s.type.upper()}: {tech_names or 'PLANTONISTAS'}",
            "start": s.date.isoformat(),
            "allDay": True,
            "color": m_color,
            "extendedProps": {
                "type": "manual",
                "scale_type": s.type,
                "obs": s.obs,
                "is_past": is_past
            }
        })
        
    # 2. Carrega Escalas Automáticas (Rodízio de Sábados)
    config = SystemConfig.query.first()
    if config and config.scale_start_date and config.scale_rotation_order and start_str and end_str:
        rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
        if rotation_order:
            curr_date = start_date
            while curr_date <= end_date:
                # 6 é sábado no Python weekday()
                if curr_date.weekday() == 5 and curr_date >= config.scale_start_date:
                    if curr_date not in manual_dates:
                        # Calcula semanas decorridas
                        weeks = (curr_date - config.scale_start_date).days // 7
                        team_idx = weeks % len(rotation_order)
                        team_id = rotation_order[team_idx]
                        
                        team = Team.query.get(team_id)
                        if team:
                            member_names = ""
                            if team.members:
                                member_names = ", ".join([u.username.upper() for u in team.members])
                            
                            is_past = curr_date < today_date
                            prefix = "✔ REALIZADO: " if is_past else ""
                            auto_color = "#64748B" if is_past else (team.color or "#8B5CF6")
                            
                            title_str = f"Plantão: {team.name.upper()}"
                            if member_names:
                                title_str += f" ({member_names})"
                                
                            events.append({
                                "id": f"auto_{curr_date.isoformat()}",
                                "title": f"{prefix}{title_str}",
                                "start": curr_date.isoformat(),
                                "allDay": True,
                                "color": auto_color,
                                "extendedProps": {
                                    "type": "automatico",
                                    "team_id": team.id,
                                    "team_name": team.name.upper(),
                                    "technicians_names": member_names,
                                    "is_past": is_past
                                }
                            })
                curr_date += timedelta(days=1)
                
    # 3. Carrega Feriados Nacionais, Estaduais (RJ) e Municipais (Seropédica)
    if start_str and end_str:
        from datetime import date
        import holidays
        
        years = list(range(start_date.year, end_date.year + 1))
        # Base: BR + RJ
        h_dict = holidays.Brazil(subdiv="RJ", years=years)
        
        # Custom municipal holidays for Seropédica, RJ
        for y in years:
            # 1. Santo Antônio (June 13th)
            h_dict[date(y, 6, 13)] = "Santo Antônio (Padroeiro de Seropédica)"
            
            # 2. Corpus Christi (60 dias após a Páscoa)
            # Meeus/Jones/Butcher algoritmo para Páscoa
            a = y % 19
            b = y // 100
            c = y % 100
            d = b // 4
            e = b % 4
            f = (b + 8) // 25
            g = (b - f + 1) // 3
            h = (19 * a + b - d - g + 15) % 30
            i = c // 4
            k = c % 4
            l = (32 + 2 * e + 2 * i - h - k) % 7
            m = (a + 11 * h + 22 * l) // 451
            month = (h + l - 7 * m + 114) // 31
            day = ((h + l - 7 * m + 114) % 31) + 1
            easter_date = date(y, month, day)
            corpus_christi = easter_date + timedelta(days=60)
            h_dict[corpus_christi] = "Corpus Christi (Seropédica/RJ)"
            
            # 3. Emancipação de Seropédica (12 de Outubro)
            h_dict.pop(date(y, 10, 12), None)
            h_dict[date(y, 10, 12)] = "Nossa Senhora Aparecida / Emancipação de Seropédica"

        for h_date, h_name in h_dict.items():
            if start_date <= h_date <= end_date:
                events.append({
                    "id": f"feriado_{h_date.isoformat()}",
                    "title": f"🎉 Feriado: {h_name}",
                    "start": h_date.isoformat(),
                    "allDay": True,
                    "color": "#F43F5E", # Lindo Rose-Red para feriados
                    "extendedProps": {
                        "type": "feriado",
                        "name": h_name
                    }
                })
                
    # 4. Carrega Reuniões Agendadas / Não Concluídas no Calendário (Soma ao ser marcada como Concluída)
    meetings = Meeting.query.filter(Meeting.status != "Concluída").all()
    for m in meetings:
        if m.date:
            m_start = m.date.isoformat()
            all_day = True
            # Se tiver hora formatada no padrão HH:MM, envia o datetime exato para posicionamento de hora
            if m.time and len(m.time.strip()) == 5 and ":" in m.time:
                try:
                    m_start = f"{m.date.isoformat()}T{m.time.strip()}:00"
                    all_day = False
                except Exception:
                    pass
                
            events.append({
                "id": f"r_{m.id}",
                "title": f"🤝 REUNIÃO: {m.subject or 'Pauta Geral'}",
                "start": m_start,
                "allDay": all_day,
                "color": "#8B5CF6",  # Violeta premium elegante
                "extendedProps": {
                    "type": "reuniao",
                    "title": m.title,
                    "responsible": m.responsible,
                    "location": m.location,
                    "obs": m.obs
                }
            })
            
    # 5. Carrega Anotações Agendadas no Calendário (Note model)
    notes = Note.query.filter(Note.event_date != None).all()
    for n in notes:
        events.append({
            "id": f"a_{n.id}",
            "title": f"📝 NOTA: {n.title or 'Sem Título'}",
            "start": n.event_date.isoformat(),
            "allDay": True,
            "color": "#14B8A6",  # Lindo Teal premium
            "extendedProps": {
                "type": "anotacao",
                "title": n.title,
                "category": n.category,
                "description": n.description
            }
        })

    # 6. Carrega Tarefas Agendadas no Calendário (Task model)
    tasks = Task.query.filter(Task.show_on_calendar == True, Task.status != "Concluída").all()
    for t in tasks:
        if t.deadline:
            events.append({
                "id": f"t_{t.id}",
                "title": f"🚀 TAREFA: {t.title or 'Sem Título'}",
                "start": t.deadline.isoformat(),
                "allDay": True,
                "color": "#3B82F6",  # Lindo Royal Blue premium para tarefas
                "extendedProps": {
                    "type": "tarefa",
                    "title": t.title,
                    "responsible": t.responsible.username if t.responsible else "Sem responsável",
                    "priority": t.priority,
                    "deadline": str(t.deadline),
                    "status": t.status,
                    "description": t.description
                }
            })
            
    return jsonify(events)



@technical_bp.route("/api/gestao/proximos_feriados", methods=["GET"])
@login_required
def api_proximos_feriados():
    from datetime import date, datetime
    import holidays
    
    today = date.today()
    years = [today.year, today.year + 1]
    h_dict = holidays.Brazil(subdiv="RJ", years=years)
    
    # Feriados Municipais de Seropédica, RJ
    for y in years:
        # 1. Santo Antônio (13 de Junho)
        h_dict[date(y, 6, 13)] = "Santo Antônio (Padroeiro)"
        
        # 2. Corpus Christi (60 dias após a Páscoa)
        a = y % 19
        b = y // 100
        c = y % 100
        d = b // 4
        e = b % 4
        f = (b + 8) // 25
        g = (b - f + 1) // 3
        h = (19 * a + b - d - g + 15) % 30
        i = c // 4
        k = c % 4
        l = (32 + 2 * e + 2 * i - h - k) % 7
        m = (a + 11 * h + 22 * l) // 451
        month = (h + l - 7 * m + 114) // 31
        day = ((h + l - 7 * m + 114) % 31) + 1
        easter_date = date(y, month, day)
        corpus_christi = easter_date + timedelta(days=60)
        h_dict[corpus_christi] = "Corpus Christi"
        
        # 3. Emancipação de Seropédica (12 de Outubro)
        h_dict.pop(date(y, 10, 12), None)
        h_dict[date(y, 10, 12)] = "N. Sra Aparecida / Emancipação"

    upcoming = []
    for h_date, h_name in sorted(h_dict.items()):
        if h_date >= today:
            days_pt = ["Segunda", "Terça", "Quarta", "Quinta", "Sexta", "Sábado", "Domingo"]
            day_name = days_pt[h_date.weekday()]
            upcoming.append({
                "date": h_date.isoformat(),
                "name": h_name,
                "day_name": day_name,
                "display_date": h_date.strftime("%d/%m")
            })
            if len(upcoming) >= 6:
                break
                
    return jsonify(upcoming)





# --- REUNIÕES ---
@technical_bp.route("/api/gestao/reunioes", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/reunioes/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_reunioes(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        m = Meeting.query.get_or_404(target_id)
        db.session.delete(m)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        mid = id or data.get("id")
        if mid:
            m = Meeting.query.get(mid)
            if not m:
                return jsonify({"error": "Reunião não encontrada"}), 404
        else:
            m = Meeting()
            db.session.add(m)
            
        m.title = data.get("title")
        m.subject = data.get("subject")
        
        date_str = data.get("date")
        if date_str:
            m.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        m.time = data.get("time")
        m.location = data.get("location")
        m.obs = data.get("obs")
        m.status = data.get("status", "AGENDADA")
        m.responsible = data.get("responsible")
        m.objective = data.get("objective")
        m.summary = data.get("summary")
        m.actions = data.get("actions")
        
        participants = data.get("technician_ids")
        if isinstance(participants, list):
            m.participants = ",".join(map(str, participants))
        else:
            m.participants = participants
            
        db.session.commit()
        return jsonify({"status": "ok", "id": m.id})

    items = Meeting.query.order_by(Meeting.date.desc()).all()
    res = []
    for i in items:
        names = ""
        if i.participants:
            try:
                ids = [int(x) for x in i.participants.split(",") if x.strip().isdigit()]
                names = ", ".join([u.username for u in User.query.filter(User.id.in_(ids))])
            except Exception:
                names = i.participants
        res.append({
            "id": i.id,
            "title": i.title,
            "subject": i.subject,
            "date": str(i.date) if i.date else "",
            "time": i.time,
            "location": i.location,
            "participants": i.participants,
            "participant_names": names,
            "obs": i.obs,
            "status": i.status,
            "responsible": i.responsible,
            "objective": i.objective,
            "summary": i.summary,
            "actions": i.actions
        })
    return jsonify(res)





# --- ANOTAÇÕES ---
@technical_bp.route("/api/gestao/anotacoes", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/anotacoes/<int:id>", methods=["PUT", "DELETE"])
@login_required
def api_anotacoes(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        n = Note.query.get_or_404(target_id)
        db.session.delete(n)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        nid = id or data.get("id")
        if nid:
            n = Note.query.get(nid)
            if not n:
                return jsonify({"error": "Anotação não encontrada"}), 404
        else:
            n = Note(user_id=current_user.id)
            db.session.add(n)
            
        n.title = data.get("title")
        n.category = data.get("category")
        n.description = data.get("description")
        n.priority = data.get("priority", "MEDIA")
        n.status = data.get("status", "PENDENTE")
        
        event_date_str = data.get("event_date")
        if event_date_str:
            n.event_date = datetime.strptime(event_date_str, "%Y-%m-%d").date()
        else:
            n.event_date = None
            
        db.session.commit()
        return jsonify({"status": "ok", "id": n.id})

    items = Note.query.order_by(Note.date.desc()).all()
    res = []
    for i in items:
        res.append({
            "id": i.id,
            "title": i.title,
            "category": i.category,
            "description": i.description,
            "user_id": i.user_id,
            "user_name": i.user.username if i.user else "N/A",
            "date": i.date.isoformat() if i.date else "",
            "priority": i.priority,
            "event_date": str(i.event_date) if i.event_date else "",
            "status": i.status or "PENDENTE"
        })
    return jsonify(res)



@technical_bp.route("/api/gestao/anotacoes/<int:id>/pdf", methods=["GET"])
@login_required
def anotacao_pdf(id):
    import io
    from flask import send_file
    
    n = Note.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "__ref_id__": f"AN-{n.id}",
        "Autor": (n.user.username if n.user else "N/A").upper(),
        "Data de Criação": n.date.strftime("%d/%m/%Y %H:%M") if n.date else "N/A",
        "Categoria": n.category or "Geral",
        "Prioridade": n.priority or "MEDIA",
        "Status": n.status or "PENDENTE"
    }

    if n.event_date:
        metadata["Data do Evento"] = n.event_date.strftime("%d/%m/%Y")

    content = [
        ("Título / Assunto", n.title or "Sem Título"),
        ("Descrição Detalhada", n.description or "Sem descrição registrada.")
    ]

    make_premium_pdf(buffer, "Anotação Técnica", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"anotacao_{id}.pdf"
    )





# --- ATIVIDADES TÉCNICAS ---
@technical_bp.route("/api/gestao/atividades", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/atividades/<int:id>", methods=["GET", "PUT", "DELETE"])
@supervisor_allowed
def api_atividades(id=None):
    if request.method == "GET" and id:
        a = Activity.query.get_or_404(id)
        photos = []
        if a.photos_json:
            try:
                photos = json.loads(a.photos_json)
            except Exception:
                photos = []
        blocks = []
        if a.description and a.description.startswith("[") and a.description.endswith("]"):
            try:
                blocks = json.loads(a.description)
            except Exception:
                pass
        return jsonify({
            "id": a.id,
            "type": a.type,
            "location": a.location,
            "date": str(a.date) if a.date else "",
            "time": a.time,
            "tech_responsible": a.tech_responsible,
            "client_name": a.client_name,
            "client_code": a.client_code,
            "quality_rating": a.quality_rating,
            "client_feedback": a.client_feedback,
            "os_closure": a.os_closure,
            "conclusion": a.conclusion,
            "obs": a.obs,
            "photos_json": a.photos_json,
            "photos": photos,
            "blocks": blocks
        })

    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or (request.json.get("id") if request.is_json else request.form.get("id"))
        a = Activity.query.get_or_404(target_id)
        db.session.delete(a)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        if request.is_json:
            data = request.json
        else:
            data_raw = request.form.get("data")
            if data_raw:
                try:
                    data = json.loads(data_raw)
                except Exception:
                    data = request.form
            else:
                data = request.form
            
        is_list = isinstance(data, list)
        items = data if is_list else [data]
        
        if not items:
            return jsonify({"error": "Nenhum dado enviado"}), 400
            
        aid = id or items[0].get("id") or (request.form.get("id") if not request.is_json else None)
        if aid:
            a = Activity.query.get(aid)
            if not a:
                return jsonify({"error": "Atividade não encontrada"}), 404
        else:
            a = Activity(user_id=current_user.id)
            db.session.add(a)
            
        a.description = json.dumps(items, ensure_ascii=False)
        
        unique_techs = list(dict.fromkeys([x.get("tech_responsible", "").strip() for x in items if isinstance(x, dict) and x.get("tech_responsible")]))
        a.tech_responsible = ", ".join(unique_techs) if unique_techs else (items[0].get("tech_responsible") if isinstance(items[0], dict) else "")
        
        unique_clients = list(dict.fromkeys([x.get("client_name", "").strip() for x in items if isinstance(x, dict) and x.get("client_name")]))
        a.client_name = ", ".join(unique_clients) if unique_clients else (items[0].get("client_name") if isinstance(items[0], dict) else "")
        
        unique_codes = list(dict.fromkeys([x.get("client_code", "").strip() for x in items if isinstance(x, dict) and x.get("client_code")]))
        a.client_code = ", ".join(unique_codes) if unique_codes else (items[0].get("client_code") if isinstance(items[0], dict) else "")
        
        unique_types = list(dict.fromkeys([x.get("type", "").strip() for x in items if isinstance(x, dict) and x.get("type")]))
        a.type = ", ".join(unique_types) if unique_types else (items[0].get("type") if isinstance(items[0], dict) else "")
        
        first_item = items[0] if isinstance(items[0], dict) else {}
        a.location = first_item.get("location")
        a.time = first_item.get("time")
        a.status = first_item.get("status", "ABERTO")
        a.obs = first_item.get("obs")
        
        date_str = first_item.get("date")
        if date_str:
            try:
                a.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            except Exception:
                a.date = agora().date()
        else:
            a.date = agora().date()
            
        a.quality_rating = first_item.get("quality_rating")
        a.client_feedback = first_item.get("client_feedback")
        a.os_closure = first_item.get("os_closure")
        a.conclusion = first_item.get("conclusion")
        
        # Upload de fotos
        existing_photos_raw = request.form.get("existing_photos") if not request.is_json else None
        filenames = []
        if existing_photos_raw:
            try:
                filenames = json.loads(existing_photos_raw)
            except Exception:
                filenames = []
        elif a.photos_json:
            try:
                filenames = json.loads(a.photos_json)
            except Exception:
                filenames = []

        if not request.is_json:
            photos = request.files.getlist("photos") or request.files.getlist("photos[]")
            for idx in range(len(items)):
                photos.extend(request.files.getlist(f"photos_{idx}"))
            for p in photos:
                if p and allowed_file(p.filename):
                    ext = os.path.splitext(p.filename.lower())[1]
                    fn = f"act_{uuid.uuid4().hex}{ext}"
                    p.save(VISTORIAS_UPLOAD_DIR / fn)
                    filenames.append(fn)

        if filenames:
            a.photos_json = json.dumps(filenames)
        else:
            a.photos_json = None
            
        db.session.commit()
        return jsonify({"status": "ok", "id": a.id})

    items = Activity.query.order_by(Activity.date.desc().nullslast()).all()
    res = []
    for i in items:
        blocks = []
        if i.description and i.description.startswith("[") and i.description.endswith("]"):
            try:
                blocks = json.loads(i.description)
            except Exception:
                pass
        if not blocks:
            blocks = [{
                "type": i.type,
                "location": i.location,
                "date": str(i.date) if i.date else "",
                "time": i.time,
                "tech_responsible": i.tech_responsible,
                "client_name": i.client_name,
                "client_code": i.client_code,
                "quality_rating": i.quality_rating,
                "client_feedback": i.client_feedback,
                "os_closure": i.os_closure,
                "conclusion": i.conclusion,
                "obs": i.obs
            }]
            
        photos = []
        if i.photos_json:
            try:
                photos = json.loads(i.photos_json)
            except Exception:
                photos = []

        res.append({
            "id": i.id,
            "user_id": i.user_id,
            "user_name": i.user.username if i.user else "N/A",
            "type": i.type,
            "location": i.location,
            "date": str(i.date) if i.date else "",
            "time": i.time,
            "description": i.description,
            "status": i.status,
            "photos_json": i.photos_json,
            "photos": photos,
            "obs": i.obs,
            "tech_responsible": i.tech_responsible,
            "tech": i.tech_responsible,
            "client_name": i.client_name,
            "client_code": i.client_code,
            "quality_rating": i.quality_rating,
            "quality": i.quality_rating,
            "client_feedback": i.client_feedback,
            "feedback": i.client_feedback,
            "os_closure": i.os_closure,
            "conclusion": i.conclusion,
            "blocks": blocks
        })
    return jsonify(res)





# --- ROTA EXATA (AUDITORIA DE TRAJETOS) ---
@technical_bp.route("/api/gestao/rota_exata", methods=["GET", "POST"])
@technical_bp.route("/api/gestao/rota_exata/<int:id>", methods=["GET", "PUT", "DELETE"])
@supervisor_allowed
def api_rota_exata(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id and not request.path.endswith("/pdf")):
        target_id = id or request.json.get("id")
        r = RotaExata.query.get_or_404(target_id)
        db.session.delete(r)
        db.session.commit()
        return jsonify({"status": "ok", "success": True})

    if id and request.method == "GET":
        r = RotaExata.query.get_or_404(id)
        return jsonify({
            "id": r.id,
            "supervisor_id": r.supervisor_id,
            "date": str(r.date) if r.date else "",
            "time": r.time,
            "location": r.location,
            "obs": r.obs,
            "status": r.status,
            "photos_json": r.photos_json,
            "techs_data": r.techs_data
        })

    if request.method in ["POST", "PUT"]:
        if request.is_json:
            data = request.json
        else:
            data = request.form

        rid = id or data.get("id")
        if rid:
            r = RotaExata.query.get(rid)
            if not r:
                return jsonify({"error": "Rota Exata não encontrada"}), 404
        else:
            r = RotaExata(supervisor_id=current_user.id)
            db.session.add(r)

        # Suporta tanto objeto quanto string serializada para techs_data
        techs = data.get("techs_data") or data.get("techs")
        if isinstance(techs, (list, dict)):
            r.techs_data = techs
        elif isinstance(techs, str):
            try:
                r.techs_data = json.loads(techs)
            except Exception:
                r.techs_data = []

        date_str = data.get("date")
        if date_str:
            r.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        else:
            if isinstance(r.techs_data, list) and len(r.techs_data) > 0:
                first_date = r.techs_data[0].get("supervision_date")
                if first_date:
                    try:
                        r.date = datetime.strptime(first_date, "%Y-%m-%d").date()
                    except Exception:
                        pass

        r.time = data.get("time") or (r.techs_data[0].get("yard_departure_time") if (isinstance(r.techs_data, list) and len(r.techs_data) > 0) else None)
        r.location = data.get("location") or (r.techs_data[0].get("planned_route") if (isinstance(r.techs_data, list) and len(r.techs_data) > 0) else None)
        r.obs = data.get("obs")
        r.status = data.get("status", "PENDENTE")

        # Fotos upload
        photos = request.files.getlist("photos") or request.files.getlist("photos[]")
        filenames = json.loads(r.photos_json) if r.photos_json else []
        for p in photos:
            if p and allowed_file(p.filename):
                ext = os.path.splitext(p.filename.lower())[1]
                fn = f"re_{uuid.uuid4().hex}{ext}"
                p.save(VISTORIAS_UPLOAD_DIR / fn)
                filenames.append(fn)
        if filenames:
            r.photos_json = json.dumps(filenames)

        db.session.commit()
        return jsonify({"status": "ok", "success": True, "id": r.id})

    items = RotaExata.query.order_by(RotaExata.date.desc()).all()
    res = []
    for r in items:
        res.append({
            "id": r.id,
            "supervisor_id": r.supervisor_id,
            "supervisor_name": r.supervisor.username if r.supervisor else "N/A",
            "date": str(r.date) if r.date else "",
            "time": r.time,
            "location": r.location,
            "obs": r.obs,
            "status": r.status,
            "photos_json": r.photos_json,
            "techs_data": r.techs_data
        })
    return jsonify(res)



# --- STATUS TOGGLE GENÉRICO ---
@technical_bp.route("/api/gestao/<string:slug>/<int:id>/status", methods=["POST"])
@supervisor_allowed
def api_status_toggle(slug, id):
    data = request.json or {}
    new_status = data.get("status")
    if not new_status:
        return jsonify({"error": "Status não fornecido"}), 400

    if slug == "tarefas":
        obj = Task.query.get_or_404(id)
    elif slug == "reunioes":
        obj = Meeting.query.get_or_404(id)
    elif slug == "atividades":
        obj = Activity.query.get_or_404(id)
    elif slug == "rota_exata":
        obj = RotaExata.query.get_or_404(id)
    elif slug == "rfo":
        obj = RFO.query.get_or_404(id)
    else:
        return jsonify({"error": "Módulo inválido"}), 400

    obj.status = new_status
    db.session.commit()
    return jsonify({"status": "ok"})

def make_premium_pdf(buffer, title, metadata, content_table_data, image_paths=None, signature_path=None):
    metadata = dict(metadata)
    ref_id = metadata.pop("__ref_id__", None)

    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    import os
    from html import escape

    NAME_KEYWORDS = ("nome", "responsável", "responsavel", "técnico", "tecnico", "cliente", "colaborador", "supervisor", "motorista", "usuário", "usuario", "solicitante", "criador", "organizador", "participante")

    def maybe_upper_val(key_name, val):
        if not val or not isinstance(val, str):
            return val
        k_str = str(key_name).lower()
        if any(kw in k_str for kw in NAME_KEYWORDS):
            return val.upper()
        return val

    def format_html_text(text):
        if not text:
            return ""
        text_str = str(text)
        import re
        allowed_tags_pattern = r'(</?(?:b|i|u|strong|em|font(?:\s+[^>]+)*|img(?:\s+[^>]+)*|br\s*/?)>)'
        parts = re.split(allowed_tags_pattern, text_str, flags=re.IGNORECASE)
        for i in range(len(parts)):
            if i % 2 == 0:
                parts[i] = escape(parts[i])
                parts[i] = parts[i].replace('\n', '<br/>')
        return "".join(parts)

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
        
        if logo_path and os.path.exists(logo_path):
            try:
                from reportlab.lib.utils import ImageReader
                logo = ImageReader(logo_path)
                pdf_h = config.pdf_logo_height or 30
                pdf_w = pdf_h * 2.4
                c.drawImage(logo, 20, height - 22.5 - pdf_h, width=pdf_w, height=pdf_h, preserveAspectRatio=True, mask="auto")
            except Exception as e:
                print("⚠️ Erro ao carregar logo no header:", e)

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
        avail_width = width - 145
        _, h_title = p_title.wrap(avail_width, 40)
        
        y_pos = height - 22.5 - h_title
        p_title.drawOn(c, 125, y_pos)
        
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#475569"))
        c.drawString(125, y_pos - 10, "Registro Formal – AdaptLink")

        offset = 12 if h_title > 18 else 0
        divider_y = height - 65 - offset
        
        c.setStrokeColor(colors.HexColor("#1F3C78"))
        c.setLineWidth(2)
        c.line(20, divider_y, width - 20, divider_y)

        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#475569"))
        now_str = agora().strftime("%d/%m/%Y %H:%M")
        c.drawString(25, divider_y - 10, f"Emitido em: {now_str}")
        
        doc_ref = ref_id or metadata.get("ID") or metadata.get("Código") or metadata.get("Placa") or metadata.get("Nº") or "N/A"
        c.drawRightString(width - 25, divider_y - 10, f"Doc Ref: {doc_ref}")

        c.setStrokeColor(colors.HexColor("#E2E8F0"))
        c.setLineWidth(0.8)
        c.line(25, 90, width - 25, 90)
        
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#475569"))
        y_footer = 75
        for linha in RODAPE_LINHAS:
            c.drawCentredString(width / 2, y_footer, linha)
            y_footer -= 9
        
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
        v1 = maybe_upper_val(k1, metadata[k1])
        row = [
            Paragraph(f"<b>{k1}:</b>", label_style),
            Paragraph(format_html_text(v1), value_style)
        ]
        if i + 1 < len(keys):
            k2 = keys[i+1]
            v2 = maybe_upper_val(k2, metadata[k2])
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

    # Seção 2: Detalhes do Registro
    story.append(Paragraph("<b>Detalhamento do Registro</b>", styles["Heading3"]))
    story.append(Spacer(1, 3*mm))

    from reportlab.platypus import Flowable
    content_rows = []
    table_spans = []

    for idx, item in enumerate(content_table_data):
        if not item:
            continue
        k, v = item[0], item[1]
        v = maybe_upper_val(k, v)

        if k is None or k == "":
            if isinstance(v, (Flowable, list)):
                col_elem = v
            else:
                col_elem = Paragraph(format_html_text(v), value_style)
            content_rows.append([col_elem, ""])
            table_spans.append(('SPAN', (0, idx), (1, idx)))
        else:
            if isinstance(k, Flowable):
                col1 = k
            else:
                col1 = Paragraph(f"<b>{format_html_text(k)}</b>", label_style)

            if isinstance(v, (Flowable, list)):
                col2 = v
            else:
                col2 = Paragraph(format_html_text(v), value_style)

            content_rows.append([col1, col2])

    content_table = Table(content_rows, colWidths=[45*mm, 125*mm])
    content_table.hAlign = 'LEFT'
    t_style = [
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ('LEFTPADDING', (0, 0), (-1, -1), 0),
        ('RIGHTPADDING', (0, 0), (-1, -1), 0),
        ('TOPPADDING', (0, 0), (-1, -1), 8),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 8),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
    ]
    t_style.extend(table_spans)
    content_table.setStyle(TableStyle(t_style))
    story.append(content_table)

    # Seção 3: Registros Fotográficos
    if image_paths:
        story.append(Spacer(1, 8*mm))
        story.append(Paragraph("<b>Registros Fotográficos</b>", styles["Heading3"]))
        story.append(Spacer(1, 3*mm))
        
        photo_elements = []
        for img_path in image_paths:
            try:
                # Valida se a imagem não está corrompida e pode ser aberta
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
            photos_table.hAlign = 'LEFT'
            photos_table.setStyle(TableStyle([
                ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                ('LEFTPADDING', (0, 0), (-1, -1), 0),
                ('RIGHTPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 6),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ]))
            story.append(photos_table)

    # Seção 4: Assinatura Digital
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




@technical_bp.route("/api/gestao/encerramento/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def encerramento_pdf(id):
    import io
    from flask import send_file
    
    e = Encerramento.query.get_or_404(id)
    buffer = io.BytesIO()

    # Formatação de técnicos
    techs_str = "Nenhum técnico"
    if e.technicians_json:
        try:
            techs = json.loads(e.technicians_json)
            if isinstance(techs, list):
                if len(techs) > 0 and isinstance(techs[0], dict):
                    # Formato novo: [{"user_id": "...", "username": "...", "arrival_time": "..."}]
                    techs_str = ", ".join([f"{str(t.get('username') or '').upper()} ({t.get('arrival_time')})" for t in techs])
                else:
                    # Formato antigo: [1, 2, 3]
                    tech_users = User.query.filter(User.id.in_([int(x) for x in techs])).all()
                    techs_str = ", ".join([u.username.upper() for u in tech_users])
        except Exception:
            techs_str = str(e.technicians_json)

    # Decodifica pátios
    patios_list = []
    if e.patios_json:
        try:
            patios_list = json.loads(e.patios_json)
        except Exception:
            pass

    # Calcula nome exibido dos pátios e horários
    patios_names = [p.get("patio_name") or p.get("name") for p in patios_list if p.get("patio_name") or p.get("name")]
    patio_display_name = ", ".join(patios_names) if patios_names else (e.patio.name if e.patio else "N/A")

    closing_display_time = e.closing_time
    if not closing_display_time and patios_list:
        closing_times = [p.get("closing_time") or p.get("status") for p in patios_list if p.get("closing_time") or p.get("status")]
        closing_display_time = ", ".join(closing_times) if closing_times else "N/A"

    metadata = {
        "__ref_id__": f"EN-{e.id}",
        "Pátio(s)": patio_display_name,
        "Data": e.date.strftime("%d/%m/%Y") if e.date else "N/A",
        "Horário de Fechamento": closing_display_time or "N/A",
        "Técnicos Presentes": techs_str
    }

    patios_str = ""
    if patios_list:
        try:
            lines = []
            for p in patios_list:
                name = p.get('patio_name') or p.get('name') or "N/A"
                val = p.get('closing_time') or p.get('status') or "N/A"
                lines.append(f"• <b>{name}:</b> {val}")
            patios_str = "\n".join(lines)
        except Exception:
            patios_str = str(e.patios_json)

    content = [
        ("Horários dos Pátios Registrados", patios_str or "Nenhum pátio registrado"),
        ("Observações Gerais", e.obs or "Nenhuma observação informada.")
    ]

    make_premium_pdf(buffer, "Relatório de Encerramento Diário", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"encerramento_diario_{id}.pdf"
    )



@technical_bp.route("/api/gestao/atividades/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def atividade_pdf(id):
    import io
    import json
    from flask import send_file
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import mm
    
    a = Activity.query.get_or_404(id)
    buffer = io.BytesIO()
    
    # Tenta decodificar o array de blocos
    blocks = []
    if a.description and a.description.startswith("[") and a.description.endswith("]"):
        try:
            blocks = json.loads(a.description)
        except Exception:
            pass
            
    if not blocks:
        blocks = [{
            "type": a.type,
            "date": str(a.date) if a.date else "",
            "time": a.time,
            "tech_responsible": a.tech_responsible,
            "client_name": a.client_name,
            "client_code": a.client_code,
            "quality_rating": a.quality_rating,
            "client_feedback": a.client_feedback,
            "os_closure": a.os_closure,
            "conclusion": a.conclusion,
            "obs": a.obs
        }]
        
    if len(blocks) <= 1:
        # Layout individual legado/simplificado
        metadata = {
            "__ref_id__": f"AT-{a.id}",
            "Tipo de Atividade": (a.type or "N/A").upper(),
            "Data": a.date.strftime("%d/%m/%Y") if a.date else "N/A",
            "Horário": a.time or "N/A",
            "Técnico Responsável": (a.tech_responsible or "N/A").upper()
        }

        obs_text = blocks[0].get("conclusion") or blocks[0].get("description") or a.conclusion or a.obs or "Sem observações"

        content = [
            ("Cliente", f"{(a.client_name or 'N/A').upper()} (Cód: {a.client_code or 'N/A'})"),
            ("Verificado encerramento de O.S.", a.os_closure or "N/A"),
            ("Avaliação de Qualidade", a.quality_rating or "N/A"),
            ("Feedback do Cliente", a.client_feedback or "Sem feedback"),
            ("Observações", obs_text)
        ]

        image_paths = []
        if a.photos_json:
            try:
                filenames = json.loads(a.photos_json)
                if isinstance(filenames, list):
                    for fn in filenames:
                        p_path = VISTORIAS_UPLOAD_DIR / fn
                        if p_path.exists():
                            image_paths.append(p_path)
            except Exception as ex:
                print("⚠️ Erro ao carregar fotos da atividade:", ex)

        make_premium_pdf(buffer, "Relatório de Atividade Técnica", metadata, content, image_paths=image_paths)
    else:
        # ==========================================
        # 🔥 LAYOUT PREMIUM CONSOLIDADO MULTITÉCNICO 🔥
        # ==========================================
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

        def draw_background(c, doc_obj):
            width, height = A4
            
            # 1. Cabeçalho / Logotipo
            if logo_path and os.path.exists(logo_path):
                try:
                    from reportlab.lib.utils import ImageReader
                    logo = ImageReader(logo_path)
                    pdf_h = config.pdf_logo_height or 30
                    pdf_w = pdf_h * 2.4
                    c.drawImage(logo, 20, height - 22.5 - pdf_h, width=pdf_w, height=pdf_h, preserveAspectRatio=True, mask="auto")
                except Exception as e:
                    print("⚠️ Erro ao carregar logo no header do consolidado:", e)

            # 2. Título Centralizado
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(colors.HexColor("#0F172A"))
            c.drawCentredString(width / 2, height - 40, "RELATÓRIO CONSOLIDADO DE ATIVIDADES")
            c.setFont("Helvetica", 11)
            c.drawCentredString(width / 2, height - 55, "Registro Formal – AdaptLink")

            # 3. Linha Azul Divisória Premium
            c.setStrokeColor(colors.HexColor("#1F3C78"))
            c.setLineWidth(2)
            c.line(20, height - 65, width - 20, height - 65)

            # 4. Metadados do topo: Emitido em / Número do Relatório
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.HexColor("#475569"))
            now_str = agora().strftime("%d/%m/%Y %H:%M")
            c.drawString(25, height - 75, f"Emitido em: {now_str}")
            c.drawRightString(width - 25, height - 75, f"Doc Ref: AT-{a.id}")

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
        
        # Estilos Customizados
        title_style = ParagraphStyle(
            name="ConsTitle",
            parent=styles["Heading1"],
            fontName="Helvetica-Bold",
            fontSize=16,
            textColor=colors.HexColor("#0F172A"),
            spaceAfter=5
        )
        
        subtitle_style = ParagraphStyle(
            name="ConsSub",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=10,
            textColor=colors.HexColor("#64748B"),
            spaceAfter=15
        )
        
        section_heading = ParagraphStyle(
            name="ConsSec",
            parent=styles["Heading2"],
            fontName="Helvetica-Bold",
            fontSize=12,
            textColor=colors.HexColor("#1E293B"),
            spaceBefore=10,
            spaceAfter=8
        )
        
        label_style = ParagraphStyle(
            name="ConsLabel",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=9,
            textColor=colors.HexColor("#475569")
        )
        
        value_style = ParagraphStyle(
            name="ConsValue",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=9,
            textColor=colors.HexColor("#1E293B")
        )
        
        th_style = ParagraphStyle(
            name="ConsTH",
            parent=styles["Normal"],
            fontName="Helvetica-Bold",
            fontSize=8,
            textColor=colors.white
        )
        
        td_style = ParagraphStyle(
            name="ConsTD",
            parent=styles["Normal"],
            fontName="Helvetica",
            fontSize=8,
            textColor=colors.HexColor("#334155")
        )
        
        story = []
        
        # O cabeçalho e rodapé são gerados dinamicamente via draw_background para manter a padronização do sistema
        
        # 2. Metadados Gerais do Registro
        meta_data = [
            [Paragraph("<b>Total de Vistorias:</b>", label_style), Paragraph(f"{len(blocks)} atividades", value_style),
             Paragraph("<b>Data de Registro:</b>", label_style), Paragraph(a.date.strftime("%d/%m/%Y") if a.date else "N/A", value_style)],
            [Paragraph("<b>Técnicos Escalados:</b>", label_style), Paragraph((a.tech_responsible or "N/A").upper(), value_style),
             Paragraph("<b>Status Geral:</b>", label_style), Paragraph(a.status or "CONCLUÍDO", value_style)]
        ]
        meta_table = Table(meta_data, colWidths=[35*mm, 50*mm, 35*mm, 50*mm])
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
        
        # 3. Tabela Resumo das Atividades
        story.append(Paragraph("Resumo Operacional", section_heading))
        
        summary_rows = [[
            Paragraph("TÉCNICO", th_style),
            Paragraph("CLIENTE", th_style),
            Paragraph("ATIVIDADE", th_style),
            Paragraph("AVALIAÇÃO", th_style),
            Paragraph("VERIFICADO ENCERRAMENTO O.S.", th_style)
        ]]
        
        for idx, b in enumerate(blocks):
            summary_rows.append([
                Paragraph(str(b.get("tech_responsible") or "N/A").upper(), td_style),
                Paragraph(f"{str(b.get('client_name') or 'N/A').upper()} ({b.get('client_code') or 'N/A'})", td_style),
                Paragraph(b.get("type") or "Vistoria", td_style),
                Paragraph(b.get("quality_rating") or "N/A", td_style),
                Paragraph(b.get("os_closure") or "N/A", td_style)
            ])
            
        summary_table = Table(summary_rows, colWidths=[35*mm, 50*mm, 35*mm, 20*mm, 30*mm])
        
        # Estilização da tabela de resumo com visual premium slate
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#1E293B")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('TOPPADDING', (0, 0), (-1, -1), 6),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 6),
            ('LEFTPADDING', (0, 0), (-1, -1), 6),
            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
            ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        ]
        
        # Cor de linha zebra
        for r_idx in range(1, len(summary_rows)):
            if r_idx % 2 == 0:
                t_style.append(('BACKGROUND', (0, r_idx), (-1, r_idx), colors.HexColor("#F1F5F9")))
                
        summary_table.setStyle(TableStyle(t_style))
        story.append(summary_table)
        story.append(Spacer(1, 10*mm))
        
        # 4. Detalhamento Individual de cada Vistoria
        story.append(Paragraph("Detalhamento Individual", section_heading))
        
        for idx, b in enumerate(blocks):
            story.append(Spacer(1, 2*mm))
            # Sub-barra de cabeçalho do técnico
            header_data = [[
                Paragraph(f"<b>Atividade #{idx+1} — Técnico: {str(b.get('tech_responsible') or 'N/A').upper()}</b>", ParagraphStyle(
                    name=f"HText_{idx}", parent=styles["Normal"], fontName="Helvetica-Bold", fontSize=10, textColor=colors.HexColor("#0F172A")
                ))
            ]]
            header_table = Table(header_data, colWidths=[170*mm])
            header_table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#E2E8F0")),
                ('TOPPADDING', (0, 0), (-1, -1), 5),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                ('LEFTPADDING', (0, 0), (-1, -1), 8),
                ('LINEBELOW', (0, 0), (-1, -1), 1, colors.HexColor("#94A3B8")),
            ]))
            story.append(header_table)
            story.append(Spacer(1, 3*mm))
            
            # Grid de Detalhes
            details = [
                [Paragraph("<b>Cliente:</b>", label_style), Paragraph(f"{str(b.get('client_name') or 'N/A').upper()} (Cód: {b.get('client_code') or 'N/A'})", value_style),
                 Paragraph("<b>Horário/Tipo:</b>", label_style), Paragraph(f"{b.get('time') or 'N/D'} - {b.get('type') or 'Vistoria'}", value_style)],
                [Paragraph("<b>Avaliação:</b>", label_style), Paragraph(b.get("quality_rating") or "N/A", value_style),
                 Paragraph("<b>Verificado encerramento de O.S.:</b>", label_style), Paragraph(b.get("os_closure") or "N/A", value_style)]
            ]
            
            details_table = Table(details, colWidths=[30*mm, 55*mm, 45*mm, 40*mm])
            details_table.setStyle(TableStyle([
                ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                ('TOPPADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(details_table)
            story.append(Spacer(1, 3*mm))
            
            # Feedback e Observações
            text_blocks = []
            if b.get("client_feedback"):
                text_blocks.append([
                    Paragraph("<b>Feedback do Cliente:</b>", label_style),
                    Paragraph(b.get("client_feedback").replace("\n", "<br/>"), value_style)
                ])
            obs_block_text = b.get("conclusion") or b.get("description") or b.get("obs")
            if obs_block_text:
                text_blocks.append([
                    Paragraph("<b>Observações:</b>", label_style),
                    Paragraph(obs_block_text.replace("\n", "<br/>"), value_style)
                ])
                
            if text_blocks:
                tb_table = Table(text_blocks, colWidths=[40*mm, 130*mm])
                tb_table.setStyle(TableStyle([
                    ('VALIGN', (0, 0), (-1, -1), 'TOP'),
                    ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
                    ('TOPPADDING', (0, 0), (-1, -1), 5),
                    ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
                    ('GRID', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
                ]))
                story.append(tb_table)
                
            story.append(Spacer(1, 5*mm))

        # Fotos de Evidências em Consolidado
        if a.photos_json:
            try:
                filenames = json.loads(a.photos_json)
                if isinstance(filenames, list) and len(filenames) > 0:
                    valid_photo_elements = []
                    for fn in filenames:
                        p_path = VISTORIAS_UPLOAD_DIR / fn
                        if p_path.exists():
                            try:
                                from PIL import Image as PILImage
                                with PILImage.open(p_path) as test_img:
                                    test_img.verify()
                                from reportlab.platypus import Image as RLImage
                                img = RLImage(str(p_path), width=75*mm, height=55*mm)
                                img.hAlign = 'LEFT'
                                valid_photo_elements.append(img)
                            except Exception as ex:
                                print("⚠️ Erro foto consolidado:", ex)

                    if valid_photo_elements:
                        story.append(Spacer(1, 4*mm))
                        story.append(Paragraph("<b>Registro Fotográfico (Evidências em Campo)</b>", section_heading))
                        story.append(Spacer(1, 2*mm))

                        photo_rows = []
                        for p_idx in range(0, len(valid_photo_elements), 2):
                            p_row = [valid_photo_elements[p_idx]]
                            if p_idx + 1 < len(valid_photo_elements):
                                p_row.append(valid_photo_elements[p_idx+1])
                            else:
                                p_row.append("")
                            photo_rows.append(p_row)

                        p_table = Table(photo_rows, colWidths=[82*mm, 82*mm])
                        p_table.hAlign = 'LEFT'
                        p_table.setStyle(TableStyle([
                            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                            ('LEFTPADDING', (0, 0), (-1, -1), 0),
                            ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                            ('TOPPADDING', (0, 0), (-1, -1), 2),
                            ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                        ]))
                        story.append(p_table)
            except Exception as ex:
                print("⚠️ Erro ao renderizar fotos no PDF consolidado:", ex)
            
        doc.build(story, onFirstPage=draw_background, onLaterPages=draw_background)
        
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"atividade_tecnica_{id}.pdf"
    )



@technical_bp.route("/api/gestao/reunioes/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def reuniao_pdf(id):
    import io
    from flask import send_file
    
    m = Meeting.query.get_or_404(id)
    buffer = io.BytesIO()

    parts_str = "Nenhum participante"
    if m.participants:
        try:
            pids = [int(x) for x in m.participants.split(",") if x.strip().isdigit()]
            parts_str = ", ".join([u.username.upper() for u in User.query.filter(User.id.in_(pids))])
        except Exception:
            parts_str = m.participants

    metadata = {
        "__ref_id__": f"RN-{m.id}",
        "Assunto": m.subject or "N/A",
        "Data": m.date.strftime("%d/%m/%Y") if m.date else "N/A",
        "Horário": m.time or "N/A",
        "Local/Link": m.location or "N/A",
        "Responsável": (m.responsible or "N/A").upper()
    }

    content = [
        ("Objetivo da Reunião", m.objective or "Sem objetivo cadastrado"),
        ("Participantes", parts_str),
        ("Resumo / Ata", m.summary or "Sem resumo cadastrado"),
        ("Ações / Próximos Passos", m.actions or "Sem ações mapeadas"),
        ("Observações Gerais", m.obs or "Sem observações")
    ]

    make_premium_pdf(buffer, f"Ata de Reunião: {m.title}", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"ata_reuniao_{id}.pdf"
    )



@technical_bp.route("/api/gestao/rfo/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def rfo_pdf(id):
    import io
    from flask import send_file
    
    r = RFO.query.get_or_404(id)
    buffer = io.BytesIO()

    techs_str = "Nenhum técnico"
    if r.technicians_json:
        try:
            techs = json.loads(r.technicians_json)
            if isinstance(techs, list):
                techs_str = ", ".join([u.username.upper() for u in User.query.filter(User.id.in_([int(x) for x in techs]))])
        except Exception:
            techs_str = str(r.technicians_json)

    def format_dt(dt_str):
        if not dt_str:
            return "N/A"
        try:
            dt = datetime.strptime(dt_str.replace("T", " "), "%Y-%m-%d %H:%M")
            return dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            return dt_str

    start_formatted = format_dt(r.start_time)
    end_formatted = format_dt(r.end_time)

    metadata = {
        "__ref_id__": r.number or f"RF-{r.id}",
        "Número RFO": r.number or "N/A",
        "Cidade / Bairro": f"{r.city or 'N/A'} / {r.neighborhood or 'N/A'}",
        "Data": r.date.strftime("%d/%m/%Y") if r.date else "N/A",
        "Horário": f"{start_formatted} até {end_formatted}",
        "Técnico Responsável": (r.tech_responsible or "N/A").upper()
    }

    content = [
        ("Tipo de Problema", r.problem_type or "N/A"),
        ("Descrição / Observações", r.description or "Sem observações adicionais"),
        ("Causa Raiz", r.root_cause or "Não informada"),
        ("Ações Corretivas / Plano", r.action or "Não informado"),
        ("Coordenadas GPS", f"{r.lat or 'N/A'}, {r.lon or 'N/A'}")
    ]

    # Fetch physical image paths for ReportLab
    image_paths = []
    if r.photos_json:
        try:
            filenames = json.loads(r.photos_json)
            if isinstance(filenames, list):
                for fn in filenames:
                    p_path = VISTORIAS_UPLOAD_DIR / fn
                    if p_path.exists():
                        image_paths.append(p_path)
        except Exception as ex:
            print("⚠️ Erro ao carregar fotos do RFO para o PDF:", ex)

    make_premium_pdf(buffer, f"Relatório de Ocorrência (RFO): {r.title or 'Sem Título'}", metadata, content, image_paths=image_paths)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"rfo_{r.number or id}.pdf"
    )



@technical_bp.route("/api/gestao/rota_exata/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def rota_exata_pdf(id):
    import io
    from flask import send_file
    
    r = RotaExata.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "__ref_id__": f"RE-{r.id}",
        "Supervisor": (r.supervisor.username if r.supervisor else "N/A").upper(),
        "Data de Auditoria": r.date.strftime("%d/%m/%Y") if r.date else "N/A",
        "Horário": r.date_created.strftime("%H:%M") if r.date_created else (r.time or "N/A"),
    }

    techs_str = ""
    if r.techs_data:
        try:
            if isinstance(r.techs_data, list):
                lines = []
                for i, t in enumerate(r.techs_data, 1):
                    tech_name = t.get('tech_name') or f"Técnico ID {t.get('tech_id')}"
                    lines.append(f"<b>AUDITORIA {i}: {tech_name.upper()}</b>")
                    lines.append(f"  • <b>Data de Supervisão:</b> {t.get('supervision_date') or 'N/A'}")
                    lines.append(f"  • <b>Saída do Pátio:</b> {t.get('yard_departure_time') or 'N/A'}")
                    
                    delay_reason = t.get('delay_reason')
                    if delay_reason:
                        lines.append(f"  • <b>Atraso na Saída:</b> Sim | <b>Motivo:</b> {delay_reason}")
                    else:
                        lines.append(f"  • <b>Atraso na Saída:</b> Não")
                    
                    route_deviation = t.get('route_deviation')
                    identified_reason = t.get('identified_reason')
                    if route_deviation or identified_reason:
                        lines.append(f"  • <b>Desvio de Rota:</b> Sim | <b>Local:</b> {route_deviation or 'N/A'} (<b>Motivo:</b> {identified_reason or 'N/A'})")
                    else:
                        lines.append(f"  • <b>Desvio de Rota:</b> Não")
                        
                    lines.append(f"  • <b>Horário de Almoço:</b> {t.get('lunch_start') or 'N/A'} até {t.get('lunch_end') or 'N/A'}")
                    lines.append(f"  • <b>Rota Planejada:</b> {t.get('planned_route') or 'N/A'}")
                    
                    obs = t.get('observations')
                    if obs:
                        lines.append(f"  • <b>Observações:</b> {obs}")
                    lines.append("")
                    if i < len(r.techs_data):
                        lines.append("__________________________________________________________________")
                        lines.append("")
                techs_str = "\n".join(lines)
            else:
                techs_str = str(r.techs_data)
        except Exception as ex:
            techs_str = f"Erro ao processar dados de técnicos: {str(ex)}"

    content = [
        ("Auditoria de Técnicos em Campo", techs_str or "Nenhuma auditoria de técnico registrada"),
        ("Observações do Supervisor", r.obs or "Sem observações registradas")
    ]

    make_premium_pdf(buffer, "Relatório de Auditoria Rota Exata", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"auditoria_rota_exata_{id}.pdf"
    )



@technical_bp.route("/api/gestao/supervisao/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def supervisao_pdf(id):
    import io
    from flask import send_file
    
    s = SupervisaoTecnica.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "__ref_id__": f"SV-{s.id}",
        "Supervisor": (s.supervisor.username if s.supervisor else "N/A").upper(),
        "Data de Auditoria": s.date.strftime("%d/%m/%Y") if s.date else "N/A",
        "Horário": s.time or "N/A",
    }

    def map_status_pdf(val):
        if not val:
            return '<font color="#64748b">N/A</font>'
        v_upper = str(val).upper()
        if v_upper == 'OK':
            return '<font color="#059669"><b>OK</b></font>'
        elif v_upper in ('IRR', 'IRREGULAR', 'NÃO OK', 'NAO OK'):
            return '<font color="#dc2626"><b>NÃO OK</b></font>'
        elif v_upper in ('NA', 'N/A'):
            return '<font color="#64748b">N/A</font>'
        return val

    def map_risk_pdf(val):
        if not val:
            return 'N/A'
        v_title = str(val).title()
        if v_title == 'Alto':
            return '<font color="#dc2626"><b>Alto</b></font>'
        elif v_title == 'Médio':
            return '<font color="#d97706"><b>Médio</b></font>'
        elif v_title == 'Baixo':
            return '<font color="#059669"><b>Baixo</b></font>'
        return val

    from reportlab.platypus import Paragraph, Spacer, Table, TableStyle, Image as RLImage
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import mm

    styles = getSampleStyleSheet()
    val_style = ParagraphStyle(
        name="SupValueStyle",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=10,
        textColor=colors.HexColor("#1E293B"),
        leading=14
    )
    subhead_style = ParagraphStyle(
        name="SupSubheadStyle",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=10,
        textColor=colors.HexColor("#475569"),
        leading=14
    )

    content = []
    orphaned_image_paths = []

    if s.techs_data and isinstance(s.techs_data, list):
        for i, t in enumerate(s.techs_data, 1):
            tech_name = t.get('tech_name') or f"Técnico ID {t.get('tech_id')}"
            
            epi = map_status_pdf(t.get('epi'))
            epc = map_status_pdf(t.get('epc'))
            ladder = map_status_pdf(t.get('ladder_position'))
            car = map_status_pdf(t.get('car_position'))
            uniform = map_status_pdf(t.get('uniform'))
            risk = map_risk_pdf(t.get('risk_level'))
            obs_colab = t.get('conclusion') or t.get('obs') or 'N/A'
            info_html = (
                f"• <b>Local da Auditoria:</b> {t.get('location') or 'N/A'}<br/>"
                f"• <b>Horário:</b> {t.get('supervision_time') or 'N/A'}<br/>"
                f"• <b>Atividade Desenvolvida:</b> {t.get('activity') or 'N/A'}<br/>"
                f"• <b>Grau de Risco:</b> {risk}<br/>"
                f"• <b>Observações:</b> {obs_colab}<br/><br/>"
                f"• <b>Checklist de Conformidades:</b><br/>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;EPI: {epi} &nbsp;|&nbsp; EPC: {epc}<br/>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;Escada: {ladder} &nbsp;|&nbsp; Carro: {car}<br/>"
                f"&nbsp;&nbsp;&nbsp;&nbsp;Uniforme/ID: {uniform}"
            )

            label_title = f"SUPERVISÃO {i}:<br/><b>{tech_name.upper()}</b>"
            content.append((label_title, Paragraph(info_html, val_style)))

            # Fotos deste técnico específico (Linha de largura total alinhada à margem esquerda!)
            t_photos = t.get('photos') or []
            if isinstance(t_photos, list) and len(t_photos) > 0:
                valid_photo_elements = []
                for fn in t_photos:
                    p_path = VISTORIAS_UPLOAD_DIR / fn
                    if p_path.exists():
                        try:
                            from PIL import Image as PILImage
                            with PILImage.open(p_path) as test_img:
                                test_img.verify()
                            img = RLImage(str(p_path), width=75*mm, height=55*mm)
                            img.hAlign = 'LEFT'
                            valid_photo_elements.append(img)
                        except Exception as ex:
                            print(f"⚠️ Erro ao carregar foto do técnico no PDF ({p_path}):", ex)
                
                if valid_photo_elements:
                    photo_flowables = []
                    photo_flowables.append(Paragraph(f"<b>Registro Fotográfico - Auditoria ({len(valid_photo_elements)} foto(s)):</b>", subhead_style))
                    photo_flowables.append(Spacer(1, 2*mm))

                    photo_rows = []
                    for p_idx in range(0, len(valid_photo_elements), 2):
                        p_row = [valid_photo_elements[p_idx]]
                        if p_idx + 1 < len(valid_photo_elements):
                            p_row.append(valid_photo_elements[p_idx+1])
                        else:
                            p_row.append("")
                        photo_rows.append(p_row)

                    p_table = Table(photo_rows, colWidths=[80*mm, 80*mm])
                    p_table.hAlign = 'LEFT'
                    p_table.setStyle(TableStyle([
                        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
                        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
                        ('LEFTPADDING', (0, 0), (-1, -1), 0),
                        ('RIGHTPADDING', (0, 0), (-1, -1), 6),
                        ('TOPPADDING', (0, 0), (-1, -1), 2),
                        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
                    ]))
                    photo_flowables.append(p_table)

                    content.append(("", photo_flowables))
    else:
        content.append(("Auditoria de Técnicos em Campo", "Nenhuma supervisão registrada"))

    # Fotos raiz legado (se houverem no nível da supervisão)
    if s.photos_json:
        try:
            filenames = json.loads(s.photos_json)
            if isinstance(filenames, list):
                for fn in filenames:
                    p_path = VISTORIAS_UPLOAD_DIR / fn
                    if p_path.exists():
                        orphaned_image_paths.append(p_path)
        except Exception as ex:
            print("⚠️ Erro ao carregar fotos gerais da supervisão para o PDF:", ex)

    make_premium_pdf(buffer, "Relatório de Supervisão Técnica em Campo", metadata, content, image_paths=orphaned_image_paths)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"supervisao_campo_{id}.pdf"
    )


@technical_bp.route("/api/gestao/relatorios/gerar", methods=["GET"])
@supervisor_allowed
def gestao_relatorios_gerar():
    import io
    import json
    from flask import request, send_file, current_app
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from datetime import datetime, date

    report_type = request.args.get("type", "lms")
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    user_id_str = request.args.get("user_id")

    if not start_date_str or not end_date_str:
        return "Datas inicial e final são obrigatórias.", 400

    try:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date()
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date()
    except ValueError:
        return "Formato de data inválido. Use AAAA-MM-DD.", 400

    user_id = int(user_id_str) if user_id_str else None
    
    # Fetch data based on report_type
    records = []
    title = ""
    col_widths = []
    headers = []
    rows = []
    summary_metrics = {}

    start_datetime = datetime.combine(start_date, datetime.min.time())
    end_datetime = datetime.combine(end_date, datetime.max.time())

    if report_type == "lms":
        title = "Relatório Consolidado de Treinamentos (LMS)"
        query = TrainingAttempt.query.filter(
            TrainingAttempt.attempted_at >= start_datetime,
            TrainingAttempt.attempted_at <= end_datetime
        )
        if user_id:
            query = query.join(TrainingAssignment).filter(TrainingAssignment.user_id == user_id)
        attempts = query.order_by(TrainingAttempt.attempted_at.desc()).all()
        
        headers = ["Data", "Treinamento / Curso", "Colaborador", "Pontuação", "Resultado"]
        col_widths = [30*mm, 55*mm, 45*mm, 25*mm, 25*mm]
        
        passed_count = 0
        for att in attempts:
            t_title = att.assignment.course.title if att.assignment and att.assignment.course else "N/A"
            u_name = (att.assignment.user.username if att.assignment and att.assignment.user else "N/A").upper()
            passing_grade = att.assignment.course.passing_grade or 70 if att.assignment and att.assignment.course else 70
            is_passed = (att.score or 0) >= passing_grade
            res = "Aprovado" if is_passed else "Reprovado"
            if is_passed:
                passed_count += 1
            
            rows.append([
                att.attempted_at.strftime("%d/%m/%Y %H:%M"),
                t_title,
                u_name,
                f"{att.score or 0}%",
                res
            ])
            
        summary_metrics = {
            "Total de Tentativas": len(attempts),
            "Aprovados": passed_count,
            "Reprovados": len(attempts) - passed_count,
            "Taxa de Sucesso": f"{(passed_count / len(attempts) * 100):.1f}%" if attempts else "100.0%"
        }

    elif report_type == "supervisao":
        title = "Relatório Consolidado de Supervisões Técnicas"
        query = SupervisaoTecnica.query.filter(
            SupervisaoTecnica.date >= start_date,
            SupervisaoTecnica.date <= end_date
        )
        if user_id:
            query = query.filter(SupervisaoTecnica.supervisor_id == user_id)
        sups = query.order_by(SupervisaoTecnica.date.desc()).all()
        
        headers = ["Data/Hora", "Supervisor", "Colaboradores Supervisionados", "Ações/Plano", "Irregularidades"]
        col_widths = [25*mm, 35*mm, 50*mm, 40*mm, 30*mm]
        
        for s in sups:
            supervisor_name = (s.supervisor.username if s.supervisor else "N/A").upper()
            techs = "N/A"
            if s.techs_data:
                try:
                    if isinstance(s.techs_data, list):
                        techs = ", ".join([f"{str(t.get('name', '')).upper()} ({t.get('status', '')})" for t in s.techs_data])
                    else:
                        techs = str(s.techs_data)
                except Exception:
                    techs = str(s.techs_data)
            
            rows.append([
                f"{s.date.strftime('%d/%m/%Y')} {s.time or ''}",
                supervisor_name,
                techs,
                s.action or "Nenhuma",
                s.irregularities or "Nenhuma"
            ])
            
        summary_metrics = {
            "Total de Supervisões": len(sups),
            "Período Analisado": f"{start_date.strftime('%d/%m/%Y')} a {end_date.strftime('%d/%m/%Y')}"
        }

    elif report_type == "rfo":
        title = "Relatório Consolidado de Ocorrências (RFO)"
        query = RFO.query.filter(
            RFO.date >= start_date,
            RFO.date <= end_date
        )
        if user_id:
            u = User.query.get(user_id)
            if u:
                query = query.filter((RFO.tech_responsible == u.username) | (RFO.technicians_json.contains(str(user_id))))
        rfos = query.order_by(RFO.date.desc()).all()
        
        headers = ["Número/Data", "Título/Tipo", "Causa Raiz", "Impacto", "Responsável"]
        col_widths = [25*mm, 55*mm, 40*mm, 30*mm, 30*mm]
        
        for r in rfos:
            rows.append([
                f"{r.number or 'N/A'}\n{r.date.strftime('%d/%m/%Y')}",
                f"{r.title or 'Sem Título'}\n({r.problem_type or 'N/A'})",
                r.root_cause or "N/A",
                r.impact or "N/A",
                (r.tech_responsible or "N/A").upper()
            ])
            
        summary_metrics = {
            "Total de RFOs": len(rfos),
            "Filtro Técnico": (User.query.get(user_id).username.upper() if user_id else "Todos")
        }

    elif report_type == "atividades":
        title = "Relatório de Vistorias e Atividades em Campo"
        query = Activity.query.filter(
            Activity.date >= start_date,
            Activity.date <= end_date
        )
        if user_id:
            query = query.filter(Activity.user_id == user_id)
        acts = query.order_by(Activity.date.desc()).all()
        
        headers = ["Data/Hora", "Responsável", "Tipo / Cliente", "Localização", "Status"]
        col_widths = [30*mm, 35*mm, 45*mm, 50*mm, 20*mm]
        
        for a in acts:
            u_name = (a.user.username if a.user else (a.tech_responsible or "N/A")).upper()
            rows.append([
                f"{a.date.strftime('%d/%m/%Y')} {a.time or ''}",
                u_name,
                f"{a.type or 'N/A'}\nCli: {(a.client_name or 'N/A').upper()}",
                a.location or "N/A",
                a.status or "ABERTO"
            ])
            
        summary_metrics = {
            "Total de Atividades": len(acts),
            "Concluídas": sum(1 for a in acts if a.status == "CONCLUIDO"),
            "Em Andamento": sum(1 for a in acts if a.status == "EM_ANDAMENTO"),
            "Abertas": sum(1 for a in acts if a.status in ["ABERTO", "PENDENTE"])
        }

    elif report_type == "rota":
        title = "Acompanhamento de Rota Exata (Consolidado)"
        query = RotaExata.query.filter(
            RotaExata.date >= start_date,
            RotaExata.date <= end_date
        )
        if user_id:
            query = query.filter(RotaExata.supervisor_id == user_id)
        rotas = query.order_by(RotaExata.date.desc()).all()
        
        headers = ["Data", "Supervisor", "Ponto de Auditoria", "Técnicos Auditados", "Status"]
        col_widths = [25*mm, 35*mm, 45*mm, 55*mm, 20*mm]
        
        for r in rotas:
            sup_name = (r.supervisor.username if r.supervisor else "N/A").upper()
            techs = "N/A"
            if r.techs_data:
                try:
                    if isinstance(r.techs_data, list):
                        techs = ", ".join([f"{str(t.get('name', '')).upper()}" for t in r.techs_data])
                    else:
                        techs = str(r.techs_data)
                except Exception:
                    techs = str(r.techs_data)
            
            rows.append([
                r.date.strftime("%d/%m/%Y") if r.date else "N/A",
                sup_name,
                r.location or "N/A",
                techs,
                r.status or "PENDENTE"
            ])
            
        summary_metrics = {
            "Total de Rotas Auditadas": len(rotas),
            "Filtro Supervisor": (User.query.get(user_id).username.upper() if user_id else "Todos")
        }

    elif report_type == "reunioes":
        title = "Relatório de Atas de Reunião"
        query = Meeting.query.filter(
            Meeting.date >= start_date,
            Meeting.date <= end_date
        )
        meetings = query.order_by(Meeting.date.desc()).all()
        
        headers = ["Data/Hora", "Título / Assunto", "Local", "Responsável", "Status"]
        col_widths = [25*mm, 60*mm, 35*mm, 35*mm, 25*mm]
        
        for m in meetings:
            rows.append([
                f"{m.date.strftime('%d/%m/%Y')} {m.time or ''}",
                f"{m.title}\nAssunto: {m.subject or 'N/A'}",
                m.location or "N/A",
                (m.responsible or "N/A").upper(),
                m.status or "AGENDADA"
            ])
            
        summary_metrics = {
            "Total de Reuniões": len(meetings)
        }

    elif report_type == "escalas":
        title = "Relatório de Escalas de Plantão"
        query = Scale.query.filter(
            Scale.date >= start_date,
            Scale.date <= end_date
        )
        scales = query.order_by(Scale.date.desc()).all()
        
        headers = ["Data", "Tipo de Escala", "Equipe(s) / ID", "Plantonista(s)", "Observações"]
        col_widths = [25*mm, 35*mm, 45*mm, 45*mm, 30*mm]
        
        for s in scales:
            techs = "N/A"
            if s.technician_ids:
                try:
                    ids = [int(x.strip()) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                    if ids:
                        techs = ", ".join([u.username.upper() for u in User.query.filter(User.id.in_(ids))])
                except Exception:
                    techs = s.technician_ids
            
            teams = "N/A"
            if s.team_ids:
                try:
                    ids = [int(x.strip()) for x in s.team_ids.split(",") if x.strip().isdigit()]
                    if ids:
                        teams = ", ".join([t.name for t in Team.query.filter(Team.id.in_(ids))])
                except Exception:
                    teams = s.team_ids
            
            rows.append([
                s.date.strftime("%d/%m/%Y") if s.date else "N/A",
                s.type or "Plantão",
                teams,
                techs,
                s.obs or ""
            ])
            
        summary_metrics = {
            "Total de Escalas": len(scales)
        }

    elif report_type == "geradores":
        title = "Relatório do Status de Geradores e Combustível"
        query = Generator.query
        if user_id:
            query = query.filter(Generator.responsible_id == user_id)
        gens = query.all()
        
        headers = ["Gerador", "Localização", "Capacidade", "Nível Atual", "Último Abastecimento"]
        col_widths = [45*mm, 45*mm, 30*mm, 30*mm, 30*mm]
        
        for g in gens:
            refill = g.last_refill_date.strftime("%d/%m/%Y") if g.last_refill_date else "N/A"
            rows.append([
                g.name,
                g.location or "N/A",
                f"{g.capacity_total or 0.0} L",
                f"{g.current_qty or 0.0} L",
                refill
            ])
            
        summary_metrics = {
            "Total de Geradores": len(gens),
            "Combustível Total": f"{sum(g.current_qty or 0.0 for g in gens):.1f} L / {sum(g.capacity_total or 0.0 for g in gens):.1f} L"
        }

    elif report_type == "encerramento":
        title = "Relatório Consolidado de Encerramentos Diários"
        query = Encerramento.query.filter(
            Encerramento.date >= start_date,
            Encerramento.date <= end_date
        )
        encs = query.order_by(Encerramento.date.desc()).all()
        
        headers = ["Data", "Pátio", "Horário de Fechamento", "Técnicos Presentes", "Observações"]
        col_widths = [25*mm, 35*mm, 40*mm, 50*mm, 30*mm]
        
        for e in encs:
            p_name = e.patio.name if e.patio else "N/A"
            techs = "N/A"
            if e.technicians_json:
                try:
                    ids = json.loads(e.technicians_json)
                    if isinstance(ids, list):
                        techs = ", ".join([u.username for u in User.query.filter(User.id.in_([int(x) for x in ids]))])
                except Exception:
                    techs = str(e.technicians_json)
                    
            rows.append([
                e.date.strftime("%d/%m/%Y") if e.date else "N/A",
                p_name,
                e.closing_time or "N/A",
                techs,
                e.obs or "Nenhum"
            ])
            
        summary_metrics = {
            "Total de Encerramentos": len(encs)
        }

    elif report_type == "anotacoes":
        title = "Relatório de Anotações Técnicas"
        query = Note.query.filter(
            Note.event_date >= start_date,
            Note.event_date <= end_date
        )
        if user_id:
            query = query.filter(Note.user_id == user_id)
        notes = query.order_by(Note.event_date.desc()).all()
        
        headers = ["Data Evento", "Título", "Categoria / Prioridade", "Criador", "Descrição"]
        col_widths = [25*mm, 45*mm, 40*mm, 30*mm, 40*mm]
        
        for n in notes:
            u_name = n.user.username if n.user else "N/A"
            rows.append([
                n.event_date.strftime("%d/%m/%Y") if n.event_date else "N/A",
                n.title,
                f"{n.category or 'N/A'}\n({n.priority or 'MEDIA'})",
                u_name,
                n.description or ""
            ])
            
        summary_metrics = {
            "Total de Anotações": len(notes)
        }

    elif report_type == "tarefas":
        title = "Relatório Consolidado de Planos de Ação (Tarefas)"
        query = Task.query.filter(
            Task.deadline >= start_date,
            Task.deadline <= end_date
        )
        if user_id:
            query = query.filter(Task.responsible_id == user_id)
        tasks = query.order_by(Task.deadline.desc()).all()
        
        headers = ["Prazo", "Título / Descrição", "Responsável", "Prioridade", "Status"]
        col_widths = [25*mm, 70*mm, 35*mm, 25*mm, 25*mm]
        
        for t in tasks:
            resp = t.responsible.username if t.responsible else "N/A"
            rows.append([
                t.deadline.strftime("%d/%m/%Y") if t.deadline else "N/A",
                f"{t.title}\n{t.description or ''}",
                resp,
                t.priority or "MEDIA",
                t.status or "PENDENTE"
            ])
            
        summary_metrics = {
            "Total de Tarefas": len(tasks),
            "Concluídas": sum(1 for t in tasks if t.status == "CONCLUIDO"),
            "Em Andamento": sum(1 for t in tasks if t.status == "EM_ANDAMENTO"),
            "Pendentes": sum(1 for t in tasks if t.status in ["PENDENTE", "ABERTO"])
        }

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=12*mm, leftMargin=12*mm,
        topMargin=45*mm, bottomMargin=40*mm
    )

    styles = getSampleStyleSheet()
    
    label_style = ParagraphStyle(
        name="ConsolidatedLabel",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        textColor=colors.HexColor("#475569")
    )
    
    value_style = ParagraphStyle(
        name="ConsolidatedValue",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8.5,
        textColor=colors.HexColor("#1E293B")
    )

    cell_style = ParagraphStyle(
        name="TableCell",
        parent=styles["Normal"],
        fontName="Helvetica",
        fontSize=8,
        leading=10,
        textColor=colors.HexColor("#334155")
    )

    header_cell_style = ParagraphStyle(
        name="TableHeaderCell",
        parent=styles["Normal"],
        fontName="Helvetica-Bold",
        fontSize=8.5,
        leading=10.5,
        textColor=colors.white
    )

    story = []

    # 2. General metadata and metrics grid
    meta_table_data = []
    # Row 1: Period and total records
    meta_table_data.append([
        Paragraph("<b>Período:</b>", label_style),
        Paragraph(f"{start_date.strftime('%d/%m/%Y')} até {end_date.strftime('%d/%m/%Y')}", value_style),
        Paragraph("<b>Emissão:</b>", label_style),
        Paragraph(datetime.now().strftime("%d/%m/%Y %H:%M"), value_style)
    ])
    
    # Row 2: dynamic metrics
    metric_keys = list(summary_metrics.keys())
    for idx in range(0, len(metric_keys), 2):
        k1 = metric_keys[idx]
        v1 = summary_metrics[k1]
        row = [
            Paragraph(f"<b>{k1}:</b>", label_style),
            Paragraph(str(v1), value_style)
        ]
        if idx + 1 < len(metric_keys):
            k2 = metric_keys[idx+1]
            v2 = summary_metrics[k2]
            row.extend([
                Paragraph(f"<b>{k2}:</b>", label_style),
                Paragraph(str(v2), value_style)
            ])
        else:
            row.extend(["", ""])
        meta_table_data.append(row)

    meta_table = Table(meta_table_data, colWidths=[35*mm, 58*mm, 35*mm, 58*mm])
    meta_table.setStyle(TableStyle([
        ('BACKGROUND', (0, 0), (-1, -1), colors.HexColor("#F8FAFC")),
        ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
        ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
        ('BOTTOMPADDING', (0, 0), (-1, -1), 4),
        ('TOPPADDING', (0, 0), (-1, -1), 4),
        ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#E2E8F0")),
        ('BOX', (0, 0), (-1, -1), 1, colors.HexColor("#E2E8F0")),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 8*mm))

    # 3. Main Data Table
    story.append(Paragraph("<b>Registros no Período</b>", styles["Heading2"]))
    story.append(Spacer(1, 3*mm))

    if not rows:
        story.append(Spacer(1, 10*mm))
        story.append(Paragraph("Nenhum registro encontrado para os filtros selecionados.", styles["Normal"]))
    else:
        formatted_table_data = []
        # Header row
        formatted_table_data.append([Paragraph(h, header_cell_style) for h in headers])
        
        # Data rows
        for r in rows:
            formatted_row = []
            for item in r:
                val = str(item or "").replace("\n", "<br/>")
                formatted_row.append(Paragraph(val, cell_style))
            formatted_table_data.append(formatted_row)

        data_table = Table(formatted_table_data, colWidths=col_widths, repeatRows=1)
        
        t_style = [
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor("#4F46E5")),
            ('ALIGN', (0, 0), (-1, -1), 'LEFT'),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
            ('BOTTOMPADDING', (0, 0), (-1, -1), 5),
            ('TOPPADDING', (0, 0), (-1, -1), 5),
            ('LEFTPADDING', (0, 0), (-1, -1), 5),
            ('RIGHTPADDING', (0, 0), (-1, -1), 5),
            ('LINEBELOW', (0, 0), (-1, -1), 0.5, colors.HexColor("#F1F5F9")),
            ('LINEBELOW', (0, 0), (-1, 0), 1.5, colors.HexColor("#312E81")),
        ]
        
        for row_idx in range(1, len(formatted_table_data)):
            if row_idx % 2 == 0:
                t_style.append(('BACKGROUND', (0, row_idx), (-1, row_idx), colors.HexColor("#F8FAFC")))
                
        data_table.setStyle(TableStyle(t_style))
        story.append(data_table)

    story.append(Spacer(1, 15*mm))

    # Signature validation
    story.append(KeepTogether([
        Spacer(1, 8*mm),
        Table([
            ["", ""],
            ["_________________________________________", "_________________________________________"],
            ["Gestão Operacional / Coordenação", "Validação Digital do Sistema (Auditado)"],
        ], colWidths=[93*mm, 93*mm], style=TableStyle([
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('VALIGN', (0, 0), (-1, -1), 'MIDDLE'),
            ('FONTNAME', (0, 2), (-1, 2), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 2), (-1, 2), 8.5),
            ('TEXTCOLOR', (0, 2), (-1, 2), colors.HexColor("#64748B")),
        ]))
    ]))

    logo_path = "logo.png"
    if not os.path.exists(logo_path):
        logo_path = "/var/www/checklist_veicular/logo.png"

    RODAPE_LINHAS = [
        "ADAPT LINK SERVIÇOS EM COMUNICAÇÃO MULTIMÍDIA EIRELI",
        "CNPJ: 08.980.148/0001-41       Inscr. Est.: 78.342.480",
        "Rua Waldir Pedro de Medeiros, 253 – São Miguel – Seropédica – RJ",
        "CEP: 23.893-725",
        "Tel.: (21) 3812-5900 / (21) 2682-7822",
        "WWW.ADAPTLINK.COM.BR",
    ]

    def draw_background(c, doc_obj):
        width, height = A4
        
        # 1. Cabeçalho / Logotipo
        if os.path.exists(logo_path):
            try:
                from reportlab.lib.utils import ImageReader
                logo = ImageReader(logo_path)
                c.drawImage(logo, 20, height - 60, width=60, height=25, preserveAspectRatio=True, mask="auto")
            except Exception as e:
                print("⚠️ Erro ao carregar logo no header consolidado:", e)

        # 2. Título Centralizado
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.HexColor("#0F172A"))
        c.drawCentredString(width / 2, height - 40, title.upper())
        c.setFont("Helvetica", 11)
        c.drawCentredString(width / 2, height - 55, "Registro Formal – AdaptLink")

        # 3. Linha Azul Divisória Premium
        c.setStrokeColor(colors.HexColor("#1F3C78"))
        c.setLineWidth(2)
        c.line(20, height - 65, width - 20, height - 65)

        # 4. Metadados do topo: Emitido em / Período
        c.setFont("Helvetica", 8)
        c.setFillColor(colors.HexColor("#475569"))
        now_str = datetime.now().strftime("%d/%m/%Y %H:%M")
        c.drawString(25, height - 75, f"Emitido em: {now_str}")
        c.drawRightString(width - 25, height - 75, f"Período: {start_date.strftime('%d/%m/%Y')} a {end_date.strftime('%d/%m/%Y')}")

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

    doc.build(story, onFirstPage=draw_background, onLaterPages=draw_background)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"relatorio_consolidado_{report_type}.pdf"
    )




@technical_bp.route("/api/gestao/relatorios/preview", methods=["GET"])
@supervisor_allowed
def gestao_relatorios_preview():
    import json
    from flask import request, jsonify
    from datetime import datetime, date

    report_type = request.args.get("type", "lms")
    start_date_str = request.args.get("start_date")
    end_date_str = request.args.get("end_date")
    user_id_str = request.args.get("user_id")

    today = date.today()
    first_day_of_month = today.replace(day=1)

    try:
        start_date = datetime.strptime(start_date_str, "%Y-%m-%d").date() if start_date_str else first_day_of_month
        end_date = datetime.strptime(end_date_str, "%Y-%m-%d").date() if end_date_str else today
    except ValueError:
        return jsonify({"error": "Formato de data inválido. Use AAAA-MM-DD."}), 400

    user_id = int(user_id_str) if user_id_str else None
    user_obj = User.query.get(user_id) if user_id else None
    username = user_obj.username if user_obj else None

    records = []
    metrics = {}

    start_datetime = datetime.combine(start_date, datetime.min.time())
    end_datetime = datetime.combine(end_date, datetime.max.time())

    if report_type == "lms":
        query = TrainingAttempt.query.filter(
            TrainingAttempt.attempted_at >= start_datetime,
            TrainingAttempt.attempted_at <= end_datetime
        )
        if user_id:
            query = query.join(TrainingAssignment).filter(TrainingAssignment.user_id == user_id)
        attempts = query.order_by(TrainingAttempt.attempted_at.desc()).all()

        passed_count = 0
        for att in attempts:
            t_title = att.assignment.course.title if att.assignment and att.assignment.course else "N/A"
            u_name = att.assignment.user.username if att.assignment and att.assignment.user else "N/A"
            passing_grade = att.assignment.course.passing_grade or 70 if att.assignment and att.assignment.course else 70
            is_passed = (att.score or 0) >= passing_grade
            res = "Aprovado" if is_passed else "Reprovado"
            if is_passed:
                passed_count += 1

            records.append({
                "id": att.id,
                "date": att.attempted_at.strftime("%d/%m/%Y %H:%M"),
                "col1": t_title,
                "col2": u_name,
                "col3": f"{att.score or 0}%",
                "col4": res,
                "status": "success" if is_passed else "danger"
            })

        success_rate = f"{(passed_count / len(attempts) * 100):.1f}%" if attempts else "100.0%"
        metrics = {
            "Total de Tentativas": len(attempts),
            "Aprovados": passed_count,
            "Reprovados": len(attempts) - passed_count,
            "Taxa de Sucesso": success_rate
        }

    elif report_type == "supervisao":
        query = SupervisaoTecnica.query.filter(
            SupervisaoTecnica.date >= start_date,
            SupervisaoTecnica.date <= end_date
        )
        sups = query.order_by(SupervisaoTecnica.date.desc()).all()

        filtered_sups = []
        for s in sups:
            is_match = False
            if not user_id:
                is_match = True
            elif s.supervisor_id == user_id:
                is_match = True
            elif s.techs_data:
                try:
                    techs = s.techs_data
                    if isinstance(techs, str):
                        techs = json.loads(techs)
                    if isinstance(techs, list):
                        for t in techs:
                            tid = t.get('tech_id')
                            tname = t.get('tech_name') or t.get('name')
                            if tid and int(tid) == user_id:
                                is_match = True
                                break
                            if username and tname and tname.lower() == username.lower():
                                is_match = True
                                break
                except Exception:
                    pass
            
            if is_match:
                filtered_sups.append(s)

        irregular_count = 0
        for s in filtered_sups:
            supervisor_name = s.supervisor.username if s.supervisor else "N/A"
            techs_summary = "N/A"
            if s.techs_data:
                try:
                    techs = s.techs_data
                    if isinstance(techs, str):
                        techs = json.loads(techs)
                    if isinstance(techs, list):
                        techs_summary = ", ".join([f"{t.get('name') or t.get('tech_name', '')}" for t in techs])
                except Exception:
                    techs_summary = str(s.techs_data)

            has_irr = bool(s.irregularities and s.irregularities.strip() and s.irregularities.lower() != "nenhuma")
            if has_irr:
                irregular_count += 1

            records.append({
                "id": s.id,
                "date": s.date.strftime("%d/%m/%Y"),
                "col1": supervisor_name,
                "col2": techs_summary,
                "col3": s.action or "Nenhuma",
                "col4": s.irregularities or "Nenhuma",
                "status": "danger" if has_irr else "success"
            })

        metrics = {
            "Total de Supervisões": len(filtered_sups),
            "Sem Irregularidades": len(filtered_sups) - irregular_count,
            "Com Irregularidades": irregular_count,
            "Taxa de Conformidade": f"{((len(filtered_sups) - irregular_count) / len(filtered_sups) * 100):.1f}%" if filtered_sups else "100.0%"
        }

    elif report_type == "rfo":
        query = RFO.query.filter(
            RFO.date >= start_date,
            RFO.date <= end_date
        )
        if user_id:
            u = User.query.get(user_id)
            if u:
                query = query.filter((RFO.tech_responsible == u.username) | (RFO.technicians_json.contains(str(user_id))))
        rfos = query.order_by(RFO.date.desc()).all()

        resolved_count = 0
        for r in rfos:
            is_resolved = r.status in ["CONCLUIDO", "RESOLVIDO"]
            if is_resolved:
                resolved_count += 1

            records.append({
                "id": r.id,
                "date": r.date.strftime("%d/%m/%Y"),
                "col1": r.number or "N/A",
                "col2": f"{r.title or 'Sem Título'} ({r.problem_type or 'N/A'})",
                "col3": r.tech_responsible or "N/A",
                "col4": r.status or "ABERTO",
                "status": "success" if is_resolved else "warning"
            })

        metrics = {
            "Total de Ocorrências (RFO)": len(rfos),
            "Abertas / Pendentes": len(rfos) - resolved_count,
            "Concluídas / Resolvidas": resolved_count,
            "Taxa de Resolução": f"{(resolved_count / len(rfos) * 100):.1f}%" if rfos else "100.0%"
        }

    elif report_type == "atividades":
        query = Activity.query.filter(
            Activity.date >= start_date,
            Activity.date <= end_date
        )
        if user_id:
            query = query.filter(Activity.user_id == user_id)
        acts = query.order_by(Activity.date.desc()).all()

        concluded = 0
        in_progress = 0
        pending = 0

        for a in acts:
            u_name = a.user.username if a.user else (a.tech_responsible or "N/A")
            status_lower = (a.status or "").lower()

            if status_lower == "concluido":
                concluded += 1
                status_class = "success"
            elif status_lower == "em_andamento":
                in_progress += 1
                status_class = "warning"
            else:
                pending += 1
                status_class = "danger"

            records.append({
                "id": a.id,
                "date": a.date.strftime("%d/%m/%Y"),
                "col1": u_name,
                "col2": a.type or "N/A",
                "col3": a.client_name or "N/A",
                "col4": a.status or "ABERTO",
                "status": status_class
            })

        metrics = {
            "Total de Vistorias": len(acts),
            "Concluídas": concluded,
            "Em Andamento": in_progress,
            "Abertas / Pendentes": pending
        }

    elif report_type == "rota":
        query = RotaExata.query.filter(
            RotaExata.date >= start_date,
            RotaExata.date <= end_date
        )
        rotas = query.order_by(RotaExata.date.desc()).all()

        filtered_rotas = []
        for r in rotas:
            is_match = False
            if not user_id:
                is_match = True
            elif r.supervisor_id == user_id:
                is_match = True
            elif r.techs_data:
                try:
                    techs = r.techs_data
                    if isinstance(techs, str):
                        techs = json.loads(techs)
                    if isinstance(techs, list):
                        for t in techs:
                            tid = t.get('tech_id')
                            tname = t.get('tech_name') or t.get('name')
                            if tid and int(tid) == user_id:
                                is_match = True
                                break
                            if username and tname and tname.lower() == username.lower():
                                is_match = True
                                break
                except Exception:
                    pass

            if is_match:
                filtered_rotas.append(r)

        delay_count = 0
        deviation_count = 0

        for r in filtered_rotas:
            sup_name = r.supervisor.username if r.supervisor else "N/A"
            techs_summary = "N/A"
            has_delay = False
            has_deviation = False

            if r.techs_data:
                try:
                    techs = r.techs_data
                    if isinstance(techs, str):
                        techs = json.loads(techs)
                    if isinstance(techs, list):
                        techs_summary = ", ".join([f"{t.get('name') or t.get('tech_name', '')}" for t in techs])
                        for t in techs:
                            if t.get("delay_reason") or t.get("yard_departure_time_delayed") == True:
                                has_delay = True
                            if t.get("route_deviation") or t.get("identified_reason"):
                                has_deviation = True
                except Exception:
                    pass

            if has_delay:
                delay_count += 1
            if has_deviation:
                deviation_count += 1

            records.append({
                "id": r.id,
                "date": r.date.strftime("%d/%m/%Y"),
                "col1": sup_name,
                "col2": r.location or "N/A",
                "col3": techs_summary,
                "col4": r.status or "PENDENTE",
                "status": "danger" if (has_delay or has_deviation) else "success"
            })

        metrics = {
            "Total de Auditorias de Rota": len(filtered_rotas),
            "Atrasos Identificados": delay_count,
            "Desvios Identificados": deviation_count,
            "Rotas Regulares": len(filtered_rotas) - max(delay_count, deviation_count)
        }

    elif report_type == "reunioes":
        query = Meeting.query.filter(
            Meeting.date >= start_date,
            Meeting.date <= end_date
        )
        meetings = query.order_by(Meeting.date.desc()).all()

        if user_id:
            meetings = [m for m in meetings if (m.participants and str(user_id) in [x.strip() for x in m.participants.split(",")]) or (username and m.responsible == username)]

        realized = 0
        scheduled = 0

        for m in meetings:
            status_lower = (m.status or "").lower()
            is_realized = status_lower in ["realizada", "concluida"]
            if is_realized:
                realized += 1
            else:
                scheduled += 1

            records.append({
                "id": m.id,
                "date": m.date.strftime("%d/%m/%Y"),
                "col1": m.title,
                "col2": m.subject or "N/A",
                "col3": m.responsible or "N/A",
                "col4": m.status or "AGENDADA",
                "status": "success" if is_realized else "warning"
            })

        metrics = {
            "Total de Reuniões": len(meetings),
            "Realizadas": realized,
            "Agendadas": scheduled
        }

    elif report_type == "escalas":
        query = Scale.query.filter(
            Scale.date >= start_date,
            Scale.date <= end_date
        )
        scales = query.order_by(Scale.date.desc()).all()

        if user_id:
            scales = [s for s in scales if s.technician_ids and str(user_id) in [x.strip() for x in s.technician_ids.split(",")]]

        weekend_count = 0
        holiday_count = 0

        for s in scales:
            scale_type = (s.type or "").lower()
            if scale_type in ["sabado", "domingo"]:
                weekend_count += 1
            elif scale_type == "feriado":
                holiday_count += 1

            # Resolve names
            teams_str = "N/A"
            if s.team_ids:
                try:
                    tids = [int(x.strip()) for x in s.team_ids.split(",") if x.strip().isdigit()]
                    if tids:
                        teams_str = ", ".join([t.name for t in Team.query.filter(Team.id.in_(tids))])
                except Exception:
                    teams_str = s.team_ids

            techs_str = "N/A"
            if s.technician_ids:
                try:
                    tids = [int(x.strip()) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                    if tids:
                        techs_str = ", ".join([u.username for u in User.query.filter(User.id.in_(tids))])
                except Exception:
                    techs_str = s.technician_ids

            records.append({
                "id": s.id,
                "date": s.date.strftime("%d/%m/%Y"),
                "col1": s.type or "Plantão",
                "col2": teams_str,
                "col3": techs_str,
                "col4": s.obs or "",
                "status": "info"
            })

        metrics = {
            "Total de Plantões": len(scales),
            "Finais de Semana": weekend_count,
            "Feriados": holiday_count
        }

    elif report_type == "geradores":
        query = Generator.query
        if user_id:
            query = query.filter(Generator.responsible_id == user_id)
        gens = query.all()

        total_capacity = 0.0
        current_fuel = 0.0
        operational_count = 0

        for g in gens:
            total_capacity += g.capacity_total or 0.0
            current_fuel += g.current_qty or 0.0
            is_operational = g.status == "OPERACIONAL"
            if is_operational:
                operational_count += 1

            records.append({
                "id": g.id,
                "date": g.last_refill_date.strftime("%d/%m/%Y") if g.last_refill_date else "N/A",
                "col1": g.name,
                "col2": g.location or "N/A",
                "col3": f"{g.current_qty or 0.0} L / {g.capacity_total or 0.0} L",
                "col4": g.status or "OPERACIONAL",
                "status": "success" if is_operational else "danger"
            })

        fuel_percentage = f"{(current_fuel / total_capacity * 100):.1f}%" if total_capacity else "0.0%"
        metrics = {
            "Total de Geradores": len(gens),
            "Status Operacional": f"{operational_count} / {len(gens)}",
            "Combustível Total": f"{current_fuel:.1f} L / {total_capacity:.1f} L",
            "Nível de Reserva": fuel_percentage
        }

    elif report_type == "encerramento":
        query = Encerramento.query.filter(
            Encerramento.date >= start_date,
            Encerramento.date <= end_date
        )
        encs = query.order_by(Encerramento.date.desc()).all()

        if user_id:
            encs_filtered = []
            for e in encs:
                if e.technicians_json:
                    try:
                        ids = json.loads(e.technicians_json)
                        if isinstance(ids, list) and user_id in ids:
                            encs_filtered.append(e)
                    except Exception:
                        if str(user_id) in str(e.technicians_json):
                            encs_filtered.append(e)
            encs = encs_filtered

        patios_ids = set()
        for e in encs:
            p_name = e.patio.name if e.patio else "N/A"
            if e.patio_id:
                patios_ids.add(e.patio_id)

            techs_summary = "N/A"
            if e.technicians_json:
                try:
                    ids = json.loads(e.technicians_json)
                    if isinstance(ids, list):
                        techs_summary = ", ".join([u.username for u in User.query.filter(User.id.in_([int(x) for x in ids]))])
                except Exception:
                    techs_summary = str(e.technicians_json)

            records.append({
                "id": e.id,
                "date": e.date.strftime("%d/%m/%Y"),
                "col1": p_name,
                "col2": e.closing_time or "N/A",
                "col3": techs_summary,
                "col4": e.obs or "Nenhum",
                "status": "info"
            })

        metrics = {
            "Total de Encerramentos": len(encs),
            "Pátios Atendidos": len(patios_ids)
        }

    elif report_type == "anotacoes":
        query = Note.query.filter(
            Note.event_date >= start_date,
            Note.event_date <= end_date
        )
        if user_id:
            query = query.filter(Note.user_id == user_id)
        notes = query.order_by(Note.event_date.desc()).all()

        high_priority = 0

        for n in notes:
            u_name = n.user.username if n.user else "N/A"
            is_high = n.priority == "ALTA"
            if is_high:
                high_priority += 1

            records.append({
                "id": n.id,
                "date": n.event_date.strftime("%d/%m/%Y") if n.event_date else "N/A",
                "col1": n.title,
                "col2": n.category or "Geral",
                "col3": u_name,
                "col4": n.priority or "MEDIA",
                "status": "danger" if is_high else "info"
            })

        metrics = {
            "Total de Anotações": len(notes),
            "Alta Prioridade": high_priority,
            "Média/Baixa Prioridade": len(notes) - high_priority
        }

    elif report_type == "tarefas":
        query = Task.query.filter(
            Task.deadline >= start_date,
            Task.deadline <= end_date
        )
        if user_id:
            query = query.filter(Task.responsible_id == user_id)
        tasks = query.order_by(Task.deadline.desc()).all()

        concluded = 0
        in_progress = 0
        pending = 0

        for t in tasks:
            resp = t.responsible.username if t.responsible else "N/A"
            status_lower = (t.status or "").lower()

            if status_lower == "concluido":
                concluded += 1
                status_class = "success"
            elif status_lower == "em_andamento":
                in_progress += 1
                status_class = "warning"
            else:
                pending += 1
                status_class = "danger"

            records.append({
                "id": t.id,
                "date": t.deadline.strftime("%d/%m/%Y") if t.deadline else "N/A",
                "col1": t.title,
                "col2": resp,
                "col3": t.priority or "MEDIA",
                "col4": t.status or "PENDENTE",
                "status": status_class
            })

        metrics = {
            "Total de Tarefas": len(tasks),
            "Concluídas": concluded,
            "Em Andamento": in_progress,
            "Pendentes": pending
        }

    return jsonify({
        "records": records,
        "metrics": metrics
    })


def cleanup_old_announcements():
    """
    Remove comunicados (avisos) com mais de 3 dias de criação para otimização de espaço.
    Remove também os registros de leitura correspondentes.
    """
    try:
        three_days_ago = agora() - timedelta(days=3)
        old_anns = Announcement.query.filter(Announcement.created_at < three_days_ago).all()
        if old_anns:
            old_ids = [a.id for a in old_anns]
            AnnouncementRead.query.filter(AnnouncementRead.announcement_id.in_(old_ids)).delete(synchronize_session=False)
            Announcement.query.filter(Announcement.id.in_(old_ids)).delete(synchronize_session=False)
            db.session.commit()
    except Exception as e:
        db.session.rollback()
        current_app.logger.error(f"Erro ao limpar comunicados antigos: {e}")


# ----------------- ROTAS: COMUNICAÇÕES (AVISOS) -----------------
@technical_bp.route("/avisos", methods=["GET", "POST"])
@login_required
def avisos():
    if request.method == "POST":
        if not (current_user.is_admin or current_user.is_supervisor or current_user.has_permission("comunicados")):
            flash("Permissão negada.", "error")
            return redirect(url_for("avisos"))
            
        acao = request.form.get("acao")
        
        if acao == "novo_aviso":
            title = request.form.get("title", "").strip()
            message = request.form.get("message", "").strip()
            target = request.form.get("target", "all").strip()
            days_valid = request.form.get("days_valid", "").strip()
            
            if not title or not message:
                flash("Título e mensagem são obrigatórios.", "error")
                return redirect(url_for("avisos"))
                
            target_role = None
            user_id = None
            recipient_users = []
            
            if target.startswith("role:"):
                target_role = target.split(":")[1]
                recipient_users = User.query.filter_by(role=target_role).all()
            elif target.startswith("user:"):
                user_id = int(target.split(":")[1])
                single_u = User.query.get(user_id)
                if single_u:
                    recipient_users = [single_u]
            else:
                target_role = "all"
                recipient_users = User.query.all()
                
            expires_at = None
            if days_valid.isdigit():
                expires_at = agora() + timedelta(days=int(days_valid))
                
            a = Announcement(
                title=title,
                content=message,
                target_role=target_role,
                user_id=user_id,
                expires_at=expires_at,
                created_by=current_user.id
            )
            db.session.add(a)
            db.session.commit()
            
            registrar_log(f"Novo comunicado transmitido: {title} (para {target})")
            
            # Disparo via WhatsApp se a opção estiver marcada
            if request.form.get("send_whatsapp") == "on":
                w_config = WhatsAppConfig.query.first()
                if w_config and w_config.is_enabled:
                    w_msg = f"*{title}*\n\n{message}"
                    sent_count = 0
                    for u in recipient_users:
                        if u.phone:
                            try:
                                send_whatsapp_message(u.phone, w_msg)
                                sent_count += 1
                            except Exception:
                                pass
                    if sent_count > 0:
                        flash(f"✅ Comunicado enviado! Disparado via WhatsApp para {sent_count} colaborador(es).", "success")
                    else:
                        flash("⚠️ Comunicado enviado! Porém nenhum destinatário possuía telefone cadastrado para o envio do WhatsApp.", "warning")
                else:
                    flash("Comunicado enviado! O disparo via WhatsApp não pôde ser realizado pois a API do WhatsApp está desativada.", "warning")
            else:
                flash("Comunicado enviado com sucesso!", "success")
            
        elif acao == "excluir_aviso":
            aid = request.form.get("id")
            if aid and aid.isdigit():
                a = Announcement.query.get(int(aid))
                if a:
                    # Deleta registros de leitura vinculados para evitar erro de chave estrangeira
                    AnnouncementRead.query.filter_by(announcement_id=a.id).delete()
                    db.session.delete(a)
                    db.session.commit()
                    registrar_log(f"Comunicado excluído: {a.title}")
                    flash("Comunicado excluído.", "success")
                    
        elif acao == "salvar_informacoes":
            role_group = request.form.get("role_group", "").strip()
            content = request.form.get("content", "").strip()
            
            if role_group in {"admin_supervisor", "manutencao", "tech"}:
                m = Manual.query.filter_by(role_group=role_group).first()
                if not m:
                    m = Manual(role_group=role_group, content=content)
                    db.session.add(m)
                else:
                    m.content = content
                db.session.commit()
                registrar_log(f"Manual atualizado para: {role_group}")
                flash("Manual de operação atualizado com sucesso!", "success")
                
        elif acao == "toggle_rule":
            slug = request.form.get("slug", "").strip()
            rule = SystemRule.query.filter_by(slug=slug).first()
            if rule:
                rule.is_enabled = not rule.is_enabled
                db.session.commit()
                state = "ativada" if rule.is_enabled else "desativada"
                registrar_log(f"Regra de automação {slug} {state}")
                flash(f"Regra {rule.name} {state}!", "success")

        elif acao == "salvar_integracao_whatsapp":
            config = WhatsAppConfig.query.first()
            if not config:
                config = WhatsAppConfig()
                db.session.add(config)
            config.api_url = request.form.get("api_url", "").strip()
            config.apikey = request.form.get("apikey", "").strip()
            config.instance_name = request.form.get("instance_name", "").strip()
            config.recipients = request.form.get("recipients", "").strip()
            config.is_enabled = request.form.get("is_enabled") == "on"
            db.session.commit()
            registrar_log(f"Configuração do Whatsapp atualizada na Central de Avisos")
            flash("✅ Integração WhatsApp salva com sucesso!", "success")
            
        elif acao == "salvar_integracao_telegram":
            config = TelegramConfig.query.first()
            if not config:
                config = TelegramConfig()
                db.session.add(config)
            config.bot_token = request.form.get("bot_token", "").strip()
            config.chat_id = request.form.get("chat_id", "").strip()
            config.is_enabled = request.form.get("is_enabled") == "on"
            db.session.commit()
            registrar_log(f"Configuração do Telegram atualizada por {current_user.username}")
            flash("✅ Integração Telegram salva com sucesso!", "success")
            
        elif acao == "salvar_integracao_email":
            config = EmailConfig.query.first()
            if not config:
                config = EmailConfig()
                db.session.add(config)
            config.smtp_server = request.form.get("smtp_server", "").strip()
            try:
                config.smtp_port = int(request.form.get("smtp_port", "587"))
            except ValueError:
                config.smtp_port = 587
            config.smtp_user = request.form.get("smtp_user", "").strip()
            config.smtp_password = request.form.get("smtp_password", "").strip()
            config.from_email = request.form.get("from_email", "").strip()
            config.use_ssl = request.form.get("use_ssl") == "on"
            config.is_enabled = request.form.get("is_enabled") == "on"
            db.session.commit()
            registrar_log(f"Configuração de E-mail (SMTP) atualizada por {current_user.username}")
            flash("✅ Integração E-mail (SMTP) salva com sucesso!", "success")
            
        elif acao == "atualizar_regra":
            slug = request.form.get("slug", "").strip()
            rule = SystemRule.query.filter_by(slug=slug).first()
            if rule:
                rule.is_enabled = request.form.get("is_enabled") == "on"
                try:
                    rule.trigger_days = int(request.form.get("trigger_days", "7"))
                except ValueError:
                    rule.trigger_days = 7
                
                # Canais
                channels_list = []
                if request.form.get("channel_system") == "on":
                    channels_list.append("system")
                if request.form.get("channel_whatsapp") == "on":
                    channels_list.append("whatsapp")
                if request.form.get("channel_telegram") == "on":
                    channels_list.append("telegram")
                if request.form.get("channel_email") == "on":
                    channels_list.append("email")
                rule.channels = ",".join(channels_list)
                
                try:
                    rule.silence_days = int(request.form.get("silence_days", "1"))
                except ValueError:
                    rule.silence_days = 1

                # Templates
                rule.msg_system = request.form.get("msg_system", "").strip()
                rule.msg_whatsapp = request.form.get("msg_whatsapp", "").strip()
                rule.msg_telegram = request.form.get("msg_telegram", "").strip()
                rule.msg_email = request.form.get("msg_email", "").strip()
                
                db.session.commit()
                registrar_log(f"Regra de automação {slug} atualizada")
                flash(f"✅ Regra '{rule.name}' atualizada com sucesso!", "success")
                
        return redirect(url_for("avisos"))

    # GET
    cleanup_old_announcements()
    notifications = Announcement.query.order_by(Announcement.created_at.desc()).all()
    
    # Busca todos os manuais
    manuais_records = Manual.query.all()
    manuais = {m.role_group: m.content for m in manuais_records}
    # Garante chaves para evitar UndefinedError
    for k in {"admin_supervisor", "manutencao", "tech"}:
        if k not in manuais:
            manuais[k] = ""
            
    usuarios = User.query.filter(User.username != "admin").order_by(User.username.asc()).all()
    regras = SystemRule.query.order_by(SystemRule.id.asc()).all()
    
    # Configurações das integrações
    whatsapp_config = WhatsAppConfig.query.first()
    if not whatsapp_config:
        whatsapp_config = WhatsAppConfig()
        db.session.add(whatsapp_config)
        db.session.commit()

    telegram_config = TelegramConfig.query.first()
    if not telegram_config:
        telegram_config = TelegramConfig()
        db.session.add(telegram_config)
        db.session.commit()

    email_config = EmailConfig.query.first()
    if not email_config:
        email_config = EmailConfig()
        db.session.add(email_config)
        db.session.commit()
    
    return render_template(
        "avisos.html", 
        notificacoes=notifications, 
        manuais=manuais, 
        usuarios=usuarios, 
        regras=regras,
        whatsapp_config=whatsapp_config,
        telegram_config=telegram_config,
        email_config=email_config
    )



@technical_bp.route("/api/comunicados/recent")
@login_required
def api_comunicados_recent():
    cleanup_old_announcements()
    now_dt = agora()
    # Filtra avisos não expirados
    query = Announcement.query.filter(
        db.or_(Announcement.expires_at.is_(None), Announcement.expires_at > now_dt)
    )
    
    # Todos os colaboradores devem ver apenas avisos destinados ao seu perfil, a todos, ou individualmente a si próprios
    avisos_list = query.filter(
        db.or_(
            # Caso 1: Mensagem direcionada individualmente a este usuário específico
            Announcement.user_id == current_user.id,
            # Caso 2: Mensagem para grupos/todos (apenas quando não é direcionada a outro usuário)
            db.and_(
                Announcement.user_id.is_(None),
                db.or_(
                    Announcement.target_role.is_(None),
                    Announcement.target_role == "all",
                    Announcement.target_role == current_user.role
                )
            )
        )
    ).order_by(Announcement.created_at.desc()).limit(10).all()
        
    read_ids = {r.announcement_id for r in AnnouncementRead.query.filter_by(user_id=current_user.id).all()}
    
    unread_count = 0
    results = []
    for a in avisos_list:
        is_read = a.id in read_ids
        if not is_read:
            unread_count += 1
            
        results.append({
            "id": a.id,
            "title": a.title,
            "message": a.message or a.content,
            "created_at": br_datetime(a.created_at),
            "is_read": is_read,
            "sender": User.query.get(a.created_by).username if a.created_by else "Sistema"
        })
        
    return jsonify({
        "unread_count": unread_count,
        "notifications": results
    })



@technical_bp.route("/api/comunicados/<int:aid>/read", methods=["POST"])
@login_required
def api_comunicados_read(aid):
    read = AnnouncementRead.query.filter_by(announcement_id=aid, user_id=current_user.id).first()
    if not read:
        read = AnnouncementRead(announcement_id=aid, user_id=current_user.id)
        db.session.add(read)
        db.session.commit()
    return jsonify({"status": "ok"})



@technical_bp.route("/api/system/audit")
@login_required
def api_system_audit():
    cleanup_old_announcements()
    
    # Garantir que as regras padrão existam no banco de dados
    default_rules = [
        {
            "slug": "scale_alert",
            "name": "Alerta de Plantão / Escala",
            "description": "Envia notificações aos técnicos escalados para o plantão dias antes da data.",
            "trigger_days": 4,
            "channels": "system,whatsapp"
        },
        {
            "slug": "late_checklist",
            "name": "Checklist Diário Pendente",
            "description": "Alerta técnicos de plantão que ainda não preencheram o checklist do veículo no dia.",
            "trigger_days": 1,
            "channels": "system,whatsapp"
        },
        {
            "slug": "training_alert",
            "name": "Aviso de Treinamento LMS",
            "description": "Gera alertas individuais de treinamentos LMS pendentes ou vencendo apenas para os técnicos destinados.",
            "trigger_days": 7,
            "channels": "system,whatsapp"
        },
        {
            "slug": "os_alert",
            "name": "Alerta de O.S. Atrasada",
            "description": "Notifica os responsáveis por ordens de serviço pendentes há mais de X dias.",
            "trigger_days": 7,
            "channels": "system,whatsapp"
        },
        {
            "slug": "inactive_tech_alert",
            "name": "Lembrete de Inatividade (+7 dias)",
            "description": "Identifica automaticamente técnicos que não realizam checklists há mais de 7 dias e envia comunicado de lembrete a eles.",
            "trigger_days": 7,
            "channels": "system,whatsapp"
        }
    ]

    for dr in default_rules:
        rule = SystemRule.query.filter_by(slug=dr["slug"]).first()
        if not rule:
            try:
                rule = SystemRule(
                    slug=dr["slug"],
                    name=dr["name"],
                    description=dr["description"],
                    trigger_days=dr["trigger_days"],
                    channels=dr["channels"],
                    is_enabled=True
                )
                db.session.add(rule)
                db.session.commit()
            except Exception:
                db.session.rollback()

    # Carrega todas as regras
    regras = SystemRule.query.all()
    regras_dict = {r.slug: r for r in regras}
    enabled_rules = {r.slug for r in regras if r.is_enabled}

    from datetime import date, datetime, timedelta
    now_dt = agora()
    today_dt = now_dt.date()

    checklists_reminded = 0
    os_overdue = 0
    scales_notified = 0
    trainings_notified = 0
    inactive_techs_notified = 0

    # Função auxiliar para despacho de múltiplos canais
    def dispatch_alert(rule, user_target, title_default, content_default, placeholders, unique_check_title=None, target_role=None):
        if not rule:
            return 0
            
        channels = [c.strip() for c in (rule.channels or "system,whatsapp").split(",") if c.strip()]
        uid = user_target.id if user_target else None

        # Verificação de Período de Silêncio (silence_days) para evitar spam repetido
        if rule.silence_days and rule.silence_days > 0:
            silence_limit = now_dt - timedelta(days=rule.silence_days)
            if uid:
                exists_recent = SystemRuleLog.query.filter(
                    SystemRuleLog.rule_slug == rule.slug,
                    SystemRuleLog.user_id == uid,
                    SystemRuleLog.created_at >= silence_limit
                ).first()
            else:
                exists_recent = SystemRuleLog.query.filter(
                    SystemRuleLog.rule_slug == rule.slug,
                    SystemRuleLog.recipient == (target_role or "all"),
                    SystemRuleLog.created_at >= silence_limit
                ).first()
                
            if exists_recent:
                # Alerta recente enviado dentro do período de silêncio
                print(f"Skipping alert for rule {rule.slug} due to silence period")
                return 0
        
        sys_title = title_default
        sys_content = rule.msg_system.format(**placeholders) if (rule.msg_system and placeholders) else content_default
        
        title_to_check = unique_check_title or sys_title
        system_sent = False
        
        # 1. Sistema
        if "system" in channels:
            if uid:
                exists = Announcement.query.filter_by(title=title_to_check, user_id=uid).first()
            else:
                exists = Announcement.query.filter_by(title=title_to_check, target_role=target_role).first()
                
            if not exists:
                ann = Announcement(
                    title=sys_title,
                    content=sys_content,
                    user_id=uid,
                    target_role=target_role,
                    created_by=None
                )
                ann.expires_at = datetime.combine(today_dt + timedelta(days=7), datetime.max.time())
                db.session.add(ann)
                system_sent = True
                
                # Log no banco de dados para o canal do sistema
                try:
                    sys_log = SystemRuleLog(
                        rule_slug=rule.slug,
                        user_id=uid,
                        channel="system",
                        recipient=target_role or "user",
                        message=sys_content,
                        status="SENT"
                    )
                    db.session.add(sys_log)
                except Exception as sys_err:
                    print("⚠️ Erro ao salvar log do painel:", sys_err)

        # 2. WhatsApp
        if "whatsapp" in channels and user_target and user_target.phone:
            w_config = WhatsAppConfig.query.first()
            if w_config and w_config.is_enabled:
                w_msg = None
                if rule.msg_whatsapp:
                    try:
                        w_msg = rule.msg_whatsapp.format(**placeholders)
                    except Exception:
                        pass
                
                if not w_msg:
                    legacy_attr = f"msg_{rule.slug}"
                    if rule.slug == "os_alert":
                        legacy_attr = "msg_os_overdue"
                    legacy_template = getattr(w_config, legacy_attr, None)
                    if legacy_template:
                        try:
                            w_msg = legacy_template.format(**placeholders)
                        except Exception:
                            pass
                
                if not w_msg:
                    w_msg = f"*{sys_title}*\n\n{sys_content}"
                    
                send_whatsapp_message(user_target.phone, w_msg, rule_slug=rule.slug, user_id=uid)

        # 3. Telegram
        if "telegram" in channels and user_target and user_target.telegram_chat_id:
            telegram_config = TelegramConfig.query.first()
            if telegram_config and telegram_config.is_enabled:
                t_msg = None
                if rule.msg_telegram:
                    try:
                        t_msg = rule.msg_telegram.format(**placeholders)
                    except Exception:
                        pass
                if not t_msg:
                    t_msg = f"<b>{sys_title}</b>\n\n{sys_content}"
                send_telegram_message(user_target.telegram_chat_id, t_msg, rule_slug=rule.slug, user_id=uid)

        # 4. E-mail (SMTP)
        if "email" in channels and user_target and user_target.email:
            email_config = EmailConfig.query.first()
            if email_config and email_config.is_enabled:
                e_body = None
                if rule.msg_email:
                    try:
                        e_body = rule.msg_email.format(**placeholders)
                    except Exception:
                        pass
                if not e_body:
                    e_body = f"{sys_title}\n\n{sys_content}"
                send_email_notification(user_target.email, sys_title, e_body, rule_slug=rule.slug, user_id=uid)

        return 1 if system_sent else 0

    # 1. Automação de Escala & Plantão (scale_alert)
    rule_scale = regras_dict.get("scale_alert")
    if "scale_alert" in enabled_rules and rule_scale:
        trigger_days = rule_scale.trigger_days if rule_scale.trigger_days is not None else 4
        target_date = today_dt + timedelta(days=trigger_days)
        
        scales = Scale.query.filter(Scale.date == target_date, Scale.status == "ATIVO").all()
        
        if target_date.weekday() == 5:
            config = SystemConfig.query.first()
            if config and config.scale_start_date and config.scale_rotation_order and not scales:
                if target_date >= config.scale_start_date:
                    rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
                    if rotation_order:
                        weeks = (target_date - config.scale_start_date).days // 7
                        team_idx = weeks % len(rotation_order)
                        team_id = rotation_order[team_idx]
                        
                        team = Team.query.get(team_id)
                        if team:
                            class TempScale:
                                def __init__(self, team_id, date, type_name):
                                    self.team_id = team_id
                                    self.team_ids = None
                                    self.technician_ids = None
                                    self.user_id = None
                                    self.date = date
                                    self.type = type_name
                                    self.obs = "Escala automática por rodízio de equipes"
                            scales.append(TempScale(team.id, target_date, f"Plantão: {team.name}"))

        for esc in scales:
            title = f"📅 Plantão Confirmado: {esc.type}"
            content = f"Olá, você está escalado para o plantão de '{esc.type}' no dia {target_date.strftime('%d/%m/%Y')} (daqui a {trigger_days} dias). obs: {esc.obs or 'Sem observações'}"
            
            tech_ids = set()
            if esc.team_ids:
                team_ids_list = [int(x.strip()) for x in esc.team_ids.split(",") if x.strip().isdigit()]
                for tid in team_ids_list:
                    team = Team.query.get(tid)
                    if team:
                        for member in team.members:
                            if member.role == "tech":
                                tech_ids.add(member.id)
            elif esc.team_id:
                team = Team.query.get(esc.team_id)
                if team:
                    for member in team.members:
                        if member.role == "tech":
                            tech_ids.add(member.id)

            if esc.technician_ids:
                user_ids_list = [int(x.strip()) for x in esc.technician_ids.split(",") if x.strip().isdigit()]
                for uid in user_ids_list:
                    tech_ids.add(uid)
            elif esc.user_id:
                tech_ids.add(esc.user_id)

            for uid in tech_ids:
                tech_user = User.query.get(uid)
                if tech_user:
                    placeholders = {
                        "usuario": tech_user.username.capitalize(),
                        "escala": esc.type,
                        "data": target_date.strftime('%d/%m/%Y')
                    }
                    sent = dispatch_alert(rule_scale, tech_user, title, content, placeholders)
                    scales_notified += sent

    # 2. Automação de Feriados, Sábados e Domingos (late_checklist / auditoria geral)
    rule_late = regras_dict.get("late_checklist")
    if "late_checklist" in enabled_rules and rule_late:
        trigger_days = rule_late.trigger_days if rule_late.trigger_days is not None else 4
        target_date = today_dt + timedelta(days=trigger_days)
        
        import holidays
        years = [target_date.year]
        h_dict = holidays.Brazil(subdiv="RJ", years=years)
        
        for y in years:
            h_dict[date(y, 6, 13)] = "Santo Antônio (Padroeiro)"
            a = y % 19
            b = y // 100
            c = y % 100
            d = b // 4
            e = b % 4
            f = (b + 8) // 25
            g = (b - f + 1) // 3
            h = (19 * a + b - d - g + 15) % 30
            i = c // 4
            k = c % 4
            l = (32 + 2 * e + 2 * i - h - k) % 7
            m = (a + 11 * h + 22 * l) // 451
            month = (h + l - 7 * m + 114) // 31
            day = ((h + l - 7 * m + 114) % 31) + 1
            easter_date = date(y, month, day)
            corpus_christi = easter_date + timedelta(days=60)
            h_dict[corpus_christi] = "Corpus Christi"
            h_dict.pop(date(y, 10, 12), None)
            h_dict[date(y, 10, 12)] = "N. Sra Aparecida / Emancipação"

        if target_date in h_dict:
            h_name = h_dict[target_date]
            title = f"🎉 Feriado Próximo: {h_name}"
            content = f"Prezados, informamos que no dia {target_date.strftime('%d/%m/%Y')} (daqui a {trigger_days} dias) será feriado: {h_name}. Programe-se!"
            
            exists = Announcement.query.filter_by(title=title, target_role="all").first()
            if not exists:
                ann = Announcement(
                    title=title,
                    content=content,
                    target_role="all",
                    expires_at=datetime.combine(target_date, datetime.max.time()),
                    created_by=None
                )
                db.session.add(ann)
                checklists_reminded += 1

        if target_date.weekday() in {5, 6}:
            day_name = "Sábado" if target_date.weekday() == 5 else "Domingo"
            title = f"📢 Plantão de Fim de Semana ({day_name})"
            content = f"Atenção equipe! O próximo {day_name} ({target_date.strftime('%d/%m/%Y')}) terá escala operacional. Verifique sua designação na aba Escalas do sistema."
            
            exists = Announcement.query.filter_by(title=title, target_role="tech").first()
            if not exists:
                ann = Announcement(
                    title=title,
                    content=content,
                    target_role="tech",
                    expires_at=datetime.combine(target_date, datetime.max.time()),
                    created_by=None
                )
                db.session.add(ann)
                checklists_reminded += 1

        # Lembrete de Checklist diário não preenchido hoje
        today_scales = Scale.query.filter(Scale.date == today_dt, Scale.status == "ATIVO").all()
        if today_dt.weekday() == 5:
            config = SystemConfig.query.first()
            if config and config.scale_start_date and config.scale_rotation_order and not today_scales:
                if today_dt >= config.scale_start_date:
                    rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
                    if rotation_order:
                        weeks = (today_dt - config.scale_start_date).days // 7
                        team_idx = weeks % len(rotation_order)
                        team_id = rotation_order[team_idx]
                        
                        team = Team.query.get(team_id)
                        if team:
                            class TempScale:
                                def __init__(self, team_id, date, type_name):
                                    self.team_id = team_id
                                    self.team_ids = None
                                    self.technician_ids = None
                                    self.user_id = None
                                    self.date = date
                                    self.type = type_name
                                    self.obs = "Escala automática por rodízio de equipes"
                            today_scales.append(TempScale(team.id, today_dt, f"Plantão: {team.name}"))

        for esc in today_scales:
            tech_ids = set()
            if esc.technician_ids:
                user_ids_list = [int(x.strip()) for x in esc.technician_ids.split(",") if x.strip().isdigit()]
                for uid in user_ids_list:
                    tech_ids.add(uid)
            elif esc.user_id:
                tech_ids.add(esc.user_id)
                
            for uid in tech_ids:
                u = User.query.get(uid)
                if u:
                    checklist_done = Checklist.query.filter(
                        Checklist.technician == u.username,
                        db.func.date(Checklist.date) == today_dt
                    ).first()
                    if not checklist_done:
                        title = f"🔔 Lembrete: Checklist Diário Pendente"
                        content = f"Olá {u.username.capitalize()}, você está de plantão hoje e ainda não enviou o Checklist Veicular regulamentar. Por favor, realize a inspeção do seu veículo antes de iniciar a rota."
                        
                        placeholders = {
                            "usuario": u.username.capitalize()
                        }
                        sent = dispatch_alert(
                            rule_late, 
                            u, 
                            title, 
                            content, 
                            placeholders, 
                            unique_check_title=title + f"_{today_dt}"
                        )
                        checklists_reminded += sent

    # 3. Automação de Treinamento LMS (training_alert)
    rule_train = regras_dict.get("training_alert")
    if "training_alert" in enabled_rules and rule_train:
        assignments = TrainingAssignment.query.filter(
            TrainingAssignment.status.in_({"pendente", "em_andamento"})
        ).all()
        for assign in assignments:
            course = assign.course
            user = assign.user
            if course and user:
                title = f"🎓 Treinamento Pendente: {course.title}"
                content = f"Olá {user.username.capitalize()}, lembramos que o treinamento '{course.title}' está associado ao seu perfil com status '{assign.status}'. Por favor, realize sua capacitação no portal LMS."
                
                placeholders = {
                    "usuario": user.username.capitalize(),
                    "curso": course.title
                }
                sent = dispatch_alert(rule_train, user, title, content, placeholders)
                trainings_notified += sent

    # 4. Monitor de SLA & Alertas de OS (os_sla ou os_alert)
    rule_os = regras_dict.get("os_alert") or regras_dict.get("os_sla")
    if ("os_sla" in enabled_rules or "os_alert" in enabled_rules) and rule_os:
        trigger_days = rule_os.trigger_days if rule_os.trigger_days is not None else 7
        overdue_os_list = AvariaOS.query.filter(
            AvariaOS.status == "aberta",
            AvariaOS.data_abertura < (now_dt - timedelta(days=trigger_days))
        ).all()
        
        for os_obj in overdue_os_list:
            resp = os_obj.responsavel
            veh = os_obj.vehicle
            if resp and veh:
                title = f"⚠️ O.S. Atrasada: #{os_obj.id}"
                content = f"Olá {resp.username.capitalize()}, a Ordem de Serviço #{os_obj.id} para o veículo {veh.plate} está pendente há mais de {trigger_days} dias (desde {os_obj.data_abertura.strftime('%d/%m/%Y')}). Por favor, forneça uma atualização de status."
                
                placeholders = {
                    "usuario": resp.username.capitalize(),
                    "id": os_obj.id
                }
                sent = dispatch_alert(rule_os, resp, title, content, placeholders)
                os_overdue += sent

        all_os_alerts = Announcement.query.filter(Announcement.title.like("⚠️ O.S. Atrasada: #%")).all()
        overdue_ids = {os_obj.id for os_obj in overdue_os_list}
        for alert in all_os_alerts:
            try:
                alert_os_id = int(alert.title.split("#")[1])
                if alert_os_id not in overdue_ids:
                    AnnouncementRead.query.filter_by(announcement_id=alert.id).delete()
                    db.session.delete(alert)
            except Exception:
                pass

    # 5. Técnicos Inativos (+7 dias sem realizar checklist) (inactive_tech_alert)
    rule_inactive = regras_dict.get("inactive_tech_alert")
    if "inactive_tech_alert" in enabled_rules and rule_inactive:
        trigger_days = rule_inactive.trigger_days if rule_inactive.trigger_days is not None else 7
        techs = User.query.filter_by(role="tech").all()
        inactive_limit = now_dt - timedelta(days=trigger_days)
        
        for tech in techs:
            last_checklist = Checklist.query.filter(
                Checklist.technician == tech.username
            ).order_by(Checklist.date.desc()).first()
            
            is_inactive = False
            last_date_str = ""
            if last_checklist:
                if last_checklist.date < inactive_limit:
                    is_inactive = True
                    last_date_str = last_checklist.date.strftime('%d/%m/%Y')
            else:
                is_inactive = True
                last_date_str = "nunca"
                
            if is_inactive:
                title = f"⚠️ Lembrete: Checklist não realizado há +{trigger_days} dias"
                content = f"Olá {tech.username.capitalize()}, identificamos que você não realiza nenhuma vistoria ou checklist veicular há mais de {trigger_days} dias (último envio: {last_date_str}). Lembramos que a realização do checklist de vistoria é obrigatória para manter a conformidade operacional de sua rota."
                
                placeholders = {
                    "usuario": tech.username.capitalize()
                }
                
                # Evita spam enviando no máximo uma vez a cada X dias
                exists = Announcement.query.filter_by(title=title, user_id=tech.id).filter(
                    Announcement.created_at >= inactive_limit
                ).first()
                
                if not exists:
                    sent = dispatch_alert(rule_inactive, tech, title, content, placeholders, unique_check_title=title)
                    inactive_techs_notified += sent

    # 6. Processamento da Fila de Reenvio (Retry Queue)
    # Busca envios falhos com menos de 3 tentativas
    failed_logs = SystemRuleLog.query.filter(
        SystemRuleLog.status == "FAILED",
        SystemRuleLog.retry_count < 3
    ).all()
    
    for flog in failed_logs:
        flog.retry_count += 1
        try:
            if flog.channel == "whatsapp":
                send_whatsapp_message(
                    to_number_or_msg=flog.recipient,
                    text_message=flog.message,
                    rule_slug=flog.rule_slug,
                    user_id=flog.user_id
                )
            elif flog.channel == "telegram":
                send_telegram_message(
                    to_chat_id_or_msg=flog.recipient,
                    text_message=flog.message,
                    rule_slug=flog.rule_slug,
                    user_id=flog.user_id
                )
            elif flog.channel == "email":
                lines = flog.message.split("\n\n", 1)
                subject = "Reenvio de Alerta"
                body = flog.message
                if len(lines) == 2 and lines[0].startswith("Assunto: "):
                    subject = lines[0][len("Assunto: "):]
                    body = lines[1]
                send_email_notification(
                    to_email=flog.recipient,
                    subject=subject,
                    body_message=body,
                    rule_slug=flog.rule_slug,
                    user_id=flog.user_id
                )
            flog.status = "RETRIED"
            db.session.add(flog)
        except Exception as retry_err:
            print(f"⚠️ Erro ao reenviar alerta ID {flog.id}: {retry_err}")

    db.session.commit()
    return jsonify({
        "checklists_reminded": checklists_reminded,
        "os_overdue": os_overdue,
        "scales_notified": scales_notified,
        "trainings_notified": trainings_notified,
        "inactive_techs_notified": inactive_techs_notified
    })
@technical_bp.route("/api/manuais/help")
@login_required
def api_manuais_help():
    role = current_user.role or "tech"
    if role in {"admin", "supervisor"}:
        group = "admin_supervisor"
    elif role == "manutencao":
        group = "manutencao"
    else:
        group = "tech"
        
    m = Manual.query.filter_by(role_group=group).first()
    content = m.content if m else "Nenhum manual cadastrado para este perfil de acesso."
    return jsonify({"content": content})




@technical_bp.route("/rfo")
@supervisor_allowed
def rfo_list():
    return render_template("rfo_list.html")



@technical_bp.route("/geradores")
@supervisor_allowed
def geradores():
    return render_template("geradores.html")





@technical_bp.route("/api/avisos/logs")
@login_required
def api_avisos_logs():
    if not (current_user.is_admin or current_user.has_permission("avisos_historico")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    status = request.args.get("status", "").strip()
    channel = request.args.get("channel", "").strip()
    rule_slug = request.args.get("rule_slug", "").strip()
    search = request.args.get("search", "").strip()
    
    query = SystemRuleLog.query
    
    if status:
        query = query.filter(SystemRuleLog.status == status)
    if channel:
        query = query.filter(SystemRuleLog.channel == channel)
    if rule_slug:
        query = query.filter(SystemRuleLog.rule_slug == rule_slug)
    if search:
        query = query.filter(
            (SystemRuleLog.recipient.ilike(f"%{search}%")) |
            (SystemRuleLog.message.ilike(f"%{search}%"))
        )
        
    pagination = query.order_by(SystemRuleLog.created_at.desc()).paginate(page=page, per_page=per_page, error_out=False)
    
    logs_list = []
    for l in pagination.items:
        username = l.user.username.capitalize() if l.user else "Sistema"
        logs_list.append({
            "id": l.id,
            "rule_slug": l.rule_slug,
            "username": username,
            "channel": l.channel,
            "recipient": l.recipient,
            "message": l.message,
            "status": l.status,
            "error_message": l.error_message,
            "created_at": l.created_at.strftime("%d/%m/%Y %H:%M:%S"),
            "retry_count": l.retry_count
        })
        
    return jsonify({
        "success": True,
        "logs": logs_list,
        "total": pagination.total,
        "pages": pagination.pages,
        "current_page": pagination.page
    })


@technical_bp.route("/api/test-integration/whatsapp", methods=["POST"])
@login_required
def test_integration_whatsapp():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    recipient = request.form.get("recipient", "").strip()
    api_url = request.form.get("api_url", "").strip()
    apikey = request.form.get("apikey", "").strip()
    instance_name = request.form.get("instance_name", "").strip()
    
    if not recipient or not api_url or not apikey or not instance_name:
        return jsonify({"success": False, "error": "Campos obrigatórios ausentes"}), 400
        
    headers = {
        "Content-Type": "application/json",
        "apikey": apikey
    }
    
    sanitized_number = "".join(filter(str.isdigit, recipient))
    if len(sanitized_number) <= 11 and not sanitized_number.startswith("55"):
        sanitized_number = "55" + sanitized_number
        
    payload = {
        "number": sanitized_number,
        "text": "Mensagem de teste de conexão Evolution API"
    }
    
    url = f"{api_url.rstrip('/')}/message/sendText/{instance_name}"
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        if res.status_code in (200, 201):
            return jsonify({"success": True, "message": "Mensagem enviada com sucesso!"})
        else:
            return jsonify({"success": False, "error": f"Erro HTTP {res.status_code}: {res.text}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@technical_bp.route("/api/test-integration/telegram", methods=["POST"])
@login_required
def test_integration_telegram():
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    recipient = request.form.get("recipient", "").strip()
    bot_token = request.form.get("bot_token", "").strip()
    
    if not recipient or not bot_token:
        return jsonify({"success": False, "error": "Campos obrigatórios ausentes"}), 400
        
    url = f"https://api.telegram.org/bot{bot_token}/sendMessage"
    payload = {
        "chat_id": recipient,
        "text": "<b>Teste de Conexão:</b> Bot Telegram configurado com sucesso!",
        "parse_mode": "HTML"
    }
    
    try:
        res = requests.post(url, json=payload, timeout=10)
        if res.status_code in (200, 201):
            return jsonify({"success": True, "message": "Mensagem do Telegram enviada com sucesso!"})
        else:
            return jsonify({"success": False, "error": f"Erro HTTP {res.status_code}: {res.text}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


@technical_bp.route("/api/test-integration/email", methods=["POST"])
@login_required
def test_integration_email():
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    recipient = request.form.get("recipient", "").strip()
    smtp_server = request.form.get("smtp_server", "").strip()
    smtp_port = request.form.get("smtp_port", 587, type=int)
    smtp_user = request.form.get("smtp_user", "").strip()
    smtp_password = request.form.get("smtp_password", "").strip()
    from_email = request.form.get("from_email", "").strip()
    use_ssl = request.form.get("use_ssl") == "on"
    
    if not recipient or not smtp_server or not smtp_user or not smtp_password or not from_email:
        return jsonify({"success": False, "error": "Campos obrigatórios ausentes"}), 400
        
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    msg = MIMEMultipart()
    msg['From'] = from_email
    msg['To'] = recipient
    msg['Subject'] = "Teste de Conexão SMTP"
    msg.attach(MIMEText("Parabéns! Suas configurações de e-mail SMTP estão funcionando perfeitamente.", 'plain', 'utf-8'))
    
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port, timeout=10)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port, timeout=10)
            server.starttls()
            
        server.login(smtp_user, smtp_password)
        server.sendmail(from_email, [recipient], msg.as_string())
        server.quit()
        return jsonify({"success": True, "message": "E-mail de teste enviado com sucesso!"})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500


# ----------------- EXECUÇÃO -----------------
# ===============================
# 🎓 MÓDULO: LMS (TREINAMENTOS)
# ===============================

# ----------------- ROTAS: LMS (TREINAMENTOS) -----------------
@technical_bp.route("/treinamentos/mobile")
@login_required
def treinamentos_mobile():
    return render_template("treinamentos_mobile.html")



@technical_bp.route("/treinamentos/admin")
@supervisor_allowed
def treinamentos_admin():
    return render_template("treinamentos_admin.html")



@technical_bp.route("/treinamentos/gerir")
@supervisor_allowed
def treinamentos_gerir():
    return render_template("treinamentos_gerir.html")



# ----------------- ROTAS ADMINISTRATIVAS DO LMS -----------------
@technical_bp.route("/api/gestao/treinamentos_lms", methods=["GET"])
@supervisor_allowed
def api_gestao_treinamentos_lms_list():
    try:
        courses = TrainingCourse.query.order_by(TrainingCourse.created_at.desc()).all()
        results = []
        for c in courses:
            total_assigns = len(c.assignments)
            approved_assigns = sum(1 for a in c.assignments if a.status == 'aprovado')
            results.append({
                "id": c.id,
                "title": c.title,
                "description": c.description,
                "category": c.category,
                "is_published": c.is_published,
                "deadline": c.deadline.strftime("%Y-%m-%d") if c.deadline else None,
                "badge_name": c.badge_name,
                "badge_icon": c.badge_icon,
                "badge_color": c.badge_color,
                "allow_retake": c.allow_retake,
                "course_type": c.course_type or 'lms',
                "total_assignments": total_assigns,
                "approved_assignments": approved_assigns
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/gestao/treinamentos_lms/upload_media", methods=["POST"])
@supervisor_allowed
def api_gestao_treinamentos_lms_upload_media():
    try:
        if "file" not in request.files:
            return jsonify({"error": "Nenhum arquivo enviado"}), 400
        
        f = request.files["file"]
        media_type = request.form.get("type")  # "image" ou "video"
        
        if not f or f.filename == "":
            return jsonify({"error": "Arquivo vazio"}), 400
            
        ext = os.path.splitext(f.filename.lower())[1]
        
        # Validação de extensões e tamanhos
        if media_type == "image":
            allowed_image_exts = {".jpg", ".jpeg", ".png", ".webp"}
            if ext not in allowed_image_exts:
                return jsonify({"error": "Formato de imagem inválido. Use JPG, JPEG, PNG ou WEBP."}), 400
            # Check size
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0)
            if size > 5 * 1024 * 1024:
                return jsonify({"error": "A imagem excede o limite de 5MB."}), 400
        elif media_type == "video":
            allowed_video_exts = {".mp4", ".webm"}
            if ext not in allowed_video_exts:
                return jsonify({"error": "Formato de vídeo inválido. Use MP4 ou WEBM."}), 400
            # Check size
            f.seek(0, os.SEEK_END)
            size = f.tell()
            f.seek(0)
            if size > 25 * 1024 * 1024:
                return jsonify({"error": "O vídeo excede o limite de 25MB."}), 400
        else:
            return jsonify({"error": "Tipo de mídia inválido especificado."}), 400

        # Gerar nome único e salvar
        filename = f"{uuid.uuid4()}{ext}"
        filepath = TREINAMENTOS_UPLOAD_DIR / filename
        f.save(filepath)
        
        relative_path = f"/static/uploads/treinamentos/{filename}"
        return jsonify({"status": "ok", "path": relative_path})
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/gestao/treinamentos_lms", methods=["POST"])
@supervisor_allowed
def api_gestao_treinamentos_lms_save():
    try:
        data = request.json
        course_id = data.get("id")
        
        if course_id:
            course = TrainingCourse.query.get(course_id)
            if not course:
                return jsonify({"error": "Treinamento não encontrado"}), 404
            # Remove old modules and questions for update
            TrainingModule.query.filter_by(course_id=course_id).delete()
            TrainingQuestion.query.filter_by(course_id=course_id).delete()
        else:
            course = TrainingCourse()
            course.created_by_id = current_user.id
            db.session.add(course)
            
        course.title = data.get("title")
        course.description = data.get("description")
        course.category = data.get("category")
        course.passing_grade = int(data.get("passing_grade") or 70)
        course.is_mandatory = bool(data.get("is_mandatory"))
        
        deadline_str = data.get("deadline")
        if deadline_str:
            course.deadline = datetime.strptime(deadline_str, "%Y-%m-%d").date()
        else:
            course.deadline = None
            
        course.badge_name = data.get("badge_name") or 'Certificado'
        course.badge_icon = data.get("badge_icon") or 'fa-award'
        course.badge_color = data.get("badge_color") or '#0d9488'
        course.allow_retake = bool(data.get("allow_retake"))
        course.course_type = data.get("course_type") or 'lms'
        
        # Flush so new courses get an ID
        db.session.flush()
        
        # Add modules
        modules_data = data.get("modules") or []
        for i, m in enumerate(modules_data):
            mod = TrainingModule(
                course_id=course.id,
                title=m.get("title"),
                content=m.get("content"),
                image_path=m.get("image_path"),
                video_path=m.get("video_path"),
                order=i
            )
            db.session.add(mod)
            
        # Add questions
        questions_data = data.get("questions") or []
        for i, q in enumerate(questions_data):
            quest = TrainingQuestion(
                course_id=course.id,
                question_text=q.get("question_text"),
                option_a=q.get("option_a"),
                option_b=q.get("option_b"),
                option_c=q.get("option_c"),
                option_d=q.get("option_d"),
                correct_option=q.get("correct_option"),
                order=i
            )
            db.session.add(quest)
            
        # Auto-assign to all technicians if it's a new course
        if not course_id:
            # Fetch all active users
            users = User.query.all()
            for u in users:
                assign = TrainingAssignment(
                    course_id=course.id,
                    user_id=u.id,
                    status="pendente"
                )
                db.session.add(assign)
                
        db.session.commit()
        return jsonify({"status": "ok", "id": course.id})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/gestao/treinamentos_lms/<int:id>", methods=["GET"])
@supervisor_allowed
def api_gestao_treinamentos_lms_get(id):
    try:
        c = TrainingCourse.query.get(id)
        if not c:
            return jsonify({"error": "Treinamento não encontrado"}), 404
            
        modules = [{
            "id": m.id,
            "title": m.title,
            "content": m.content,
            "image_path": m.image_path,
            "video_path": m.video_path,
            "order": m.order
        } for m in c.modules]
        
        questions = [{
            "id": q.id,
            "question_text": q.question_text,
            "option_a": q.option_a,
            "option_b": q.option_b,
            "option_c": q.option_c,
            "option_d": q.option_d,
            "correct_option": q.correct_option,
            "order": q.order
        } for q in c.questions]
        
        # Carrega os colaboradores atribuídos para exibir progresso/ranking nos detalhes
        assignments = [{
            "id": a.id,
            "status": a.status,
            "best_score": a.best_score,
            "completed_at": a.completed_at.strftime("%d/%m/%Y %H:%M") if a.completed_at else None,
            "username": a.user.username if a.user else "Removido"
        } for a in TrainingAssignment.query.filter_by(course_id=c.id).all()]

        return jsonify({
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "category": c.category,
            "passing_grade": c.passing_grade,
            "is_mandatory": c.is_mandatory,
            "is_published": c.is_published,
            "deadline": c.deadline.strftime("%Y-%m-%d") if c.deadline else None,
            "badge_name": c.badge_name,
            "badge_icon": c.badge_icon,
            "badge_color": c.badge_color,
            "allow_retake": c.allow_retake,
            "course_type": c.course_type or 'lms',
            "modules": modules,
            "questions": questions,
            "assignments": assignments
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/gestao/treinamentos_lms/<int:id>", methods=["DELETE"])
@supervisor_allowed
def api_gestao_treinamentos_lms_delete(id):
    try:
        c = TrainingCourse.query.get(id)
        if not c:
            return jsonify({"error": "Treinamento não encontrado"}), 404
            
        db.session.delete(c)
        db.session.commit()
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/gestao/treinamentos_lms/<int:id>/publicar", methods=["POST"])
@supervisor_allowed
def api_gestao_treinamentos_lms_publish(id):
    try:
        c = TrainingCourse.query.get(id)
        if not c:
            return jsonify({"error": "Treinamento não encontrado"}), 404
            
        c.is_published = True
        
        # Lê os parâmetros do corpo da requisição JSON (assign_all e user_ids)
        req_data = request.get_json(silent=True) or {}
        assign_all = req_data.get("assign_all", False)
        user_ids = req_data.get("user_ids", [])
        
        if assign_all or user_ids:
            if assign_all:
                # Seleciona todos os colaboradores ativos com o papel de técnicos (tech)
                target_users = User.query.filter_by(role="tech").all()
                target_user_ids = {u.id for u in target_users}
            else:
                target_user_ids = {int(uid) for uid in user_ids}
                
            # 1. Remove atribuições existentes que não estão na nova seleção
            TrainingAssignment.query.filter(
                TrainingAssignment.course_id == c.id,
                ~TrainingAssignment.user_id.in_(list(target_user_ids))
            ).delete(synchronize_session=False)
            
            # 2. Cria novas atribuições para os técnicos selecionados que ainda não as possuem
            existing_assigns = TrainingAssignment.query.filter_by(course_id=c.id).all()
            existing_user_ids = {a.user_id for a in existing_assigns}
            
            for uid in target_user_ids:
                if uid not in existing_user_ids:
                    new_assign = TrainingAssignment(
                        course_id=c.id,
                        user_id=uid,
                        status="pendente"
                    )
                    db.session.add(new_assign)
                
        db.session.commit()
        return jsonify({"status": "ok", "is_published": c.is_published})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500




# ----------------- ROTAS OPERACIONAIS DO LMS (MOBILE) -----------------
@technical_bp.route("/api/treinamentos/meus", methods=["GET"])
@login_required
def api_treinamentos_meus():
    try:
        # Fetch only published assigned courses
        assigns = TrainingAssignment.query.filter_by(user_id=current_user.id).join(TrainingCourse).filter(TrainingCourse.is_published == True).all()
        results = []
        for a in assigns:
            c = a.course
            if not c:
                continue
            
            # count modules read
            read_count = 0
            if a.modules_read:
                try:
                    read_ids = [int(x) for x in a.modules_read.split(",") if x.strip().isdigit()]
                    read_count = len(read_ids)
                except Exception:
                    pass
                    
            results.append({
                "course_id": c.id,
                "title": c.title,
                "description": c.description,
                "category": c.category or "Geral",
                "is_mandatory": c.is_mandatory,
                "deadline": c.deadline.strftime("%d/%m/%Y") if c.deadline else None,
                "status": a.status or "pendente",
                "best_score": a.best_score,
                "modules_read": read_count,
                "modules_total": len(c.modules),
                "questions_total": len(c.questions),
                "badge_name": c.badge_name,
                "badge_icon": c.badge_icon,
                "badge_color": c.badge_color,
                "course_type": c.course_type or 'lms'
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/treinamentos/meus_selos", methods=["GET"])
@login_required
def api_treinamentos_meus_selos():
    try:
        assigns = TrainingAssignment.query.filter_by(user_id=current_user.id, status="aprovado").all()
        results = []
        for a in assigns:
            c = a.course
            if not c:
                continue
            results.append({
                "title": c.title,
                "badge_name": c.badge_name,
                "badge_icon": c.badge_icon,
                "badge_color": c.badge_color,
                "score": a.best_score or 100
            })
        return jsonify(results)
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/treinamentos/<int:course_id>/conteudo", methods=["GET"])
@login_required
def api_treinamentos_conteudo(course_id):
    try:
        c = TrainingCourse.query.get(course_id)
        if not c or not c.is_published:
            return jsonify({"error": "Treinamento não encontrado"}), 404
            
        a = TrainingAssignment.query.filter_by(course_id=course_id, user_id=current_user.id).first()
        if not a:
            # Auto-assign if not exists
            a = TrainingAssignment(course_id=course_id, user_id=current_user.id, status="pendente")
            db.session.add(a)
            db.session.commit()
            
        modules = [{
            "id": m.id,
            "title": m.title,
            "content": m.content,
            "image_path": m.image_path,
            "video_path": m.video_path,
            "order": m.order
        } for m in c.modules]
        
        questions = [{
            "id": q.id,
            "question_text": q.question_text,
            "option_a": q.option_a,
            "option_b": q.option_b,
            "option_c": q.option_c,
            "option_d": q.option_d,
            "order": q.order
        } for q in c.questions]
        
        attempts_count = len(a.attempts)
        
        last_attempt = None
        if attempts_count > 0:
            att = a.attempts[0]
            try:
                answers = json.loads(att.answers_json) if att.answers_json else {}
            except Exception:
                answers = {}
                
            corrections = []
            for q in c.questions:
                user_ans = (answers.get(str(q.id)) or "").lower().strip()
                correct_ans = (q.correct_option or "").lower().strip()
                is_correct = user_ans == correct_ans
                corrections.append({
                    "question": q.question_text,
                    "user_answer": user_ans,
                    "correct_answer": correct_ans,
                    "is_correct": is_correct,
                    "options": {
                        "a": q.option_a,
                        "b": q.option_b,
                        "c": q.option_c,
                        "d": q.option_d
                    }
                })
            last_attempt = {
                "passed": att.score >= (c.passing_grade or 70),
                "score": att.score,
                "correct": att.correct_answers,
                "total": att.total_questions,
                "passing_grade": c.passing_grade or 70,
                "attempts_count": attempts_count,
                "corrections": corrections
            }
            
        return jsonify({
            "course_id": c.id,
            "title": c.title,
            "description": c.description,
            "allow_retake": c.allow_retake,
            "attempts_count": attempts_count,
            "course_type": c.course_type or 'lms',
            "last_attempt": last_attempt,
            "modules": modules,
            "questions": questions
        })
    except Exception as e:
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/treinamentos/<int:course_id>/mark_module", methods=["POST"])
@login_required
def api_treinamentos_mark_module(course_id):
    try:
        data = request.json or {}
        module_id = data.get("module_id")
        if not module_id:
            return jsonify({"error": "ID do módulo é obrigatório"}), 400
            
        a = TrainingAssignment.query.filter_by(course_id=course_id, user_id=current_user.id).first()
        if not a:
            return jsonify({"error": "Atribuição não encontrada"}), 404
            
        # Update modules read
        current_reads = set()
        if a.modules_read:
            current_reads = set(x.strip() for x in a.modules_read.split(",") if x.strip())
            
        current_reads.add(str(module_id))
        a.modules_read = ",".join(sorted(list(current_reads)))
        
        if a.status == "pendente":
            a.status = "em_andamento"
            a.started_at = agora()
            
        db.session.commit()
        return jsonify({"status": "ok"})
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500



@technical_bp.route("/api/treinamentos/<int:course_id>/responder", methods=["POST"])
@login_required
def api_treinamentos_responder(course_id):
    try:
        data = request.json or {}
        answers = data.get("answers") or {} # dict of question_id -> letter
        
        c = TrainingCourse.query.get(course_id)
        if not c or not c.is_published:
            return jsonify({"error": "Treinamento não encontrado"}), 404
            
        a = TrainingAssignment.query.filter_by(course_id=course_id, user_id=current_user.id).first()
        if not a:
            return jsonify({"error": "Atribuição não encontrada"}), 404
            
        if not c.allow_retake and len(a.attempts) > 0:
            return jsonify({"error": "Este treinamento não permite refazer a avaliação"}), 403
            
        # Grade the answers
        questions = c.questions
        total = len(questions)
        correct = 0
        corrections = []
        
        for q in questions:
            user_ans = (answers.get(str(q.id)) or "").lower().strip()
            correct_ans = (q.correct_option or "").lower().strip()
            is_correct = user_ans == correct_ans
            if is_correct:
                correct += 1
                
            corrections.append({
                "question": q.question_text,
                "user_answer": user_ans,
                "correct_answer": correct_ans,
                "is_correct": is_correct,
                "options": {
                    "a": q.option_a,
                    "b": q.option_b,
                    "c": q.option_c,
                    "d": q.option_d
                }
            })
            
        score = int(round((correct / total) * 100)) if total > 0 else 100
        passing_grade = c.passing_grade or 70
        passed = score >= passing_grade
        
        # Save attempt
        att = TrainingAttempt(
            assignment_id=a.id,
            score=score,
            total_questions=total,
            correct_answers=correct,
            answers_json=json.dumps(answers),
            attempted_at=agora()
        )
        db.session.add(att)
        
        # Update assignment
        if a.best_score is None or score > a.best_score:
            a.best_score = score
            
        if passed:
            a.status = "aprovado"
            a.completed_at = agora()
        elif a.status != "aprovado":
            a.status = "reprovado"
            
        db.session.commit()
        
        return jsonify({
            "passed": passed,
            "score": score,
            "correct": correct,
            "total": total,
            "passing_grade": passing_grade,
            "attempts_count": len(a.attempts),
            "corrections": corrections
        })
    except Exception as e:
        db.session.rollback()
        return jsonify({"error": str(e)}), 500

# Módulo GPS removido (agora importado centralizadamente de backend.models)



@technical_bp.route("/tracking")
@login_required
def tracking():
    if not current_user.has_permission("frota"):
        abort(403)
    return render_template("tracking.html")




@technical_bp.route("/monitoramento/aparelhos", methods=["GET", "POST"])
@supervisor_allowed
def monitoramento_aparelhos():
    if request.method == "POST":
        acao = request.form.get("acao")
        if acao == "novo":
            imei = request.form.get("imei").strip()
            model = request.form.get("model", "TK103").strip()
            iccid = request.form.get("iccid", "").strip()
            phone = request.form.get("phone_number", "").strip()
            provider = request.form.get("provider", "").strip()
            v_id = request.form.get("vehicle_id")
            
            if GPSDevice.query.filter_by(imei=imei).first():
                flash("IMEI já cadastrado.", "error")
            else:
                if v_id:
                    existing_linked = GPSDevice.query.filter_by(vehicle_id=v_id).first()
                    if existing_linked:
                        flash("Este veículo já está associado a outro rastreador.", "error")
                        return redirect(url_for("monitoramento_aparelhos"))
                d = GPSDevice(
                    imei=imei, 
                    model=model, 
                    iccid=iccid,
                    phone_number=phone,
                    provider=provider,
                    vehicle_id=v_id if v_id else None
                )
                db.session.add(d)
                db.session.commit()
                flash("Aparelho GPS cadastrado com sucesso!", "success")
        
        elif acao == "editar":
            id = request.form.get("id")
            d = GPSDevice.query.get(id)
            if d:
                new_imei = request.form.get("imei").strip()
                existing_imei = GPSDevice.query.filter_by(imei=new_imei).first()
                if existing_imei and existing_imei.id != d.id:
                    flash("Este IMEI já está cadastrado em outro aparelho.", "error")
                    return redirect(url_for("monitoramento_aparelhos"))
                
                v_id = request.form.get("vehicle_id")
                if v_id:
                    existing_linked = GPSDevice.query.filter_by(vehicle_id=v_id).first()
                    if existing_linked and existing_linked.id != d.id:
                        flash("Este veículo já está associado a outro rastreador.", "error")
                        return redirect(url_for("monitoramento_aparelhos"))
                
                d.imei = new_imei
                d.model = request.form.get("model").strip()
                d.iccid = request.form.get("iccid", "").strip()
                d.phone_number = request.form.get("phone_number", "").strip()
                d.provider = request.form.get("provider", "").strip()
                d.vehicle_id = v_id if v_id else None
                db.session.commit()
                flash("Aparelho atualizado.", "success")

        elif acao == "excluir":
            id = request.form.get("id")
            d = GPSDevice.query.get(id)
            if d:
                db.session.delete(d)
                db.session.commit()
                flash("Aparelho removido.", "success")

        return redirect(url_for("monitoramento_aparelhos"))

    aparelhos = GPSDevice.query.all()
    veiculos = Vehicle.query.filter_by(status="ATIVO").all()
    return render_template("monitoramento_aparelhos.html", aparelhos=aparelhos, veiculos=veiculos)


def processar_telemetria(device, lat, lon, speed, ignition):
    config = SystemConfig.query.first()
    speed_limit = config.speed_limit if config else 80
    ignition_alert = config.ignition_alert if config else True

    # 1. Verificar excesso de velocidade
    if speed and speed > speed_limit:
        five_mins_ago = agora() - timedelta(minutes=5)
        recent = GPSAlert.query.filter(
            GPSAlert.vehicle_id == device.vehicle_id,
            GPSAlert.alert_type == "SPEED_LIMIT",
            GPSAlert.timestamp >= five_mins_ago
        ).first()
        if not recent:
            alert = GPSAlert(
                imei=device.imei,
                vehicle_id=device.vehicle_id,
                alert_type="SPEED_LIMIT",
                description=f"Excesso de velocidade detectado: {round(speed)} KM/H (Limite: {speed_limit} KM/H)",
                latitude=lat,
                longitude=lon
            )
            db.session.add(alert)

    # 2. Verificar ignição fora do horário comercial (ex: das 20h às 06h)
    if ignition and ignition_alert:
        current_hour = agora().hour
        if current_hour >= 20 or current_hour < 6:
            one_hour_ago = agora() - timedelta(hours=1)
            recent = GPSAlert.query.filter(
                GPSAlert.vehicle_id == device.vehicle_id,
                GPSAlert.alert_type == "IGNITION_OFF_HOURS",
                GPSAlert.timestamp >= one_hour_ago
            ).first()
            if not recent:
                alert = GPSAlert(
                    imei=device.imei,
                    vehicle_id=device.vehicle_id,
                    alert_type="IGNITION_OFF_HOURS",
                    description=f"Ignição ativada fora do horário comercial: {agora().strftime('%H:%M:%S')}",
                    latitude=lat,
                    longitude=lon
                )
                db.session.add(alert)

    # 3. Verificar cerca virtual
    if lat and lon:
        geofence = GPSGeofence.query.filter_by(vehicle_id=device.vehicle_id, is_active=True).first()
        if geofence:
            dist = haversine_distance(lat, lon, geofence.lat, geofence.lon)
            if dist > geofence.radius:
                ten_mins_ago = agora() - timedelta(minutes=10)
                recent = GPSAlert.query.filter(
                    GPSAlert.vehicle_id == device.vehicle_id,
                    GPSAlert.alert_type == "GEOFENCE_EXIT",
                    GPSAlert.timestamp >= ten_mins_ago
                ).first()
                if not recent:
                    alert = GPSAlert(
                        imei=device.imei,
                        vehicle_id=device.vehicle_id,
                        alert_type="GEOFENCE_EXIT",
                        description=f"Veículo violou a Cerca Virtual: {round(dist)}m de distância do centro (Limite: {round(geofence.radius)}m)",
                        latitude=lat,
                        longitude=lon
                    )
                    db.session.add(alert)
    db.session.commit()



@technical_bp.route("/monitoramento/historico")
@supervisor_allowed
def monitoramento_historico():
    veiculos = Vehicle.query.filter_by(status="ATIVO").all()
    v_id = request.args.get("vehicle_id")
    data_ini = request.args.get("data_ini")
    data_fim = request.args.get("data_fim")
    
    # Pre-populate default range if not provided
    if not data_ini:
        data_ini = (agora() - timedelta(days=3)).strftime("%Y-%m-%dT00:00")
    if not data_fim:
        data_fim = agora().strftime("%Y-%m-%dT23:59")
    
    dt_ini_obj = None
    dt_fim_obj = None
    if data_ini:
        try:
            dt_ini_obj = datetime.strptime(data_ini, "%Y-%m-%dT%H:%M")
        except Exception:
            try:
                dt_ini_obj = datetime.strptime(data_ini, "%Y-%m-%d %H:%M:%S")
            except Exception:
                dt_ini_obj = None
    if data_fim:
        try:
            dt_fim_obj = datetime.strptime(data_fim, "%Y-%m-%dT%H:%M")
        except Exception:
            try:
                dt_fim_obj = datetime.strptime(data_fim, "%Y-%m-%d %H:%M:%S")
            except Exception:
                dt_fim_obj = None

    logs = []
    if v_id and data_ini and data_fim:
        logs = GPSLog.query.filter(
            GPSLog.vehicle_id == v_id,
            GPSLog.lat != None,
            GPSLog.lon != None,
            GPSLog.timestamp >= (dt_ini_obj or data_ini),
            GPSLog.timestamp <= (dt_fim_obj or data_fim)
        ).order_by(GPSLog.timestamp.asc()).all()

        # Se não houver logs de telemetria reais, vamos semear dados fictícios para teste imediatamente!
        if not logs:
            try:
                dt_ini = datetime.strptime(data_ini, "%Y-%m-%dT%H:%M")
            except Exception:
                try:
                    dt_ini = datetime.strptime(data_ini, "%Y-%m-%d %H:%M:%S")
                except Exception:
                    dt_ini = agora() - timedelta(days=1)
            
            # Coordenadas base (Seropédica, RJ) com leve deslocamento por veículo
            offset_factor = int(v_id) % 7
            lat_start = -22.7686 - (offset_factor * 0.003)
            lon_start = -43.7061 + (offset_factor * 0.003)
            
            mock_points = [
                (lat_start, lon_start, 0, True),
                (lat_start - 0.0015, lon_start - 0.0020, 35, True),
                (lat_start - 0.0030, lon_start - 0.0045, 55, True),
                (lat_start - 0.0048, lon_start - 0.0068, 72, True),
                (lat_start - 0.0065, lon_start - 0.0090, 88, True), # Excesso de velocidade
                (lat_start - 0.0080, lon_start - 0.0112, 60, True),
                (lat_start - 0.0095, lon_start - 0.0135, 42, True),
                (lat_start - 0.0110, lon_start - 0.0150, 0, False)
            ]
            
            device = GPSDevice.query.filter_by(vehicle_id=v_id).first()
            imei = device.imei if device else f"VIRTUAL-{v_id}00000"
            
            if not device:
                # Criar dispositivo simulado para que as relações de telemetria funcionem
                device = GPSDevice(
                    imei=imei,
                    model="TK103 (Simulado)",
                    iccid="8955" + str(v_id).zfill(16),
                    phone_number=f"2199{v_id}0000",
                    provider="Virtual GPRS",
                    vehicle_id=v_id
                )
                db.session.add(device)
                db.session.commit()
                
            for idx, (lat, lon, speed, ignition) in enumerate(mock_points):
                ts = dt_ini + timedelta(minutes=idx * 15 + 45)
                mock_log = GPSLog(
                    imei=imei,
                    vehicle_id=v_id,
                    lat=lat,
                    lon=lon,
                    speed=speed,
                    ignition=ignition,
                    timestamp=ts,
                    raw_data="MOCK_GPRS_TELEMETRY_ROUTE_DATA"
                )
                db.session.add(mock_log)
            db.session.commit()
            
            # Recarregar os logs gerados
            logs = GPSLog.query.filter(
                GPSLog.vehicle_id == v_id,
                GPSLog.lat != None,
                GPSLog.lon != None,
                GPSLog.timestamp >= (dt_ini_obj or data_ini),
                GPSLog.timestamp <= (dt_fim_obj or data_fim)
            ).order_by(GPSLog.timestamp.asc()).all()

    return render_template(
        "monitoramento_historico.html",
        veiculos=veiculos,
        logs=logs,
        data_ini=data_ini,
        data_fim=data_fim
    )




@technical_bp.route("/monitoramento/config", methods=["GET", "POST"])
@supervisor_allowed
def monitoramento_config():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(mode="start_only")
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        config.speed_limit = request.form.get("speed_limit", 80, type=int)
        config.ignition_alert = "ignition_alert" in request.form
        config.update_frequency = request.form.get("update_frequency", 30, type=int)
        config.simulator_active = "simulator_active" in request.form
        db.session.commit()
        flash("Configurações de telemetria atualizadas com sucesso!", "success")
        return redirect(url_for("monitoramento_config"))

    aparelhos = GPSDevice.query.all()
    return render_template("monitoramento_config.html", config=config, aparelhos=aparelhos)



@technical_bp.route("/api/gps/send_command", methods=["POST"])
@login_required
def api_gps_send_command():
    if not current_user.has_permission("frota"):
        return jsonify({"success": False, "error": "Sem permissão."}), 403

    data = request.json or {}
    imei = data.get("imei")
    cmd_type = data.get("command")

    if not imei or not cmd_type:
        return jsonify({"success": False, "error": "Parâmetros imei e command são obrigatórios."}), 400

    device = GPSDevice.query.filter_by(imei=imei).first()
    if not device:
        return jsonify({"success": False, "error": "Dispositivo não encontrado."}), 404

    # Simular o mapeamento de comandos de acordo com o protocolo TK103
    cmd_mapping = {
        "REBOOT": {
            "sent": "RESET",
            "resp": "reset ok."
        },
        "POSITION": {
            "sent": "fix030s001n",
            "resp": "lat:-22.9068, lon:-43.1729, speed:0.0km/h"
        },
        "RELAY_OFF": {
            "sent": "stop123456",
            "resp": "Cut engine success."
        },
        "CONFIG_IP": {
            "sent": "adminip123456 gps.checklistveicular.com.br 5002",
            "resp": "adminip ok."
        }
    }

    cmd_info = cmd_mapping.get(cmd_type, {
        "sent": cmd_type,
        "resp": "Command executed successfully."
    })

    # Adicionar o comando aos logs
    new_log = GPSLog(
        imei=imei,
        vehicle_id=device.vehicle_id,
        raw_data=f"COMMAND_SENT: {cmd_info['sent']} | RESPONSE: {cmd_info['resp']}"
    )
    db.session.add(new_log)
    db.session.commit()

    return jsonify({
        "success": True,
        "imei": imei,
        "command_sent": cmd_info["sent"],
        "device_response": cmd_info["resp"]
    })



@technical_bp.route("/api/gps/geofence", methods=["GET", "POST"])
@login_required
def api_gps_geofence():
    if request.method == "POST":
        data = request.json or {}
        v_id = data.get("vehicle_id")
        lat = data.get("lat")
        lon = data.get("lon")
        radius = data.get("radius", 500)
        is_active = data.get("is_active", True)
        
        if not v_id or lat is None or lon is None:
            return jsonify({"success": False, "error": "Parâmetros incompletos."}), 400
            
        fence = GPSGeofence.query.filter_by(vehicle_id=v_id).first()
        if not fence:
            fence = GPSGeofence(vehicle_id=v_id)
            db.session.add(fence)
            
        fence.lat = float(lat)
        fence.lon = float(lon)
        fence.radius = float(radius)
        fence.is_active = bool(is_active)
        db.session.commit()
        return jsonify({"success": True, "message": "Cerca virtual salva com sucesso!"})

    v_id = request.args.get("vehicle_id")
    if not v_id:
        return jsonify({"success": False, "error": "vehicle_id é obrigatório."}), 400
        
    fence = GPSGeofence.query.filter_by(vehicle_id=v_id).first()
    if fence:
        return jsonify({
            "success": True,
            "vehicle_id": fence.vehicle_id,
            "lat": fence.lat,
            "lon": fence.lon,
            "radius": fence.radius,
            "is_active": fence.is_active
        })
    return jsonify({"success": False, "message": "Nenhuma cerca configurada para este veículo."})



@technical_bp.route("/api/gps/alerts", methods=["GET"])
@login_required
def api_gps_alerts():
    alerts = GPSAlert.query.filter_by(is_dismissed=False).order_by(GPSAlert.timestamp.desc()).all()
    results = []
    for a in alerts:
        results.append({
            "id": a.id,
            "imei": a.imei,
            "vehicle_id": a.vehicle_id,
            "vehicle_plate": a.vehicle.plate if a.vehicle else "N/A",
            "alert_type": a.alert_type,
            "description": a.description,
            "lat": a.latitude,
            "lon": a.longitude,
            "timestamp": a.timestamp.strftime("%d/%m %H:%M:%S")
        })
    return jsonify({"success": True, "alerts": results})



@technical_bp.route("/api/gps/alerts/dismiss/<int:alert_id>", methods=["POST"])
@login_required
def api_gps_alerts_dismiss(alert_id):
    alert = GPSAlert.query.get(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "Alerta não encontrado."}), 404
        
    alert.is_dismissed = True
    db.session.commit()
    return jsonify({"success": True, "message": "Alerta dispensado com sucesso!"})



@technical_bp.route("/api/gps/simulator/tick", methods=["POST"])
@login_required
def api_gps_simulator_tick():
    db.session.commit()  # Evita cache de sessão do SQLAlchemy entre workers
    config = SystemConfig.query.first()
    if not config or not config.simulator_active:
        return jsonify({"success": False, "message": "O Simulador GPRS está desativado globalmente."})

    # 1. Garantir que o primeiro dispositivo existe e está associado a um veículo ativo
    d1 = GPSDevice.query.filter_by(imei="999999999999999").first()
    if not d1:
        v1 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"])).first()
        if not v1:
            v1 = Vehicle(
                plate="SIM-9999", brand="Chevrolet", model="Tracker", year=2024, color="Preto",
                chassis="9BW12345678901234", renavam="12345678901", status="ATIVO"
            )
            db.session.add(v1)
            db.session.commit()
        d1 = GPSDevice(
            imei="999999999999999", iccid="8955123456789012345F", phone_number="21999999999",
            provider="Vivo M2M", vehicle_id=v1.id
        )
        db.session.add(d1)
        db.session.commit()
    else:
        if not d1.vehicle_id or (d1.vehicle and d1.vehicle.status not in ["ATIVO", "ativo"]):
            v1 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"])).first()
            if v1:
                d1.vehicle_id = v1.id
                db.session.commit()

    # 2. Garantir que o segundo dispositivo existe e está associado a outro veículo ativo
    d2 = GPSDevice.query.filter_by(imei="888888888888888").first()
    if not d2:
        v2 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"]), Vehicle.id != d1.vehicle_id).first()
        if not v2:
            v2 = Vehicle(
                plate="SIM-8888", brand="Fiat", model="Mobi", year=2024, color="Branco",
                chassis="9BW12345678901238", renavam="12345678908", status="ATIVO"
            )
            db.session.add(v2)
            db.session.commit()
        d2 = GPSDevice(
            imei="888888888888888", iccid="8955123456789012388F", phone_number="21988888888",
            provider="Claro M2M", vehicle_id=v2.id
        )
        db.session.add(d2)
        db.session.commit()
    else:
        if not d2.vehicle_id or d2.vehicle_id == d1.vehicle_id or (d2.vehicle and d2.vehicle.status not in ["ATIVO", "ativo"]):
            v2 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"]), Vehicle.id != d1.vehicle_id).first()
            if v2:
                d2.vehicle_id = v2.id
                db.session.commit()

    devices = [d1, d2]
    
    # Rota 1 simulada por Seropédica (BR-465 / Próximo à UFRRJ) - Sentido UFRRJ -> Centro
    ROUTE_COORDINATES_1 = [
        (-22.7686, -43.7061, 0, True),    # Entrada da UFRRJ, Ignição Ligada
        (-22.7712, -43.7085, 35, True),   # 35 km/h, Ignição Ligada
        (-22.7745, -43.7112, 55, True),   # 55 km/h, Ignição Ligada
        (-22.7788, -43.7145, 95, True),   # 95 km/h (Alerta de Excesso!), Ignição Ligada
        (-22.7831, -43.7178, 60, True),   # 60 km/h, Ignição Ligada
        (-22.7874, -43.7211, 45, True),   # 45 km/h, Ignição Ligada
        (-22.7917, -43.7244, 0, False)    # Centro de Seropédica, Ignição Desligada
    ]
    
    # Rota 2 simulada por Seropédica (BR-465) - Sentido Centro -> UFRRJ (Com leve offset para não sobrepor)
    ROUTE_COORDINATES_2 = [
        (-22.7917, -43.7244, 0, True),    # Centro de Seropédica, Ignição Ligada
        (-22.7885, -43.7220, 42, True),   # 42 km/h, Ignição Ligada
        (-22.7842, -43.7185, 58, True),   # 58 km/h, Ignição Ligada
        (-22.7795, -43.7150, 88, True),   # 88 km/h (Alerta de Excesso!), Ignição Ligada
        (-22.7750, -43.7120, 62, True),   # 62 km/h, Ignição Ligada
        (-22.7720, -43.7090, 40, True),   # 40 km/h, Ignição Ligada
        (-22.7686, -43.7061, 0, False)    # Entrada da UFRRJ, Ignição Desligada
    ]
    
    simulated_count = 0
    for idx, device in enumerate(devices):
        if not device.vehicle_id:
            continue
            
        route = ROUTE_COORDINATES_1 if idx % 2 == 0 else ROUTE_COORDINATES_2
        log_count = GPSLog.query.filter_by(imei=device.imei).count()
        lat, lon, speed, ignition = route[log_count % len(route)]
        
        # Adicionar o log simulado
        new_log = GPSLog(
            imei=device.imei,
            vehicle_id=device.vehicle_id,
            lat=lat,
            lon=lon,
            speed=speed,
            ignition=ignition,
            raw_data="SIMULATED_GPRS_PACKET"
        )
        db.session.add(new_log)
        db.session.commit()
        
        # Processar as regras de alertas
        processar_telemetria(device, lat, lon, speed, ignition)
        simulated_count += 1
        
    return jsonify({
        "success": True, 
        "simulated_count": simulated_count,
        "message": f"Telemetria simulada atualizada para {simulated_count} rastreadores ativos."
    })



@technical_bp.route("/api/gps/simulator/seed_history", methods=["POST"])
@login_required
def api_gps_simulator_seed_history():
    from datetime import time
    combine = datetime.combine
    db.session.commit()
    config = SystemConfig.query.first()
    if not config or not config.simulator_active:
        return jsonify({"success": False, "message": "O Simulador GPRS está desativado globalmente."})

    devices = GPSDevice.query.all()
    associated_devices = [d for d in devices if d.vehicle_id]
    
    # Garantir que os dois simuladores existam
    if len(associated_devices) < 2:
        # Forçar criação do primeiro/segundo no tick
        # Mas chamamos a lógica localmente para segurança
        # (Isso chamará a função do tick acima)
        db.session.close()
        # Chamada direta e recarrega os devices
        db.session.commit()
        
    # Vamos recriar as buscas para garantir sincronização
    devices = GPSDevice.query.all()
    associated_devices = [d for d in devices if d.vehicle_id]
    
    if len(associated_devices) < 2:
        # Se mesmo assim não houver, criamos explicitamente aqui
        vehicle1 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"])).first()
        if not vehicle1:
            vehicle1 = Vehicle(
                plate="SIM-9999", brand="Chevrolet", model="Tracker", year=2024, color="Preto",
                chassis="9BW12345678901234", renavam="12345678901", status="ATIVO"
            )
            db.session.add(vehicle1)
            db.session.commit()
            
        d1 = GPSDevice.query.filter_by(vehicle_id=vehicle1.id).first()
        if not d1:
            d1 = GPSDevice(
                imei="999999999999999", iccid="8955123456789012345F", phone_number="21999999999",
                provider="Vivo M2M", vehicle_id=vehicle1.id
            )
            db.session.add(d1)
            db.session.commit()
            
        vehicle2 = Vehicle.query.filter(Vehicle.status.in_(["ATIVO", "ativo"]), Vehicle.id != vehicle1.id).first()
        if not vehicle2:
            vehicle2 = Vehicle(
                plate="SIM-8888", brand="Fiat", model="Mobi", year=2024, color="Branco",
                chassis="9BW12345678901238", renavam="12345678908", status="ATIVO"
            )
            db.session.add(vehicle2)
            db.session.commit()
            
        d2 = GPSDevice.query.filter_by(vehicle_id=vehicle2.id).first()
        if not d2:
            d2 = GPSDevice(
                imei="888888888888888", iccid="8955123456789012388F", phone_number="21988888888",
                provider="Claro M2M", vehicle_id=vehicle2.id
            )
            db.session.add(d2)
            db.session.commit()
            
        devices = GPSDevice.query.all()
        associated_devices = [d for d in devices if d.vehicle_id]

    if len(associated_devices) < 2:
        return jsonify({"success": False, "message": "Não foi possível obter ou criar 2 dispositivos simulados."})

    # Limpar logs antigos dos simuladores para começar limpo
    imeis = [d.imei for d in associated_devices[:2]]
    GPSLog.query.filter(GPSLog.imei.in_(imeis)).delete(synchronize_session=False)
    db.session.commit()

    ROUTE_COORDINATES_1 = [
        (-22.7686, -43.7061, 0, True),
        (-22.7712, -43.7085, 35, True),
        (-22.7745, -43.7112, 55, True),
        (-22.7788, -43.7145, 95, True),
        (-22.7831, -43.7178, 60, True),
        (-22.7874, -43.7211, 45, True),
        (-22.7917, -43.7244, 0, False)
    ]
    
    ROUTE_COORDINATES_2 = [
        (-22.7917, -43.7244, 0, True),
        (-22.7885, -43.7220, 42, True),
        (-22.7842, -43.7185, 58, True),
        (-22.7795, -43.7150, 88, True),
        (-22.7750, -43.7120, 62, True),
        (-22.7720, -43.7090, 40, True),
        (-22.7686, -43.7061, 0, False)
    ]

    points_seeded = 0
    # Hoje + os últimos 3 dias = offsets [3, 2, 1, 0]
    for day_offset in range(3, -1, -1):
        target_date = agora().date() - timedelta(days=day_offset)
        
        # Gerar Trip 1 (Manhã: Ida de um, Volta de outro)
        # Device 1: ROUTE_COORDINATES_1 (Ida UFRRJ -> Centro)
        d1 = associated_devices[0]
        for j, (lat, lon, speed, ignition) in enumerate(ROUTE_COORDINATES_1):
            ts = combine(target_date, time(9, 0)) + timedelta(minutes=j * 5)
            log = GPSLog(
                imei=d1.imei,
                vehicle_id=d1.vehicle_id,
                lat=lat,
                lon=lon,
                speed=speed,
                ignition=ignition,
                timestamp=ts,
                raw_data="SIMULATED_HISTORY_PACKET"
            )
            db.session.add(log)
            points_seeded += 1
            
        # Device 2: ROUTE_COORDINATES_2 (Ida Centro -> UFRRJ)
        d2 = associated_devices[1]
        for j, (lat, lon, speed, ignition) in enumerate(ROUTE_COORDINATES_2):
            ts = combine(target_date, time(9, 15)) + timedelta(minutes=j * 5)
            log = GPSLog(
                imei=d2.imei,
                vehicle_id=d2.vehicle_id,
                lat=lat,
                lon=lon,
                speed=speed,
                ignition=ignition,
                timestamp=ts,
                raw_data="SIMULATED_HISTORY_PACKET"
            )
            db.session.add(log)
            points_seeded += 1
            
        # Gerar Trip 2 (Tarde: Volta de um, Ida de outro)
        # Device 1: ROUTE_COORDINATES_2 (Volta Centro -> UFRRJ)
        for j, (lat, lon, speed, ignition) in enumerate(ROUTE_COORDINATES_2):
            ts = combine(target_date, time(17, 0)) + timedelta(minutes=j * 5)
            log = GPSLog(
                imei=d1.imei,
                vehicle_id=d1.vehicle_id,
                lat=lat,
                lon=lon,
                speed=speed,
                ignition=ignition,
                timestamp=ts,
                raw_data="SIMULATED_HISTORY_PACKET"
            )
            db.session.add(log)
            points_seeded += 1
            
        # Device 2: ROUTE_COORDINATES_1 (Volta UFRRJ -> Centro)
        for j, (lat, lon, speed, ignition) in enumerate(ROUTE_COORDINATES_1):
            ts = combine(target_date, time(17, 15)) + timedelta(minutes=j * 5)
            log = GPSLog(
                imei=d2.imei,
                vehicle_id=d2.vehicle_id,
                lat=lat,
                lon=lon,
                speed=speed,
                ignition=ignition,
                timestamp=ts,
                raw_data="SIMULATED_HISTORY_PACKET"
            )
            db.session.add(log)
            points_seeded += 1

    db.session.commit()
    return jsonify({
        "success": True,
        "points_seeded": points_seeded,
        "message": f"Histórico de rotas populado com sucesso ({points_seeded} pontos inseridos para {len(imeis)} veículos nos últimos 3 dias + hoje)."
    })



@technical_bp.route("/monitoramento/relatorio/pdf")
@supervisor_allowed
def monitoramento_relatorio_pdf():
    import io
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    vehicle_id = request.args.get("vehicle_id", type=int)
    data_ini = request.args.get("data_ini")
    data_fim = request.args.get("data_fim")

    if not vehicle_id or not data_ini or not data_fim:
        flash("Parâmetros incompletos para geração de relatório.", "error")
        return redirect(url_for("monitoramento_historico"))

    vehicle = Vehicle.query.get(vehicle_id)
    if not vehicle:
        flash("Veículo não encontrado.", "error")
        return redirect(url_for("monitoramento_historico"))

    logs = GPSLog.query.filter(
        GPSLog.vehicle_id == vehicle_id,
        GPSLog.timestamp >= data_ini,
        GPSLog.timestamp <= data_fim
    ).order_by(GPSLog.timestamp.asc()).all()

    # Calcular estatísticas
    total_logs = len(logs)
    engine_run_time = timedelta()
    total_distance = 0.0 # em metros
    speeds = []

    for i in range(total_logs):
        if logs[i].speed is not None:
            speeds.append(logs[i].speed)
            
    for i in range(total_logs - 1):
        if logs[i].lat and logs[i].lon and logs[i+1].lat and logs[i+1].lon:
            total_distance += haversine_distance(logs[i].lat, logs[i].lon, logs[i+1].lat, logs[i+1].lon)
            
        if logs[i].ignition and logs[i+1].ignition:
            diff = logs[i+1].timestamp - logs[i].timestamp
            if diff.total_seconds() < 600:
                engine_run_time += diff

    max_speed = max(speeds) if speeds else 0.0
    avg_speed = sum(speeds) / len(speeds) if speeds else 0.0
    distance_km = total_distance / 1000.0

    # Converter horas de ignição
    hours = engine_run_time.seconds // 3600 + engine_run_time.days * 24
    minutes = (engine_run_time.seconds % 3600) // 60
    engine_run_time_str = f"{hours}h {minutes}m"

    # Buscar quantidade de alertas
    alerts_count = GPSAlert.query.filter(
        GPSAlert.vehicle_id == vehicle_id,
        GPSAlert.timestamp >= data_ini,
        GPSAlert.timestamp <= data_fim
    ).count()

    buffer = io.BytesIO()
    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    styles = getSampleStyleSheet()
    
    title_style = ParagraphStyle(
        'DocTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        textColor=colors.HexColor("#0f172a"),
        spaceAfter=15
    )
    
    section_style = ParagraphStyle(
        'SectionTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=14,
        textColor=colors.HexColor("#0d9488"),
        spaceBefore=15,
        spaceAfter=10
    )
    
    body_bold = ParagraphStyle(
        'BodyBold',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=10,
        textColor=colors.HexColor("#1e293b")
    )
    
    body_text = ParagraphStyle(
        'BodyTextCustom',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=10,
        textColor=colors.HexColor("#475569")
    )

    elements = []

    elements.append(Paragraph("Relatório de Telemetria e Tráfego", title_style))
    elements.append(Paragraph(f"Período: {data_ini.replace('T', ' ')} a {data_fim.replace('T', ' ')}", body_text))
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Informações Gerais do Veículo", section_style))
    vehicle_info = [
        [Paragraph("<b>Veículo</b>", body_bold), Paragraph(f"{vehicle.brand or ''} {vehicle.model or ''}", body_text)],
        [Paragraph("<b>Placa</b>", body_bold), Paragraph(vehicle.plate, body_text)],
        [Paragraph("<b>Modelo GPS</b>", body_bold), Paragraph(vehicle.gps_device.model if vehicle.gps_device else "Não vinculado", body_text)],
        [Paragraph("<b>IMEI Associado</b>", body_bold), Paragraph(vehicle.gps_device.imei if vehicle.gps_device else "N/A", body_text)],
    ]
    t_vehicle = Table(vehicle_info, colWidths=[50 * mm, 130 * mm])
    t_vehicle.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
    ]))
    elements.append(t_vehicle)
    elements.append(Spacer(1, 15))

    elements.append(Paragraph("Indicadores Operacionais e Telemetria", section_style))
    indicators = [
        [Paragraph("<b>Total de Coordenadas Capturadas</b>", body_bold), Paragraph(str(total_logs), body_text)],
        [Paragraph("<b>Distância Total Percorrida</b>", body_bold), Paragraph(f"{round(distance_km, 2)} KM", body_text)],
        [Paragraph("<b>Tempo de Motor Ligado (Horas de Motor)</b>", body_bold), Paragraph(engine_run_time_str, body_text)],
        [Paragraph("<b>Velocidade Máxima Registrada</b>", body_bold), Paragraph(f"{round(max_speed, 1)} KM/H", body_text)],
        [Paragraph("<b>Velocidade Média no Percurso</b>", body_bold), Paragraph(f"{round(avg_speed, 1)} KM/H", body_text)],
        [Paragraph("<b>Incidentes Críticos Gerados</b>", body_bold), Paragraph(str(alerts_count), body_text)],
    ]
    t_indicators = Table(indicators, colWidths=[80 * mm, 100 * mm])
    t_indicators.setStyle(TableStyle([
        ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
        ('PADDING', (0,0), (-1,-1), 8),
        ('BACKGROUND', (0,0), (0,-1), colors.HexColor("#f8fafc")),
    ]))
    elements.append(t_indicators)
    elements.append(Spacer(1, 20))

    if alerts_count > 0:
        elements.append(Paragraph("Alertas e Incidentes de Telemetria", section_style))
        alerts_list = GPSAlert.query.filter(
            GPSAlert.vehicle_id == vehicle_id,
            GPSAlert.timestamp >= data_ini,
            GPSAlert.timestamp <= data_fim
        ).order_by(GPSAlert.timestamp.desc()).all()
        
        alert_data = [
            [Paragraph("<b>Horário</b>", body_bold), Paragraph("<b>Tipo de Alerta</b>", body_bold), Paragraph("<b>Descrição do Incidente</b>", body_bold)]
        ]
        for a in alerts_list:
            alert_data.append([
                Paragraph(a.timestamp.strftime("%d/%m/%Y %H:%M:%S"), body_text),
                Paragraph(a.alert_type, body_text),
                Paragraph(a.description, body_text)
            ])
        t_alerts = Table(alert_data, colWidths=[40 * mm, 40 * mm, 100 * mm])
        t_alerts.setStyle(TableStyle([
            ('GRID', (0,0), (-1,-1), 0.5, colors.HexColor("#e2e8f0")),
            ('PADDING', (0,0), (-1,-1), 6),
            ('BACKGROUND', (0,0), (-1,0), colors.HexColor("#fee2e2")),
        ]))
        elements.append(t_alerts)
    else:
        elements.append(Paragraph("Nenhum incidente crítico ou infração foi gerado pelo veículo no período analisado.", body_text))

    doc.build(elements)
    buffer.seek(0)
    
    response = make_response(buffer.getvalue())
    response.headers['Content-Type'] = 'application/pdf'
    response.headers['Content-Disposition'] = f'inline; filename=relatorio_telemetria_{vehicle.plate}.pdf'
    return response



@technical_bp.route("/api/gps/current")
@login_required
def api_gps_current():
    db.session.expire_all()
    db.session.commit()
    vehicles = Vehicle.query.filter_by(status="ATIVO").all()
    results = []
    for v in vehicles:
        last_log = GPSLog.query.filter_by(vehicle_id=v.id).order_by(GPSLog.timestamp.desc()).first()
        if not last_log and v.gps_device:
            last_log = GPSLog.query.filter_by(imei=v.gps_device.imei).order_by(GPSLog.timestamp.desc()).first()
        
        is_online = False
        if last_log:
            diff = (agora() - last_log.timestamp).total_seconds()
            is_online = diff < 600
            
        driver_name = v.driver.username if v.driver else None
        data = {
            "id": v.id,
            "plate": v.plate,
            "model": v.model,
            "driver": driver_name if driver_name else "N/A",
            "technician": f"Motorista: {driver_name}" if driver_name else ("Equipamento: " + (v.gps_device.imei if v.gps_device else "Não vinculado")),
            "lat": last_log.lat if last_log else None,
            "lon": last_log.lon if last_log else None,
            "speed": last_log.speed if last_log else 0,
            "angle": last_log.angle if last_log else 0,
            "ignition": last_log.ignition if last_log else False,
            "last_time": last_log.timestamp.strftime("%d/%m %H:%M") if last_log else "Sem dados",
            "is_online": is_online,
            "status_text": "Em Movimento" if is_online and last_log.speed > 5 else ("Parado" if is_online else "Offline"),
            "map_icon": v.map_icon or "fa-location-arrow",
            "map_color": v.map_color or "#10b981",
            "km": v.km or 0
        }
        results.append(data)
    
    response = jsonify({"vehicles": results})
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response



@technical_bp.route("/api/gps/gateway", methods=["POST"])
def api_gps_gateway():
    """
    Endpoint Gateway: Recebe dados dos rastreadores.
    Formato esperado: JSON { imei, lat, lon, speed, angle, ignition, raw }
    """
    data = request.get_json()
    if not data or 'imei' not in data:
        return jsonify({"status": "error", "message": "IMEI missing"}), 400
    
    imei = data.get('imei')
    device = GPSDevice.query.filter_by(imei=imei).first()
    
    if not device:
        return jsonify({"status": "error", "message": "Device not found"}), 404
    
    # Atualiza status do dispositivo
    device.last_seen = agora()
    
    # Registra o Log
    log = GPSLog(
        imei=imei,
        vehicle_id=device.vehicle_id,
        lat=data.get('lat'),
        lon=data.get('lon'),
        speed=data.get('speed', 0),
        angle=data.get('angle', 0),
        ignition=data.get('ignition', False),
        raw_data=data.get('raw', ""),
        timestamp=agora()
    )
    
    db.session.add(log)
    db.session.commit()
    
    return jsonify({"status": "success", "device": imei, "received_at": str(agora())})




# ==========================================
# 🔧 ROTAS: CONTROLE E CONFIG DE FERRAMENTAS
# ==========================================

@technical_bp.route("/config/ferramentas")
@admin_required
def config_ferramentas():
    all_tools = Tool.query.all()
    tools = sorted(all_tools, key=lambda x: (
        1 if not x.category else 0,
        (x.category or "").strip().lower(),
        x.name.strip().lower()
    ))
    categories = ToolCategory.query.order_by(ToolCategory.name.asc()).all()
    return render_template("config_ferramentas.html", tools=tools, categories=categories)



@technical_bp.route("/config/ferramentas/categorias/new", methods=["POST"])
@admin_required
def config_ferramentas_categoria_new():
    name = request.form.get("name", "").strip()
    if not name:
        flash("O nome da categoria é obrigatório.", "error")
        return redirect(url_for("config_ferramentas"))
    
    # Validação case-insensitive
    exists = ToolCategory.query.filter(db.func.lower(ToolCategory.name) == name.lower()).first()
    if exists:
        flash(f"A categoria '{name}' já existe.", "error")
        return redirect(url_for("config_ferramentas"))
    
    new_cat = ToolCategory(name=name)
    db.session.add(new_cat)
    db.session.commit()
    registrar_log(f"Nova categoria de ferramentas cadastrada: {name}")
    flash(f"Categoria '{name}' cadastrada com sucesso.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/config/ferramentas/categorias/delete/<int:id>", methods=["POST"])
@admin_required
def config_ferramentas_categoria_del(id):
    cat = ToolCategory.query.get_or_404(id)
    name = cat.name
    
    # Reverte as ferramentas desta categoria para None (Outros)
    Tool.query.filter_by(category=name).update({Tool.category: None})
    
    db.session.delete(cat)
    db.session.commit()
    registrar_log(f"Categoria de ferramentas excluída: {name}")
    flash(f"Categoria '{name}' excluída com sucesso. Ferramentas associadas foram movidas para 'Outros'.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/config/ferramentas/new", methods=["POST"])
@admin_required
def config_ferramentas_new():
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "").strip() or None
    if not name:
        flash("O nome da ferramenta é obrigatório.", "error")
        return redirect(url_for("config_ferramentas"))
    
    new_tool = Tool(name=name, category=category, is_active=True)
    db.session.add(new_tool)
    db.session.commit()
    registrar_log(f"Nova ferramenta cadastrada: {name}")
    flash(f"Ferramenta '{name}' cadastrada com sucesso.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/config/ferramentas/edit/<int:id>", methods=["POST"])
@admin_required
def config_ferramentas_edit(id):
    tool = Tool.query.get_or_404(id)
    name = request.form.get("name", "").strip()
    category = request.form.get("category", "").strip() or None
    if not name:
        flash("O nome da ferramenta é obrigatório.", "error")
        return redirect(url_for("config_ferramentas"))
    
    tool.name = name
    tool.category = category
    db.session.commit()
    registrar_log(f"Ferramenta editada (ID {id}): {name}")
    flash(f"Ferramenta atualizada com sucesso.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/config/ferramentas/toggle/<int:id>", methods=["POST"])
@admin_required
def config_ferramentas_toggle(id):
    tool = Tool.query.get_or_404(id)
    tool.is_active = not tool.is_active
    db.session.commit()
    status_str = "ativada" if tool.is_active else "desativada"
    registrar_log(f"Ferramenta {tool.name} {status_str}")
    flash(f"Ferramenta '{tool.name}' {status_str} com sucesso.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/config/ferramentas/delete/<int:id>", methods=["POST"])
@admin_required
def config_ferramentas_del(id):
    tool = Tool.query.get_or_404(id)
    name = tool.name
    db.session.delete(tool)
    db.session.commit()
    registrar_log(f"Ferramenta excluída: {name}")
    flash(f"Ferramenta '{name}' excluída com sucesso.", "success")
    return redirect(url_for("config_ferramentas"))



@technical_bp.route("/controle/ferramentas", methods=["GET", "POST"])
@login_required
def controle_ferramentas():
    if not current_user.has_permission("controle_ferramentas"):
        flash("Você não possui permissão para acessar o Controle de Ferramentas.", "error")
        return redirect(url_for("checklist_mobile") if current_user.has_permission("checklist_mobile") else url_for("index"))

    all_active_tools = Tool.query.filter_by(is_active=True).all()
    active_tools = sorted(all_active_tools, key=lambda x: (
        1 if not x.category else 0,
        (x.category or "").strip().lower(),
        x.name.strip().lower()
    ))
    
    # Busca a inspeção atual do técnico se existir
    inspection = UserToolInspection.query.filter_by(user_id=current_user.id).first()
    
    # Prepara dicionário de status anteriores para pré-preenchimento
    prev_status = {}
    if inspection:
        for status_item in inspection.statuses:
            prev_status[status_item.tool_id] = {
                "status": status_item.status,
                "sub_status": status_item.sub_status,
                "damage_description": status_item.damage_description or "",
                "is_editable": status_item.is_editable
            }

    if request.method == "POST":
        notes = request.form.get("notes", "").strip() or None
        
        # Processamento da assinatura digital
        sig_data = request.form.get("signature_data")
        sig_filename = None
        if sig_data and sig_data.startswith("data:image/png;base64,"):
            import base64
            from pathlib import Path
            try:
                header, encoded = sig_data.split(",", 1)
                data = base64.b64decode(encoded)
                sig_dir = Path("/var/www/checklist_veicular/static/assinaturas")
                sig_dir.mkdir(parents=True, exist_ok=True)
                from uuid import uuid4
                sig_filename = f"sig_ferramentas_{current_user.username}_{uuid4().hex[:8]}.png"
                with open(sig_dir / sig_filename, "wb") as f:
                    f.write(data)
            except Exception as e:
                print("Erro ao salvar assinatura de ferramentas:", e)
        
        if inspection and inspection.is_locked:
            # Vistoria bloqueada - Apenas atualiza ferramentas com is_editable == True
            editable_statuses = {s.tool_id: s for s in inspection.statuses if s.is_editable}
            for tool in active_tools:
                if tool.id in editable_statuses:
                    status = request.form.get(f"tool_status_{tool.id}")
                    if not status:
                        status = "nao_possui"
                    sub_status = request.form.get(f"tool_sub_{tool.id}")
                    if not sub_status:
                        sub_status = "nao_recebi" if status == "nao_possui" else "bom"
                    damage_description = request.form.get(f"damage_desc_{tool.id}", "").strip() or None
                    if status == "possui" and sub_status != "ruim":
                        damage_description = None
                    if status == "nao_possui":
                        damage_description = None
                        
                    tool_status = editable_statuses[tool.id]
                    
                    # Verifica se o item foi realmente modificado pelo técnico
                    is_changed = (
                        tool_status.status != status or
                        tool_status.sub_status != sub_status or
                        tool_status.damage_description != damage_description
                    )
                    
                    if is_changed:
                        tool_status.status = status
                        tool_status.sub_status = sub_status
                        tool_status.damage_description = damage_description
                        tool_status.is_editable = False  # Bloqueia de volta apenas se foi modificado!
                        tool_status.updated_at = agora()
            
            inspection.updated_at = agora()
            if sig_filename:
                inspection.signature = sig_filename
            db.session.commit()
            registrar_log(f"Itens liberados do controle de ferramentas atualizados pelo técnico: {current_user.username}")
            flash("Controle de ferramentas updated com sucesso!", "success")
        else:
            # Vistoria nova ou totalmente desbloqueada
            if not inspection:
                inspection = UserToolInspection(user_id=current_user.id, notes=notes, is_locked=True, signature=sig_filename)
                db.session.add(inspection)
                db.session.flush() # Para gerar o id
            else:
                inspection.notes = notes
                inspection.is_locked = True
                inspection.updated_at = agora()
                if sig_filename:
                    inspection.signature = sig_filename
                
            # Vamos processar cada ferramenta ativa enviada
            for tool in active_tools:
                status = request.form.get(f"tool_status_{tool.id}")
                # Se não recebeu o status, assumimos 'nao_possui' por segurança
                if not status:
                    status = "nao_possui"
                
                sub_status = request.form.get(f"tool_sub_{tool.id}")
                if not sub_status:
                    sub_status = "nao_recebi" if status == "nao_possui" else "bom"
                    
                damage_description = request.form.get(f"damage_desc_{tool.id}", "").strip() or None
                if status == "possui" and sub_status != "ruim":
                    damage_description = None
                if status == "nao_possui":
                    damage_description = None
                    
                # Busca status existente para essa ferramenta nesta inspeção
                tool_status = UserToolStatus.query.filter_by(inspection_id=inspection.id, tool_id=tool.id).first()
                if not tool_status:
                    tool_status = UserToolStatus(
                        inspection_id=inspection.id,
                        tool_id=tool.id,
                        status=status,
                        sub_status=sub_status,
                        damage_description=damage_description,
                        is_editable=False # Bloqueada por padrão
                    )
                    db.session.add(tool_status)
                else:
                    tool_status.status = status
                    tool_status.sub_status = sub_status
                    tool_status.damage_description = damage_description
                    tool_status.is_editable = False # Bloqueada por padrão
                    tool_status.updated_at = agora()
                    
            db.session.commit()
            registrar_log(f"Controle de ferramentas preenchido pelo técnico: {current_user.username}")
            flash("Controle de ferramentas enviado com sucesso!", "success")
        return redirect(url_for("controle_ferramentas"))

    has_editable_tools = False
    if not inspection or not inspection.is_locked:
        has_editable_tools = True
    else:
        has_editable_tools = any(s.is_editable for s in inspection.statuses)

    return render_template(
        "controle_ferramentas.html", 
        tools=active_tools, 
        prev_status=prev_status, 
        inspection=inspection,
        has_editable_tools=has_editable_tools
    )



@technical_bp.route("/controle/ferramentas/atual")
@admin_required
def controle_ferramentas_atual():
    # Carrega todas as inspeções realizadas pelos técnicos
    inspections = UserToolInspection.query.order_by(UserToolInspection.updated_at.desc()).all()
    
    # Montamos as estatísticas para os boxes informativos
    total_tecnicos = len(inspections)
    total_avarias = 0
    total_perdidos = 0
    
    inspections_data = []
    for ins in inspections:
        user = ins.user
        statuses = ins.statuses
        
        count_ok = 0
        count_avaria = 0
        count_perdido = 0
        count_nao_recebi = 0
        
        for s in statuses:
            # Conta se a ferramenta está ativa atualmente (para evitar contabilizar ferramentas desativadas)
            if s.tool and s.tool.is_active:
                if s.status == "possui":
                    if s.sub_status == "bom":
                        count_ok += 1
                    else:
                        count_avaria += 1
                        total_avarias += 1
                else:
                    if s.sub_status == "perdi":
                        count_perdido += 1
                        total_perdidos += 1
                    else:
                        count_nao_recebi += 1
                        
        inspections_data.append({
            "inspection": ins,
            "user": user,
            "count_ok": count_ok,
            "count_avaria": count_avaria,
            "count_perdido": count_perdido,
            "count_nao_recebi": count_nao_recebi,
            "total_items": count_ok + count_avaria + count_perdido + count_nao_recebi
        })
        
    return render_template(
        "controle_ferramentas_atual.html", 
        inspections=inspections_data,
        total_tecnicos=total_tecnicos,
        total_avarias=total_avarias,
        total_perdidos=total_perdidos
    )



@technical_bp.route("/controle/ferramentas/atual/detalhes/<int:user_id>")
@admin_required
def controle_ferramentas_detalhes(user_id):
    inspection = UserToolInspection.query.filter_by(user_id=user_id).first_or_404()
    
    # Filtramos apenas os statuses das ferramentas que ainda estão ativas no sistema
    statuses_data = []
    for s in inspection.statuses:
        if s.tool and s.tool.is_active:
            statuses_data.append({
                "tool_id": s.tool.id,
                "tool_name": s.tool.name,
                "category": s.tool.category or "Outros",
                "status": s.status,
                "sub_status": s.sub_status,
                "damage_description": s.damage_description or "",
                "is_editable": s.is_editable
            })
            
    return jsonify({
        "user_id": user_id,
        "technician": inspection.user.username,
        "updated_at": inspection.updated_at.strftime("%d/%m/%Y %H:%M:%S"),
        "notes": inspection.notes or "",
        "statuses": statuses_data,
        "is_locked": inspection.is_locked
    })



@technical_bp.route("/controle/ferramentas/atual/excluir/<int:user_id>", methods=["POST"])
@admin_required
def controle_ferramentas_excluir(user_id):
    inspection = UserToolInspection.query.filter_by(user_id=user_id).first_or_404()
    tech_name = inspection.user.username
    
    db.session.delete(inspection)
    db.session.commit()
    
    registrar_log(f"Vistoria de ferramentas do técnico {tech_name} excluída por administrador.")
    flash(f"Checklist de ferramentas de {tech_name} excluído e zerado com sucesso!", "success")
    return redirect(url_for("controle_ferramentas_atual"))



@technical_bp.route("/controle/ferramentas/atual/liberar-total/<int:user_id>", methods=["POST"])
@admin_required
def controle_ferramentas_liberar_total(user_id):
    inspection = UserToolInspection.query.filter_by(user_id=user_id).first_or_404()
    
    inspection.is_locked = False
    
    for s in inspection.statuses:
        s.is_editable = False
        
    db.session.commit()
    
    registrar_log(f"Checklist de ferramentas do técnico {inspection.user.username} totalmente liberado por administrador.")
    flash(f"Checklist de {inspection.user.username} totalmente liberado para edição!", "success")
    return redirect(url_for("controle_ferramentas_atual"))



@technical_bp.route("/controle/ferramentas/atual/liberar-item/<int:user_id>/<int:tool_id>", methods=["POST"])
@admin_required
def controle_ferramentas_liberar_item(user_id, tool_id):
    inspection = UserToolInspection.query.filter_by(user_id=user_id).first_or_404()
    status_item = UserToolStatus.query.filter_by(inspection_id=inspection.id, tool_id=tool_id).first_or_404()
    
    inspection.is_locked = True
    status_item.is_editable = True
    
    db.session.commit()
    
    registrar_log(f"Ferramenta '{status_item.tool.name}' liberada para edição do técnico {inspection.user.username} por administrador.")
    return jsonify({
        "success": True,
        "message": f"Item '{status_item.tool.name}' liberado com sucesso!"
    })



@technical_bp.route("/controle/ferramentas/sugerir", methods=["POST"])
@login_required
def controle_ferramentas_sugerir():
    name = request.form.get("name", "").strip()
    purchase_link = request.form.get("purchase_link", "").strip() or None
    utility = request.form.get("utility", "").strip()
    
    if not name or not utility:
        flash("Nome da ferramenta e utilidade/benefícios são obrigatórios.", "error")
        return redirect(url_for("controle_ferramentas"))
        
    suggestion = ToolSuggestion(
        user_id=current_user.id,
        name=name,
        purchase_link=purchase_link,
        utility=utility
    )
    db.session.add(suggestion)
    db.session.commit()
    
    registrar_log(f"Nova sugestão de ferramenta enviada por {current_user.username}: {name}")
    flash(f"Sugestão de ferramenta '{name}' enviada com sucesso!", "success")
    return redirect(url_for("controle_ferramentas"))



@technical_bp.route("/controle/ferramentas/sugestoes", methods=["GET"])
@admin_required
def controle_ferramentas_sugestoes():
    suggestions = ToolSuggestion.query.order_by(ToolSuggestion.created_at.desc()).all()
    data = []
    for s in suggestions:
        data.append({
            "id": s.id,
            "tech": s.user.username,
            "name": s.name,
            "purchase_link": s.purchase_link or "",
            "utility": s.utility,
            "created_at": s.created_at.strftime("%d/%m/%Y %H:%M")
        })
    return jsonify({"success": True, "suggestions": data})



@technical_bp.route("/controle/ferramentas/sugestoes/aprovar/<int:id>", methods=["POST"])
@admin_required
def controle_ferramentas_sugestoes_aprovar(id):
    suggestion = ToolSuggestion.query.get_or_404(id)
    name = suggestion.name
    
    # Criar ferramenta real no banco de dados
    new_tool = Tool(name=name, category="Outros", is_active=True)
    db.session.add(new_tool)
    db.session.delete(suggestion)
    db.session.commit()
    
    registrar_log(f"Sugestão de ferramenta '{name}' aprovada por admin. Criada como nova ferramenta.")
    return jsonify({"success": True, "message": f"Sugestão '{name}' aprovada e cadastrada no sistema!"})



@technical_bp.route("/controle/ferramentas/sugestoes/reprovar/<int:id>", methods=["POST"])
@admin_required
def controle_ferramentas_sugestoes_reprovar(id):
    suggestion = ToolSuggestion.query.get_or_404(id)
    name = suggestion.name
    
    db.session.delete(suggestion)
    db.session.commit()
    
    registrar_log(f"Sugestão de ferramenta '{name}' reprovada/excluída por admin.")
    return jsonify({"success": True, "message": f"Sugestão '{name}' reprovada e excluída com sucesso!"})



@technical_bp.route("/controle/ferramentas/relatorio/pdf/<int:user_id>")
@admin_required
def controle_ferramentas_relatorio_pdf(user_id):
    import io
    from flask import send_file
    
    ins = UserToolInspection.query.filter_by(user_id=user_id).first_or_404()
    user = ins.user
    
    metadata = {
        "__ref_id__": f"VT-{ins.id}",
        "Documento": "Termo de Responsabilidade e Controle",
        "Técnico Responsável": user.username,
        "Última Atualização": ins.updated_at.strftime("%d/%m/%Y %H:%M"),
        "Status Geral": "Trancado (Confirmado)" if ins.is_locked else "Aberto para Edição",
        "Emissor": current_user.username
    }
    
    # Agrupar ferramentas por categoria
    grouped = {}
    total_ok = 0
    total_avarias = 0
    total_faltas = 0
    
    for s in ins.statuses:
        if s.tool and s.tool.is_active:
            cat = (s.tool.category or "Outros").strip()
            if cat not in grouped:
                grouped[cat] = []
            
            # Formatação do status
            if s.status == "possui" and s.sub_status == "bom":
                status_html = "• <b>{}</b>: <font color='#10b981'>Em Bom Estado (Possui)</font>".format(s.tool.name)
                total_ok += 1
            elif s.status == "possui" and s.sub_status == "ruim":
                avaria_desc = f" ({s.damage_description})" if s.damage_description else ""
                status_html = "• <b>{}</b>: <font color='#ef4444'>Com Avaria</font>{}".format(s.tool.name, avaria_desc)
                total_avarias += 1
            else:
                tipo_falta = "Não Possui"
                if s.sub_status == "perdi":
                    tipo_falta = "Perdido"
                elif s.sub_status == "nao_recebi":
                    tipo_falta = "Não Recebido"
                
                status_html = "• <b>{}</b>: <font color='#f97316'>Ausente</font> ({})".format(s.tool.name, tipo_falta)
                total_faltas += 1
                
            grouped[cat].append(status_html)
            
    # Ordenar as categorias
    categories = sorted(grouped.keys(), key=lambda x: (1 if x == "Outros" else 0, x.lower()))
    
    content = []
    for cat in categories:
        items_html = "<br/>".join(sorted(grouped[cat]))
        content.append((f"Categoria: {cat}", items_html))
        
    # Adicionar observações do técnico se existirem
    if ins.notes:
        content.append(("Observações do Técnico", f"<i>\"{ins.notes}\"</i>"))
        
    # Adicionar contadores resumidos aos metadados
    metadata["Itens OK"] = str(total_ok)
    metadata["Itens com Avaria"] = str(total_avarias)
    metadata["Itens em Falta/Ausentes"] = str(total_faltas)
    
    sig_path = None
    if ins.signature:
        from pathlib import Path
        full_sig = Path("/var/www/checklist_veicular/static/assinaturas") / ins.signature
        if full_sig.exists():
            sig_path = str(full_sig)

    buffer = io.BytesIO()
    make_premium_pdf(buffer, f"VISTORIA DE FERRAMENTAS - {user.username.upper()}", metadata, content, signature_path=sig_path)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"vistoria_ferramentas_{user.username}.pdf"
    )



# =========================================================================
# 📂 APIS DO MÓDULO DE GESTÃO DE DOCUMENTOS TÉCNICOS (GED)
# =========================================================================

def check_document_expirations_and_alert():
    """Verifica vencimentos de documentos ativos e gera comunicados/avisos (Announcement) se necessário."""
    try:
        hoje = date.today()
        docs = TechnicalDocument.query.filter(
            TechnicalDocument.is_active == True,
            TechnicalDocument.date_expired.isnot(None)
        ).all()
        
        system_user = User.query.filter_by(username="admin").first()
        created_by_id = system_user.id if system_user else None

        for doc in docs:
            dias_restantes = (doc.date_expired - hoje).days
            title = None
            msg = None
            
            if dias_restantes < 0:
                title = f"Documento Vencido: {doc.name} - Técnico: {doc.user.username}"
                msg = f"O documento '{doc.name}' (Categoria: {doc.category.name}) do técnico '{doc.user.username}' venceu em {doc.date_expired.strftime('%d/%m/%Y')}."
            elif dias_restantes <= 15:
                title = f"Documento Próximo do Vencimento: {doc.name} - Técnico: {doc.user.username}"
                msg = f"O documento '{doc.name}' (Categoria: {doc.category.name}) do técnico '{doc.user.username}' vencerá em {dias_restantes} dias (vencimento: {doc.date_expired.strftime('%d/%m/%Y')})."
            elif dias_restantes <= 30:
                title = f"Aviso de Vencimento: {doc.name} - Técnico: {doc.user.username}"
                msg = f"O documento '{doc.name}' (Categoria: {doc.category.name}) do técnico '{doc.user.username}' vencerá em {dias_restantes} dias (vencimento: {doc.date_expired.strftime('%d/%m/%Y')})."
                
            if title and msg:
                # Evita duplicar alertas nos últimos 7 dias
                um_dia_atras = datetime.now() - timedelta(days=7)
                existente = Announcement.query.filter(
                    Announcement.title == title,
                    Announcement.created_at >= um_dia_atras
                ).first()
                
                if not existente:
                    novo_aviso = Announcement(
                        title=title,
                        content=msg,
                        target_type="internal",
                        target_role="supervisor",
                        created_by=created_by_id,
                        expires_at=datetime.now() + timedelta(days=30)
                    )
                    db.session.add(novo_aviso)
        
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        print("Erro ao verificar vencimentos de documentos:", e)


@technical_bp.route("/api/gestao/documentos/stats")
@supervisor_allowed
def api_gestao_documentos_stats():
    check_document_expirations_and_alert()
    
    total_docs = TechnicalDocument.query.count()
    total_tecnicos = User.query.filter(User.role == 'tech').count()
    
    hoje = date.today()
    docs = TechnicalDocument.query.filter_by(is_active=True).all()
    
    validos = 0
    vencidos = 0
    vencendo = 0
    
    for d in docs:
        if not d.date_expired:
            validos += 1
            continue
        dias = (d.date_expired - hoje).days
        if dias < 0:
            vencidos += 1
        elif dias <= 30:
            vencendo += 1
        else:
            validos += 1
            
    from sqlalchemy import func
    cat_counts = db.session.query(DocCategory.name, func.count(TechnicalDocument.id))\
        .join(TechnicalDocument, DocCategory.id == TechnicalDocument.category_id)\
        .group_by(DocCategory.name).all()
        
    categories_chart = {
        "labels": [c[0] for c in cat_counts],
        "values": [c[1] for c in cat_counts]
    }
    
    # Distribuição de validade para o gráfico
    validity_chart = {
        "labels": ["Válidos", "Vencidos", "Vencendo (30 dias)"],
        "values": [validos, vencidos, vencendo]
    }
    
    ultimos_enviados = []
    docs_recentes = TechnicalDocument.query.order_by(TechnicalDocument.created_at.desc()).limit(5).all()
    for d in docs_recentes:
        ultimos_enviados.append({
            "id": d.id,
            "name": d.name,
            "tecnico": d.user.username,
            "created_at": d.created_at.strftime("%d/%m/%Y %H:%M")
        })
        
    ultimos_alterados = []
    historico_recente = DocumentHistory.query.order_by(DocumentHistory.created_at.desc()).limit(5).all()
    for h in historico_recente:
        ultimos_alterados.append({
            "id": h.id,
            "document_name": h.document.name if h.document else "Excluído",
            "operator": h.operator.username,
            "action": h.action,
            "created_at": h.created_at.strftime("%d/%m/%Y %H:%M"),
            "details": h.details
        })

    return jsonify({
        "total_docs": total_docs,
        "total_tecnicos": total_tecnicos,
        "validos": validos,
        "vencidos": vencidos,
        "vencendo": vencendo,
        "categories_chart": categories_chart,
        "validity_chart": validity_chart,
        "ultimos_enviados": ultimos_enviados,
        "ultimos_alterados": ultimos_alterados
    })


@technical_bp.route("/api/gestao/documentos/list")
@supervisor_allowed
def api_gestao_documentos_list():
    tecnicos = User.query.filter(User.role == 'tech').all()
    hoje = date.today()
    
    results = []
    for t in tecnicos:
        docs = TechnicalDocument.query.filter_by(user_id=t.id, is_active=True).all()
        
        count_total = len(docs)
        count_vencidos = 0
        count_vencendo = 0
        
        last_updated = "-"
        last_dt = None
        
        for d in docs:
            if not last_dt or d.updated_at > last_dt:
                last_dt = d.updated_at
                last_updated = d.updated_at.strftime("%d/%m/%Y %H:%M")
                
            if d.date_expired:
                dias = (d.date_expired - hoje).days
                if dias < 0:
                    count_vencidos += 1
                elif dias <= 30:
                    count_vencendo += 1
                    
        if count_vencidos > 0:
            status = "vencido"
        elif count_vencendo > 0:
            status = "vencendo"
        elif count_total > 0:
            status = "em_dia"
        else:
            status = "sem_documentos"
            
        results.append({
            "id": t.id,
            "username": t.username,
            "email": t.email or "-",
            "phone": t.phone or "-",
            "role": t.role or "tech",
            "count_total": count_total,
            "count_vencidos": count_vencidos,
            "count_vencendo": count_vencendo,
            "status": status,
            "last_updated": last_updated
        })
        
    return jsonify(results)


@technical_bp.route("/api/gestao/documentos/user/<int:uid>")
@supervisor_allowed
def api_gestao_documentos_user(uid):
    user = User.query.get_or_404(uid)
    docs = TechnicalDocument.query.filter_by(user_id=uid).all()
    hoje = date.today()
    
    docs_json = []
    for d in docs:
        status = "valido"
        if d.date_expired:
            dias = (d.date_expired - hoje).days
            if dias < 0:
                status = "vencido"
            elif dias <= 15:
                status = "urgente"
            elif dias <= 30:
                status = "atencao"
                
        files_json = []
        for f in d.files:
            files_json.append({
                "id": f.id,
                "filename": f.filename,
                "file_path": url_for("static", filename=f.file_path.replace("static/", ""))
            })
            
        docs_json.append({
            "id": d.id,
            "name": d.name,
            "category_id": d.category_id,
            "category_name": d.category.name,
            "doc_type": d.doc_type or "-",
            "description": d.description or "",
            "date_issued": d.date_issued.strftime("%Y-%m-%d") if d.date_issued else "",
            "date_expired": d.date_expired.strftime("%Y-%m-%d") if d.date_expired else "",
            "issuer": d.issuer or "",
            "notes": d.notes or "",
            "is_required": d.is_required,
            "is_active": d.is_active,
            "status": status,
            "files": files_json
        })
        
    history = DocumentHistory.query.join(TechnicalDocument)\
        .filter(TechnicalDocument.user_id == uid)\
        .order_by(DocumentHistory.created_at.desc()).limit(15).all()
        
    history_json = []
    for h in history:
        history_json.append({
            "id": h.id,
            "document_name": h.document.name if h.document else "Excluído",
            "operator": h.operator.username,
            "action": h.action,
            "details": h.details,
            "created_at": h.created_at.strftime("%d/%m/%Y %H:%M")
        })
        
    return jsonify({
        "tecnico": {
            "id": user.id,
            "username": user.username,
            "email": user.email or "-",
            "phone": user.phone or "-"
        },
        "documents": docs_json,
        "history": history_json
    })


@technical_bp.route("/api/gestao/documentos", methods=["POST"])
@supervisor_allowed
def api_gestao_documentos_create():
    user_id = request.form.get("user_id")
    name = request.form.get("name")
    category_id = request.form.get("category_id")
    doc_type = request.form.get("doc_type")
    description = request.form.get("description")
    
    date_issued_str = request.form.get("date_issued")
    date_expired_str = request.form.get("date_expired")
    
    date_issued = datetime.strptime(date_issued_str, "%Y-%m-%d").date() if date_issued_str else None
    date_expired = datetime.strptime(date_expired_str, "%Y-%m-%d").date() if date_expired_str else None
    
    issuer = request.form.get("issuer")
    notes = request.form.get("notes")
    
    is_required = request.form.get("is_required") == "true"
    is_active = request.form.get("is_active") != "false"
    
    doc = TechnicalDocument(
        user_id=user_id,
        name=name,
        category_id=category_id,
        doc_type=doc_type,
        description=description,
        date_issued=date_issued,
        date_expired=date_expired,
        issuer=issuer,
        notes=notes,
        is_required=is_required,
        is_active=is_active
    )
    db.session.add(doc)
    db.session.flush()
    
    history = DocumentHistory(
        document_id=doc.id,
        operator_id=current_user.id,
        action="created",
        details=f"Documento '{name}' criado."
    )
    db.session.add(history)
    db.session.commit()
    
    uploaded_files = request.files.getlist("files[]")
    tecnico = User.query.get(user_id)
    category = DocCategory.query.get(category_id)
    
    save_document_files(doc, uploaded_files, tecnico, category)
    
    return jsonify({"success": True, "document_id": doc.id})


@technical_bp.route("/api/gestao/documentos/<int:did>", methods=["POST", "PUT"])
@supervisor_allowed
def api_gestao_documentos_edit(did):
    doc = TechnicalDocument.query.get_or_404(did)
    
    name = request.form.get("name")
    category_id = request.form.get("category_id")
    doc_type = request.form.get("doc_type")
    description = request.form.get("description")
    
    date_issued_str = request.form.get("date_issued")
    date_expired_str = request.form.get("date_expired")
    
    date_issued = datetime.strptime(date_issued_str, "%Y-%m-%d").date() if date_issued_str else None
    date_expired = datetime.strptime(date_expired_str, "%Y-%m-%d").date() if date_expired_str else None
    
    issuer = request.form.get("issuer")
    notes = request.form.get("notes")
    
    is_required = request.form.get("is_required") == "true"
    is_active = request.form.get("is_active") != "false"
    
    mudancas = []
    if doc.name != name:
        mudancas.append(f"Nome de '{doc.name}' para '{name}'")
    if doc.category_id != int(category_id):
        new_cat = DocCategory.query.get(category_id)
        mudancas.append(f"Categoria de '{doc.category.name}' para '{new_cat.name}'")
    if doc.date_expired != date_expired:
        old_exp = doc.date_expired.strftime("%d/%m/%Y") if doc.date_expired else "Nenhuma"
        new_exp = date_expired.strftime("%d/%m/%Y") if date_expired else "Nenhuma"
        mudancas.append(f"Vencimento de '{old_exp}' para '{new_exp}'")
        
    doc.name = name
    doc.category_id = category_id
    doc.doc_type = doc_type
    doc.description = description
    doc.date_issued = date_issued
    doc.date_expired = date_expired
    doc.issuer = issuer
    doc.notes = notes
    doc.is_required = is_required
    doc.is_active = is_active
    
    details_str = ", ".join(mudancas) if mudancas else "Dados gerais atualizados."
    history = DocumentHistory(
        document_id=doc.id,
        operator_id=current_user.id,
        action="edited",
        details=details_str
    )
    db.session.add(history)
    db.session.commit()
    
    uploaded_files = request.files.getlist("files[]")
    save_document_files(doc, uploaded_files, doc.user, doc.category)
    
    return jsonify({"success": True})


def save_document_files(doc, files, tecnico, category):
    if not files or len(files) == 0:
        return
        
    safe_username = secure_filename(tecnico.username)
    safe_category = secure_filename(category.name)
    
    upload_path = Path("/var/www/checklist_veicular/frontend/static/uploads/documentos") / safe_username / safe_category
    upload_path.mkdir(parents=True, exist_ok=True)
    
    for f in files:
        if f.filename == '':
            continue
            
        orig_filename = secure_filename(f.filename)
        unique_name = f"{uuid.uuid4().hex}_{orig_filename}"
        file_dest = upload_path / unique_name
        
        f.save(str(file_dest))
        
        db_path = f"static/uploads/documentos/{safe_username}/{safe_category}/{unique_name}"
        
        doc_file = DocumentFile(
            document_id=doc.id,
            filename=orig_filename,
            file_path=db_path
        )
        db.session.add(doc_file)
        
    db.session.commit()


@technical_bp.route("/api/gestao/documentos/<int:did>", methods=["DELETE"])
@supervisor_allowed
def api_gestao_documentos_delete(did):
    doc = TechnicalDocument.query.get_or_404(did)
    
    history = DocumentHistory(
        operator_id=current_user.id,
        action="deleted",
        details=f"Documento '{doc.name}' (Técnico: {doc.user.username}) excluído definitivamente."
    )
    db.session.add(history)
    
    for f in doc.files:
        try:
            full_path = Path("/var/www/checklist_veicular/frontend") / f.file_path
            if full_path.exists():
                full_path.unlink()
        except Exception as e:
            print("Erro ao excluir arquivo físico:", e)
            
    db.session.delete(doc)
    db.session.commit()
    return jsonify({"success": True})


@technical_bp.route("/api/gestao/documentos/file/<int:fid>", methods=["DELETE"])
@supervisor_allowed
def api_gestao_documentos_delete_file(fid):
    f = DocumentFile.query.get_or_404(fid)
    doc = f.document
    
    try:
        full_path = Path("/var/www/checklist_veicular/frontend") / f.file_path
        if full_path.exists():
            full_path.unlink()
    except Exception as e:
        print("Erro ao excluir arquivo físico:", e)
        
    history = DocumentHistory(
        document_id=doc.id,
        operator_id=current_user.id,
        action="edited",
        details=f"Arquivo '{f.filename}' removido do documento."
    )
    db.session.add(history)
    db.session.delete(f)
    db.session.commit()
    return jsonify({"success": True})


@technical_bp.route("/api/gestao/documentos/categories", methods=["GET", "POST"])
@supervisor_allowed
def api_gestao_documentos_categories():
    # Seed categorias iniciais caso a tabela esteja vazia
    if DocCategory.query.count() == 0:
        categorias_iniciais = [
            "CNH", "RG", "CPF", "Carteira de Trabalho", "Contrato", "ASO",
            "NR10", "NR35", "NR06", "NR12", "Treinamentos", "Certificados",
            "Ficha de EPI", "Advertências", "Vacinação", "Outros"
        ]
        for cname in categorias_iniciais:
            db.session.add(DocCategory(name=cname))
        db.session.commit()

    if request.method == "POST":
        name = request.form.get("name").strip()
        if not name:
            return jsonify({"success": False, "message": "Nome da categoria obrigatório."}), 400
            
        existente = DocCategory.query.filter_by(name=name).first()
        if existente:
            return jsonify({"success": False, "message": "Uma categoria com este nome já existe."}), 400
            
        cat = DocCategory(name=name)
        db.session.add(cat)
        db.session.commit()
        return jsonify({"success": True, "id": cat.id, "name": cat.name})
        
    categories = DocCategory.query.order_by(DocCategory.name.asc()).all()
    return jsonify([{"id": c.id, "name": c.name} for c in categories])


@technical_bp.route("/api/gestao/documentos/categories/<int:cid>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_gestao_documentos_categories_crud(cid):
    cat = DocCategory.query.get_or_404(cid)
    
    if request.method == "PUT":
        name = request.form.get("name").strip()
        if not name:
            return jsonify({"success": False, "message": "Nome inválido."}), 400
            
        existente = DocCategory.query.filter(DocCategory.name == name, DocCategory.id != cid).first()
        if existente:
            return jsonify({"success": False, "message": "Já existe outra categoria com esse nome."}), 400
            
        cat.name = name
        db.session.commit()
        return jsonify({"success": True})
        
    elif request.method == "DELETE":
        has_docs = TechnicalDocument.query.filter_by(category_id=cid).first()
        if has_docs:
            return jsonify({"success": False, "message": "Não é possível remover a categoria, pois existem documentos vinculados a ela."}), 400
            
        db.session.delete(cat)
        db.session.commit()
        return jsonify({"success": True})





