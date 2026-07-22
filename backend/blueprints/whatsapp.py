# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
whatsapp_bp = GlobalBlueprint("whatsapp", __name__)

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
    AvariaOS, Log, Vistoria, VistoriaFoto, SystemConfig, WhatsAppConfig, WhatsAppLog,
    NetworkNode, NetworkSplitter, NetworkEdge, GPSDevice, GPSLog
)
from backend.utils import (
    agora, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts, parse_periodo
)




# ----------------- GESTÃO WHATSAPP EVOLUTION -----------------
@whatsapp_bp.route("/whatsapp")
@login_required
def whatsapp_conversas():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_conversas")):
        flash("Acesso restrito ao chat do WhatsApp.", "error")
        return redirect(url_for("dashboard"))
    
    config = WhatsAppConfig.query.first()
    from flask import make_response
    response = make_response(render_template("whatsapp_conversas.html", whatsapp_config=config))
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate, public, max-age=0"
    response.headers["Pragma"] = "no-cache"
    response.headers["Expires"] = "0"
    return response




@whatsapp_bp.route("/whatsapp/config")
@login_required
def whatsapp_config():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        flash("Acesso restrito às configurações do WhatsApp.", "error")
        return redirect(url_for("dashboard"))
    
    config = WhatsAppConfig.query.first()
    return render_template("whatsapp_config.html", whatsapp_config=config)




@whatsapp_bp.route("/api/whatsapp/config", methods=["POST"])
@login_required
def whatsapp_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
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
    registrar_log(f"Configuração do Whatsapp atualizada por {current_user.username}")
    flash("✅ Configurações salvas com sucesso!", "success")
    return redirect(url_for("whatsapp_config"))




@whatsapp_bp.route("/api/whatsapp/templates", methods=["POST"])
@login_required
def whatsapp_templates_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = WhatsAppConfig.query.first()
    if not config:
        config = WhatsAppConfig()
        db.session.add(config)
        
    config.msg_checklist_fail = request.form.get("msg_checklist_fail", "").strip()
    config.msg_os_opened = request.form.get("msg_os_opened", "").strip()
    config.msg_os_closed = request.form.get("msg_os_closed", "").strip()
    config.msg_new_vistoria = request.form.get("msg_new_vistoria", "").strip()
    
    # Novos templates das automações / comunicados
    config.msg_scale_alert = request.form.get("msg_scale_alert", "").strip()
    config.msg_late_checklist = request.form.get("msg_late_checklist", "").strip()
    config.msg_training_alert = request.form.get("msg_training_alert", "").strip()
    config.msg_os_overdue = request.form.get("msg_os_overdue", "").strip()
    config.msg_inactive_tech = request.form.get("msg_inactive_tech", "").strip()
    
    db.session.commit()
    registrar_log(f"Templates do Whatsapp atualizados por {current_user.username}")
    flash("✅ Templates salvos com sucesso!", "success")
    return redirect(url_for("whatsapp_config"))




@whatsapp_bp.route("/api/whatsapp/chat/send", methods=["POST"])
@login_required
def whatsapp_chat_send():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_conversas")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    number = request.form.get("number", "").strip()
    message = request.form.get("message", "").strip()
    file = request.files.get("file")
    
    if not number:
        return jsonify({"success": False, "error": "Número de telefone é obrigatório"}), 400
        
    if not message and not file:
        return jsonify({"success": False, "error": "Mensagem ou arquivo é obrigatório"}), 400
        
    # Sanitiza o número
    if "@" in number:
        sanitized_number = number
    else:
        sanitized_number = "".join(filter(str.isdigit, number))
        if len(sanitized_number) <= 11 and not sanitized_number.startswith("55"):
            sanitized_number = "55" + sanitized_number
        
    config = WhatsAppConfig.query.first()
    if not config or not config.apikey:
        return jsonify({"success": False, "error": "Evolution API não está configurada"}), 400
        
    import requests
    
    if file:
        url = f"{config.api_url.rstrip('/')}/message/sendMedia/{config.instance_name}"
        headers = {
            "apikey": config.apikey
        }
        # Ler conteúdo do arquivo
        file_data = file.read()
        files = {
            "file": (file.filename, file_data, file.content_type)
        }
        data = {
            "number": sanitized_number,
            "caption": message
        }
        try:
            res = requests.post(url, data=data, files=files, headers=headers, timeout=30)
            if res.status_code in (200, 201):
                return jsonify({"success": True, "data": res.json()})
            else:
                return jsonify({"success": False, "error": f"Erro Evolution API: Status {res.status_code}", "details": res.text}), 400
        except Exception as err:
            return jsonify({"success": False, "error": f"Erro de conexão com a API: {str(err)}"}), 500
    else:
        headers = {
            "Content-Type": "application/json",
            "apikey": config.apikey
        }
        payload = {
            "number": sanitized_number,
            "text": message
        }
        url = f"{config.api_url.rstrip('/')}/message/sendText/{config.instance_name}"
        
        try:
            res = requests.post(url, json=payload, headers=headers, timeout=10)
            if res.status_code in (200, 201):
                return jsonify({"success": True, "data": res.json()})
            else:
                return jsonify({"success": False, "error": f"Erro Evolution API: Status {res.status_code}", "details": res.text}), 400
        except Exception as err:
            return jsonify({"success": False, "error": f"Erro de conexão com a API: {str(err)}"}), 500




@whatsapp_bp.route("/api/whatsapp/status", methods=["GET"])
@login_required
def whatsapp_connection_status():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = WhatsAppConfig.query.first()
    if not config or not config.apikey or not config.api_url:
        return jsonify({"status": "disconnected", "error": "Configurações incompletas"})
        
    import requests
    headers = {
        "apikey": config.apikey
    }
    url = f"{config.api_url.rstrip('/')}/instance/connectionState/{config.instance_name}"
    
    try:
        res = requests.get(url, headers=headers, timeout=8)
        if res.status_code == 200:
            data = res.json()
            state = "disconnected"
            if isinstance(data, dict):
                inst = data.get("instance", {})
                if isinstance(inst, dict):
                    state = inst.get("state", "disconnected")
                else:
                    state = data.get("state", "disconnected")
            
            if state in ("open", "CONNECTED", "connected"):
                return jsonify({"status": "connected", "details": data})
            else:
                return jsonify({"status": "disconnected", "state": state, "details": data})
        else:
            return jsonify({"status": "disconnected", "error": f"Status {res.status_code}"})
    except Exception as err:
        return jsonify({"status": "disconnected", "error": str(err)})




@whatsapp_bp.route("/api/whatsapp/chats", methods=["GET"])
@login_required
def whatsapp_api_chats():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_conversas")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = WhatsAppConfig.query.first()
    if not config or not config.apikey or not config.api_url:
        return jsonify({"success": False, "error": "WhatsApp não configurado"}), 400
        
    import requests
    headers = {
        "apikey": config.apikey,
        "Content-Type": "application/json"
    }
    url = f"{config.api_url.rstrip('/')}/chat/findChats/{config.instance_name}"
    
    try:
        res = requests.post(url, json={}, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            chats_list = data
            if isinstance(data, dict):
                chats_list = data.get("chats") or data.get("records") or data.get("data") or []
            return jsonify({"success": True, "chats": chats_list})
        else:
            return jsonify({"success": False, "error": f"Erro Evolution API: status {res.status_code}", "details": res.text}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão: {str(e)}"}), 500




@whatsapp_bp.route("/api/whatsapp/messages", methods=["GET"])
@login_required
def whatsapp_api_messages():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_conversas")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    number = request.args.get("number", "").strip()
    if not number:
        return jsonify({"success": False, "error": "Número de telefone é obrigatório"}), 400
        
    config = WhatsAppConfig.query.first()
    if not config or not config.apikey or not config.api_url:
        return jsonify({"success": False, "error": "WhatsApp não configurado"}), 400
        
    if "@" in number:
        remote_jid = number
    else:
        sanitized_number = "".join(filter(str.isdigit, number))
        if not sanitized_number:
            return jsonify({"success": False, "error": "Número inválido"}), 400
            
        if len(sanitized_number) <= 11 and not sanitized_number.startswith("55"):
            sanitized_number = "55" + sanitized_number
            
        remote_jid = f"{sanitized_number}@s.whatsapp.net"
    
    import requests
    headers = {
        "apikey": config.apikey,
        "Content-Type": "application/json"
    }
    url = f"{config.api_url.rstrip('/')}/chat/findMessages/{config.instance_name}"
    
    payload = {
        "where": {
            "key": {
                "remoteJid": remote_jid
            }
        },
        "limit": 100
    }
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=10)
        if res.status_code == 200:
            data = res.json()
            messages_list = data
            if isinstance(data, dict):
                if "messages" in data:
                    inner = data["messages"]
                    if isinstance(inner, dict):
                        messages_list = inner.get("records") or inner.get("data") or []
                    elif isinstance(inner, list):
                        messages_list = inner
                elif "records" in data:
                    messages_list = data["records"]
                elif "data" in data:
                    messages_list = data["data"]
            return jsonify({"success": True, "messages": messages_list})
        else:
            return jsonify({"success": False, "error": f"Erro Evolution API: status {res.status_code}", "details": res.text}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão: {str(e)}"}), 500


@whatsapp_bp.route("/api/whatsapp/media/base64", methods=["POST"])
@login_required
def whatsapp_api_media_base64():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_conversas")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    data = request.get_json(force=True, silent=True) or {}
    message_key = data.get("key") or {}
    message_id = data.get("id") or message_key.get("id")
    
    if not message_key and not message_id:
        return jsonify({"success": False, "error": "Chave ou ID da mensagem é obrigatório"}), 400
        
    config = WhatsAppConfig.query.first()
    if not config or not config.apikey or not config.api_url:
        return jsonify({"success": False, "error": "WhatsApp não configurado"}), 400
        
    import requests
    headers = {
        "apikey": config.apikey,
        "Content-Type": "application/json"
    }
    url = f"{config.api_url.rstrip('/')}/chat/getBase64FromMediaMessage/{config.instance_name}"
    
    payload = {
        "message": {
            "key": message_key if message_key else {"id": message_id}
        },
        "convertToMp4": False
    }
    
    try:
        res = requests.post(url, json=payload, headers=headers, timeout=15)
        if res.status_code in (200, 201):
            res_data = res.json()
            base64_data = res_data.get("base64")
            mimetype = res_data.get("mimetype") or "image/jpeg"
            
            if base64_data:
                if not base64_data.startswith("data:"):
                    base64_data = f"data:{mimetype};base64,{base64_data}"
                return jsonify({"success": True, "base64": base64_data, "mimetype": mimetype})
            else:
                return jsonify({"success": False, "error": "Mídia não retornada pela API"}), 400
        else:
            return jsonify({"success": False, "error": f"Erro Evolution API: status {res.status_code}"}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro ao obter mídia: {str(e)}"}), 500



# ===========================
# VISTORIAS (SUPERVISOR) - ROTAS CORRIGIDAS
# - salva OBS por item (obs_<item>)
# - salva FOTO por item (foto_<item>)  -> grava filename no model
# - status_geral automático (ok/avarias)
# ===========================

def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXT


@whatsapp_bp.route("/api/whatsapp/logs", methods=["GET"])
@login_required
def whatsapp_logs():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        return jsonify({"error": "Acesso negado"}), 403
        
    logs = WhatsAppLog.query.order_by(WhatsAppLog.sent_at.desc()).limit(100).all()
    res = []
    for l in logs:
        res.append({
            "id": l.id,
            "phone": l.phone,
            "message": l.message,
            "status_code": l.status_code,
            "status_text": l.status_text,
            "sent_at": l.sent_at.strftime("%d/%m/%Y %H:%M:%S")
        })
    return jsonify(res)


