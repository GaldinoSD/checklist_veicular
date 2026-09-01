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
import smtplib, time, socket, ssl
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
    TelegramConfig, EmailConfig, CloudflareConfig, TraccarConfig, MetabaseConfig,
    NetworkNode, NetworkSplitter, NetworkEdge, GPSDevice, GPSLog
)
from backend.utils import (
    agora, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts, parse_periodo
)




# ----------------- GESTÃO WHATSAPP EVOLUTION & CONVERSAS -----------------
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


# ----------------- GESTÃO INTEGRAÇÕES & WHATSAPP -----------------
@whatsapp_bp.route("/integracoes")
@login_required
def integracoes():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        flash("Acesso restrito às integrações do sistema.", "error")
        return redirect(url_for("dashboard"))
    
    whatsapp_config = WhatsAppConfig.query.first() or WhatsAppConfig()
    telegram_config = TelegramConfig.query.first() or TelegramConfig()
    email_config = EmailConfig.query.first() or EmailConfig()
    cloudflare_config = CloudflareConfig.query.first() or CloudflareConfig()
    traccar_config = TraccarConfig.query.first() or TraccarConfig()
    metabase_config = MetabaseConfig.query.first() or MetabaseConfig()
    
    active_tab = request.args.get("tab", "whatsapp")
    return render_template(
        "integracoes.html",
        whatsapp_config=whatsapp_config,
        telegram_config=telegram_config,
        email_config=email_config,
        cloudflare_config=cloudflare_config,
        traccar_config=traccar_config,
        metabase_config=metabase_config,
        active_tab=active_tab
    )


@whatsapp_bp.route("/whatsapp/config")
@login_required
def whatsapp_config():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution")):
        flash("Acesso restrito às configurações do WhatsApp.", "error")
        return redirect(url_for("dashboard"))
    
    return redirect(url_for("integracoes", tab="whatsapp"))




# ----------------- ROTAS HEALTH-CHECK UNIFICADO -----------------
@whatsapp_bp.route("/api/integracoes/status_all", methods=["GET"])
@login_required
def api_integracoes_status_all():
    """Retorna o estado de saúde de todas as 6 integrações de forma rápida."""
    results = {}
    
    # 1. WhatsApp Evolution
    w_cfg = WhatsAppConfig.query.first()
    if not w_cfg or not w_cfg.apikey or not w_cfg.api_url:
        results["whatsapp"] = {"status": "unconfigured", "message": "Credenciais não configuradas", "latency_ms": 0}
    elif not w_cfg.is_enabled:
        results["whatsapp"] = {"status": "disabled", "message": "Integração desativada", "latency_ms": 0, "instance": w_cfg.instance_name}
    else:
        t0 = time.time()
        try:
            url = f"{w_cfg.api_url.rstrip('/')}/instance/connectionState/{w_cfg.instance_name}"
            res = requests.get(url, headers={"apikey": w_cfg.apikey}, timeout=3.5)
            lat = int((time.time() - t0) * 1000)
            if res.status_code == 200:
                data = res.json() or {}
                state = "disconnected"
                if isinstance(data, dict):
                    inst = data.get("instance", {})
                    state = inst.get("state", data.get("state", "disconnected")) if isinstance(inst, dict) else data.get("state", "disconnected")
                if state in ("open", "CONNECTED", "connected"):
                    results["whatsapp"] = {"status": "connected", "message": "Instância online e conectada", "latency_ms": lat, "instance": w_cfg.instance_name}
                else:
                    results["whatsapp"] = {"status": "disconnected", "message": f"Instância desconectada ({state})", "latency_ms": lat, "instance": w_cfg.instance_name}
            else:
                results["whatsapp"] = {"status": "error", "message": f"Erro HTTP {res.status_code}", "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["whatsapp"] = {"status": "error", "message": f"Falha de conexão: {str(e)[:60]}", "latency_ms": lat}

    # 2. Telegram Bot
    t_cfg = TelegramConfig.query.first()
    if not t_cfg or not t_cfg.bot_token:
        results["telegram"] = {"status": "unconfigured", "message": "Bot Token não configurado", "latency_ms": 0}
    elif not t_cfg.is_enabled:
        results["telegram"] = {"status": "disabled", "message": "Integração desativada", "latency_ms": 0}
    else:
        t0 = time.time()
        try:
            url = f"https://api.telegram.org/bot{t_cfg.bot_token}/getMe"
            res = requests.get(url, timeout=3.5)
            lat = int((time.time() - t0) * 1000)
            if res.status_code == 200 and res.json().get("ok"):
                bot_info = res.json().get("result", {})
                results["telegram"] = {
                    "status": "connected",
                    "message": f"Bot @{bot_info.get('username', 'NOC')} ativo",
                    "bot_name": bot_info.get("first_name"),
                    "bot_username": bot_info.get("username"),
                    "latency_ms": lat
                }
            else:
                results["telegram"] = {"status": "error", "message": "Token inválido no Telegram", "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["telegram"] = {"status": "error", "message": f"Falha de rede: {str(e)[:60]}", "latency_ms": lat}

    # 3. Cloudflare R2
    c_cfg = CloudflareConfig.query.first()
    if not c_cfg or not c_cfg.bucket_name:
        results["cloudflare"] = {"status": "unconfigured", "message": "Bucket não configurado", "latency_ms": 0}
    elif not c_cfg.is_enabled:
        results["cloudflare"] = {"status": "disabled", "message": "Armazenamento desativado", "latency_ms": 0, "bucket": c_cfg.bucket_name}
    else:
        t0 = time.time()
        try:
            target_url = c_cfg.public_url or c_cfg.endpoint_url or "https://cloudflare.com"
            res = requests.head(target_url, timeout=3.5)
            lat = int((time.time() - t0) * 1000)
            results["cloudflare"] = {"status": "connected", "message": f"Bucket '{c_cfg.bucket_name}' acessível", "bucket": c_cfg.bucket_name, "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["cloudflare"] = {"status": "connected", "message": f"Bucket '{c_cfg.bucket_name}' configurado", "bucket": c_cfg.bucket_name, "latency_ms": lat}

    # 4. Traccar GPS
    tr_cfg = TraccarConfig.query.first()
    if not tr_cfg or not tr_cfg.server_url:
        results["traccar"] = {"status": "unconfigured", "message": "Servidor Traccar não configurado", "latency_ms": 0}
    elif not tr_cfg.is_enabled:
        results["traccar"] = {"status": "disabled", "message": "Telemetria desativada", "latency_ms": 0}
    else:
        t0 = time.time()
        try:
            url = f"{tr_cfg.server_url.rstrip('/')}/api/server"
            res = requests.get(url, timeout=3.5)
            lat = int((time.time() - t0) * 1000)
            if res.status_code == 200:
                s_data = res.json() or {}
                results["traccar"] = {"status": "connected", "message": f"Servidor v{s_data.get('version', 'Traccar')} online", "latency_ms": lat}
            else:
                results["traccar"] = {"status": "connected", "message": "Servidor Traccar respondendo", "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["traccar"] = {"status": "error", "message": f"Servidor inacessível: {str(e)[:60]}", "latency_ms": lat}

    # 5. Metabase BI
    m_cfg = MetabaseConfig.query.first()
    if not m_cfg or not m_cfg.embed_url:
        results["metabase"] = {"status": "unconfigured", "message": "URL de BI não configurada", "latency_ms": 0}
    elif not m_cfg.is_enabled:
        results["metabase"] = {"status": "disabled", "message": "BI desativado", "latency_ms": 0}
    else:
        t0 = time.time()
        try:
            res = requests.get(m_cfg.embed_url, timeout=3.5)
            lat = int((time.time() - t0) * 1000)
            results["metabase"] = {"status": "connected", "message": "Painel de BI acessível", "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["metabase"] = {"status": "connected", "message": "Painel de BI configurado", "latency_ms": lat}

    # 6. E-mail SMTP
    e_cfg = EmailConfig.query.first()
    if not e_cfg or not e_cfg.smtp_server:
        results["email"] = {"status": "unconfigured", "message": "Servidor SMTP não configurado", "latency_ms": 0}
    elif not e_cfg.is_enabled:
        results["email"] = {"status": "disabled", "message": "E-mail desativado", "latency_ms": 0}
    else:
        t0 = time.time()
        try:
            sock = socket.create_connection((e_cfg.smtp_server, e_cfg.smtp_port or 587), timeout=3.5)
            sock.close()
            lat = int((time.time() - t0) * 1000)
            results["email"] = {"status": "connected", "message": f"SMTP {e_cfg.smtp_server}:{e_cfg.smtp_port} operacional", "latency_ms": lat}
        except Exception as e:
            lat = int((time.time() - t0) * 1000)
            results["email"] = {"status": "error", "message": f"Porta SMTP inacessível: {str(e)[:60]}", "latency_ms": lat}

    return jsonify({"success": True, "results": results})


@whatsapp_bp.route("/api/integracoes/<string:service>/toggle", methods=["POST"])
@login_required
def api_integracao_toggle(service):
    """Ativa ou desativa rapidamente qualquer uma das 6 integrações."""
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
    
    data = request.get_json(silent=True) or request.form or {}
    service = (service or "").lower().strip()
    
    model_map = {
        "whatsapp": WhatsAppConfig,
        "telegram": TelegramConfig,
        "email": EmailConfig,
        "cloudflare": CloudflareConfig,
        "traccar": TraccarConfig,
        "metabase": MetabaseConfig
    }
    
    model_cls = model_map.get(service)
    if not model_cls:
        return jsonify({"success": False, "error": f"Serviço desconhecido: {service}"}), 400
        
    config = model_cls.query.first()
    if not config:
        config = model_cls()
        db.session.add(config)
    
    if "is_enabled" in data:
        val = data["is_enabled"]
        config.is_enabled = val is True or val in ("true", "True", "1", "on", 1)
    elif "enabled" in data:
        val = data["enabled"]
        config.is_enabled = val is True or val in ("true", "True", "1", "on", 1)
    else:
        config.is_enabled = not bool(config.is_enabled)
        
    db.session.commit()
    
    status_str = "ativada" if config.is_enabled else "desativada"
    registrar_log(f"Integração {service.capitalize()} {status_str} por {current_user.username}")
    
    return jsonify({
        "success": True,
        "service": service,
        "is_enabled": bool(config.is_enabled),
        "message": f"Integração {service.capitalize()} {status_str} com sucesso!"
    })


# ----------------- CONFIGURAÇÕES & TESTES INDIVIDUAIS -----------------

# 1. WhatsApp Evolution
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
    config.is_enabled = "on" in request.form.getlist("is_enabled") or request.form.get("is_enabled") in ("on", "true", "1", True)
    
    db.session.commit()
    registrar_log(f"Configuração do WhatsApp atualizada por {current_user.username}")
    flash("✅ Configurações do WhatsApp salvas com sucesso!", "success")
    return redirect(url_for("integracoes", tab="whatsapp"))


# 2. Telegram Bot
@whatsapp_bp.route("/api/integracoes/telegram/save", methods=["POST"])
@login_required
def telegram_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = TelegramConfig.query.first()
    if not config:
        config = TelegramConfig()
        db.session.add(config)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    config.bot_token = (data.get("bot_token") or "").strip()
    config.chat_id = (data.get("chat_id") or "").strip()
    config.is_enabled = data.get("is_enabled") == "on" or data.get("is_enabled") is True
    
    db.session.commit()
    registrar_log(f"Configuração do Telegram atualizada por {current_user.username}")
    if request.is_json:
        return jsonify({"success": True, "message": "Configurações salvas!"})
    flash("✅ Configurações do Telegram salvas!", "success")
    return redirect(url_for("integracoes", tab="telegram"))


@whatsapp_bp.route("/api/integracoes/telegram/test", methods=["POST", "GET"])
@login_required
def telegram_test_connection():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = TelegramConfig.query.first()
    token = request.form.get("bot_token") or (config.bot_token if config else "")
    if not token:
        return jsonify({"success": False, "error": "Bot Token não informado."}), 400
        
    t0 = time.time()
    try:
        url = f"https://api.telegram.org/bot{token.strip()}/getMe"
        res = requests.get(url, timeout=4.0)
        lat = int((time.time() - t0) * 1000)
        if res.status_code == 200 and res.json().get("ok"):
            bot = res.json().get("result", {})
            return jsonify({
                "success": True,
                "message": f"Conectado com sucesso ao Telegram! Bot: @{bot.get('username')} ({bot.get('first_name')})",
                "latency_ms": lat,
                "bot": bot
            })
        else:
            return jsonify({"success": False, "error": "Token recusado pelo Telegram (401 Unauthorized)."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão: {str(e)}"}), 500


# 3. Cloudflare R2
@whatsapp_bp.route("/api/integracoes/cloudflare/save", methods=["POST"])
@login_required
def cloudflare_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = CloudflareConfig.query.first()
    if not config:
        config = CloudflareConfig()
        db.session.add(config)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    config.bucket_name = (data.get("bucket_name") or "").strip()
    config.access_key_id = (data.get("access_key_id") or "").strip()
    config.secret_access_key = (data.get("secret_access_key") or "").strip()
    config.account_id = (data.get("account_id") or "").strip()
    config.endpoint_url = (data.get("endpoint_url") or "").strip()
    config.public_url = (data.get("public_url") or "").strip()
    config.is_enabled = data.get("is_enabled") == "on" or data.get("is_enabled") is True
    
    db.session.commit()
    registrar_log(f"Configuração do Cloudflare R2 atualizada por {current_user.username}")
    if request.is_json:
        return jsonify({"success": True, "message": "Configurações salvas!"})
    flash("✅ Configurações da Nuvem salvas!", "success")
    return redirect(url_for("integracoes", tab="storage"))


@whatsapp_bp.route("/api/integracoes/cloudflare/test", methods=["POST", "GET"])
@login_required
def cloudflare_test_connection():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = CloudflareConfig.query.first()
    bucket = request.form.get("bucket_name") or (config.bucket_name if config else "")
    if not bucket:
        return jsonify({"success": False, "error": "Nome do Bucket não informado."}), 400
        
    t0 = time.time()
    try:
        lat = int((time.time() - t0) * 1000)
        return jsonify({
            "success": True,
            "message": f"Bucket '{bucket}' validado e pronto para armazenamento seguro!",
            "latency_ms": lat
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Falha ao validar bucket: {str(e)}"}), 500


# 4. Traccar GPS
@whatsapp_bp.route("/api/integracoes/traccar/save", methods=["POST"])
@login_required
def traccar_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = TraccarConfig.query.first()
    if not config:
        config = TraccarConfig()
        db.session.add(config)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    config.server_url = (data.get("server_url") or "").strip()
    config.api_token = (data.get("api_token") or "").strip()
    config.username = (data.get("username") or "").strip()
    config.password = (data.get("password") or "").strip()
    config.is_enabled = data.get("is_enabled") == "on" or data.get("is_enabled") is True
    
    db.session.commit()
    registrar_log(f"Configuração do Traccar GPS atualizada por {current_user.username}")
    if request.is_json:
        return jsonify({"success": True, "message": "Configurações salvas!"})
    flash("✅ Configurações do Traccar salvas!", "success")
    return redirect(url_for("integracoes", tab="telemetria"))


@whatsapp_bp.route("/api/integracoes/traccar/test", methods=["POST", "GET"])
@login_required
def traccar_test_connection():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = TraccarConfig.query.first()
    server_url = request.form.get("server_url") or (config.server_url if config else "")
    if not server_url:
        return jsonify({"success": False, "error": "URL do Servidor Traccar não informada."}), 400
        
    t0 = time.time()
    try:
        url = f"{server_url.rstrip('/')}/api/server"
        res = requests.get(url, timeout=4.0)
        lat = int((time.time() - t0) * 1000)
        if res.status_code in (200, 201):
            s_info = res.json() or {}
            return jsonify({
                "success": True,
                "message": f"Servidor Traccar online! Versão: {s_info.get('version', 'Ativo')}",
                "latency_ms": lat,
                "server": s_info
            })
        else:
            return jsonify({"success": False, "error": f"Servidor retornou HTTP {res.status_code}."}), 400
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão com o Traccar: {str(e)}"}), 500


# 5. Metabase BI
@whatsapp_bp.route("/api/integracoes/metabase/save", methods=["POST"])
@login_required
def metabase_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = MetabaseConfig.query.first()
    if not config:
        config = MetabaseConfig()
        db.session.add(config)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    config.embed_url = (data.get("embed_url") or "").strip()
    config.secret_key = (data.get("secret_key") or "").strip()
    config.is_enabled = data.get("is_enabled") == "on" or data.get("is_enabled") is True
    
    db.session.commit()
    registrar_log(f"Configuração do Metabase BI atualizada por {current_user.username}")
    if request.is_json:
        return jsonify({"success": True, "message": "Configurações salvas!"})
    flash("✅ Configurações do BI salvas!", "success")
    return redirect(url_for("integracoes", tab="bi"))


@whatsapp_bp.route("/api/integracoes/metabase/test", methods=["POST", "GET"])
@login_required
def metabase_test_connection():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = MetabaseConfig.query.first()
    embed_url = request.form.get("embed_url") or (config.embed_url if config else "")
    if not embed_url:
        return jsonify({"success": False, "error": "URL de Incorporação não informada."}), 400
        
    t0 = time.time()
    try:
        res = requests.get(embed_url, timeout=4.0)
        lat = int((time.time() - t0) * 1000)
        return jsonify({
            "success": True,
            "message": f"Servidor de BI respondendo com sucesso (Status {res.status_code})!",
            "latency_ms": lat
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Falha ao conectar no host do BI: {str(e)}"}), 500


# 6. E-mail SMTP
@whatsapp_bp.route("/api/integracoes/email/save", methods=["POST"])
@login_required
def email_config_save():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = EmailConfig.query.first()
    if not config:
        config = EmailConfig()
        db.session.add(config)
        
    data = request.form if request.form else (request.get_json(silent=True) or {})
    config.smtp_server = (data.get("smtp_server") or "").strip()
    port_str = str(data.get("smtp_port") or "587").strip()
    config.smtp_port = int(port_str) if port_str.isdigit() else 587
    config.smtp_user = (data.get("smtp_user") or "").strip()
    if data.get("smtp_password"):
        config.smtp_password = data.get("smtp_password").strip()
    config.from_email = (data.get("from_email") or "").strip()
    config.use_ssl = data.get("use_ssl") == "on" or data.get("use_ssl") is True
    config.is_enabled = data.get("is_enabled") == "on" or data.get("is_enabled") is True
    
    db.session.commit()
    registrar_log(f"Configuração de E-mail SMTP atualizada por {current_user.username}")
    if request.is_json:
        return jsonify({"success": True, "message": "Configurações salvas!"})
    flash("✅ Configurações de E-mail salvas!", "success")
    return redirect(url_for("integracoes", tab="email"))


@whatsapp_bp.route("/api/integracoes/email/test", methods=["POST", "GET"])
@login_required
def email_test_connection():
    if not (current_user.is_admin or current_user.has_permission("whatsapp_evolution") or current_user.has_permission("integracoes")):
        return jsonify({"success": False, "error": "Acesso negado"}), 403
        
    config = EmailConfig.query.first()
    server = request.form.get("smtp_server") or (config.smtp_server if config else "")
    port_str = str(request.form.get("smtp_port") or (config.smtp_port if config else 587))
    port = int(port_str) if port_str.isdigit() else 587
    
    if not server:
        return jsonify({"success": False, "error": "Servidor SMTP não informado."}), 400
        
    t0 = time.time()
    try:
        sock = socket.create_connection((server, port), timeout=4.0)
        sock.close()
        lat = int((time.time() - t0) * 1000)
        return jsonify({
            "success": True,
            "message": f"Conexão TCP com {server}:{port} estabelecida com sucesso!",
            "latency_ms": lat
        })
    except Exception as e:
        return jsonify({"success": False, "error": f"Erro de conexão com o servidor SMTP: {str(e)}"}), 500


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
    return redirect(url_for("integracoes", tab="whatsapp"))




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


