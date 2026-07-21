# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
auth_bp = GlobalBlueprint("auth", __name__)

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
    agora, haversine_distance, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts, get_remaining_attempts
)




# ----------------- LOGIN -----------------
@auth_bp.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        client_ip = request.remote_addr or "unknown"
        
        # 🛡️ Rate Limiting — proteção contra brute-force
        _cleanup_old_attempts()
        allowed, wait_seconds = _check_rate_limit(client_ip)
        if not allowed:
            minutes = wait_seconds // 60
            seconds = wait_seconds % 60
            if minutes > 0:
                flash(f"Muitas tentativas de login. Aguarde {minutes}min {seconds}s.", "login_error")
            else:
                flash(f"Muitas tentativas de login. Aguarde {seconds} segundos.", "login_error")
            registrar_log(f"Rate limit atingido para IP: {client_ip}")
            return render_template("login.html")
        
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        u = User.query.filter_by(username=username.upper()).first()
        if u and u.check_password(password):
            _clear_attempts(client_ip)  # Login OK → limpa histórico
            login_user(u)
            registrar_log(f"Login efetuado: {u.username}")

            # Redirecionamento por papel
            if u.is_admin or u.is_supervisor:
                return redirect(url_for("dashboard"))
            if u.is_manutencao:
                return redirect(url_for("manutencao_os"))
            return redirect(url_for("checklist_mobile"))

        # Login falhou → registra tentativa
        _record_attempt(client_ip)
        remaining_attempts = get_remaining_attempts(client_ip)
        if remaining_attempts <= 2 and remaining_attempts > 0:
            flash(f"Usuário ou senha inválidos. Restam {remaining_attempts} tentativa(s).", "login_error")
        else:
            flash("Usuário ou senha inválidos.", "login_error")
        registrar_log(f"Tentativa de login falhada para '{username}' de IP: {client_ip}")

    return render_template("login.html")




@auth_bp.route("/logout")
@login_required
def logout():
    registrar_log(f"Logout efetuado: {current_user.username}")
    logout_user()
    return redirect(url_for("login"))




@auth_bp.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin or current_user.is_supervisor:
            return redirect(url_for("dashboard"))
        if current_user.is_manutencao:
            return redirect(url_for("manutencao_os"))
        return redirect(url_for("checklist_mobile"))
    return redirect(url_for("login"))




# ----------------- DASHBOARD -----------------
@auth_bp.route("/dashboard")
@supervisor_allowed
def dashboard():
    view = request.args.get("view", "veiculos")
    periodo = request.args.get("periodo", "")
    
    # Lista de veículos para filtros
    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()

    # --- Lógica comum de Checklists Recentes ---
    recentes = Checklist.query.order_by(Checklist.date.desc()).limit(5).all()

    # --- Lógica de Estatísticas de Usuários (necessário para view='veiculos') ---
    user_stats_list = []
    if view == "veiculos":
        now = agora()
        start_week = (now - timedelta(days=now.weekday())).replace(hour=0, minute=0, second=0, microsecond=0)
        start_month = now.replace(day=1, hour=0, minute=0, second=0, microsecond=0)
        start_year = now.replace(month=1, day=1, hour=0, minute=0, second=0, microsecond=0)

        # Trata período selecionado se houver
        periodo_custom = False
        start_dt = None
        end_dt = None
        if periodo and " - " in periodo:
            try:
                start_str, end_str = periodo.split(" - ")
                start_dt = datetime.strptime(start_str.strip(), "%Y-%m-%d")
                end_dt = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
                periodo_custom = True
            except Exception:
                pass

        # Coleta todos os usuários cadastrados (exceto admin) e técnicos presentes nos checklists
        user_map = {}  # lower_name -> display_name
        all_users = User.query.filter(User.username != 'admin').all()
        for u in all_users:
            uname = (u.username or "").strip()
            if uname and uname.lower() != "admin":
                user_map[uname.lower()] = uname

        # Também inclui técnicos registrados na tabela de checklists que não estejam na lista de usuários
        tech_in_checklists = db.session.query(db.func.lower(Checklist.technician)).filter(Checklist.technician != None).group_by(db.func.lower(Checklist.technician)).all()
        for (t_name,) in tech_in_checklists:
            if t_name and t_name.strip() and t_name.strip().lower() != "admin":
                t_clean = t_name.strip()
                if t_clean.lower() not in user_map:
                    user_map[t_clean.lower()] = t_clean.upper()

        for lower_name, display_name in user_map.items():
            if periodo_custom and start_dt and end_dt:
                total = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name).count()
                semanal = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name, Checklist.date >= start_dt, Checklist.date <= end_dt).count()
                mensal = 0
                anual = 0
            else:
                total = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name).count()
                semanal = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name, Checklist.date >= start_week).count()
                mensal = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name, Checklist.date >= start_month).count()
                anual = Checklist.query.filter(db.func.lower(Checklist.technician) == lower_name, Checklist.date >= start_year).count()

            if total > 0 or semanal > 0 or mensal > 0 or anual > 0:
                user_stats_list.append({
                    'username': display_name,
                    'semanal': semanal,
                    'mensal': mensal,
                    'anual': anual,
                    'total': total
                })

        if periodo_custom:
            user_stats_list.sort(key=lambda x: x['semanal'], reverse=True)
        else:
            user_stats_list.sort(key=lambda x: x['total'], reverse=True)

    return render_template(
        "dashboard.html",
        view=view,
        veiculos=veiculos,
        recentes=recentes,
        user_stats_list=user_stats_list,
        periodo=periodo
    )



# --- API DASHBOARD FROTA (DADOS REAIS) ---
@auth_bp.route("/api/frota/dashboard_stats")
@supervisor_allowed
def api_frota_stats():
    now = agora()
    start_7d = now - timedelta(days=7)
    start_month = now.replace(day=1, hour=0, minute=0, second=0)
    start_30d = now - timedelta(days=30)

    # Coleta filtro de período personalizado da URL se houver (Formato: AAAA-MM-DD - AAAA-MM-DD)
    periodo = request.args.get("periodo", "").strip()
    if periodo and " - " in periodo:
        try:
            start_str, end_str = periodo.split(" - ")
            start_dt = datetime.strptime(start_str.strip(), "%Y-%m-%d")
            end_dt = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            start_7d = start_dt
            start_month = start_dt
            start_30d = start_dt
            now = end_dt
        except Exception:
            pass

    # 1. Saúde da Frota (Percentual OK nos checklists do período)
    total_7d = Checklist.query.filter(Checklist.date >= start_7d, Checklist.date <= now).count()
    ok_7d = Checklist.query.filter(Checklist.date >= start_7d, Checklist.date <= now, Checklist.status == "OK").count()
    fleet_health = int((ok_7d / total_7d * 100)) if total_7d > 0 else 100

    # 2. Custo de Manutenção (Período - Apenas OS Finalizadas)
    total_cost = db.session.query(db.func.sum(AvariaOS.valor_gasto)).filter(
        AvariaOS.status == "finalizada",
        AvariaOS.data_fechamento >= start_month, 
        AvariaOS.data_fechamento <= now
    ).scalar() or 0

    # 3. Checklists do Período e O.S Abertas
    if periodo and " - " in periodo:
        checklists_today = Checklist.query.filter(Checklist.date >= start_7d, Checklist.date <= now).count()
    else:
        start_today = now.replace(hour=0, minute=0, second=0, microsecond=0)
        checklists_today = Checklist.query.filter(Checklist.date >= start_today, Checklist.date <= now).count()
        
    open_os = AvariaOS.query.filter_by(status="aberta").count()

    # 4. Histórico de KM Rodados Reais Diários (Movimentação manual + Telemetria GPS + Odometer checklists)
    km_labels = []
    km_values = []
    
    delta_days = (now - start_7d).days
    max_days = min(delta_days, 15) if delta_days > 0 else 7
    
    for i in range(max_days, -1, -1):
        day = (now - timedelta(days=i)).date()
        
        # 4.1 Movimentações Manuais
        from sqlalchemy.orm import aliased
        SaidaAlias = aliased(VehicleMov)
        km_mov = db.session.query(
            db.func.sum(VehicleMov.km - SaidaAlias.km)
        ).join(
            SaidaAlias, VehicleMov.saida_id == SaidaAlias.id
        ).filter(
            VehicleMov.tipo == "entrada",
            db.func.date(VehicleMov.data_hora) == day
        ).scalar() or 0
        
        # 4.2 Telemetria GPS (se houver logs no dia)
        gps_distance = 0.0
        vehicle_ids = [r[0] for r in db.session.query(GPSLog.vehicle_id).filter(
            db.func.date(GPSLog.timestamp) == day,
            GPSLog.vehicle_id != None
        ).distinct().all()]
        
        for v_id in vehicle_ids:
            logs = GPSLog.query.filter(
                GPSLog.vehicle_id == v_id,
                db.func.date(GPSLog.timestamp) == day,
                GPSLog.lat != None,
                GPSLog.lon != None
            ).order_by(GPSLog.timestamp.asc()).all()
            
            if len(logs) > 1:
                v_dist = 0.0
                for j in range(len(logs) - 1):
                    v_dist += haversine_distance(logs[j].lat, logs[j].lon, logs[j+1].lat, logs[j+1].lon)
                gps_distance += v_dist
        
        km_gps = gps_distance / 1000.0
        
        # 4.3 Odômetro do checklist (para veículos sem telemetria GPS neste dia)
        km_checklist = 0
        veiculos_com_gps = set(vehicle_ids)
        
        day_checklists = Checklist.query.filter(
            db.func.date(Checklist.date) == day
        ).all()
        
        from collections import defaultdict
        checklists_by_vehicle = defaultdict(list)
        for c in day_checklists:
            if c.vehicle_id and c.vehicle_id not in veiculos_com_gps:
                checklists_by_vehicle[c.vehicle_id].append(c)
                
        for v_id, c_list in checklists_by_vehicle.items():
            c_list.sort(key=lambda x: x.date, reverse=True)
            latest_today_km = c_list[0].km or 0
            
            last_before = Checklist.query.filter(
                Checklist.vehicle_id == v_id,
                db.func.date(Checklist.date) < day
            ).order_by(Checklist.date.desc()).first()
            
            if last_before:
                diff = latest_today_km - (last_before.km or 0)
                if diff > 0:
                    km_checklist += diff
        
        km_day = km_mov + km_gps + km_checklist
        
        km_labels.append(day.strftime("%d/%m"))
        km_values.append(int(km_day))

    # 5. Distribuição de Status do Período
    status_dist = {}
    for st in ["OK", "Atenção", "Crítico"]:
        count = Checklist.query.filter(
            Checklist.date >= start_30d, 
            Checklist.date <= now, 
            Checklist.status == st
        ).count()
        status_dist[st] = count

    # 6. Alertas de Revisão (Top 3 críticos baseados no odômetro atual)
    rev_alerts = []
    veiculos = Vehicle.query.all()
    for v in veiculos:
        if v.km:
            rem = REV_INTERVAL - (v.km % REV_INTERVAL)
            if rem <= REV_ALERT_MARGIN:
                perc = int(((REV_INTERVAL - rem) / REV_INTERVAL) * 100)
                rev_alerts.append({"plate": v.plate, "remaining": rem, "perc": perc})
    rev_alerts.sort(key=lambda x: x["remaining"])

    # 7. O.S Recentes
    latest_os = []
    recent_os_objs = AvariaOS.query.order_by(AvariaOS.data_abertura.desc()).limit(5).all()
    for o in recent_os_objs:
        latest_os.append({
            "plate": o.vehicle.plate if o.vehicle else "N/A",
            "desc": o.descricao[:30] + "..." if len(o.descricao) > 30 else o.descricao,
            "gravity": o.gravidade or "Média"
        })

    # 8. Estatísticas adicionais da Frota (Melhoria requisitada)
    total_vehicles = Vehicle.query.count()
    active_vehicles = Vehicle.query.filter_by(status="ATIVO").count()
    maintenance_vehicles = Vehicle.query.filter_by(status="MANUTENCAO").count()
    inactive_vehicles = Vehicle.query.filter(Vehicle.status.in_(["INATIVO", "DESATIVADO"])).count()

    type_carro = Vehicle.query.filter_by(type="carro").count()
    type_moto = Vehicle.query.filter_by(type="moto").count()
    type_caminhao = Vehicle.query.filter_by(type="caminhao").count()
    type_van = Vehicle.query.filter_by(type="van").count()

    return json.dumps({
        "fleet_health": fleet_health,
        "total_cost_month": float(total_cost),
        "checklists_today": checklists_today,
        "open_os": open_os,
        "km_history": {"labels": km_labels, "values": km_values},
        "status_dist": status_dist,
        "rev_alerts": rev_alerts[:3],
        "latest_os": latest_os,
        "total_vehicles": total_vehicles,
        "active_vehicles": active_vehicles,
        "maintenance_vehicles": maintenance_vehicles,
        "inactive_vehicles": inactive_vehicles,
        "types_dist": {
            "carro": type_carro,
            "moto": type_moto,
            "caminhao": type_caminhao,
            "van": type_van
        }
    })



# --- API DASHBOARD GESTÃO (DADOS REAIS) ---
@auth_bp.route("/api/gestao/dashboard_stats")
@supervisor_allowed
def api_gestao_stats():
    now = agora()
    start_month = now.replace(day=1, hour=0, minute=0, second=0)

    # Coleta filtro de período da URL se houver
    periodo = request.args.get("periodo", "").strip()
    if periodo and " - " in periodo:
        try:
            start_str, end_str = periodo.split(" - ")
            start_dt = datetime.strptime(start_str.strip(), "%Y-%m-%d")
            end_dt = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
            start_month = start_dt
            now = end_dt
        except Exception:
            pass

    # 1. LMS Completion (Porcentagem de atribuições concluídas com aprovação no LMS)
    total_assigns = TrainingAssignment.query.count()
    approved_assigns = TrainingAssignment.query.filter_by(status="aprovado").count()
    lms_completion = int((approved_assigns / total_assigns * 100)) if total_assigns > 0 else 0

    # 2. Auditorias consolidadas (Checklists de supervisor + Supervisão em Campo + Rota Exata + Vistorias no período)
    audits = Checklist.query.join(User, db.func.lower(Checklist.technician) == db.func.lower(User.username)).filter(
        User.role == "supervisor",
        Checklist.date >= start_month,
        Checklist.date <= now
    ).count()

    supervisoes = SupervisaoTecnica.query.filter(
        SupervisaoTecnica.date >= start_month.date(),
        SupervisaoTecnica.date <= now.date()
    ).count()

    rotas = RotaExata.query.filter(
        RotaExata.date >= start_month.date(),
        RotaExata.date <= now.date()
    ).count()

    vistorias = Vistoria.query.filter(
        Vistoria.created_at >= start_month,
        Vistoria.created_at <= now
    ).count()

    total_audits = audits + supervisoes + rotas + vistorias

    # 3. RFO e Tarefas
    rfo_active = RFO.query.filter_by(status="ABERTO").count()
    tasks_pending = Task.query.filter(Task.status != "CONCLUÍDO").count()

    # 4. Atividades consolidado (Volume de Checklists + Vistorias + RFOs no período)
    act_labels = []
    act_values = []
    
    delta_days = (now - start_month).days
    max_days = min(delta_days, 15) if delta_days > 0 else 7
    
    for i in range(max_days, -1, -1):
        day = (now - timedelta(days=i)).date()
        checklists_count = Checklist.query.filter(db.func.date(Checklist.date) == day).count()
        vistorias_count = Vistoria.query.filter(db.func.date(Vistoria.created_at) == day).count()
        rfos_count = RFO.query.filter(RFO.date == day).count()
        
        total_day_act = checklists_count + vistorias_count + rfos_count
        
        act_labels.append(day.strftime("%d/%m"))
        act_values.append(total_day_act)

    # 5. RFO por Tipo / Categoria
    rfo_types = db.session.query(RFO.problem_type, db.func.count(RFO.id)).group_by(RFO.problem_type).all()
    rfo_dist = {t[0] if t[0] else "Outros": t[1] for t in rfo_types}

    # 6. Ranking real de Técnicos (Baseado no somatório dos scores de treinamentos LMS aprovados)
    top_users = db.session.query(
        User.username,
        db.func.sum(TrainingAssignment.best_score).label('total_score')
    ).join(
        TrainingAssignment, User.id == TrainingAssignment.user_id
    ).filter(
        TrainingAssignment.status == "aprovado"
    ).group_by(
        User.id
    ).order_by(
        db.text('total_score DESC')
    ).limit(5).all()
    
    ranking = []
    for u in top_users:
        ranking.append({
            "name": u[0],
            "points": int(u[1]) if u[1] else 0
        })

    # 7. Alertas de Geradores (Nível de combustível <= 30%)
    generator_alerts = []
    low_fuel_generators = Generator.query.all()
    for g in low_fuel_generators:
        if g.capacity_total and g.capacity_total > 0 and g.current_qty is not None:
            perc = int((g.current_qty / g.capacity_total * 100))
            if perc <= 30:
                generator_alerts.append({
                    "name": g.name,
                    "perc": perc
                })

    # 8. Tarefas Críticas Pendentes (Prioridade Alta)
    critical_tasks = []
    crit_task_objs = Task.query.filter(
        Task.status != "CONCLUÍDO",
        Task.priority == "ALTA"
    ).order_by(Task.deadline.asc()).limit(5).all()
    
    for t in crit_task_objs:
        critical_tasks.append({
            "title": t.title,
            "responsible": t.responsible.username if t.responsible else "Não atribuído",
            "priority": t.priority
        })

    # 9. Saúde Real da Frota no período
    total_fleet = Checklist.query.filter(Checklist.date >= start_month, Checklist.date <= now).count()
    ok_fleet = Checklist.query.filter(Checklist.date >= start_month, Checklist.date <= now, Checklist.status == "OK").count()
    real_fleet_health = int((ok_fleet / total_fleet * 100)) if total_fleet > 0 else 100

    # 10. Escalas de Plantão Ativo Hoje
    today_date = now.date()
    escalas_hoje = []
    escalas_objs = Scale.query.filter(Scale.date == today_date, Scale.status == "ATIVO").all()
    
    # Adiciona a escala automática de sábado se for o caso e não houver manual cadastrada
    if not escalas_objs and today_date.weekday() == 5:
        config = SystemConfig.query.first()
        if config and config.scale_start_date and config.scale_rotation_order:
            if today_date >= config.scale_start_date:
                rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
                if rotation_order:
                    weeks = (today_date - config.scale_start_date).days // 7
                    team_idx = weeks % len(rotation_order)
                    team_id = rotation_order[team_idx]
                    
                    team = Team.query.get(team_id)
                    if team:
                        tech_names = [member.username for member in team.members if member.role == "tech"]
                        escalas_hoje.append({
                            "type": f"Plantão: {team.name}",
                            "obs": "Escala automática por rodízio de equipes",
                            "techs": tech_names
                        })

    for esc in escalas_objs:
        tech_names = []
        if esc.technician_ids:
            ids = [int(i.strip()) for i in esc.technician_ids.split(",") if i.strip().isdigit()]
            users = User.query.filter(User.id.in_(ids)).all()
            tech_names = [u.username for u in users]
        
        escalas_hoje.append({
            "type": esc.type or "Plantão",
            "obs": esc.obs or "Sem observações",
            "techs": tech_names
        })

    # 11. Últimos Encerramentos Diários
    recent_encerramentos = []
    enc_objs = Encerramento.query.order_by(Encerramento.date.desc()).limit(5).all()
    for enc in enc_objs:
        recent_encerramentos.append({
            "date": enc.date.strftime("%d/%m/%Y") if enc.date else "N/A",
            "patio": enc.patio.name if enc.patio else "Geral",
            "closing_time": enc.closing_time or "N/A"
        })

    return json.dumps({
        "lms_completion": lms_completion,
        "total_audits_month": total_audits,
        "fleet_health": real_fleet_health,
        "rfo_active": rfo_active,
        "tasks_pending": tasks_pending,
        "atividades_history": {"labels": act_labels, "values": act_values},
        "rfo_by_type": rfo_dist,
        "ranking": ranking,
        "generator_alerts": generator_alerts,
        "critical_tasks": critical_tasks,
        "escalas_hoje": escalas_hoje,
        "recent_encerramentos": recent_encerramentos
    })



# ----------------- USUÁRIOS (admin) -----------------
# ----------------- USUÁRIOS (admin) -----------------
@auth_bp.route("/usuarios")
@admin_required
def users():
    users_list = User.query.order_by(User.id.asc()).all()
    return render_template("users.html", items=users_list)




@auth_bp.route("/usuarios/<int:uid>/senha", methods=["POST"])
@admin_required
def users_pwd(uid):
    u = User.query.get_or_404(uid)
    pwd = request.form.get("password", "").strip()

    # 🔐 Verificação especial apenas para o admin principal
    if u.username == "admin":
        master = request.form.get("master_key", "").strip()

        if not master:
            flash("Para alterar a senha do ADMIN é necessário informar a senha mestre.", "error")
            return redirect(url_for("users"))

        if master != MASTER_PASSWORD:
            flash("Senha mestre incorreta. Operação não autorizada.", "error")
            return redirect(url_for("users"))

    # Validação da nova senha
    if not pwd:
        flash("Senha inválida. Preencha uma nova senha.", "error")
        return redirect(url_for("users"))

    # Atualização da senha
    u.set_password(pwd)
    db.session.commit()

    registrar_log(f"Senha atualizada: {u.username}")
    flash("Senha atualizada com sucesso!", "success")
    return redirect(url_for("users"))


def get_default_perms(role):
    possible_perms = [
        "perm_dashboard", "perm_logs", "perm_relatorios", "perm_avisos",
        "perm_usuarios", "perm_veiculos", "perm_controle_veiculos",
        "perm_checklist_mobile", "perm_treinamentos_mobile", "perm_vistorias_nova",
        "perm_avarias", "perm_checklists_view", "perm_config_checklist", "perm_config_layout",
        "perm_manutencao_os", "perm_vistorias_list",
        "perm_frota", "perm_monitoramento_aparelhos", "perm_monitoramento_historico", "perm_monitoramento_config",
        "perm_gestao_equipes", "perm_gestao_calendario", "perm_gestao_escalas",
        "perm_gestao_reunioes", "perm_gestao_anotacoes", "perm_gestao_atividades",
        "perm_gestao_encerramento", "perm_gestao_rfo", "perm_gestao_tarefas",
        "perm_gestao_geradores", "perm_gestao_rota_exata", "perm_gestao_supervisao",
        "perm_gestao_treinamentos", "perm_gestao_solicitacoes", "perm_gestao_relatorios",
        "perm_whatsapp_evolution", "perm_whatsapp_conversas", "perm_gestao_mapas", "perm_gestao_powerbi", "perm_avisos_historico"
    ]
    perms = {}
    if role == "tech":
        perms = {"perm_checklist_mobile": True, "perm_treinamentos_mobile": True}
    elif role == "manutencao":
        perms = {"perm_manutencao_os": True}
    elif role == "supervisor":
        perms = {p: True for p in possible_perms if p != "perm_usuarios"}
    elif role == "admin":
        perms = {p: True for p in possible_perms}
    
    # Preenche o restante com False explicitamente para consistência
    for p in possible_perms:
        if p not in perms:
            perms[p] = False
            
    return perms


def sanitize_and_validate_phone(phone: str):
    if not phone:
        return ""
    sanitized = "".join(filter(str.isdigit, phone))
    if sanitized.startswith("55") and len(sanitized) > 10:
        sanitized = sanitized[2:]
    if len(sanitized) not in (10, 11):
        raise ValueError("Número de telefone inválido. Deve conter o DDD (2 dígitos) mais o número (ex: 21999998888).")
    return sanitized


@auth_bp.route("/usuarios/novo", methods=["POST"])
@admin_required
def users_new():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "tech").strip().lower()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    telegram_chat_id = request.form.get("telegram_chat_id", "").strip()

    if not username or not password:
        flash("Usuário e senha obrigatórios.", "error")
        return redirect(url_for("users"))

    if User.query.filter_by(username=username.upper()).first():
        flash("Usuário já existe.", "error")
        return redirect(url_for("users"))

    if phone:
        try:
            phone = sanitize_and_validate_phone(phone)
        except ValueError as err:
            flash(str(err), "error")
            return redirect(url_for("users"))

    perms = get_default_perms(role)

    u = User(username=username, role=role, email=email, phone=phone, telegram_chat_id=telegram_chat_id, permissions=json.dumps(perms))
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    registrar_log(f"Usuário criado: {username} ({role})")
    flash("Usuário cadastrado com permissões padrão.", "success")
    return redirect(url_for("users"))




@auth_bp.route("/usuarios/<int:uid>/papel", methods=["POST"])
@admin_required
def users_role(uid):
    u = User.query.get_or_404(uid)
    role = request.form.get("role", u.role).strip().lower()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
    pwd = request.form.get("password", "").strip()

    # --- Atualização de senha (se fornecida) ---
    if pwd:
        # Para o admin, exige senha mestre
        if u.username == "admin":
            master = request.form.get("master_key", "").strip()
            if not master:
                flash("Para alterar a senha do ADMIN é necessário informar a senha mestre.", "error")
                return redirect(url_for("users"))
            if master != MASTER_PASSWORD:
                flash("Senha mestre incorreta. Operação não autorizada.", "error")
                return redirect(url_for("users"))

        u.set_password(pwd)
        registrar_log(f"Senha atualizada: {u.username}")

    # --- Atualização de dados (apenas para não-admin) ---
    if u.username != "admin":
        if role not in {"admin", "supervisor", "tech", "manutencao"}:
            flash("Papel inválido.", "error")
            return redirect(url_for("users"))

        if phone:
            try:
                phone = sanitize_and_validate_phone(phone)
            except ValueError as err:
                flash(str(err), "error")
                return redirect(url_for("users"))

        u.role = role
        u.email = email
        u.phone = phone
        u.telegram_chat_id = telegram_chat_id

        # Ao mudar o papel, resetamos para as permissões padrão daquele papel
        perms = get_default_perms(role)
        u.permissions = json.dumps(perms)

    db.session.commit()

    if pwd and u.username != "admin":
        flash(f"Dados e senha atualizados com sucesso!", "success")
    elif pwd:
        flash("Senha atualizada com sucesso!", "success")
    else:
        flash(f"Dados atualizados para {role}.", "success")

    registrar_log(f"Perfil atualizado: {u.username} -> {role}")
    return redirect(url_for("users"))




@auth_bp.route("/usuarios/<int:uid>/permissions", methods=["POST"])
@admin_required
def users_permissions(uid):
    u = User.query.get_or_404(uid)
    
    # Mapeamento completo de todas as permissões presentes no template (users.html)
    possible_perms = [
        "perm_dashboard", "perm_logs", "perm_relatorios", "perm_avisos",
        "perm_usuarios", "perm_veiculos", "perm_controle_veiculos",
        "perm_checklist_mobile", "perm_treinamentos_mobile", "perm_vistorias_nova",
        "perm_avarias", "perm_checklists_view", "perm_config_checklist", "perm_config_layout",
        "perm_manutencao_os", "perm_vistorias_list",
        "perm_frota", "perm_monitoramento_aparelhos", "perm_monitoramento_historico", "perm_monitoramento_config",
        "perm_gestao_equipes", "perm_gestao_calendario", "perm_gestao_escalas",
        "perm_gestao_reunioes", "perm_gestao_anotacoes", "perm_gestao_atividades",
        "perm_gestao_encerramento", "perm_gestao_rfo", "perm_gestao_tarefas",
        "perm_gestao_geradores", "perm_gestao_rota_exata", "perm_gestao_supervisao",
        "perm_gestao_treinamentos", "perm_gestao_solicitacoes", "perm_gestao_relatorios",
        "perm_whatsapp_evolution", "perm_whatsapp_conversas",
        "perm_config_ferramentas", "perm_controle_ferramentas", "perm_controle_ferramentas_atual", "perm_gestao_mapas", "perm_gestao_powerbi", "perm_avisos_historico"
    ]
    
    perms_data = request.form.to_dict()
    processed = {}
    
    for p in possible_perms:
        if perms_data.get(p) == "on":
            processed[p] = True
        else:
            processed[p] = False
            
    u.permissions = json.dumps(processed)
    db.session.commit()
    
    registrar_log(f"Permissões granulares salvas: {u.username}")
    flash("Permissões granulares salvas com sucesso.", "success")
    return redirect(url_for("users"))




@auth_bp.route("/usuarios/<int:uid>/excluir", methods=["POST"])
@admin_required
def users_del(uid):
    if current_user.id == uid:
        flash("Você não pode excluir seu próprio usuário.", "error")
        return redirect(url_for("users"))

    u = User.query.get_or_404(uid)
    nome = u.username

    db.session.delete(u)
    db.session.commit()

    registrar_log(f"Usuário excluído: {nome}")
    flash("Usuário excluído.", "success")
    return redirect(url_for("users"))





# ----------------- LOGS DO SISTEMA (ADMIN) -----------------
@auth_bp.route("/logs")
@admin_required
def logs():
    periodo = request.args.get("periodo", "").strip()
    busca = request.args.get("busca", "").strip().lower()
    limit = int(request.args.get("limit", 10))  # quantidade inicial

    query = Log.query

    # -----------------------
    # FILTRO POR PERÍODO
    # -----------------------
    if periodo:
        try:
            ini, fim = periodo.split(" - ")
            ini_dt = datetime.strptime(ini, "%Y-%m-%d")
            fim_dt = datetime.strptime(fim, "%Y-%m-%d") + timedelta(days=1)

            # FILTRO SEM TZINFO (já usamos agora() no salvamento)
            query = query.filter(Log.data_hora >= ini_dt,
                                 Log.data_hora < fim_dt)
        except Exception:
            flash("Formato de período inválido.", "error")

    # -----------------------
    # FILTRO POR TEXTO
    # -----------------------
    if busca:
        query = query.filter(
            Log.usuario.ilike(f"%{busca}%") |
            Log.acao.ilike(f"%{busca}%")
        )

    # TOTAL REAL PARA PAGINAÇÃO
    total_logs = query.count()

    # -----------------------
    # APLICA O LIMIT (carregar mais)
    # -----------------------
    registros = query.order_by(Log.data_hora.desc()).limit(limit).all()

    return render_template(
        "logs.html",
        registros=registros,
        limit=limit,
        total_logs=total_logs
    )
