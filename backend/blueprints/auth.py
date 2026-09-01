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
            now = agora()
            u.last_login = now
            u.last_seen = now
            u.last_ip = client_ip
            db.session.commit()
            
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


@auth_bp.route("/seguranca-privacidade")
def seguranca_privacidade():
    return render_template("seguranca_privacidade.html")






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

    return jsonify({
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



# --- API DASHBOARD GESTÃO (DADOS REAIS E FOCO EM PLANTÕES & ESCALAS) ---
@auth_bp.route("/api/gestao/dashboard_stats")
@supervisor_allowed
def api_gestao_stats():
    now = agora()
    today_date = now.date()
    
    # Período padrão: mês corrente
    start_dt = now.replace(day=1, hour=0, minute=0, second=0)
    # Fim do mês corrente
    next_month = (start_dt.replace(day=28) + timedelta(days=4)).replace(day=1)
    end_dt = (next_month - timedelta(seconds=1))

    # Coleta filtro de período da URL se houver
    periodo = request.args.get("periodo", "").strip()
    if periodo and " - " in periodo:
        try:
            start_str, end_str = periodo.split(" - ")
            start_dt = datetime.strptime(start_str.strip(), "%Y-%m-%d")
            end_dt = datetime.strptime(end_str.strip(), "%Y-%m-%d").replace(hour=23, minute=59, second=59)
        except Exception:
            pass

    filter_start_date = start_dt.date()
    filter_end_date = end_dt.date()

    # Dicionários de consulta rápida para evitar N+1
    users_dict = {u.id: u for u in User.query.all()}
    teams_dict = {t.id: t for t in Team.query.all()}
    config = SystemConfig.query.first()

    weekday_map = {
        0: "Segunda-feira",
        1: "Terça-feira",
        2: "Quarta-feira",
        3: "Quinta-feira",
        4: "Sexta-feira",
        5: "Sábado",
        6: "Domingo"
    }

    def to_date(val):
        if not val:
            return None
        if isinstance(val, date) and not isinstance(val, datetime):
            return val
        if isinstance(val, datetime):
            return val.date()
        if isinstance(val, str):
            try:
                return datetime.strptime(val[:10], "%Y-%m-%d").date()
            except Exception:
                pass
        return None

    # Carrega Feriados Nacionais, Estaduais (RJ) e Municipais (Seropédica)
    import holidays
    years = [filter_start_date.year, filter_end_date.year, today_date.year, today_date.year + 1]
    years = sorted(list(set(years)))
    h_dict = holidays.Brazil(subdiv="RJ", years=years)
    for y in years:
        # 1. Santo Antônio (Padroeiro de Seropédica - 13 de Junho)
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

    # 1. Carregar todas as escalas manuais
    all_manual_scales = Scale.query.filter(db.or_(Scale.status != "INATIVO", Scale.status == None)).all()
    manual_dates_set = set()
    for s in all_manual_scales:
        sd = to_date(s.date)
        if sd:
            manual_dates_set.add(sd)

    # Unificação de escalas: manuais + automáticas por rodízio aos sábados + feriados oficiais
    unified_scales = []

    for s in all_manual_scales:
        s_date = to_date(s.date)
        if not s_date:
            continue
        tech_names = []
        tech_ids = []
        if s.technician_ids:
            tids = [int(x.strip()) for x in s.technician_ids.split(",") if x.strip().isdigit()]
            tech_ids = [tid for tid in tids if tid in users_dict]
            tech_names = [users_dict[tid].username for tid in tech_ids]
        elif s.user_id and s.user_id in users_dict:
            tech_ids = [s.user_id]
            tech_names = [users_dict[s.user_id].username]

        team_names = []
        if s.team_ids:
            tm_ids = [int(x.strip()) for x in s.team_ids.split(",") if x.strip().isdigit()]
            team_names = [teams_dict[tmid].name for tmid in tm_ids if tmid in teams_dict]
        elif s.team_id and s.team_id in teams_dict:
            team_names = [teams_dict[s.team_id].name]

        # Se não há técnicos específicos gravados no campo technician_ids, utiliza os membros da equipe vinculada
        if not tech_names:
            if s.team_ids:
                tm_ids = [int(x.strip()) for x in s.team_ids.split(",") if x.strip().isdigit()]
                for tmid in tm_ids:
                    if tmid in teams_dict and teams_dict[tmid].members:
                        for m in teams_dict[tmid].members:
                            tech_names.append(m.username)
                            tech_ids.append(m.id)
            elif s.team_id and s.team_id in teams_dict and teams_dict[s.team_id].members:
                for m in teams_dict[s.team_id].members:
                    tech_names.append(m.username)
                    tech_ids.append(m.id)

        scale_type_raw = (s.type or "Plantão").strip()
        type_lower = scale_type_raw.lower()
        obs_lower = (s.obs or "").lower()

        # Identificação robusta de tipo (incluindo feriados de calendário)
        is_holiday = (s_date in h_dict) or ("fer" in type_lower) or ("fer" in obs_lower)
        if is_holiday:
            canonical_type = "Feriado"
            h_name = h_dict.get(s_date)
            if h_name and ("plant" in type_lower or "escala" in type_lower or "geral" in type_lower or "fer" in type_lower or not scale_type_raw):
                scale_type_raw = f"Feriado: {h_name}"
        elif "dom" in type_lower or s_date.weekday() == 6:
            canonical_type = "Domingo"
        elif "sab" in type_lower or s_date.weekday() == 5:
            canonical_type = "Sábado"
        else:
            canonical_type = scale_type_raw.capitalize()

        unified_scales.append({
            "id": s.id,
            "date": s_date,
            "type": canonical_type,
            "raw_type": scale_type_raw,
            "team_name": ", ".join(team_names) if team_names else "Geral",
            "techs": tech_names,
            "tech_ids": tech_ids,
            "obs": s.obs or (f"Feriado: {h_dict[s_date]}" if s_date in h_dict else ""),
            "is_automatic": False
        })

    # Janela de cálculo para projeções e feriados (passado recente até futuro próximo)
    calc_start = min(filter_start_date, today_date - timedelta(days=90))
    calc_end = max(filter_end_date, today_date + timedelta(days=150))

    # Inclusão de Feriados Oficiais que não possuem escala manual cadastrada ainda
    for h_date, h_name in h_dict.items():
        if calc_start <= h_date <= calc_end and h_date not in manual_dates_set:
            unified_scales.append({
                "id": None,
                "date": h_date,
                "type": "Feriado",
                "raw_type": f"Feriado: {h_name}",
                "team_name": "Plantão de Feriado",
                "techs": [],
                "tech_ids": [],
                "obs": f"Feriado Oficial: {h_name}",
                "is_automatic": True
            })

    # Gerar sábados automáticos caso não haja escala manual para a data
    config_scale_start = to_date(config.scale_start_date) if (config and config.scale_start_date) else None
    if config and config_scale_start and config.scale_rotation_order:
        rotation_order = [int(x) for x in config.scale_rotation_order.split(",") if x.strip().isdigit()]
        if rotation_order:
            curr = calc_start
            while curr <= calc_end:
                if curr.weekday() == 5 and curr >= config_scale_start and curr not in manual_dates_set and curr not in h_dict:
                    weeks = (curr - config_scale_start).days // 7
                    team_idx = weeks % len(rotation_order)
                    team_id = rotation_order[team_idx]
                    team = teams_dict.get(team_id)
                    team_name = team.name if team else "Equipe Rodízio"
                    team_techs = [m.username for m in team.members] if (team and team.members) else []
                    team_tech_ids = [m.id for m in team.members] if (team and team.members) else []

                    unified_scales.append({
                        "id": None,
                        "date": curr,
                        "type": "Sábado",
                        "raw_type": f"Plantão: {team_name}",
                        "team_name": team_name,
                        "techs": team_techs,
                        "tech_ids": team_tech_ids,
                        "obs": "Escala automática por rodízio de equipes",
                        "is_automatic": True
                    })
                curr += timedelta(days=1)

    # Ordenar escalas cronologicamente
    unified_scales.sort(key=lambda x: x["date"])

    # 2. Filtragem de Métricas no Período Selecionado
    period_scales = [s for s in unified_scales if filter_start_date <= s["date"] <= filter_end_date]

    sabados_count = sum(1 for s in period_scales if s["type"] == "Sábado")
    domingos_count = sum(1 for s in period_scales if s["type"] == "Domingo")
    feriados_count = sum(1 for s in period_scales if s["type"] == "Feriado")
    outros_count = sum(1 for s in period_scales if s["type"] not in ["Sábado", "Domingo", "Feriado"])
    total_plantoes = len(period_scales)

    unique_techs_period = set()
    tech_plantao_counts = defaultdict(lambda: {"total": 0, "sabados": 0, "domingos": 0, "feriados": 0, "name": ""})
    team_plantao_counts = defaultdict(int)

    for s in period_scales:
        if s["team_name"]:
            team_plantao_counts[s["team_name"]] += 1
        for tid in s["tech_ids"]:
            unique_techs_period.add(tid)
            u = users_dict.get(tid)
            tname = u.username if u else f"Técnico #{tid}"
            tech_plantao_counts[tid]["name"] = tname
            tech_plantao_counts[tid]["total"] += 1
            if s["type"] == "Sábado":
                tech_plantao_counts[tid]["sabados"] += 1
            elif s["type"] == "Domingo":
                tech_plantao_counts[tid]["domingos"] += 1
            elif s["type"] == "Feriado":
                tech_plantao_counts[tid]["feriados"] += 1

    # Ranking de técnicos por plantão
    ranking_tecnicos = []
    for tid, info in sorted(tech_plantao_counts.items(), key=lambda x: x[1]["total"], reverse=True):
        perc = int((info["total"] / total_plantoes * 100)) if total_plantoes > 0 else 0
        ranking_tecnicos.append({
            "id": tid,
            "name": info["name"],
            "total": info["total"],
            "sabados": info["sabados"],
            "domingos": info["domingos"],
            "feriados": info["feriados"],
            "perc": perc
        })

    # 3. Dois Próximos Plantões Programados (Hero Cards)
    future_scales = [s for s in unified_scales if s["date"] >= today_date]
    dois_proximos_plantoes = []
    for idx, s in enumerate(future_scales[:2]):
        diff_days = (s["date"] - today_date).days
        if diff_days == 0:
            rel_label = "Hoje"
        elif diff_days == 1:
            rel_label = "Amanhã"
        elif diff_days < 7 and s["date"].weekday() == 5:
            rel_label = "Neste Sábado"
        elif diff_days < 7 and s["date"].weekday() == 6:
            rel_label = "Neste Domingo"
        else:
            rel_label = f"Em {diff_days} dias"

        dois_proximos_plantoes.append({
            "order": idx + 1,
            "is_today": (diff_days == 0),
            "date": str(s["date"]),
            "date_formatted": s["date"].strftime("%d/%m/%Y"),
            "weekday": weekday_map.get(s["date"].weekday(), ""),
            "days_diff": diff_days,
            "relative_label": rel_label,
            "type": s["type"],
            "raw_type": s["raw_type"],
            "team_name": s["team_name"],
            "techs": s["techs"],
            "obs": s["obs"],
            "is_automatic": s["is_automatic"]
        })

    proximo_plantao_data = dois_proximos_plantoes[0] if dois_proximos_plantoes else None

    # 4. Lista dos Próximos Plantões Programados (até 8 futuros)
    proximos_list = []
    for s in future_scales[:8]:
        d_diff = (s["date"] - today_date).days
        if d_diff == 0:
            d_label = "Hoje"
        elif d_diff == 1:
            d_label = "Amanhã"
        else:
            d_label = f"Em {d_diff}d"

        proximos_list.append({
            "date": str(s["date"]),
            "date_formatted": s["date"].strftime("%d/%m/%Y"),
            "weekday": weekday_map.get(s["date"].weekday(), ""),
            "type": s["type"],
            "team_name": s["team_name"],
            "techs": s["techs"],
            "obs": s["obs"],
            "is_automatic": s["is_automatic"],
            "relative_label": d_label
        })

    # 5. Timeline / Evolução Mensal dos Plantões (Últimos 5 meses + Próximos 2 meses)
    month_labels = []
    timeline_sabados = []
    timeline_domingos = []
    timeline_feriados = []

    base_month = now.replace(day=1)
    month_names_pt = ["Jan", "Fev", "Mar", "Abr", "Mai", "Jun", "Jul", "Ago", "Set", "Out", "Nov", "Dez"]

    for offset in range(-4, 3):
        # Deslocamento em meses
        m_year = base_month.year + (base_month.month - 1 + offset) // 12
        m_month = (base_month.month - 1 + offset) % 12 + 1
        m_start = date(m_year, m_month, 1)
        next_m = (m_start.replace(day=28) + timedelta(days=4)).replace(day=1)
        m_end = next_m - timedelta(days=1)

        m_scales = [s for s in unified_scales if m_start <= s["date"] <= m_end]
        m_label = f"{month_names_pt[m_month - 1]}/{str(m_year)[2:]}"

        month_labels.append(m_label)
        timeline_sabados.append(sum(1 for s in m_scales if s["type"] == "Sábado"))
        timeline_domingos.append(sum(1 for s in m_scales if s["type"] == "Domingo"))
        timeline_feriados.append(sum(1 for s in m_scales if s["type"] == "Feriado"))

    # 6. Informações de Prontidão Operacional & Equipes
    next_30_days = today_date + timedelta(days=30)
    proximos_30d_scales = [s for s in unified_scales if today_date <= s["date"] <= next_30_days]
    total_30d = len(proximos_30d_scales)
    cobertos_30d = sum(1 for s in proximos_30d_scales if s["techs"] or (s["is_automatic"] and s["team_name"] != "Plantão de Feriado"))
    taxa_cobertura_pct = int((cobertos_30d / total_30d * 100)) if total_30d > 0 else 100

    # Alertas de feriados nos próximos 60 dias
    next_60_days = today_date + timedelta(days=60)
    feriados_alertas = []
    for s in unified_scales:
        if s["type"] == "Feriado" and today_date <= s["date"] <= next_60_days:
            diff_d = (s["date"] - today_date).days
            tem_escala = bool(s["techs"] and len(s["techs"]) > 0)
            feriados_alertas.append({
                "date_formatted": s["date"].strftime("%d/%m"),
                "weekday": weekday_map.get(s["date"].weekday(), ""),
                "name": s["raw_type"].replace("Feriado:", "").strip() if "Feriado:" in s["raw_type"] else (s["obs"] or "Feriado"),
                "days_diff": diff_d,
                "relative_label": "Hoje" if diff_d == 0 else ("Amanhã" if diff_d == 1 else f"Em {diff_d} dias"),
                "tem_escala": tem_escala,
                "techs": s["techs"]
            })

    # Equipes técnicas ativas
    equipes_status = []
    for team in Team.query.all():
        equipes_status.append({
            "id": team.id,
            "name": team.name,
            "color": team.color or "#f59e0b",
            "members_count": len(team.members) if team.members else 0,
            "leader": team.leader.username if team.leader else "Sem líder"
        })

    prontidao_info = {
        "taxa_cobertura_pct": taxa_cobertura_pct,
        "total_30d": total_30d,
        "cobertos_30d": cobertos_30d,
        "feriados_alertas": feriados_alertas[:4],
        "equipes_status": equipes_status
    }

    # Escalas por Equipe (Cobertura)
    equipes_cobertura = []
    for tname, cnt in sorted(team_plantao_counts.items(), key=lambda x: x[1], reverse=True):
        equipes_cobertura.append({"team": tname, "count": cnt})

    # 7. Dados adicionais do ecossistema técnico (Auditorias, LMS, RFO, Geradores, etc.)
    total_assigns = TrainingAssignment.query.count()
    approved_assigns = TrainingAssignment.query.filter_by(status="aprovado").count()
    lms_completion = int((approved_assigns / total_assigns * 100)) if total_assigns > 0 else 0

    audits = Checklist.query.join(User, db.func.lower(Checklist.technician) == db.func.lower(User.username)).filter(
        User.role == "supervisor",
        Checklist.date >= start_dt,
        Checklist.date <= end_dt
    ).count()

    supervisoes = SupervisaoTecnica.query.filter(
        SupervisaoTecnica.date >= filter_start_date,
        SupervisaoTecnica.date <= filter_end_date
    ).count()

    rotas = RotaExata.query.filter(
        RotaExata.date >= filter_start_date,
        RotaExata.date <= filter_end_date
    ).count()

    vistorias = Vistoria.query.filter(
        Vistoria.created_at >= start_dt,
        Vistoria.created_at <= end_dt
    ).count()

    total_audits = audits + supervisoes + rotas + vistorias

    rfo_active = RFO.query.filter_by(status="ABERTO").count()
    tasks_pending = Task.query.filter(Task.status != "CONCLUÍDO").count()

    total_fleet = Checklist.query.filter(Checklist.date >= start_dt, Checklist.date <= end_dt).count()
    ok_fleet = Checklist.query.filter(Checklist.date >= start_dt, Checklist.date <= end_dt, Checklist.status == "OK").count()
    real_fleet_health = int((ok_fleet / total_fleet * 100)) if total_fleet > 0 else 100

    recent_encerramentos = []
    enc_objs = Encerramento.query.order_by(Encerramento.date.desc()).limit(5).all()
    for enc in enc_objs:
        recent_encerramentos.append({
            "date": enc.date.strftime("%d/%m/%Y") if enc.date else "N/A",
            "patio": enc.patio.name if enc.patio else "Geral",
            "closing_time": enc.closing_time or "N/A"
        })

    return jsonify({
        "plantao_kpis": {
            "total_plantoes": total_plantoes,
            "sabados_count": sabados_count,
            "domingos_count": domingos_count,
            "feriados_count": feriados_count,
            "outros_count": outros_count,
            "total_tecnicos_escalados": len(unique_techs_period),
            "periodo_label": f"{filter_start_date.strftime('%d/%m/%Y')} até {filter_end_date.strftime('%d/%m/%Y')}"
        },
        "proximo_plantao": proximo_plantao_data,
        "dois_proximos_plantoes": dois_proximos_plantoes,
        "proximos_plantoes": proximos_list,
        "prontidao_info": prontidao_info,
        "ranking_tecnicos_plantoes": ranking_tecnicos,
        "equipes_cobertura": equipes_cobertura,
        "timeline_plantoes": {
            "labels": month_labels,
            "sabados": timeline_sabados,
            "domingos": timeline_domingos,
            "feriados": timeline_feriados
        },
        "distribuicao_tipos": {
            "Sábado": sabados_count,
            "Domingo": domingos_count,
            "Feriado": feriados_count,
            "Outros": outros_count
        },
        # Legados e complementares
        "lms_completion": lms_completion,
        "total_audits_month": total_audits,
        "fleet_health": real_fleet_health,
        "rfo_active": rfo_active,
        "tasks_pending": tasks_pending,
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
        "perm_whatsapp_evolution", "perm_whatsapp_conversas", "perm_integracoes", "perm_gestao_mapas", "perm_gestao_powerbi", "perm_avisos_historico"
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
    full_name = request.form.get("full_name", "").strip()
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

    u = User(
        username=username,
        full_name=full_name,
        role=role,
        email=email,
        phone=phone,
        telegram_chat_id=telegram_chat_id,
        permissions=json.dumps(perms)
    )
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    registrar_log(f"Usuário criado: {username} ({role}) - Nome: {full_name or 'N/A'}")
    flash("Usuário cadastrado com permissões padrão.", "success")
    return redirect(url_for("users"))




@auth_bp.route("/usuarios/<int:uid>/papel", methods=["POST"])
@admin_required
def users_role(uid):
    u = User.query.get_or_404(uid)
    full_name = request.form.get("full_name", "").strip()
    role = request.form.get("role", u.role).strip().lower()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()
    telegram_chat_id = request.form.get("telegram_chat_id", "").strip()
    pwd = request.form.get("password", "").strip()

    # Atualiza o nome completo do colaborador se informado no formulário
    if "full_name" in request.form:
        u.full_name = full_name

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

    registrar_log(f"Perfil atualizado: {u.username} -> {role} (Nome: {u.full_name or 'N/A'})")
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
        "perm_whatsapp_evolution", "perm_whatsapp_conversas", "perm_integracoes",
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


# ----------------- MONITORAMENTO DE USUÁRIOS ONLINE & ÚLTIMO ACESSO (ADMIN ONLY) -----------------
@auth_bp.route("/api/admin/online-users", methods=["GET"])
@login_required
def api_admin_online_users():
    """Retorna lista de usuários com status online e último acesso para administradores com recuperação histórica."""
    if not current_user.is_admin:
        return jsonify({"success": False, "error": "Acesso restrito a administradores."}), 403

    from sqlalchemy import func

    now = agora()
    today_date = now.date()

    # O usuário logado está ativo agora
    current_user.last_seen = now
    current_user.last_ip = request.remote_addr
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()

    users = User.query.all()

    # Pré-carregar os máximos históricos para otimizar desempenho
    hist_logs = dict(db.session.query(func.upper(Log.usuario), func.max(Log.data_hora)).group_by(func.upper(Log.usuario)).all())
    hist_checklists = dict(db.session.query(func.upper(Checklist.technician), func.max(Checklist.date)).group_by(func.upper(Checklist.technician)).all())
    hist_movs = dict(db.session.query(func.upper(VehicleMov.responsavel), func.max(VehicleMov.data_hora)).group_by(func.upper(VehicleMov.responsavel)).all())
    hist_vistorias = dict(db.session.query(Vistoria.created_by, func.max(Vistoria.created_at)).filter(Vistoria.created_by.isnot(None)).group_by(Vistoria.created_by).all())

    data = []
    online_count = 0
    today_count = 0
    need_commit = False

    def fix_tz(dt):
        if not dt:
            return None
        # Se a data está adiantada em ~3h em relação ao horário atual de Brasília, subtrai 3 horas
        diff_s = (dt - now).total_seconds()
        if 3600 <= diff_s <= 5 * 3600:
            return dt - timedelta(hours=3)
        if dt > now:
            return now
        return dt

    for u in users:
        uname_upper = u.username.upper() if u.username else ""
        candidate_dates = []

        if u.last_seen:
            norm_ls = fix_tz(u.last_seen)
            candidate_dates.append(norm_ls)
            if norm_ls != u.last_seen:
                u.last_seen = norm_ls
                need_commit = True

        if u.last_login:
            norm_ll = fix_tz(u.last_login)
            candidate_dates.append(norm_ll)
            if norm_ll != u.last_login:
                u.last_login = norm_ll
                need_commit = True

        # Fallback para registros históricos
        if uname_upper in hist_logs and hist_logs[uname_upper]:
            candidate_dates.append(fix_tz(hist_logs[uname_upper]))
        if uname_upper in hist_checklists and hist_checklists[uname_upper]:
            candidate_dates.append(fix_tz(hist_checklists[uname_upper]))
        if uname_upper in hist_movs and hist_movs[uname_upper]:
            candidate_dates.append(fix_tz(hist_movs[uname_upper]))
        if u.id in hist_vistorias and hist_vistorias[u.id]:
            candidate_dates.append(fix_tz(hist_vistorias[u.id]))

        best_date = max(candidate_dates) if candidate_dates else None
        if best_date and best_date > now:
            best_date = now

        # Se encontrou histórico mais recente que u.last_seen, atualiza
        if best_date and (not u.last_seen or best_date > u.last_seen):
            u.last_seen = best_date
            if not u.last_login:
                u.last_login = best_date
            need_commit = True

        is_online = False
        last_seen_str = "Nunca acessou"
        last_seen_rel = "Nunca acessou"
        last_login_str = "Nunca acessou"

        if best_date:
            diff = (now - best_date).total_seconds()
            
            # Considera online se a atividade for nos últimos 5 minutos (0 a 300 segundos)
            if 0 <= diff <= 300:
                is_online = True
                online_count += 1

            if best_date.date() == today_date:
                today_count += 1

            last_seen_str = best_date.strftime("%d/%m/%Y às %H:%M:%S")

            if diff < 60:
                last_seen_rel = "Agora mesmo"
            elif diff < 3600:
                mins = int(diff // 60)
                last_seen_rel = f"Há {mins} min"
            elif diff < 86400 and best_date.date() == today_date:
                last_seen_rel = f"Hoje às {best_date.strftime('%H:%M')}"
            elif best_date.date() == (today_date - timedelta(days=1)):
                last_seen_rel = f"Ontem às {best_date.strftime('%H:%M')}"
            else:
                last_seen_rel = best_date.strftime("%d/%m/%Y às %H:%M")

        if u.last_login:
            norm_login = fix_tz(u.last_login)
            last_login_str = norm_login.strftime("%d/%m/%Y às %H:%M")

        data.append({
            "id": u.id,
            "username": u.username,
            "role": u.role or "Usuário",
            "is_online": is_online,
            "last_seen": last_seen_str,
            "last_seen_relative": last_seen_rel,
            "last_seen_raw": best_date.isoformat() if best_date else "",
            "last_login": last_login_str,
            "last_ip": u.last_ip or "-",
            "is_current": (u.id == current_user.id)
        })

    if need_commit:
        try:
            db.session.commit()
        except Exception:
            db.session.rollback()

    # Ordenação inteligente: Online primeiro, depois por data mais recente de acesso, e por fim os que nunca acessaram
    data.sort(key=lambda item: (
        not item["is_online"],
        not item["is_current"],
        -(datetime.fromisoformat(item["last_seen_raw"]).timestamp()) if item["last_seen_raw"] else float('inf'),
        item["username"]
    ))

    return jsonify({
        "success": True,
        "online_count": online_count,
        "total_count": len(users),
        "today_count": today_count,
        "users": data
    })


@auth_bp.route("/api/user/heartbeat", methods=["GET", "POST"])
@login_required
def api_user_heartbeat():
    """Mantém a presença online do usuário ativo na aba aberta."""
    now = agora()
    try:
        current_user.last_seen = now
        current_user.last_ip = request.remote_addr
        db.session.commit()
        return jsonify({"success": True, "timestamp": now.isoformat()})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "error": str(e)}), 500
