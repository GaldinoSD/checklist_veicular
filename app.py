# -*- coding: utf-8 -*-
"""
Painel de Gerenciamento de Frota – app.py
Versão com papéis: admin / supervisor / tech / manutencao

Inclui:
- SystemConfig (modo do checklist)
- Funções: desativado / somente início / início e chegada
- Rotas de avarias e manutenção
"""

import os, json, uuid
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict


# ===============================
# 🔥 CONFIGURAÇÃO DE TIMEZONE
# ===============================
import pytz
TZ = pytz.timezone("America/Sao_Paulo")

def agora():
    """Retorna horário real do Brasil sem tzinfo (compatível com SQLite e Postgres)."""
    return datetime.now(TZ).replace(tzinfo=None)

# ===============================
# IMPORTS DO FLASK E EXTENSÕES
# ===============================
from flask import (
    Flask, render_template, request, redirect, url_for,
    flash, send_from_directory, abort, jsonify
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from sqlalchemy import text  # para migrações leves no PostgreSQL
from sqlalchemy.orm import joinedload

# ===============================
# PDF
# ===============================
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    Table, TableStyle, SimpleDocTemplate,
    Paragraph, Spacer, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet

# ===============================
# IMAGENS (UPLOAD)
# ===============================
from PIL import Image

# ===============================
# 📁 CAMINHOS DO PROJETO (BASE)
# ===============================
BASE_DIR = Path(__file__).resolve().parent  # pasta onde está o app.py

# ===============================
# 📷 UPLOADS (VISTORIAS / AVARIAS)
# ===============================
ALLOWED_EXT = {".jpg", ".jpeg", ".png", ".webp"}

VISTORIAS_UPLOAD_DIR = BASE_DIR / "static" / "vistorias_fotos"
AVARIAS_UPLOAD_DIR   = BASE_DIR / "static" / "avarias_fotos"   # se você usar também

# Cria as pastas automaticamente ao iniciar o app (não dá erro se já existir)
VISTORIAS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
AVARIAS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

def allowed_file(filename: str) -> bool:
    if not filename:
        return False
    ext = os.path.splitext(filename.lower())[1]
    return ext in ALLOWED_EXT


# ================================
# 🔐 SENHA MESTRE DO ADMIN PRINCIPAL
# ================================
MASTER_PASSWORD = "26828021jJ*"


# ----------------- CONFIG BÁSICA -----------------
BASE_DIR = Path(__file__).resolve().parent
INBOX_DIR = BASE_DIR / "inbox"
RELATORIOS_DIR = BASE_DIR / "relatorios"
UPLOAD_DIR = BASE_DIR / "static" / "checklist_fotos"
LOGO_PATH = BASE_DIR / "static" / "logo.png"

REV_INTERVAL = 10000
REV_ALERT_MARGIN = 500
WEEKS_WINDOW = 4

ALLOWED_EXT = {".png", ".jpg", ".jpeg", ".webp"}

app = Flask(__name__)
app.config["SECRET_KEY"] = "altere-esta-chave"
app.config["SQLALCHEMY_DATABASE_URI"] = "postgresql://jonatas:26828021jJ@localhost/checklist"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB uploads

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"

# ========================
# FILTRO DE DATA/HORA BR
# (converte UTC -> America/Sao_Paulo)
# ========================
import pytz
from datetime import datetime

TZ = pytz.timezone("America/Sao_Paulo")

def agora():
    return datetime.now(TZ).replace(tzinfo=None)

@app.template_filter("br_datetime")
def br_datetime(dt):
    if not dt:
        return "-"

    try:
        # Se vier timezone-aware, converte pro BR
        if dt.tzinfo is not None:
            return dt.astimezone(TZ).strftime("%d/%m/%Y %H:%M")

        # ✅ Se vier naive: AUTO-DETECÇÃO
        # Compara com o horário BR atual. Se estiver "adiantado" ~3h, era UTC.
        diff_h = (dt - agora()).total_seconds() / 3600.0

        # Se a diferença estiver próxima de +3h (entre +2 e +4), tratamos como UTC
        if 2 <= diff_h <= 4:
            dt_aware = pytz.utc.localize(dt).astimezone(TZ)
            return dt_aware.strftime("%d/%m/%Y %H:%M")

        # Caso contrário, assume que já é BR
        return dt.strftime("%d/%m/%Y %H:%M")

    except Exception:
        try:
            return dt.strftime("%d/%m/%Y %H:%M")
        except Exception:
            return str(dt)

import re
from markupsafe import Markup

@app.template_filter('urlize_custom')
def urlize_custom_filter(s):
    if not s:
        return ""
    # Regex para detectar URLs (http, https, www)
    url_pattern = re.compile(
        r'((https?://|www\.)[^\s<>"]+)',
        re.IGNORECASE
    )
    
    def replace(match):
        url = match.group(0)
        href = url
        if not href.startswith('http'):
            href = 'http://' + href
        return f'<a href="{href}" target="_blank" class="text-blue-500 hover:underline">{url}</a>'
        
    return Markup(url_pattern.sub(replace, s))


# ----------------- MODELOS -----------------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin_legacy = db.Column("is_admin", db.Boolean, default=False)
    role = db.Column(db.String(20), default=None)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    permissions = db.Column(db.Text) # JSON string

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

    @property
    def is_admin(self):
        if self.role == "admin":
            return True
        return bool(self.is_admin_legacy)

    def has_permission(self, perm):
        if self.is_admin:
            return True
        if not self.permissions:
            return False
        try:
            p = json.loads(self.permissions)
            return p.get(perm, False)
        except:
            return False

    @property
    def is_supervisor(self):
        return self.role == "supervisor"

    @property
    def is_tech(self):
        return self.role == "tech"

    @property
    def is_manutencao(self):
        return self.role == "manutencao"



# ===============================
# MODELS: VEÍCULOS + MOVIMENTOS + INFORMAÇÕES
# ===============================

class Vehicle(db.Model):
    __tablename__ = "vehicle"

    id = db.Column(db.Integer, primary_key=True)
    plate = db.Column(db.String(20), unique=True, nullable=False)
    brand = db.Column(db.String(80))
    model = db.Column(db.String(80))
    year = db.Column(db.Integer)
    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="ATIVO")
    type = db.Column(db.String(20), default="carro")  # carro / moto / caminhao / van

    # Custom tracking customization fields
    driver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    driver = db.relationship('User', foreign_keys=[driver_id])
    map_icon = db.Column(db.String(50), default="fa-location-arrow")
    map_color = db.Column(db.String(20), default="#10b981")

    # ✅ 1 ficha de informações por veículo
    info = db.relationship(
        "VehicleInfo",
        backref="vehicle",
        uselist=False,
        cascade="all, delete-orphan"
    )


class VehicleInfo(db.Model):
    __tablename__ = "vehicle_info"

    id = db.Column(db.Integer, primary_key=True)

    # 1:1 com veículo
    vehicle_id = db.Column(
        db.Integer,
        db.ForeignKey("vehicle.id", ondelete="CASCADE"),
        unique=True,
        nullable=False
    )

    # Campos (você pode adicionar/remover depois)
    oil_type = db.Column(db.String(80))          # Ex: 5W30
    oil_brand = db.Column(db.String(80))         # Ex: Mobil, Castrol
    oil_capacity_l = db.Column(db.Float)         # Ex: 3.5

    filter_oil = db.Column(db.String(80))
    filter_air = db.Column(db.String(80))
    filter_fuel = db.Column(db.String(80))

    coolant_type = db.Column(db.String(80))
    brake_fluid = db.Column(db.String(80))
    tire_pressure = db.Column(db.String(40))     # Ex: "32psi/30psi"

    notes = db.Column(db.Text)

    # horário BR (sem tzinfo)
    updated_at = db.Column(db.DateTime, default=lambda: agora(), onupdate=lambda: agora())


class VehicleMov(db.Model):
    __tablename__ = "vehicle_mov"

    id = db.Column(db.Integer, primary_key=True)

    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)

    # ✅ mantém sua relação, mas deixa mais limpo:
    vehicle = db.relationship("Vehicle", backref=db.backref("movimentos", lazy=True))

    # "saida" ou "entrada"
    tipo = db.Column(db.String(10), nullable=False)

    km = db.Column(db.Integer, nullable=False, default=0)
    responsavel = db.Column(db.String(120), nullable=False)
    obs = db.Column(db.Text)

    # horário BR (sem tzinfo)
    data_hora = db.Column(db.DateTime, default=lambda: agora())

    # chegada vinculada a uma saída
    saida_id = db.Column(db.Integer, db.ForeignKey("vehicle_mov.id"), nullable=True)
    saida_ref = db.relationship("VehicleMov", remote_side=[id], uselist=False)


class Checklist(db.Model):
    __tablename__ = "checklist"

    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"))
    vehicle = db.relationship("Vehicle", backref="checklists")
    technician = db.Column(db.String(120))

    # 🔥 HORÁRIO REAL (corrigido)
    date = db.Column(db.DateTime, default=lambda: agora())

    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(40), default="OK")
    notes = db.Column(db.Text)
    raw_json = db.Column(db.Text)



class ChecklistItem(db.Model):
    __tablename__ = "checklist_item"
    id = db.Column(db.Integer, primary_key=True)
    order = db.Column(db.Integer)
    text = db.Column(db.String(255), nullable=False)
    required = db.Column(db.Boolean, default=True)
    require_justif_no = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(50), default="texto_curto")
    options = db.Column(db.Text)

# ===============================
# 📢 COMUNICAÇÕES (AVISOS)
# ===============================
class Announcement(db.Model):
    __tablename__ = "announcement"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    target_type = db.Column(db.String(50))  # internal, external, company, all
    target_id = db.Column(db.Integer)        # ID da empresa se target_type == company
    created_at = db.Column(db.DateTime, default=agora)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))

class AnnouncementRead(db.Model):
    __tablename__ = "announcement_read"
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey("announcement.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    read_at = db.Column(db.DateTime, default=agora)

# ===============================
# 🎓 LMS (TREINAMENTOS)
# ===============================
class Training(db.Model):
    __tablename__ = "training"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    target = db.Column(db.String(50))  # all, internal, specific_company
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"), nullable=True)
    created_at = db.Column(db.DateTime, default=agora)
    allow_retake = db.Column(db.Boolean, default=True)
    badge_id = db.Column(db.Integer, db.ForeignKey("badge.id"), nullable=True)

class TrainingModule(db.Model):
    __tablename__ = "training_module"
    id = db.Column(db.Integer, primary_key=True)
    training_id = db.Column(db.Integer, db.ForeignKey("training.id"))
    title = db.Column(db.String(200))
    order = db.Column(db.Integer, default=0)

class TrainingCourse(db.Model):
    __tablename__ = "training_course"
    id = db.Column(db.Integer, primary_key=True)
    module_id = db.Column(db.Integer, db.ForeignKey("training_module.id"))
    title = db.Column(db.String(200))
    content_type = db.Column(db.String(20))  # video, pdf, text
    content_url = db.Column(db.String(500))
    description = db.Column(db.Text)
    order = db.Column(db.Integer, default=0)

class TrainingAttempt(db.Model):
    __tablename__ = "training_attempt"
    id = db.Column(db.Integer, primary_key=True)
    training_id = db.Column(db.Integer, db.ForeignKey("training.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    score = db.Column(db.Float)
    passed = db.Column(db.Boolean)
    completed_at = db.Column(db.DateTime, default=agora)

class TrainingQuestion(db.Model):
    __tablename__ = "training_question"
    id = db.Column(db.Integer, primary_key=True)
    training_id = db.Column(db.Integer, db.ForeignKey("training.id"))
    question_text = db.Column(db.Text)
    options_json = db.Column(db.Text)  # JSON array of options
    correct_option = db.Column(db.Integer)

class Badge(db.Model):
    __tablename__ = "badge"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    icon = db.Column(db.String(50))
    color = db.Column(db.String(20))
    description = db.Column(db.Text)

# ===============================
# 🏗️ GESTÃO TÉCNICA E INFRA
# ===============================
class Generator(db.Model):
    __tablename__ = "generator"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200))
    capacity_total = db.Column(db.Float)
    current_qty = db.Column(db.Float)
    fuel_type = db.Column(db.String(50))
    last_refill_date = db.Column(db.Date)
    responsible_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    responsible = db.relationship("User", backref="generators")
    status = db.Column(db.String(20), default="OPERACIONAL")
    obs = db.Column(db.Text)
    reserve_cans = db.Column(db.Integer)
    reserve_liters = db.Column(db.Float)

class RFO(db.Model):
    __tablename__ = "rfo"
    id = db.Column(db.Integer, primary_key=True)
    number = db.Column(db.String(50))
    title = db.Column(db.String(200))
    date = db.Column(db.Date)
    start_time = db.Column(db.String(50))
    end_time = db.Column(db.String(50))
    city = db.Column(db.String(100))
    neighborhood = db.Column(db.String(100))
    lat = db.Column(db.String(50))
    lon = db.Column(db.String(50))
    description = db.Column(db.Text)
    root_cause = db.Column(db.Text)
    impact = db.Column(db.Text)
    action = db.Column(db.Text)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id", ondelete="SET NULL"), nullable=True)
    team = db.relationship("Team", backref="rfos")
    technicians_json = db.Column(db.Text)
    photos_json = db.Column(db.Text)
    status = db.Column(db.String(20), default="ABERTO")
    problem_type = db.Column(db.String(200))
    tech_responsible = db.Column(db.String(200))

class Solicitacao(db.Model):
    __tablename__ = "solicitacao"
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(100))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    user = db.relationship("User", backref="solicitacoes")
    date = db.Column(db.DateTime, default=agora)
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="PENDENTE")
    management_response = db.Column(db.Text)
    obs = db.Column(db.Text)

class SupervisaoTecnica(db.Model):
    __tablename__ = "supervisao_tecnica"
    id = db.Column(db.Integer, primary_key=True)
    supervisor_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    supervisor = db.relationship("User", backref="supervisoes_tecnicas")
    date = db.Column(db.Date)
    time = db.Column(db.String(10))
    checklist_json = db.Column(db.Text)
    irregularities = db.Column(db.Text)
    action = db.Column(db.Text)
    obs = db.Column(db.Text)
    photos_json = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=agora)
    techs_data = db.Column(db.JSON)

class RotaExata(db.Model):
    __tablename__ = "rota_exata"
    id = db.Column(db.Integer, primary_key=True)
    supervisor_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    supervisor = db.relationship("User", backref="rotas_exatas")
    date = db.Column(db.Date)
    time = db.Column(db.String(10))
    location = db.Column(db.String(200))
    obs = db.Column(db.Text)
    status = db.Column(db.String(20), default="PENDENTE")
    photos_json = db.Column(db.Text)
    date_created = db.Column(db.DateTime, default=agora)
    techs_data = db.Column(db.JSON)

# Tabela Associativa N:N para Equipes e Técnicos
team_members = db.Table(
    "team_members",
    db.Column("team_id", db.Integer, db.ForeignKey("team.id", ondelete="CASCADE"), primary_key=True),
    db.Column("user_id", db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), primary_key=True)
)

class Team(db.Model):
    __tablename__ = "team"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    color = db.Column(db.String(20))
    obs = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=agora)
    rotation_order = db.Column(db.Integer, default=0)
    leader_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    
    # Relationships
    leader = db.relationship("User", foreign_keys=[leader_id])
    members = db.relationship("User", secondary=team_members, backref=db.backref("teams", lazy="dynamic"))

class Task(db.Model):
    __tablename__ = "task"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    responsible_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    responsible = db.relationship("User", backref="tasks")
    priority = db.Column(db.String(20), default="MEDIA")
    deadline = db.Column(db.Date)
    status = db.Column(db.String(20), default="PENDENTE")
    obs = db.Column(db.Text)

class Patio(db.Model):
    __tablename__ = "patio"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    location = db.Column(db.String(200))

class Encerramento(db.Model):
    __tablename__ = "encerramento"
    id = db.Column(db.Integer, primary_key=True)
    patio_id = db.Column(db.Integer, db.ForeignKey("patio.id", ondelete="SET NULL"), nullable=True)
    patio = db.relationship("Patio", backref=db.backref("encerramentos", lazy=True))
    date = db.Column(db.Date)
    closing_time = db.Column(db.String(50))
    technicians_json = db.Column(db.Text) # Lista de técnicos em JSON
    obs = db.Column(db.Text)
    patios_json = db.Column(db.Text)

class Scale(db.Model):
    __tablename__ = "scale"
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(50))
    date = db.Column(db.Date)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id", ondelete="SET NULL"), nullable=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    obs = db.Column(db.Text)
    status = db.Column(db.String(20), default="ATIVO")
    technician_ids = db.Column(db.Text) # IDs de técnicos separados por vírgula
    team_ids = db.Column(db.Text) # IDs de equipes separadas por vírgula

class Meeting(db.Model):
    __tablename__ = "meeting"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(200))
    date = db.Column(db.Date)
    time = db.Column(db.String(10))
    location = db.Column(db.String(200))
    participants = db.Column(db.Text) # IDs de técnicos separados por vírgula
    obs = db.Column(db.Text)
    status = db.Column(db.String(20), default="AGENDADA")
    responsible = db.Column(db.String(200))
    objective = db.Column(db.Text)
    summary = db.Column(db.Text)
    actions = db.Column(db.Text)

class Note(db.Model):
    __tablename__ = "note"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    category = db.Column(db.String(100))
    description = db.Column(db.Text)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"))
    user = db.relationship("User", backref="notes")
    date = db.Column(db.DateTime, default=agora)
    priority = db.Column(db.String(20), default="MEDIA")
    event_date = db.Column(db.Date)

class Activity(db.Model):
    __tablename__ = "activity"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    user = db.relationship("User", backref="activities")
    type = db.Column(db.String(100))
    location = db.Column(db.String(200))
    date = db.Column(db.Date)
    time = db.Column(db.String(10))
    description = db.Column(db.Text)
    status = db.Column(db.String(20), default="ABERTO")
    photos_json = db.Column(db.Text)
    obs = db.Column(db.Text)
    tech_responsible = db.Column(db.String(120))
    client_name = db.Column(db.String(200))
    client_code = db.Column(db.String(50))
    quality_rating = db.Column(db.String(50))
    client_feedback = db.Column(db.Text)
    os_closure = db.Column(db.String(20))
    conclusion = db.Column(db.Text)

class SystemRule(db.Model):
    __tablename__ = "system_rule"
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(50), unique=True)
    name = db.Column(db.String(100))
    description = db.Column(db.String(255))
    is_enabled = db.Column(db.Boolean, default=True)

# ===============================
# 🏢 CONTRATOS E CLIENTES
# ===============================
class Company(db.Model):
    __tablename__ = "company"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    cnpj = db.Column(db.String(20))
    email = db.Column(db.String(120))

class Contract(db.Model):
    __tablename__ = "contract"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200))
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"))
    start_date = db.Column(db.DateTime)
    end_date = db.Column(db.DateTime)
    status = db.Column(db.String(20))

class ExternalCollaborator(db.Model):
    __tablename__ = "external_collaborator"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200))
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    company_id = db.Column(db.Integer, db.ForeignKey("company.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))


# ----------------------------------------
# 🚗 MODELO AVARIAS / ORDENS DE SERVIÇO
# ----------------------------------------
class AvariaOS(db.Model):
    __tablename__ = "avaria_os"

    id = db.Column(db.Integer, primary_key=True)

    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref="avarias")

    responsavel_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    responsavel = db.relationship("User", backref="os_avarias")

    gravidade = db.Column(db.String(20))
    descricao = db.Column(db.Text, nullable=False)
    km = db.Column(db.Integer)

    status = db.Column(db.String(20), default="aberta")  # aberta / finalizada

    valor_gasto = db.Column(db.Float)
    pecas_trocadas = db.Column(db.Text)
    servico_realizado = db.Column(db.Text)

    data_abertura = db.Column(db.DateTime, default=datetime.utcnow)
    data_fechamento = db.Column(db.DateTime)


class Log(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), nullable=False)
    acao = db.Column(db.String(255), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)


# ----------------------------------------
# 🚗 MODELO VISTORIAS (corrigido p/ obs + foto por item)
# ----------------------------------------

class Vistoria(db.Model):
    __tablename__ = "vistorias"

    id = db.Column(db.Integer, primary_key=True)

    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref=db.backref("vistorias", lazy=True))

    created_at = db.Column(db.DateTime, default=agora, nullable=False)

    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by_user = db.relationship("User", foreign_keys=[created_by])

    km = db.Column(db.Integer, nullable=True)

    # inicio | durante | fim
    turno = db.Column(db.String(20), default="fim", nullable=False)

    local = db.Column(db.String(120), nullable=True)

    # ok | avarias
    status_geral = db.Column(db.String(20), default="ok", nullable=False)

    observacoes = db.Column(db.Text, nullable=True)

    # -------------------------
    # Itens (status)
    # ok | avaria
    # -------------------------
    para_choque_dianteiro = db.Column(db.String(20), default="ok", nullable=False)
    para_choque_traseiro  = db.Column(db.String(20), default="ok", nullable=False)
    lateral_esquerda      = db.Column(db.String(20), default="ok", nullable=False)
    lateral_direita       = db.Column(db.String(20), default="ok", nullable=False)
    capo                  = db.Column(db.String(20), default="ok", nullable=False)
    teto                  = db.Column(db.String(20), default="ok", nullable=False)
    porta_malas           = db.Column(db.String(20), default="ok", nullable=False)
    retrovisores          = db.Column(db.String(20), default="ok", nullable=False)
    farois_lanternas      = db.Column(db.String(20), default="ok", nullable=False)
    vidros_parabrisa      = db.Column(db.String(20), default="ok", nullable=False)

    pneus                 = db.Column(db.String(20), default="ok", nullable=False)
    calotas               = db.Column(db.String(20), default="ok", nullable=False)

    # -------------------------
    # Observações por item
    # -------------------------
    obs_para_choque_dianteiro = db.Column(db.Text, nullable=True)
    obs_para_choque_traseiro  = db.Column(db.Text, nullable=True)
    obs_lateral_esquerda      = db.Column(db.Text, nullable=True)
    obs_lateral_direita       = db.Column(db.Text, nullable=True)
    obs_capo                  = db.Column(db.Text, nullable=True)
    obs_teto                  = db.Column(db.Text, nullable=True)
    obs_porta_malas           = db.Column(db.Text, nullable=True)
    obs_retrovisores          = db.Column(db.Text, nullable=True)
    obs_farois_lanternas      = db.Column(db.Text, nullable=True)
    obs_vidros_parabrisa      = db.Column(db.Text, nullable=True)

    obs_pneus                 = db.Column(db.Text, nullable=True)
    obs_calotas               = db.Column(db.Text, nullable=True)

    # -------------------------
    # Foto por item (salva o filename)
    # -------------------------
    foto_para_choque_dianteiro = db.Column(db.String(255), nullable=True)
    foto_para_choque_traseiro  = db.Column(db.String(255), nullable=True)
    foto_lateral_esquerda      = db.Column(db.String(255), nullable=True)
    foto_lateral_direita       = db.Column(db.String(255), nullable=True)
    foto_capo                  = db.Column(db.String(255), nullable=True)
    foto_teto                  = db.Column(db.String(255), nullable=True)
    foto_porta_malas           = db.Column(db.String(255), nullable=True)
    foto_retrovisores          = db.Column(db.String(255), nullable=True)
    foto_farois_lanternas      = db.Column(db.String(255), nullable=True)
    foto_vidros_parabrisa      = db.Column(db.String(255), nullable=True)

    foto_pneus                 = db.Column(db.String(255), nullable=True)
    foto_calotas               = db.Column(db.String(255), nullable=True)


# ----------------------------------------
# (Opcional) Galeria geral de fotos
# -> mantenha só se ainda quiser fotos "extras" além das fotos por item
# ----------------------------------------

class VistoriaFoto(db.Model):
    __tablename__ = "vistorias_fotos"

    id = db.Column(db.Integer, primary_key=True)

    vistoria_id = db.Column(db.Integer, db.ForeignKey("vistorias.id"), nullable=False)
    vistoria = db.relationship(
        "Vistoria",
        backref=db.backref("fotos", cascade="all, delete-orphan", lazy=True)
    )

    filename = db.Column(db.String(255), nullable=False)

    # ✅ NOVO: identifica de qual item é a foto (ex: "capo", "pneus", etc.)
    item_key = db.Column(db.String(50), nullable=True, index=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)




# --------------------------------------------------------
# 🔥 CONFIGURAÇÃO GLOBAL DO CHECKLIST 🔥
# --------------------------------------------------------
class SystemConfig(db.Model):
    __tablename__ = "system_config"
    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(20), default="start_only")
    
    # Configuração de Escala
    scale_start_date = db.Column(db.Date)
    scale_start_team_id = db.Column(db.Integer)
    scale_rotation_order = db.Column(db.String(255))
    
    # Telemetria Parâmetros
    speed_limit = db.Column(db.Integer, default=80)
    ignition_alert = db.Column(db.Boolean, default=True)
    update_frequency = db.Column(db.Integer, default=30)
    simulator_active = db.Column(db.Boolean, default=False)


@login_manager.user_loader
def load_user(uid):
    return User.query.get(int(uid))


# ----------------- MIGRAÇÃO LEVE PARA POSTGRES -----------------
def ensure_min_schema():
    """
    Garante colunas mínimas no PostgreSQL (idempotente).
    NÃO usa mais sqlite3 nem arquivos .db.
    """
    stmts = [
        # role em user
        text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS role VARCHAR(20)'),
        # type em vehicle
        text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS type VARCHAR(20) DEFAULT \'carro\''),
        text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS driver_id INTEGER REFERENCES "user"(id)'),
        text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS map_icon VARCHAR(50) DEFAULT \'fa-location-arrow\''),
        text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS map_color VARCHAR(20) DEFAULT \'#10b981\''),
        # campos em checklist_item
        text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS type VARCHAR(50) DEFAULT \'texto_curto\''),
        text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS options TEXT'),
        # campos em system_config
        text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS speed_limit INTEGER DEFAULT 80'),
        text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS ignition_alert BOOLEAN DEFAULT TRUE'),
        text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS update_frequency INTEGER DEFAULT 30'),
        text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS simulator_active BOOLEAN DEFAULT FALSE'),
        text('''
            CREATE TABLE IF NOT EXISTS gps_geofence (
                id SERIAL PRIMARY KEY,
                vehicle_id INTEGER NOT NULL UNIQUE REFERENCES vehicle(id),
                lat FLOAT NOT NULL,
                lon FLOAT NOT NULL,
                radius FLOAT DEFAULT 500.0,
                is_active BOOLEAN DEFAULT TRUE
            )
        '''),
        text('''
            CREATE TABLE IF NOT EXISTS gps_alert (
                id SERIAL PRIMARY KEY,
                imei VARCHAR(50),
                vehicle_id INTEGER NOT NULL REFERENCES vehicle(id),
                alert_type VARCHAR(50) NOT NULL,
                description VARCHAR(255),
                latitude FLOAT,
                longitude FLOAT,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_dismissed BOOLEAN DEFAULT FALSE
            )
        ''')
    ]
    for stmt in stmts:
        try:
            db.session.execute(stmt)
        except Exception as e:
            print("⚠️ Erro em ensure_min_schema:", e)
    try:
        db.session.commit()
    except Exception as e:
        print("⚠️ Erro commit ensure_min_schema:", e)
        db.session.rollback()


# ----------------- SEED DEFAULTS -----------------
DEFAULT_ITEMS = [
    ("Pneus (calibragem/estado)", "sim_nao_na"),
    ("Luzes frontais", "sim_nao_na"),
    ("Luzes traseiras", "sim_nao_na"),
    ("Setas e alerta", "sim_nao_na"),
    ("Extintor (validade)", "sim_nao_na"),
    ("Painel sem avisos críticos", "sim_nao_na"),
    ("Documentação do veículo", "sim_nao_na"),
    ("Observações gerais", "paragrafo"),
]


def seed_defaults():
    # admin
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", role="admin")
        u.set_password("admin")
        db.session.add(u)

    # sistema config inicial
    if SystemConfig.query.count() == 0:
        db.session.add(SystemConfig(mode="start_only"))

    # itens de checklist padrão
    if ChecklistItem.query.count() == 0:
        for i, (txt, typ) in enumerate(DEFAULT_ITEMS, start=1):
            db.session.add(ChecklistItem(order=i, text=txt, type=typ))

    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_min_schema()
    seed_defaults()


# ----------------- LOG -----------------
def registrar_log(acao):
    try:
        user = current_user.username if current_user.is_authenticated else "Sistema"
        db.session.add(Log(usuario=user, acao=acao))
        db.session.commit()
    except Exception as e:
        print("⚠️ Erro registrar_log:", e)
        db.session.rollback()


# ----------------- HELPERS DE PERMISSÃO -----------------
def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if not current_user.is_admin:
            flash("Acesso restrito ao administrador.", "error")
            if current_user.is_supervisor:
                return redirect(url_for("dashboard"))
            if current_user.is_manutencao:
                return redirect(url_for("manutencao_os"))
            return redirect(url_for("checklist_mobile"))
        return view(*args, **kwargs)
    return wrapper


def supervisor_allowed(view):
    """Admin + Supervisor podem acessar; técnico e manutenção NÃO."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.is_admin or current_user.is_supervisor:
            return view(*args, **kwargs)
        flash("Acesso restrito a supervisor ou administrador.", "error")
        if current_user.is_manutencao:
            return redirect(url_for("manutencao_os"))
        return redirect(url_for("checklist_mobile"))
    return wrapper


def manutencao_only(view):
    """Apenas usuários de manutenção acessam esta rota."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.is_manutencao:
            return view(*args, **kwargs)
        flash("Página exclusiva da equipe de manutenção.", "info")
        if current_user.is_admin or current_user.is_supervisor:
            return redirect(url_for("dashboard"))
        return redirect(url_for("checklist_mobile"))
    return wrapper


# Variáveis globais para o template
@app.context_processor
def inject_role_flags():
    return dict(
        ROLE_ADMIN=(current_user.is_authenticated and current_user.is_admin),
        ROLE_SUPERVISOR=(current_user.is_authenticated and current_user.is_supervisor),
        ROLE_TECH=(current_user.is_authenticated and current_user.is_tech),
        ROLE_MANUTENCAO=(current_user.is_authenticated and current_user.is_manutencao),
    )


# ----------------- FUNÇÕES AUXILIARES -----------------
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
    from collections import defaultdict

    end = datetime.utcnow()
    start = end - timedelta(weeks=weeks_back)

    # Buscar checklists no período
    rows = (Checklist.query
            .filter(Checklist.date >= start, Checklist.date <= end)
            .order_by(Checklist.vehicle_id.asc(), Checklist.date.asc())
            .all())

    # Dicionário: semana → km rodado
    weekly_km = defaultdict(int)

    # Agrupar por veículo
    last_km_per_vehicle = {}

    for c in rows:
        vid = c.vehicle_id
        km = c.km or 0
        wk = iso_week(c.date)

        # Se já existe KM anterior desse veículo, calcula diferença
        if vid in last_km_per_vehicle:
            diff = km - last_km_per_vehicle[vid]
            # Só soma se for positivo (para evitar reset de KM)
            if diff > 0:
                weekly_km[wk] += diff

        # Atualiza último KM desse veículo
        last_km_per_vehicle[vid] = km

    # Gera lista de semanas de forma ordenada
    weeks = []
    for i in range(weeks_back - 1, -1, -1):
        dt = end - timedelta(weeks=i)
        monday = dt - timedelta(days=dt.weekday())
        weeks.append(iso_week(monday + timedelta(days=3)))  # meio da semana

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


# ----------------- LOGIN -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()

        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u)
            registrar_log(f"Login efetuado: {u.username}")

            # Redirecionamento por papel
            if u.is_admin or u.is_supervisor:
                return redirect(url_for("dashboard"))
            if u.is_manutencao:
                return redirect(url_for("manutencao_os"))
            return redirect(url_for("checklist_mobile"))

        flash("Usuário ou senha inválidos.", "login_error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    registrar_log(f"Logout efetuado: {current_user.username}")
    logout_user()
    return redirect(url_for("login"))


@app.route("/")
def index():
    if current_user.is_authenticated:
        if current_user.is_admin or current_user.is_supervisor:
            return redirect(url_for("dashboard"))
        if current_user.is_manutencao:
            return redirect(url_for("manutencao_os"))
        return redirect(url_for("checklist_mobile"))
    return redirect(url_for("login"))


# ----------------- DASHBOARD -----------------
@app.route("/dashboard")
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
        # Incluindo todos os usuários exceto o admin principal para garantir reconhecimento total
        users = User.query.filter(User.username != 'admin').all()
        now = agora()
        start_week = now - timedelta(days=now.weekday())
        start_month = now.replace(day=1, hour=0, minute=0, second=0)
        start_year = now.replace(month=1, day=1, hour=0, minute=0, second=0)

        for u in users:
            total = Checklist.query.filter_by(technician=u.username).count()
            semanal = Checklist.query.filter(Checklist.technician == u.username, Checklist.date >= start_week).count()
            mensal = Checklist.query.filter(Checklist.technician == u.username, Checklist.date >= start_month).count()
            anual = Checklist.query.filter(Checklist.technician == u.username, Checklist.date >= start_year).count()
            
            user_stats_list.append({
                'username': u.username,
                'semanal': semanal,
                'mensal': mensal,
                'anual': anual,
                'total': total
            })
        # Ordenar por total desc
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
@app.route("/api/frota/dashboard_stats")
@supervisor_allowed
def api_frota_stats():
    now = agora()
    start_7d = now - timedelta(days=7)
    start_month = now.replace(day=1, hour=0, minute=0, second=0)

    # 1. Saúde da Frota (Percentual OK nos últimos 7 dias)
    total_7d = Checklist.query.filter(Checklist.date >= start_7d).count()
    ok_7d = Checklist.query.filter(Checklist.date >= start_7d, Checklist.status == "OK").count()
    fleet_health = int((ok_7d / total_7d * 100)) if total_7d > 0 else 100

    # 2. Custo de Manutenção (Mês)
    total_cost = db.session.query(db.func.sum(AvariaOS.valor_gasto)).filter(AvariaOS.data_abertura >= start_month).scalar() or 0

    # 3. Checklists Hoje e O.S Abertas
    checklists_today = Checklist.query.filter(Checklist.date >= now.replace(hour=0, minute=0, second=0)).count()
    open_os = AvariaOS.query.filter_by(status="aberta").count()

    # 4. Histórico de KM (Últimos 7 dias)
    km_labels = []
    km_values = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        km_day = db.session.query(db.func.sum(VehicleMov.km)).filter(db.func.date(VehicleMov.data_hora) == day).scalar() or 0
        km_labels.append(day.strftime("%d/%m"))
        km_values.append(int(km_day))

    # 5. Distribuição de Status (30d)
    start_30d = now - timedelta(days=30)
    status_dist = {}
    for st in ["OK", "Atenção", "Crítico"]:
        count = Checklist.query.filter(Checklist.date >= start_30d, Checklist.status == st).count()
        status_dist[st] = count

    # 6. Alertas de Revisão (Top 3 críticos)
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

    return json.dumps({
        "fleet_health": fleet_health,
        "total_cost_month": float(total_cost),
        "checklists_today": checklists_today,
        "open_os": open_os,
        "km_history": {"labels": km_labels, "values": km_values},
        "status_dist": status_dist,
        "rev_alerts": rev_alerts[:3],
        "latest_os": latest_os
    })

# --- API DASHBOARD GESTÃO (DADOS REAIS) ---
@app.route("/api/gestao/dashboard_stats")
@supervisor_allowed
def api_gestao_stats():
    now = agora()
    start_month = now.replace(day=1, hour=0, minute=0, second=0)

    # 1. LMS Completion (Média de progresso de todos os usuários)
    # Aqui assumimos que temos uma tabela de progresso ou calculamos por badges
    total_trainings = Training.query.count()
    if total_trainings > 0:
        completions = TrainingCompletion.query.count()
        total_users = User.query.filter(User.role == 'tech').count()
        lms_completion = int((completions / (total_trainings * total_users) * 100)) if total_users > 0 else 0
    else:
        lms_completion = 0

    # 2. Auditorias (Checklists feitos por supervisores no mês)
    audits = Checklist.query.join(User, Checklist.technician == User.username).filter(
        User.role == "supervisor",
        Checklist.date >= start_month
    ).count()

    # 3. RFO e Tarefas
    rfo_active = RFO.query.filter_by(status="ABERTO").count()
    tasks_pending = Task.query.filter(Task.status != "CONCLUÍDO").count()

    # 4. Atividades (Volume de Checklists nos últimos 7 dias)
    act_labels = []
    act_values = []
    for i in range(6, -1, -1):
        day = (now - timedelta(days=i)).date()
        count = Checklist.query.filter(db.func.date(Checklist.date) == day).count()
        act_labels.append(day.strftime("%d/%m"))
        act_values.append(count)

    # 5. RFO por Tipo
    rfo_types = db.session.query(RFO.tipo, db.func.count(RFO.id)).group_by(RFO.tipo).all()
    rfo_dist = {t[0]: t[1] for t in rfo_types}

    # 6. Ranking (Top 5 por conclusões)
    ranking = []
    top_users = db.session.query(
        User.username, db.func.count(TrainingCompletion.id).label('total')
    ).join(TrainingCompletion, User.id == TrainingCompletion.user_id).group_by(User.id).order_by(db.text('total DESC')).limit(10).all()
    
    for u in top_users:
        ranking.append({"name": u[0], "points": u[1] * 100}) # 100 pts por curso

    return json.dumps({
        "lms_completion": lms_completion,
        "total_audits_month": audits,
        "fleet_health": 100, # Seria similar ao de frota
        "rfo_active": rfo_active,
        "tasks_pending": tasks_pending,
        "atividades_history": {"labels": act_labels, "values": act_values},
        "rfo_by_type": rfo_dist,
        "ranking": ranking,
        "generator_alerts": [], # Implementar se houver modelo de geradores
        "critical_tasks": []
    })

# ----------------- USUÁRIOS (admin) -----------------
# ----------------- USUÁRIOS (admin) -----------------
@app.route("/usuarios")
@admin_required
def users():
    users_list = User.query.order_by(User.id.asc()).all()
    return render_template("users.html", items=users_list)


@app.route("/usuarios/<int:uid>/senha", methods=["POST"])
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


@app.route("/usuarios/novo", methods=["POST"])
@admin_required
def users_new():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "tech").strip().lower()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    if not username or not password:
        flash("Usuário e senha obrigatórios.", "error")
        return redirect(url_for("users"))

    if User.query.filter_by(username=username).first():
        flash("Usuário já existe.", "error")
        return redirect(url_for("users"))

    # Define permissões padrão por papel (Sincronizado com perm_...)
    perms = {}
    if role == "tech":
        perms = {"perm_checklist_mobile": True, "perm_treinamentos_mobile": True}
    elif role == "manutencao":
        perms = {"perm_manutencao_os": True}
    elif role == "supervisor":
        perms = {"perm_dashboard": True, "perm_relatorios": True, "perm_checklists_view": True}
    elif role == "admin":
        # Admin ganha tudo por padrão
        perms = {
            "perm_dashboard": True, "perm_logs": True, "perm_relatorios": True, "perm_avisos": True,
            "perm_usuarios": True, "perm_veiculos": True, "perm_controle_veiculos": True,
            "perm_checklist_mobile": True, "perm_treinamentos_mobile": True, "perm_manutencao_os": True
        }

    u = User(username=username, role=role, email=email, phone=phone, permissions=json.dumps(perms))
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    registrar_log(f"Usuário criado: {username} ({role})")
    flash("Usuário cadastrado com permissões padrão.", "success")
    return redirect(url_for("users"))


@app.route("/usuarios/<int:uid>/papel", methods=["POST"])
@admin_required
def users_role(uid):
    u = User.query.get_or_404(uid)
    role = request.form.get("role", "tech").strip().lower()
    email = request.form.get("email", "").strip()
    phone = request.form.get("phone", "").strip()

    if role not in {"admin", "supervisor", "tech", "manutencao"}:
        flash("Papel inválido.", "error")
        return redirect(url_for("users"))

    # Atualiza dados básicos
    u.role = role
    u.email = email
    u.phone = phone

    # Ao mudar o papel, resetamos para as permissões padrão daquele papel
    perms = {}
    if role == "tech":
        perms = {"perm_checklist_mobile": True, "perm_treinamentos_mobile": True}
    elif role == "manutencao":
        perms = {"perm_manutencao_os": True}
    elif role == "supervisor":
        perms = {"perm_dashboard": True, "perm_relatorios": True, "perm_checklists_view": True}
    
    u.permissions = json.dumps(perms)
    db.session.commit()

    registrar_log(f"Perfil atualizado: {u.username} -> {role}")
    flash(f"Dados e permissões padrão atualizados para {role}.", "success")
    return redirect(url_for("users"))


@app.route("/usuarios/<int:uid>/permissions", methods=["POST"])
@admin_required
def users_permissions(uid):
    u = User.query.get_or_404(uid)
    
    # Mapeamento completo de todas as permissões presentes no template (users.html)
    possible_perms = [
        "perm_dashboard", "perm_logs", "perm_relatorios", "perm_avisos",
        "perm_usuarios", "perm_veiculos", "perm_controle_veiculos",
        "perm_checklist_mobile", "perm_treinamentos_mobile", "perm_vistorias_nova",
        "perm_avarias", "perm_checklists_view", "perm_config_checklist",
        "perm_manutencao_os", "perm_vistorias_list",
        "perm_gestao_equipes", "perm_gestao_calendario", "perm_gestao_escalas",
        "perm_gestao_reunioes", "perm_gestao_anotacoes", "perm_gestao_atividades",
        "perm_gestao_encerramento", "perm_gestao_rfo", "perm_gestao_tarefas",
        "perm_gestao_geradores", "perm_gestao_rota_exata", "perm_gestao_supervisao",
        "perm_gestao_treinamentos", "perm_gestao_solicitacoes", "perm_gestao_relatorios"
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


@app.route("/usuarios/<int:uid>/excluir", methods=["POST"])
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


# ----------------- VEÍCULOS (admin + supervisor) -----------------
@app.route("/veiculos")
@supervisor_allowed
def vehicles():
    q = (request.args.get("q") or "").strip()
    query = Vehicle.query.options(joinedload(Vehicle.info))  # ✅ carrega info junto (evita N+1)

    if q:
        like = f"%{q}%"
        query = query.filter(
            db.or_(
                Vehicle.plate.ilike(like),
                Vehicle.brand.ilike(like),
                Vehicle.model.ilike(like),
            )
        )

    veiculos = query.order_by(Vehicle.plate.asc()).all()

    # garantir valor padrão caso venha nulo
    for v in veiculos:
        if not v.type:
            v.type = "carro"
        if not v.status:
            v.status = "ATIVO"

    colaboradores = User.query.order_by(User.username.asc()).all()
    return render_template("vehicles.html", veiculos=veiculos, q=q, colaboradores=colaboradores)


@app.route("/veiculos/novo", methods=["POST"])
@login_required
def vehicle_new():
    if not current_user.is_admin:
        abort(403)

    plate = (request.form.get("plate") or "").upper().strip()
    brand = (request.form.get("brand") or "").strip()
    model = (request.form.get("model") or "").strip()
    year_raw = (request.form.get("year") or "").strip()
    km_raw = (request.form.get("km") or "").strip()

    type_ = (request.form.get("type") or "carro").strip().lower()

    # ✅ padroniza status em MAIÚSCULO e sem acento
    status_raw = (request.form.get("status") or "ATIVO").strip().upper()
    if status_raw == "MANUTENÇÃO":
        status_raw = "MANUTENCAO"
    if status_raw not in {"ATIVO", "INATIVO", "MANUTENCAO"}:
        status_raw = "ATIVO"

    if not plate:
        flash("Placa é obrigatória.", "error")
        return redirect(url_for("vehicles"))

    if Vehicle.query.filter_by(plate=plate).first():
        flash("Já existe um veículo com essa placa.", "error")
        return redirect(url_for("vehicles"))

    year = int(year_raw) if year_raw.isdigit() else None
    km = int(km_raw) if km_raw.isdigit() else 0

    driver_id_raw = request.form.get("driver_id")
    driver_id = int(driver_id_raw) if driver_id_raw and driver_id_raw.isdigit() else None
    map_icon = request.form.get("map_icon", "fa-location-arrow").strip()
    map_color = request.form.get("map_color", "#10b981").strip()

    v = Vehicle(
        plate=plate,
        brand=brand or None,
        model=model or None,
        year=year,
        km=km,
        status=status_raw,
        type=type_,
        driver_id=driver_id,
        map_icon=map_icon,
        map_color=map_color
    )

    db.session.add(v)
    db.session.commit()

    registrar_log(f"Veículo criado: {plate} ({brand} {model}, tipo={type_})")
    flash(f"Veículo {plate} cadastrado!", "success")
    return redirect(url_for("vehicles"))


@app.route("/veiculos/<int:vid>/status", methods=["POST"])
@login_required
def vehicle_status(vid):
    if not current_user.is_admin:
        abort(403)

    v = Vehicle.query.get_or_404(vid)
    old = v.status or "ATIVO"

    status_raw = (request.form.get("status") or old).strip().upper()
    if status_raw == "MANUTENÇÃO":
        status_raw = "MANUTENCAO"
    if status_raw not in {"ATIVO", "INATIVO", "MANUTENCAO"}:
        status_raw = old

    v.status = status_raw
    db.session.commit()

    registrar_log(f"Status veículo {v.plate}: {old} -> {v.status}")
    flash("Status atualizado!", "success")
    return redirect(url_for("vehicles"))


@app.route("/veiculos/<int:vid>/editar", methods=["POST"])
@login_required
def vehicle_edit(vid):
    if not current_user.is_admin:
        abort(403)

    v = Vehicle.query.get_or_404(vid)

    v.brand = (request.form.get("brand") or "").strip() or None
    v.model = (request.form.get("model") or "").strip() or None

    year_raw = (request.form.get("year") or "").strip()
    km_raw = (request.form.get("km") or "").strip()
    type_raw = (request.form.get("type") or "carro").strip().lower()

    status_raw = (request.form.get("status") or (v.status or "ATIVO")).strip().upper()
    if status_raw == "MANUTENÇÃO":
        status_raw = "MANUTENCAO"
    if status_raw not in {"ATIVO", "INATIVO", "MANUTENCAO"}:
        status_raw = (v.status or "ATIVO")

    v.year = int(year_raw) if year_raw.isdigit() else None

    # ✅ se KM vazio, mantém o atual
    if km_raw.isdigit():
        v.km = int(km_raw)

    v.type = type_raw or "carro"
    v.status = status_raw

    driver_id_raw = request.form.get("driver_id")
    v.driver_id = int(driver_id_raw) if driver_id_raw and driver_id_raw.isdigit() else None
    v.map_icon = request.form.get("map_icon", "fa-location-arrow").strip()
    v.map_color = request.form.get("map_color", "#10b981").strip()

    db.session.commit()

    registrar_log(f"Veículo editado: {v.plate} (status={v.status})")
    flash("Veículo atualizado!", "success")
    return redirect(url_for("vehicles"))


@app.route("/veiculos/<int:vid>/excluir", methods=["POST"])
@login_required
def vehicle_delete(vid):
    if not current_user.is_admin:
        abort(403)

    v = Vehicle.query.get_or_404(vid)
    plate = v.plate

    db.session.delete(v)
    db.session.commit()

    registrar_log(f"Veículo excluído: {plate}")
    flash("Veículo excluído com sucesso!", "success")
    return redirect(url_for("vehicles"))


# ===============================
# ✅ NOVO: SALVAR/ATUALIZAR INFORMAÇÕES DO VEÍCULO
# ===============================
@app.route("/veiculos/<int:vid>/info", methods=["POST"])
@login_required
def vehicle_info_save(vid):
    if not current_user.is_admin:
        abort(403)

    v = Vehicle.query.options(joinedload(Vehicle.info)).get_or_404(vid)

    # se não existe ficha ainda, cria
    if not v.info:
        v.info = VehicleInfo(vehicle=v)

    v.info.oil_type = (request.form.get("oil_type") or "").strip() or None
    v.info.oil_brand = (request.form.get("oil_brand") or "").strip() or None

    cap = (request.form.get("oil_capacity_l") or "").strip()
    try:
        v.info.oil_capacity_l = float(cap) if cap else None
    except ValueError:
        flash("Capacidade do óleo inválida.", "error")
        return redirect(url_for("vehicles"))

    v.info.filter_oil = (request.form.get("filter_oil") or "").strip() or None
    v.info.filter_air = (request.form.get("filter_air") or "").strip() or None
    v.info.filter_fuel = (request.form.get("filter_fuel") or "").strip() or None

    v.info.coolant_type = (request.form.get("coolant_type") or "").strip() or None
    v.info.brake_fluid = (request.form.get("brake_fluid") or "").strip() or None
    v.info.tire_pressure = (request.form.get("tire_pressure") or "").strip() or None
    v.info.notes = (request.form.get("notes") or "").strip() or None

    db.session.add(v)
    db.session.commit()

    registrar_log(f"Informações do veículo atualizadas: {v.plate}")
    flash("Informações do veículo salvas!", "success")
    return redirect(url_for("vehicles"))


# ===============================
# CONTROLE DE VEÍCULOS (SEU CÓDIGO)
# ===============================
@app.route("/controle-veiculos", methods=["GET", "POST"])
@supervisor_allowed
def controle_veiculos():
    # ==========================
    # POST: registrar SAÍDA ou CHEGADA
    # ==========================
    if request.method == "POST":
        tipo = (request.form.get("tipo") or "").strip().lower()
        vehicle_id = (request.form.get("vehicle_id") or "").strip()
        saida_id = (request.form.get("saida_id") or "").strip()  # só chegada
        obs = (request.form.get("obs") or "").strip()

        # ✅ pega do select (fallback logado)
        responsavel = (request.form.get("responsavel") or "").strip() or current_user.username

        # ✅ valida se o responsável existe
        u = User.query.filter_by(username=responsavel).first()
        if not u:
            flash("Responsável inválido.", "error")
            return redirect(url_for("controle_veiculos"))

        # validações básicas
        if not vehicle_id.isdigit():
            flash("Selecione um veículo.", "error")
            return redirect(url_for("controle_veiculos"))

        try:
            km = int(request.form.get("km") or 0)
        except ValueError:
            flash("KM inválido.", "error")
            return redirect(url_for("controle_veiculos"))

        v = Vehicle.query.get(int(vehicle_id))
        if not v:
            flash("Veículo não encontrado.", "error")
            return redirect(url_for("controle_veiculos"))

        # ========= SAÍDA =========
        if tipo == "saida":
            # impede nova saída se já existe saída aberta (sem chegada)
            ultima_saida = (
                VehicleMov.query
                .filter_by(vehicle_id=v.id, tipo="saida")
                .order_by(VehicleMov.data_hora.desc())
                .first()
            )
            if ultima_saida:
                chegada_existente = VehicleMov.query.filter_by(tipo="entrada", saida_id=ultima_saida.id).first()
                if not chegada_existente:
                    flash("Esse veículo já tem uma SAÍDA aberta. Registre a chegada antes de criar outra saída.", "error")
                    return redirect(url_for("controle_veiculos"))

            # KM não pode ser menor que o KM do veículo
            if km < (v.km or 0):
                flash(f"KM informado ({km}) é menor que o KM atual do veículo ({v.km}).", "error")
                return redirect(url_for("controle_veiculos"))

            mov = VehicleMov(
                vehicle_id=v.id,
                tipo="saida",
                km=km,
                responsavel=responsavel,
                obs=obs or None,
                saida_id=None,
                data_hora=agora()  # ✅ horário BR real
            )
            db.session.add(mov)

            if km > (v.km or 0):
                v.km = km

            db.session.commit()
            registrar_log(f"Controle Veículos: SAÍDA ({v.plate}) km={km} resp={responsavel} id={mov.id}")
            flash("✅ Saída registrada com sucesso!", "success")
            return redirect(url_for("controle_veiculos"))

        # ======== CHEGADA ========
        if tipo == "entrada":
            if not saida_id.isdigit():
                flash("Chegada inválida: saída não informada.", "error")
                return redirect(url_for("controle_veiculos"))

            saida = VehicleMov.query.get(int(saida_id))
            if not saida or saida.tipo != "saida":
                flash("Saída vinculada não encontrada.", "error")
                return redirect(url_for("controle_veiculos"))

            if saida.vehicle_id != v.id:
                flash("Chegada inválida: veículo não corresponde à saída.", "error")
                return redirect(url_for("controle_veiculos"))

            # não permite chegada duplicada
            ja_tem = VehicleMov.query.filter_by(tipo="entrada", saida_id=saida.id).first()
            if ja_tem:
                flash("Essa saída já possui chegada registrada.", "error")
                return redirect(url_for("controle_veiculos"))

            # km da chegada >= km da saída
            if km < (saida.km or 0):
                flash(f"KM da chegada ({km}) não pode ser menor que KM da saída ({saida.km}).", "error")
                return redirect(url_for("controle_veiculos"))

            mov = VehicleMov(
                vehicle_id=v.id,
                tipo="entrada",
                km=km,
                responsavel=responsavel,
                obs=obs or None,
                saida_id=saida.id,
                data_hora=agora()  # ✅ horário BR real
            )
            db.session.add(mov)

            if km > (v.km or 0):
                v.km = km

            db.session.commit()
            registrar_log(f"Controle Veículos: CHEGADA ({v.plate}) km={km} resp={responsavel} saida_id={saida.id}")
            flash("✅ Chegada registrada com sucesso!", "success")
            return redirect(url_for("controle_veiculos"))

        flash("Tipo inválido.", "error")
        return redirect(url_for("controle_veiculos"))

    # ==========================
    # GET: 1 linha = SAÍDA + CHEGADA
    # ==========================
    vehicles = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    usuarios = User.query.order_by(User.username.asc()).all()

    # últimas saídas
    saidas = (
        VehicleMov.query
        .filter(VehicleMov.tipo == "saida")
        .order_by(VehicleMov.data_hora.desc())
        .limit(200)
        .all()
    )

    saida_ids = [s.id for s in saidas]
    chegadas = []
    if saida_ids:
        chegadas = (
            VehicleMov.query
            .filter(
                VehicleMov.tipo == "entrada",
                VehicleMov.saida_id.in_(saida_ids)
            )
            .all()
        )

    chegada_por_saida = {c.saida_id: c for c in chegadas}

    registros = []
    for s in saidas:
        c = chegada_por_saida.get(s.id)
        registros.append({
            "saida": s,
            "chegada": c,
            "pode_registrar_chegada": (c is None),
        })

    return render_template(
        "controle_veiculos.html",
        page_title="Controle de Entrada e Saída",
        vehicles=vehicles,
        usuarios=usuarios,
        registros=registros
    )

@app.route("/controle-veiculos/deletar/<int:mov_id>", methods=["POST"])
@supervisor_allowed
def deletar_movimento(mov_id):
    mov = VehicleMov.query.get_or_404(mov_id)
    plate = mov.vehicle.plate if mov.vehicle else "Desconhecido"
    tipo_mov = mov.tipo

    try:
        # Se for uma saída, precisamos deletar também a chegada associada a ela (se houver)
        if tipo_mov == "saida":
            chegada = VehicleMov.query.filter_by(tipo="entrada", saida_id=mov.id).first()
            if chegada:
                db.session.delete(chegada)
                registrar_log(f"Controle Veículos: CHEGADA DELETADA VINCULADA ({plate}) id={chegada.id}")
        
        db.session.delete(mov)
        db.session.commit()
        registrar_log(f"Controle Veículos: REGISTRO DELETADO ({plate}) tipo={tipo_mov} id={mov.id}")
        flash("✅ Registro excluído com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        registrar_log(f"Controle Veículos: ERRO AO EXCLUIR id={mov_id}: {str(e)}")
        flash("❌ Erro ao excluir registro.", "error")

    return redirect(url_for("controle_veiculos"))

from datetime import datetime
from flask import request, redirect, url_for, render_template, flash
from flask_login import current_user

# ----------------- AVARIAS / ORDENS DE SERVIÇO -----------------
@app.route("/avarias/registro", methods=["GET", "POST"])
@supervisor_allowed
def avarias_registro():
    if request.method == "POST":
        acao = request.form.get("acao")

        # CRIAR NOVA AVARIA
        if acao == "nova":
            nova = AvariaOS(
                vehicle_id=request.form.get("veiculo_id"),
                # ✅ NÃO VEM MAIS DO FORM - define automático
                responsavel_id=current_user.id,  # ou None, se você quiser sem responsável
                gravidade=request.form.get("gravidade"),
                descricao=request.form.get("descricao"),
                km=request.form.get("km"),
                status="aberta"
            )
            db.session.add(nova)
            db.session.commit()
            registrar_log(f"Avaria criada para veículo ID={nova.vehicle_id} (por {current_user.username})")
            return redirect(url_for("avarias_registro"))

        # FINALIZAR O.S (admin/supervisor)
        if acao == "finalizar":
            os_id = request.form.get("os_id")
            os_finalizar = AvariaOS.query.get(os_id)

            if os_finalizar:
                os_finalizar.valor_gasto = request.form.get("valor")
                os_finalizar.pecas_trocadas = request.form.get("pecas")
                os_finalizar.servico_realizado = request.form.get("servico")
                os_finalizar.status = "finalizada"
                os_finalizar.data_fechamento = datetime.utcnow()
                db.session.commit()
                registrar_log(f"O.S finalizada (admin/supervisor): ID={os_finalizar.id} (por {current_user.username})")

            return redirect(url_for("avarias_registro"))

    # GET — listar avarias e calcular estatísticas
    ordens = AvariaOS.query.order_by(AvariaOS.id.desc()).all()
    veiculos = Vehicle.query.all()

    total_avarias = len(ordens)
    abertas = sum(1 for o in ordens if o.status == "aberta")
    resolvidas = sum(1 for o in ordens if o.status == "finalizada")
    total_gasto = sum(o.valor_gasto or 0.0 for o in ordens)

    return render_template(
        "avarias_registro.html",
        ordens=ordens,
        veiculos=veiculos,
        total_avarias=total_avarias,
        abertas=abertas,
        resolvidas=resolvidas,
        total_gasto=total_gasto
    )

@app.route("/avarias/excluir/<int:avaria_id>", methods=["POST"])
@supervisor_allowed
def avarias_excluir(avaria_id):
    av = AvariaOS.query.get_or_404(avaria_id)
    plate = av.vehicle.plate if av.vehicle else "Desconhecido"
    try:
        db.session.delete(av)
        db.session.commit()
        registrar_log(f"Avarias/O.S.: REGISTRO DELETADO ({plate}) id={avaria_id} (por {current_user.username})")
        flash("✅ Registro de Avaria/O.S. excluído com sucesso!", "success")
    except Exception as e:
        db.session.rollback()
        registrar_log(f"Avarias/O.S.: ERRO AO EXCLUIR id={avaria_id}: {str(e)}")
        flash("❌ Erro ao excluir registro de Avaria/O.S.", "error")
    return redirect(url_for("avarias_registro"))


# ----------------- TELA DA MANUTENÇÃO (SOMENTE MANUTENÇÃO) -----------------
@app.route("/manutencao/os", methods=["GET", "POST"])
@manutencao_only
def manutencao_os():
    if request.method == "POST":
        acao = request.form.get("acao")

        # manutenção só FINALIZA O.S, não cria
        if acao == "finalizar":
            os_id = request.form.get("os_id")
            os_finalizar = AvariaOS.query.get(os_id)

            if os_finalizar:
                os_finalizar.valor_gasto = request.form.get("valor")
                os_finalizar.pecas_trocadas = request.form.get("pecas")
                os_finalizar.servico_realizado = request.form.get("servico")
                os_finalizar.status = "finalizada"
                os_finalizar.data_fechamento = datetime.utcnow()
                db.session.commit()
                registrar_log(f"O.S finalizada (manutenção): ID={os_finalizar.id} (por {current_user.username})")

            return redirect(url_for("manutencao_os"))

    ordens = AvariaOS.query.order_by(AvariaOS.id.desc()).all()
    return render_template("manutencao_os.html", ordens=ordens)



# ----------------- IMPORTAÇÃO DE CHECKLISTS -----------------
@app.route("/checklists/importar", methods=["POST"])
@admin_required
def checklists_import():
    INBOX_DIR.mkdir(exist_ok=True)

    files = [p for p in INBOX_DIR.iterdir() if p.suffix.lower() == ".json"]
    count = 0

    for p in files:
        try:
            data = p.read_text(encoding="utf-8")
            j = json.loads(data)

            plate = (j.get("placa") or j.get("plate") or "").upper()
            v = Vehicle.query.filter_by(plate=plate).first()

            if not v:
                v = Vehicle(
                    plate=plate,
                    brand=j.get("marca", ""),
                    model=j.get("modelo", ""),
                    km=int(j.get("km", 0)),
                )
                db.session.add(v)
                db.session.commit()

            item = Checklist(
                vehicle_id=v.id,
                technician=j.get("tecnico") or j.get("technician"),
                date=datetime.fromisoformat(j.get("data")) if j.get("data") else datetime.utcnow(),
                km=int(j.get("km", v.km or 0)),
                status=j.get("status", "OK"),
                notes=j.get("observacoes") or j.get("notes"),
                raw_json=data
            )
            db.session.add(item)

            if item.km and (not v.km or item.km > v.km):
                v.km = item.km

            db.session.commit()

            try:
                generate_checklist_pdf(item, json.loads(item.raw_json))
            except Exception as e:
                print("Erro gerando PDF importado:", e)

            p.rename(p.with_suffix(".imported.json"))
            count += 1

        except Exception as e:
            print("Erro importando", p, e)

    registrar_log(f"Importação: {count} arquivo(s) JSON")
    flash(f"Importação concluída: {count} checklist(s).", "success")
    return redirect(url_for("checklists"))


# ----------------- RELATÓRIOS -----------------
@app.route("/relatorios")
@supervisor_allowed
def reports():
    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    
    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    items = []
    for f in REPORTS_DIR.iterdir():
        if f.is_file() and f.suffix.lower() == ".pdf":
            stat = f.stat()
            items.append({
                "name": f.name,
                "size": stat.st_size,
                "mtime": datetime.fromtimestamp(stat.st_mtime)
            })
    
    # Ordenar por data (mais recente primeiro)
    items.sort(key=lambda x: x["mtime"], reverse=True)
    
    return render_template("reports.html", veiculos=veiculos, items=items)

@app.route("/relatorios/gerar", methods=["POST"])
@supervisor_allowed
def reports_generate():
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from datetime import datetime, time
    from pathlib import Path

    veiculo_id = request.form.get("veiculo_id")
    periodo = request.form.get("periodo")

    if not veiculo_id or not periodo:
        flash("Veículo e período são obrigatórios.", "error")
        return redirect(url_for("reports"))

    v = Vehicle.query.get(int(veiculo_id))
    if not v:
        flash("Veículo não encontrado.", "error")
        return redirect(url_for("reports"))

    try:
        start_str, end_str = periodo.split(" - ")
        start_date = datetime.strptime(start_str.strip(), "%Y-%m-%d")
        end_date = datetime.combine(datetime.strptime(end_str.strip(), "%Y-%m-%d"), time(23, 59, 59))
    except Exception:
        flash("Formato de período inválido.", "error")
        return redirect(url_for("reports"))

    # Consultar dados no período
    checklists = Checklist.query.filter(
        Checklist.vehicle_id == v.id,
        Checklist.date >= start_date,
        Checklist.date <= end_date
    ).order_by(Checklist.date.desc()).all()

    vistorias = Vistoria.query.filter(
        Vistoria.vehicle_id == v.id,
        Vistoria.created_at >= start_date,
        Vistoria.created_at <= end_date
    ).order_by(Vistoria.created_at.desc()).all()

    # Movimentações
    movimentos_saidas = VehicleMov.query.filter(
        VehicleMov.vehicle_id == v.id,
        VehicleMov.tipo == "saida",
        VehicleMov.data_hora >= start_date,
        VehicleMov.data_hora <= end_date
    ).order_by(VehicleMov.data_hora.desc()).all()

    saida_ids = [m.id for m in movimentos_saidas]
    movimentos_entradas = []
    if saida_ids:
        movimentos_entradas = VehicleMov.query.filter(
            VehicleMov.tipo == "entrada",
            VehicleMov.saida_id.in_(saida_ids)
        ).all()
    entradas_por_saida = {e.saida_id: e for e in movimentos_entradas}

    # Gerar PDF consolidado
    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)

    plate_safe = v.plate.replace("-", "").strip().upper()
    dt_hoje = agora().strftime("%Y%m%d_%H%M%S")
    filename = f"consolidado_{plate_safe}_{start_str.replace('-', '')}_a_{end_str.replace('-', '')}_{dt_hoje}.pdf"
    out_path = REPORTS_DIR / filename

    # Estilos de texto
    styles = getSampleStyleSheet()
    
    # Adiciona estilos únicos apenas se não existirem
    try:
        styles.add(ParagraphStyle(
            name="ReportTitle",
            parent=styles["Heading1"],
            fontSize=18,
            leading=22,
            textColor=colors.HexColor("#1F3C78"),
            alignment=1, # Centralizado
            spaceAfter=15
        ))
    except Exception:
        pass

    try:
        styles.add(ParagraphStyle(
            name="SectionHeader",
            parent=styles["Heading2"],
            fontSize=12,
            leading=16,
            textColor=colors.HexColor("#1F3C78"),
            spaceBefore=12,
            spaceAfter=6,
            keepWithNext=True
        ))
    except Exception:
        pass

    try:
        styles.add(ParagraphStyle(
            name="TableText",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            textColor=colors.HexColor("#333333")
        ))
    except Exception:
        pass

    try:
        styles.add(ParagraphStyle(
            name="TableHeaderText",
            parent=styles["Normal"],
            fontSize=8,
            leading=10,
            fontName="Helvetica-Bold",
            textColor=colors.white
        ))
    except Exception:
        pass

    # Construção do documento
    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=20 * mm,
        bottomMargin=20 * mm
    )

    elements = []

    # Cabeçalho / Título do Relatório
    elements.append(Paragraph("<b>RELATÓRIO CONSOLIDADO DE FROTA</b>", styles["ReportTitle"]))
    elements.append(Spacer(1, 5))

    # Informações do Veículo & Período
    meta_info = [
        ["Veículo / Modelo", f"{v.brand or ''} {v.model or ''} ({v.year or 'N/A'})"],
        ["Placa", v.plate],
        ["KM Atual", f"{v.km or 0} KM"],
        ["Período", f"{start_date.strftime('%d/%m/%Y')} até {end_date.strftime('%d/%m/%Y')}"],
        ["Emissão", agora().strftime("%d/%m/%Y %H:%M:%S")]
    ]
    meta_table = Table(meta_info, colWidths=[50 * mm, 130 * mm])
    meta_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F4F4")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 4),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]))
    elements.append(meta_table)
    elements.append(Spacer(1, 15))

    # --- SEÇÃO 1: CHECKLISTS OPERACIONAIS ---
    elements.append(Paragraph("<b>1. Checklists Operacionais no Período</b>", styles["SectionHeader"]))
    if checklists:
        chk_data = [[
            Paragraph("<b>Data</b>", styles["TableHeaderText"]),
            Paragraph("<b>Técnico</b>", styles["TableHeaderText"]),
            Paragraph("<b>KM</b>", styles["TableHeaderText"]),
            Paragraph("<b>Status</b>", styles["TableHeaderText"]),
            Paragraph("<b>Observações</b>", styles["TableHeaderText"])
        ]]
        for c in checklists:
            obs_text = c.notes or "-"
            chk_data.append([
                Paragraph(c.date.strftime("%d/%m/%Y %H:%M"), styles["TableText"]),
                Paragraph(c.technician or "-", styles["TableText"]),
                Paragraph(f"{c.km} KM", styles["TableText"]),
                Paragraph(c.status or "OK", styles["TableText"]),
                Paragraph(obs_text, styles["TableText"])
            ])
        chk_table = Table(chk_data, colWidths=[30 * mm, 35 * mm, 20 * mm, 20 * mm, 75 * mm])
        chk_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3C78")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(chk_table)
    else:
        elements.append(Paragraph("Nenhum checklist operacional registrado no período.", styles["TableText"]))
    elements.append(Spacer(1, 15))

    # --- SEÇÃO 2: VISTORIAS DE LATARIA/VISUAIS ---
    elements.append(Paragraph("<b>2. Vistorias Visuais / Lataria no Período</b>", styles["SectionHeader"]))
    if vistorias:
        vist_data = [[
            Paragraph("<b>Data</b>", styles["TableHeaderText"]),
            Paragraph("<b>Usuário</b>", styles["TableHeaderText"]),
            Paragraph("<b>Turno</b>", styles["TableHeaderText"]),
            Paragraph("<b>Status Geral</b>", styles["TableHeaderText"]),
            Paragraph("<b>Avarias Detectadas / Obs</b>", styles["TableHeaderText"])
        ]]
        for vis in vistorias:
            avarias = []
            if vis.para_choque_dianteiro == "avaria": avarias.append("P.-choque diant.")
            if vis.para_choque_traseiro == "avaria": avarias.append("P.-choque tras.")
            if vis.lateral_esquerda == "avaria": avarias.append("Lat. esq.")
            if vis.lateral_direita == "avaria": avarias.append("Lat. dir.")
            if vis.capo == "avaria": avarias.append("Capô")
            if vis.teto == "avaria": avarias.append("Teto")
            if vis.porta_malas == "avaria": avarias.append("Porta-malas")
            if vis.retrovisores == "avaria": avarias.append("Retrovisores")
            if vis.farois_lanternas == "avaria": avarias.append("Faróis/lant.")
            if vis.vidros_parabrisa == "avaria": avarias.append("Vidros/para-brisa")
            if vis.pneus == "avaria": avarias.append("Pneus")
            if vis.calotas == "avaria": avarias.append("Calotas")

            status_text = "Com avarias" if vis.status_geral == "avarias" else "OK"
            avarias_desc = ", ".join(avarias) if avarias else "-"
            if vis.observacoes:
                avarias_desc += f" (Obs: {vis.observacoes})"

            user_str = vis.created_by_user.username if vis.created_by_user else "-"
            
            vist_data.append([
                Paragraph(vis.created_at.strftime("%d/%m/%Y %H:%M"), styles["TableText"]),
                Paragraph(user_str, styles["TableText"]),
                Paragraph(vis.turno.upper(), styles["TableText"]),
                Paragraph(status_text, styles["TableText"]),
                Paragraph(avarias_desc, styles["TableText"])
            ])
        vist_table = Table(vist_data, colWidths=[30 * mm, 30 * mm, 20 * mm, 25 * mm, 75 * mm])
        vist_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3C78")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(vist_table)
    else:
        elements.append(Paragraph("Nenhuma vistoria visual registrada no período.", styles["TableText"]))
    elements.append(Spacer(1, 15))

    # --- SEÇÃO 3: FLUXO DE ENTRADA E SAÍDA ---
    elements.append(Paragraph("<b>3. Movimentações de Entrada e Saída (Controle E/S)</b>", styles["SectionHeader"]))
    if movimentos_saidas:
        mov_data = [[
            Paragraph("<b>Saída</b>", styles["TableHeaderText"]),
            Paragraph("<b>Chegada</b>", styles["TableHeaderText"]),
            Paragraph("<b>KM Saída</b>", styles["TableHeaderText"]),
            Paragraph("<b>KM Chegada</b>", styles["TableHeaderText"]),
            Paragraph("<b>Responsável</b>", styles["TableHeaderText"]),
            Paragraph("<b>Obs.</b>", styles["TableHeaderText"])
        ]]
        for s in movimentos_saidas:
            c = entradas_por_saida.get(s.id)
            obs_mov = s.obs or "-"
            if c and c.obs:
                obs_mov += f" | Chegada: {c.obs}"
                
            mov_data.append([
                Paragraph(s.data_hora.strftime("%d/%m/%Y %H:%M"), styles["TableText"]),
                Paragraph(c.data_hora.strftime("%d/%m/%Y %H:%M") if c else "-", styles["TableText"]),
                Paragraph(f"{s.km} KM", styles["TableText"]),
                Paragraph(f"{c.km} KM" if c else "-", styles["TableText"]),
                Paragraph(s.responsavel, styles["TableText"]),
                Paragraph(obs_mov, styles["TableText"])
            ])
        mov_table = Table(mov_data, colWidths=[28 * mm, 28 * mm, 20 * mm, 22 * mm, 28 * mm, 54 * mm])
        mov_table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1F3C78")),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#DDDDDD")),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F9F9F9")]),
            ("PADDING", (0, 0), (-1, -1), 4),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ]))
        elements.append(mov_table)
    else:
        elements.append(Paragraph("Nenhuma movimentação de entrada/saída registrada no período.", styles["TableText"]))

    # Rodapé / Assinatura
    elements.append(Spacer(1, 20))
    elements.append(Paragraph("----------------------------------------------------------------------------------------------------------------------------------", styles["TableText"]))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph("<font color='#666666'>Relatório emitido pela plataforma de Checklist Veicular. Todos os dados são auditados e protegidos.</font>", styles["TableText"]))

    try:
        doc.build(elements)
        registrar_log(f"Relatório Consolidado de Frota gerado: {filename} (Veículo: {v.plate})")
        flash("✅ Relatório consolidado gerado com sucesso!", "success")
    except Exception as e:
        registrar_log(f"Erro ao gerar Relatório Consolidado: {str(e)}")
        flash("❌ Erro ao compilar o arquivo PDF do relatório.", "error")

    return redirect(url_for("reports"))

@app.route("/relatorios/download/<nome>")
@supervisor_allowed
def report_download(nome):
    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    return send_from_directory(str(REPORTS_DIR), nome)

@app.route("/relatorios/excluir/<nome>", methods=["POST"])
@supervisor_allowed
def report_delete(nome):
    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    path = REPORTS_DIR / nome
    if path.exists():
        path.unlink()
        flash(f"Relatório {nome} excluído.", "success")
    else:
        flash("Arquivo não encontrado.", "error")
    return redirect(url_for("reports"))

# ===============================
# 🏗️ MÓDULO: GESTÃO TÉCNICA
# ===============================
@app.route("/gestao-tecnica")
@supervisor_allowed
def gestao_tecnica():
    # Reconhecer todos os colaboradores para gestão técnica
    tecnicos = User.query.filter(User.username != 'admin').all()
    tecnicos_js_data = [{"id": t.id, "username": t.username} for t in tecnicos]
    return render_template("gestao_tecnica.html", tecnicos=tecnicos, tecnicos_js_data=tecnicos_js_data)


# --- AUXILIARES E USUÁRIOS ---
@app.route("/api/gestao/users", methods=["GET"])
@login_required
def api_gestao_users():
    users = User.query.order_by(User.username.asc()).all()
    return jsonify([{"id": u.id, "username": u.username} for u in users])

# --- CONFIGURAÇÃO GLOBAL DE ESCALAS ---
@app.route("/api/gestao/config", methods=["GET", "POST"])
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
        return jsonify({"status": "ok"})
    
    return jsonify({
        "scale_start_date": str(config.scale_start_date) if config.scale_start_date else "",
        "scale_rotation_order": config.scale_rotation_order or ""
    })

# --- GERADORES ---
@app.route("/api/gestao/geradores", methods=["GET", "POST"])
@app.route("/api/gestao/geradores/<int:id>", methods=["PUT", "DELETE"])
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
        
        g.name = data.get("name")
        g.location = data.get("location")
        g.capacity_total = float(data.get("capacity_total")) if data.get("capacity_total") else None
        g.current_qty = float(data.get("current_qty")) if data.get("current_qty") else None
        g.fuel_type = data.get("fuel_type")
        refill_date = data.get("last_refill_date")
        if refill_date:
            g.last_refill_date = datetime.strptime(refill_date, "%Y-%m-%d").date()
        g.responsible_id = int(data.get("responsible_id")) if data.get("responsible_id") else None
        g.status = data.get("status", "OPERACIONAL")
        g.obs = data.get("obs")
        g.reserve_cans = int(data.get("reserve_cans")) if data.get("reserve_cans") else None
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
@app.route("/api/gestao/rfo", methods=["GET", "POST"])
@app.route("/api/gestao/rfo/<int:id>", methods=["PUT", "DELETE"])
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
            data = request.json
        else:
            data = request.form

        rid = id or data.get("id")
        if rid:
            r = RFO.query.get(rid)
            if not r:
                return jsonify({"error": "RFO não encontrado"}), 404
        else:
            r = RFO()
            db.session.add(r)
        
        r.number = data.get("number")
        r.title = data.get("title")
        r.description = data.get("description")
        r.root_cause = data.get("root_cause")
        r.impact = data.get("impact")
        r.action = data.get("action")
        r.city = data.get("city")
        r.neighborhood = data.get("neighborhood")
        r.lat = data.get("lat")
        r.lon = data.get("lon")
        r.status = data.get("status", "ABERTO")
        r.problem_type = data.get("problem_type")
        r.tech_responsible = data.get("tech_responsible")
        r.team_id = int(data.get("team_id")) if data.get("team_id") else None
        
        date_str = data.get("date")
        if date_str:
            r.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        r.start_time = data.get("start_time")
        r.end_time = data.get("end_time")
        
        # Técnicos vinculados em JSON
        tech_ids = request.form.getlist("technicians[]") or data.get("technicians", [])
        if tech_ids:
            r.technicians_json = json.dumps(tech_ids)
        
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
@app.route("/api/gestao/supervisao", methods=["GET", "POST"])
@app.route("/api/gestao/supervisao/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_supervisao(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        s = SupervisaoTecnica.query.get_or_404(target_id)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        data = request.json or {}
        sid = id or data.get("id")
        if sid:
            s = SupervisaoTecnica.query.get(sid)
            if not s:
                return jsonify({"error": "Supervisão não encontrada"}), 404
        else:
            s = SupervisaoTecnica(supervisor_id=current_user.id)
            db.session.add(s)

        date_str = data.get("date")
        if date_str:
            s.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        s.time = data.get("time")
        s.irregularities = data.get("irregularities")
        s.action = data.get("action")
        s.obs = data.get("obs")
        s.checklist_json = json.dumps(data.get("checklist", {}))
        s.techs_data = data.get("techs_data", [])

        db.session.commit()
        return jsonify({"status": "ok", "id": s.id})

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
            "techs_data": i.techs_data
        })
    return jsonify(res)

# --- SOLICITAÇÕES OPERACIONAIS ---
@app.route("/api/gestao/solicitacoes", methods=["GET", "POST"])
@app.route("/api/gestao/solicitacoes/<int:id>", methods=["DELETE"])
@app.route("/api/gestao/solicitacoes/<int:id>/respond", methods=["POST"])
@login_required
def api_solicitacoes(id=None):
    if request.method == "DELETE":
        s = Solicitacao.query.get_or_404(id)
        db.session.delete(s)
        db.session.commit()
        return jsonify({"status": "ok"})

    if id and request.path.endswith("/respond"):
        if not current_user.is_supervisor and not current_user.is_admin:
            return jsonify({"error": "Não autorizado"}), 403
        data = request.json or {}
        s = Solicitacao.query.get_or_404(id)
        s.status = data.get("status", "APROVADA")
        s.management_response = data.get("management_response")
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method == "POST":
        data = request.json or {}
        s = Solicitacao(user_id=current_user.id)
        db.session.add(s)
        s.type = data.get("type", "TROCA_PLANTAO")
        s.description = data.get("description")
        s.obs = data.get("obs")
        s.status = "PENDENTE"
        db.session.commit()
        return jsonify({"status": "ok", "id": s.id})

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
@app.route("/api/gestao/equipes", methods=["GET", "POST"])
@app.route("/api/gestao/equipes/<int:id>", methods=["PUT", "DELETE"])
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
@app.route("/api/gestao/patios", methods=["GET", "POST"])
@app.route("/api/gestao/patios/<int:id>", methods=["PUT", "DELETE"])
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
@app.route("/api/gestao/encerramento", methods=["GET", "POST"])
@app.route("/api/gestao/encerramento/<int:id>", methods=["DELETE"])
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
            
        e.patio_id = int(data.get("patio_id")) if data.get("patio_id") else None
        date_str = data.get("date")
        if date_str:
            e.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        e.closing_time = data.get("closing_time")
        
        # Suporta tanto lista/dicionário quanto string para technicians_json e patios_json
        techs = data.get("technicians_json")
        if isinstance(techs, (list, dict)):
            e.technicians_json = json.dumps(techs)
        else:
            e.technicians_json = techs

        patios_js = data.get("patios_json")
        if isinstance(patios_js, (list, dict)):
            e.patios_json = json.dumps(patios_js)
        else:
            e.patios_json = patios_js

        e.obs = data.get("obs")
        db.session.commit()
        return jsonify({"status": "ok", "id": e.id})

    items = Encerramento.query.order_by(Encerramento.date.desc()).all()
    res = []
    for i in items:
        res.append({
            "id": i.id,
            "patio_id": i.patio_id,
            "patio_name": i.patio.name if i.patio else "N/A",
            "date": str(i.date) if i.date else "",
            "closing_time": i.closing_time,
            "technicians_json": i.technicians_json,
            "obs": i.obs,
            "patios_json": i.patios_json
        })
    return jsonify(res)

# --- TAREFAS ---
@app.route("/api/gestao/tarefas", methods=["GET", "POST"])
@app.route("/api/gestao/tarefas/<int:id>", methods=["PUT", "DELETE"])
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
            db.session.add(t)
        
        t.title = data.get("title")
        t.description = data.get("description")
        t.responsible_id = int(data.get("responsible_id")) if data.get("responsible_id") else None
        t.priority = data.get("priority", "MEDIA")
        
        deadline_str = data.get("deadline")
        if deadline_str:
            t.deadline = datetime.strptime(deadline_str, "%Y-%m-%d").date()
            
        t.status = data.get("status", "PENDENTE")
        t.obs = data.get("obs")
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
            "priority": i.priority,
            "deadline": str(i.deadline) if i.deadline else "",
            "status": i.status,
            "obs": i.obs
        })
    return jsonify(res)

# --- ESCALAS DE PLANTÃO (MANUAIS E AUTOMÁTICAS) ---
@app.route("/api/gestao/escalas", methods=["GET", "POST"])
@app.route("/api/gestao/escalas/<int:id>", methods=["PUT", "DELETE"])
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
        items = Scale.query.order_by(Scale.date.desc()).all()
        res = []
        for s in items:
            tech_names = ""
            if s.technician_ids:
                try:
                    ids = [int(x) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                    tech_names = ", ".join([u.username for u in User.query.filter(User.id.in_(ids))])
                except Exception:
                    tech_names = s.technician_ids
            res.append({
                "id": s.id,
                "type": s.type,
                "date": str(s.date),
                "obs": s.obs,
                "status": s.status,
                "technician_ids": s.technician_ids,
                "technician_names": tech_names,
                "team_ids": s.team_ids
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
    
    for s in items:
        manual_dates.add(s.date)
        tech_names = ""
        if s.technician_ids:
            try:
                ids = [int(x) for x in s.technician_ids.split(",") if x.strip().isdigit()]
                tech_names = ", ".join([u.username for u in User.query.filter(User.id.in_(ids))])
            except Exception:
                tech_names = "Técnicos"
                
        # Define cores premium específicas para cada tipo de escala manual
        m_color = "#10B981"  # Padrão: Emerald para Sábado
        if s.type == "domingo":
            m_color = "#6366F1"  # Indigo para Domingo
        elif s.type == "feriado":
            m_color = "#F59E0B"  # Amber/Orange para Feriado
            
        events.append({
            "id": f"m_{s.id}",
            "title": f"{s.type.upper()}: {tech_names or 'Plantonistas'}",
            "start": s.date.isoformat(),
            "allDay": True,
            "color": m_color,
            "extendedProps": {
                "type": "manual",
                "scale_type": s.type,
                "obs": s.obs
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
                            events.append({
                                "id": f"auto_{curr_date.isoformat()}",
                                "title": f"Plantão: {team.name}",
                                "start": curr_date.isoformat(),
                                "allDay": True,
                                "color": team.color or "#8B5CF6", # Premium Violet/custom
                                "extendedProps": {
                                    "type": "automatico",
                                    "team_id": team.id
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
            
    return jsonify(events)

@app.route("/api/gestao/proximos_feriados", methods=["GET"])
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
@app.route("/api/gestao/reunioes", methods=["GET", "POST"])
@app.route("/api/gestao/reunioes/<int:id>", methods=["PUT", "DELETE"])
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
@app.route("/api/gestao/anotacoes", methods=["GET", "POST"])
@app.route("/api/gestao/anotacoes/<int:id>", methods=["PUT", "DELETE"])
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
            "event_date": str(i.event_date) if i.event_date else ""
        })
    return jsonify(res)

# --- ATIVIDADES TÉCNICAS ---
@app.route("/api/gestao/atividades", methods=["GET", "POST"])
@app.route("/api/gestao/atividades/<int:id>", methods=["PUT", "DELETE"])
@supervisor_allowed
def api_atividades(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id):
        target_id = id or request.json.get("id")
        a = Activity.query.get_or_404(target_id)
        db.session.delete(a)
        db.session.commit()
        return jsonify({"status": "ok"})

    if request.method in ["POST", "PUT"]:
        if request.is_json:
            data = request.json
        else:
            data = request.form
            
        aid = id or data.get("id")
        if aid:
            a = Activity.query.get(aid)
            if not a:
                return jsonify({"error": "Atividade não encontrada"}), 404
        else:
            a = Activity(user_id=current_user.id)
            db.session.add(a)
            
        a.type = data.get("type")
        a.location = data.get("location")
        
        date_str = data.get("date")
        if date_str:
            a.date = datetime.strptime(date_str, "%Y-%m-%d").date()
            
        a.time = data.get("time")
        a.description = data.get("description")
        a.status = data.get("status", "ABERTO")
        a.obs = data.get("obs")
        a.tech_responsible = data.get("tech_responsible")
        a.client_name = data.get("client_name")
        a.client_code = data.get("client_code")
        a.quality_rating = data.get("quality_rating")
        a.client_feedback = data.get("client_feedback")
        a.os_closure = data.get("os_closure")
        a.conclusion = data.get("conclusion")
        
        # Upload de fotos
        photos = request.files.getlist("photos") or request.files.getlist("photos[]")
        filenames = json.loads(a.photos_json) if a.photos_json else []
        for p in photos:
            if p and allowed_file(p.filename):
                ext = os.path.splitext(p.filename.lower())[1]
                fn = f"act_{uuid.uuid4().hex}{ext}"
                p.save(VISTORIAS_UPLOAD_DIR / fn)
                filenames.append(fn)
        if filenames:
            a.photos_json = json.dumps(filenames)
            
        db.session.commit()
        return jsonify({"status": "ok", "id": a.id})

    items = Activity.query.order_by(Activity.date.desc().nullslast()).all()
    res = []
    for i in items:
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
            "obs": i.obs,
            "tech_responsible": i.tech_responsible,
            "client_name": i.client_name,
            "client_code": i.client_code,
            "quality_rating": i.quality_rating,
            "client_feedback": i.client_feedback,
            "os_closure": i.os_closure,
            "conclusion": i.conclusion
        })
    return jsonify(res)

# --- ROTA EXATA (AUDITORIA DE TRAJETOS) ---
@app.route("/api/gestao/rota_exata", methods=["GET", "POST"])
@app.route("/api/gestao/rota_exata/<int:id>", methods=["GET", "PUT", "DELETE"])
@supervisor_allowed
def api_rota_exata(id=None):
    if request.method == "DELETE" or (request.method == "POST" and id and not request.path.endswith("/pdf")):
        target_id = id or request.json.get("id")
        r = RotaExata.query.get_or_404(target_id)
        db.session.delete(r)
        db.session.commit()
        return jsonify({"status": "ok"})

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

        date_str = data.get("date")
        if date_str:
            r.date = datetime.strptime(date_str, "%Y-%m-%d").date()
        r.time = data.get("time")
        r.location = data.get("location")
        r.obs = data.get("obs")
        r.status = data.get("status", "PENDENTE")
        
        # Suporta tanto objeto quanto string serializada para techs_data
        techs = data.get("techs_data")
        if isinstance(techs, (list, dict)):
            r.techs_data = techs
        elif isinstance(techs, str):
            try:
                r.techs_data = json.loads(techs)
            except Exception:
                r.techs_data = []

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
        return jsonify({"status": "ok", "id": r.id})

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
@app.route("/api/gestao/<string:slug>/<int:id>/status", methods=["POST"])
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
    else:
        return jsonify({"error": "Módulo inválido"}), 400

    obj.status = new_status
    db.session.commit()
    return jsonify({"status": "ok"})

# ==========================================
# 🔥 GERADORES DE RELATÓRIO PDF PREMIUM 🔥
# ==========================================

def make_premium_pdf(buffer, title, metadata, content_table_data):
    from reportlab.lib.pagesizes import A4
    from reportlab.lib import colors
    from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

    doc = SimpleDocTemplate(
        buffer,
        pagesize=A4,
        rightMargin=15*mm, leftMargin=15*mm,
        topMargin=15*mm, bottomMargin=15*mm
    )

    styles = getSampleStyleSheet()
    
    # Custom styles
    title_style = ParagraphStyle(
        name="PremiumTitle",
        parent=styles["Heading1"],
        fontName="Helvetica-Bold",
        fontSize=18,
        textColor=colors.HexColor("#0F172A"),
        spaceAfter=15
    )
    
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

    # 1. Logo/Header Placeholder or Decorative Banner
    story.append(Paragraph(title, title_style))
    story.append(Spacer(1, 5*mm))

    # 2. Metadata Grid
    meta_table_data = []
    keys = list(metadata.keys())
    for i in range(0, len(keys), 2):
        k1 = keys[i]
        v1 = metadata[k1]
        row = [
            Paragraph(f"<b>{k1}:</b>", label_style),
            Paragraph(str(v1), value_style)
        ]
        if i + 1 < len(keys):
            k2 = keys[i+1]
            v2 = metadata[k2]
            row.extend([
                Paragraph(f"<b>{k2}:</b>", label_style),
                Paragraph(str(v2), value_style)
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
    story.append(Spacer(1, 10*mm))

    # 3. Main content
    story.append(Paragraph("<b>Detalhamento do Registro</b>", styles["Heading2"]))
    story.append(Spacer(1, 3*mm))

    content_rows = []
    for k, v in content_table_data:
        content_rows.append([
            Paragraph(f"<b>{k}</b>", label_style),
            Paragraph(str(v), value_style)
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

    doc.build(story)

@app.route("/api/gestao/encerramento/<int:id>/pdf", methods=["GET"])
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
                # busca usernames
                techs_str = ", ".join([u.username for u in User.query.filter(User.id.in_([int(x) for x in techs]))])
        except Exception:
            techs_str = str(e.technicians_json)

    metadata = {
        "Pátio": e.patio.name if e.patio else "N/A",
        "Data": e.date.strftime("%d/%m/%Y") if e.date else "N/A",
        "Horário de Fechamento": e.closing_time or "N/A",
        "Técnicos Presentes": techs_str
    }

    patios_str = ""
    if e.patios_json:
        try:
            pjs = json.loads(e.patios_json)
            if isinstance(pjs, list):
                patios_str = "\n".join([f"- {p.get('name')}: {p.get('status')}" for p in pjs])
        except Exception:
            patios_str = str(e.patios_json)

    content = [
        ("Status dos Veículos por Pátio", patios_str or "Sem observações detalhadas de pátio"),
        ("Observações Gerais", e.obs or "Nenhuma observação informada.")
    ]

    make_premium_pdf(buffer, "Relatório de Encerramento de Pátio", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"encerramento_patio_{id}.pdf"
    )

@app.route("/api/gestao/atividades/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def atividade_pdf(id):
    import io
    from flask import send_file
    
    a = Activity.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "Tipo de Atividade": a.type or "N/A",
        "Localização": a.location or "N/A",
        "Data": a.date.strftime("%d/%m/%Y") if a.date else "N/A",
        "Horário": a.time or "N/A",
        "Técnico Responsável": a.tech_responsible or "N/A"
    }

    content = [
        ("Cliente", f"{a.client_name or 'N/A'} (Cód: {a.client_code or 'N/A'})"),
        ("Status da O.S.", a.os_closure or "N/A"),
        ("Descrição dos Serviços", a.description or "Sem descrição"),
        ("Conclusão Técnica", a.conclusion or "N/A"),
        ("Avaliação de Qualidade", a.quality_rating or "N/A"),
        ("Feedback do Cliente", a.client_feedback or "Sem feedback"),
        ("Observações", a.obs or "Sem observações")
    ]

    make_premium_pdf(buffer, "Relatório de Atividade Técnica", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"atividade_tecnica_{id}.pdf"
    )

@app.route("/api/gestao/reunioes/<int:id>/pdf", methods=["GET"])
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
            parts_str = ", ".join([u.username for u in User.query.filter(User.id.in_(pids))])
        except Exception:
            parts_str = m.participants

    metadata = {
        "Assunto": m.subject or "N/A",
        "Data": m.date.strftime("%d/%m/%Y") if m.date else "N/A",
        "Horário": m.time or "N/A",
        "Local/Link": m.location or "N/A",
        "Responsável": m.responsible or "N/A"
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

@app.route("/api/gestao/rfo/<int:id>/pdf", methods=["GET"])
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
                techs_str = ", ".join([u.username for u in User.query.filter(User.id.in_([int(x) for x in techs]))])
        except Exception:
            techs_str = str(r.technicians_json)

    metadata = {
        "Número RFO": r.number or "N/A",
        "Cidade / Bairro": f"{r.city or 'N/A'} / {r.neighborhood or 'N/A'}",
        "Data": r.date.strftime("%d/%m/%Y") if r.date else "N/A",
        "Horário": f"{r.start_time or 'N/A'} até {r.end_time or 'N/A'}",
        "Técnico Responsável": r.tech_responsible or "N/A"
    }

    content = [
        ("Tipo de Problema", r.problem_type or "N/A"),
        ("Equipe Associada", r.team.name if r.team else "N/A"),
        ("Técnicos de Campo", techs_str),
        ("Descrição da Ocorrência", r.description or "Sem descrição"),
        ("Causa Raiz", r.root_cause or "Não informada"),
        ("Impacto Causado", r.impact or "Não informado"),
        ("Ações Corretivas / Plano", r.action or "Não informado"),
        ("Coordenadas GPS", f"{r.lat or 'N/A'}, {r.lon or 'N/A'}")
    ]

    make_premium_pdf(buffer, f"Relatório de Ocorrência (RFO): {r.title}", metadata, content)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"rfo_{r.number or id}.pdf"
    )

@app.route("/api/gestao/rota_exata/<int:id>/pdf", methods=["GET"])
@supervisor_allowed
def rota_exata_pdf(id):
    import io
    from flask import send_file
    
    r = RotaExata.query.get_or_404(id)
    buffer = io.BytesIO()

    metadata = {
        "Supervisor": r.supervisor.username if r.supervisor else "N/A",
        "Data de Auditoria": r.date.strftime("%d/%m/%Y") if r.date else "N/A",
        "Horário": r.time or "N/A",
        "Ponto de Checagem": r.location or "N/A",
        "Status da Auditoria": r.status or "PENDENTE"
    }

    techs_str = ""
    if r.techs_data:
        try:
            if isinstance(r.techs_data, list):
                techs_str = "\n".join([f"- Técnico ID {t.get('tech_id')}: {t.get('status')} (Chegada: {t.get('arrival_time')}, Saída: {t.get('departure_time')})" for t in r.techs_data])
            else:
                techs_str = str(r.techs_data)
        except Exception:
            techs_str = str(r.techs_data)

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



    p = RELATORIOS_DIR / nome
    if p.exists():
        p.unlink()
        registrar_log(f"Relatório excluído: {nome}")
        flash("Relatório excluído!", "success")
    else:
        flash("Arquivo não encontrado.", "error")

    return redirect(url_for("reports"))


@app.route("/relatorios/upload", methods=["POST"])
@login_required
def report_upload():
    if not current_user.is_admin:
        abort(403)

    f = request.files.get("arquivo")
    if not f or f.filename == "":
        flash("Selecione um arquivo.", "error")
        return redirect(url_for("reports"))

    name = secure_filename(f.filename)

    RELATORIOS_DIR.mkdir(exist_ok=True)
    f.save(RELATORIOS_DIR / name)

    registrar_log(f"Relatório enviado: {name}")
    flash("Relatório enviado!", "success")
    return redirect(url_for("reports"))


# ----------------- LISTAGEM / DETALHE DE CHECKLISTS -----------------
@app.route("/checklists")
@supervisor_allowed
def checklists():
    q = request.args.get("q", "").strip().lower()

    query = Checklist.query.join(Vehicle, Checklist.vehicle_id == Vehicle.id)

    if q:
        query = query.filter(
            db.or_(
                Vehicle.plate.ilike(f"%{q}%"),
                Checklist.technician.ilike(f"%{q}%"),
                Checklist.status.ilike(f"%{q}%"),
            )
        )

    itens = query.order_by(Checklist.date.desc()).all()
    return render_template("checklists.html", itens=itens, q=q)


@app.route("/checklists/<int:cid>")
@supervisor_allowed
def checklist_detail(cid):
    c = Checklist.query.get_or_404(cid)
    try:
        data = json.loads(c.raw_json) if c.raw_json else {}
    except Exception:
        data = {}

    photos = data.get("photos", [])
    items = data.get("items", {})
    return render_template("checklist_detail.html", c=c, items=items, photos=photos)


@app.route("/checklists/<int:cid>/excluir", methods=["POST"])
@supervisor_allowed
def checklist_delete(cid):
    c = Checklist.query.get_or_404(cid)
    try:
        db.session.delete(c)
        db.session.commit()
        registrar_log(f"Checklist excluído: ID {cid} (Técnico: {c.technician})")
        flash("Checklist excluído com sucesso.", "success")
    except Exception as e:
        db.session.rollback()
        flash(f"Erro ao excluir checklist: {e}", "error")
    return redirect(url_for("checklists"))




# ----------------- CONFIGURAÇÃO DO CHECKLIST (ITENS + MODO) -----------------
@app.route("/config-checklist")
@admin_required
def config_checklist():
    items = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(mode="start_only")
        db.session.add(config)
        db.session.commit()
    return render_template("config_checklist.html", items=items, config=config)


@app.route("/config-checklist/mode", methods=["POST"])
@admin_required
def config_checklist_mode():
    mode = request.form.get("mode", "start_only")

    allowed = {"disabled", "start_only", "start_end"}
    if mode not in allowed:
        mode = "start_only"

    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(mode=mode)
        db.session.add(config)
    else:
        config.mode = mode

    db.session.commit()
    registrar_log(f"Modo do checklist atualizado para: {mode}")
    flash("Modo do checklist atualizado.", "success")
    return redirect(url_for("config_checklist"))


@app.route("/config-checklist/novo", methods=["POST"])
@admin_required
def config_checklist_new():
    text_ = request.form.get("text", "").strip()
    required = request.form.get("required") == "on"
    require_justif_no = request.form.get("require_justif_no") == "on"
    typ = request.form.get("type", "texto_curto")
    opts_raw = (request.form.get("options") or "").strip()

    if not text_:
        flash("Texto é obrigatório.", "error")
        return redirect(url_for("config_checklist"))

    opts = opts_raw or None

    last = db.session.query(db.func.max(ChecklistItem.order)).scalar() or 0
    db.session.add(
        ChecklistItem(
            order=last + 1,
            text=text_,
            required=required,
            require_justif_no=require_justif_no,
            type=typ,
            options=opts,
        )
    )
    db.session.commit()

    registrar_log(f"Item de checklist adicionado: {text_}")
    flash("Item adicionado.", "success")
    return redirect(url_for("config_checklist"))


@app.route("/config-checklist/<int:iid>/editar", methods=["POST"])
@admin_required
def config_checklist_edit(iid):
    it = ChecklistItem.query.get_or_404(iid)

    it.text = request.form.get("text", "").strip()
    it.required = request.form.get("required") == "on"
    it.require_justif_no = request.form.get("require_justif_no") == "on"
    it.type = request.form.get("type", "texto_curto")

    opts_raw = (request.form.get("options") or "").strip()
    it.options = opts_raw or None

    db.session.commit()

    registrar_log(f"Item de checklist editado: {it.text} (id={iid})")
    flash("Item atualizado.", "success")
    return redirect(url_for("config_checklist"))


@app.route("/config-checklist/<int:iid>/excluir", methods=["POST"])
@admin_required
def config_checklist_del(iid):
    it = ChecklistItem.query.get_or_404(iid)
    texto = it.text

    db.session.delete(it)
    db.session.commit()

    # reajustar ordem
    items = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    for idx, x in enumerate(items, start=1):
        x.order = idx
    db.session.commit()

    registrar_log(f"Item de checklist excluído: {texto} (id={iid})")
    flash("Item excluído.", "success")
    return redirect(url_for("config_checklist"))


@app.route("/config-checklist/<int:iid>/mover", methods=["POST"])
@admin_required
def config_checklist_move(iid):
    direction = request.form.get("dir", "up")
    it = ChecklistItem.query.get_or_404(iid)

    items = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    pos = items.index(it)

    if direction == "up" and pos > 0:
        items[pos].order, items[pos - 1].order = items[pos - 1].order, items[pos].order
    elif direction == "down" and pos < len(items) - 1:
        items[pos].order, items[pos + 1].order = items[pos + 1].order, items[pos].order

    db.session.commit()

    registrar_log(f"Item de checklist movido: {it.text} (id={iid}, dir={direction})")
    flash("Ordem atualizada.", "success")
    return redirect(url_for("config_checklist"))


# ----------------- GERADOR DE PDF -----------------
def generate_checklist_pdf(checklist_obj: Checklist, raw: dict) -> str:
    from reportlab.lib.pagesizes import A4
    from reportlab.lib.units import mm
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image as RLImage
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    import datetime

    # timezone seguro
    try:
        from zoneinfo import ZoneInfo
        UTC = ZoneInfo("UTC")
        BRT = ZoneInfo("America/Sao_Paulo")
    except Exception:
        from datetime import timezone, timedelta
        UTC = timezone.utc
        BRT = timezone(timedelta(hours=-3))

    RELATORIOS_DIR.mkdir(parents=True, exist_ok=True)
    plate = checklist_obj.vehicle.plate if checklist_obj.vehicle else "SEM_PLACA"
    safe_user = (checklist_obj.technician or "tecnico").replace(" ", "_")

    dt_utc = checklist_obj.date.replace(tzinfo=UTC) if checklist_obj.date.tzinfo is None else checklist_obj.date.astimezone(UTC)
    dt_brt = dt_utc.astimezone(BRT)
    dt_str = dt_brt.strftime("%Y-%m-%d_%Hh%M")
    now_brt_str = datetime.datetime.now(BRT).strftime("%d/%m/%Y %H:%M")

    filename = f"checklist_{safe_user}_{plate}_{dt_str}.pdf"
    out_path = RELATORIOS_DIR / filename

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodyJustify", parent=styles["Normal"], leading=14))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading3"], spaceAfter=6,
                              textColor=colors.HexColor("#1F3C78")))

    AZUL = colors.Color(25/255, 60/255, 120/255)
    CINZA_TEXTO = colors.HexColor("#4D4D4D")

    RODAPE_LINHAS = [
        "ADAPT LINK SERVIÇOS EM COMUNICAÇÃO MULTIMÍDIA EIRELI",
        "CNPJ: 08.980.148/0001-41       Inscr. Est.: 78.342.480",
        "Rua Waldir Pedro de Medeiros, 253 – São Miguel – Seropédica – RJ",
        "CEP: 23.893-725",
        "Tel.: (21) 3812-5900 / (21) 2682-7822",
        "WWW.ADAPTLINK.COM.BR",
    ]

    def header_footer_factory(titulo: str, subtitulo: str):
        def _on_page(c, doc):
            width, height = A4
            if LOGO_PATH.exists():
                try:
                    c.drawImage(LOGO_PATH, 15*mm, height-28*mm, 28*mm, 14*mm,
                                preserveAspectRatio=True, mask="auto")
                except Exception:
                    pass
            c.setStrokeColor(AZUL)
            c.setLineWidth(1.0)
            c.line(15*mm, height-32*mm, width-15*mm, height-32*mm)
            c.setFont("Helvetica-Bold", 14)
            c.setFillColor(AZUL)
            c.drawCentredString(width/2, height-17*mm, titulo)
            c.setFont("Helvetica", 11)
            c.setFillColor(colors.black)
            c.drawCentredString(width/2, height-24*mm, subtitulo)
            c.setFont("Helvetica", 8)
            c.setFillColor(CINZA_TEXTO)
            c.drawString(15*mm, height-36*mm, f"Emitido em: {now_brt_str}")
            c.drawRightString(width-15*mm, height-36*mm, "Relatório gerado automaticamente")

            footer_line_y = 32*mm
            c.setStrokeColor(colors.HexColor("#BBBBBB"))
            c.setLineWidth(0.8)
            c.line(15*mm, footer_line_y, width-15*mm, footer_line_y)
            c.setFont("Helvetica", 8)
            c.setFillColor(colors.HexColor("#6E6E6E"))
            y = 28*mm
            for linha in RODAPE_LINHAS:
                c.drawCentredString(width/2, y, linha)
                y -= 4*mm
            c.setFont("Helvetica-Oblique", 8)
            c.drawRightString(width-15*mm, 6*mm, f"Página {c.getPageNumber()}")
        return _on_page

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        rightMargin=20 * mm,
        leftMargin=20 * mm,
        topMargin=45 * mm,
        bottomMargin=40 * mm
    )

    elements = []

    # Cabeçalho / meta
    elements.append(Paragraph("<b>Informações do Checklist</b>", styles["SectionTitle"]))
    meta_data = [
        ["Técnico", checklist_obj.technician or "-"],
        ["Placa", plate],
        ["Veículo", f"{checklist_obj.vehicle.brand or ''} {checklist_obj.vehicle.model or ''}".strip()],
        ["KM", str(checklist_obj.km)],
        ["Data", dt_brt.strftime("%d/%m/%Y %H:%M")],
        ["Status", checklist_obj.status],
    ]

    t = Table(meta_data, colWidths=[40 * mm, 110 * mm])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#707070")),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("ROWBACKGROUNDS", (0, 0), (-1, -1), [colors.white, colors.HexColor("#F4F4F4")]),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 10))

    # Itens
    elements.append(Paragraph("<b>Itens Verificados</b>", styles["SectionTitle"]))
    data_tbl = [["Item", "Resposta", "Justificativa"]]
    items = raw.get("items", {})

    for nome, val in items.items():
        resp = val.get("resposta", "")
        if isinstance(resp, list):
            resp = ", ".join(map(str, resp))
        just = val.get("justificativa", "") or "-"

        data_tbl.append([
            Paragraph(nome, styles["BodyJustify"]),
            Paragraph(str(resp), styles["BodyJustify"]),
            Paragraph(just, styles["BodyJustify"]),
        ])

    tbl = Table(data_tbl, colWidths=[80 * mm, 35 * mm, 45 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 10))

    photos = raw.get("photos", [])
    if photos:
        elements.append(Paragraph("<b>Fotos Registradas</b>", styles["SectionTitle"]))
        for p in photos[:6]:
            try:
                img_path = BASE_DIR / p.lstrip("/")
                if not img_path.exists():
                    img_path = BASE_DIR / "static" / Path(p).name
                img = RLImage(str(img_path), width=60 * mm, height=45 * mm)
                elements.append(img)
                elements.append(Spacer(1, 5))
            except Exception:
                continue

    elements.append(Spacer(1, 15))
    elements.append(Paragraph("<b>Assinatura do Técnico</b>", styles["SectionTitle"]))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph(f"Nome: {checklist_obj.technician or '-'}", styles["BodyJustify"]))
    elements.append(Paragraph(f"Data: {dt_brt.strftime('%d/%m/%Y %H:%M')}", styles["BodyJustify"]))

    doc.build(
        elements,
        onFirstPage=header_footer_factory(
            "RELATÓRIO DE CHECKLIST VEICULAR",
            f"Veículo: {plate}  |  Técnico: {checklist_obj.technician or '-'}",
        ),
        onLaterPages=header_footer_factory(
            "RELATÓRIO DE CHECKLIST VEICULAR",
            f"Veículo: {plate}  |  Técnico: {checklist_obj.technician or '-'}",
        )
    )

    return str(out_path)


# ----------------- CHECKLIST TÉCNICO (MODO) -----------------
@app.route("/checklist", methods=["GET", "POST"])
@login_required
def checklist_mobile():
    vehicles = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    items_qs = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    success = False

    config = SystemConfig.query.first()
    mode = config.mode if config else "start_only"

    # se desativado, não permite nem GET nem POST
    if mode == "disabled":
        flash("Checklist desativado pelo supervisor.", "error")
        return render_template(
            "checklist_mobile.html",
            vehicles=[],
            items=[],
            success=False,
            disabled=True
        )

    if request.method == "POST":
        vehicle_id = request.form.get("vehicle_id")
        km = request.form.get("km") or 0
        tech = current_user.username

        if not vehicle_id:
            flash("Selecione um veículo.", "error")
            return redirect(url_for("checklist_mobile"))

        try:
            km = int(km)
        except ValueError:
            flash("KM inválido.", "error")
            return redirect(url_for("checklist_mobile"))

        # =====================================================
        # 🔥 CORRIGIDO: PEGAR DATA LOCAL REAL
        # =====================================================
        today = agora().date()

        q_today = Checklist.query.filter(
            Checklist.technician == tech,
            db.func.date(Checklist.date) == today
        )

        # regras por modo
        if mode == "start_only":
            if q_today.count() >= 1:
                flash("Você já realizou o checklist de início hoje.", "error")
                return redirect(url_for("checklist_mobile"))

        elif mode == "start_end":
            count_today = q_today.count()
            v_id_int = int(vehicle_id)

            if count_today >= 2:
                flash("Você já realizou checklist de início e chegada hoje.", "error")
                return redirect(url_for("checklist_mobile"))

            if count_today == 1:
                first = q_today.order_by(Checklist.date.asc()).first()
                if first.vehicle_id != v_id_int:
                    flash("O checklist de chegada deve ser feito para o mesmo veículo do início.", "error")
                    return redirect(url_for("checklist_mobile"))

        # 🔍 VALIDAÇÃO DE KM
        v = Vehicle.query.get(vehicle_id)
        if v:
            km_atual = v.km or 0

            if km < km_atual:
                flash(
                    f"A quilometragem informada ({km} km) é inferior ao KM atual do veículo ({km_atual} km).",
                    "error"
                )
                return redirect(url_for("checklist_mobile"))

        # monta respostas
        respostas = {}
        for idx, item in enumerate(items_qs, start=1):
            key = f"item{idx}"
            if item.type == "checkboxes":
                val = request.form.getlist(key)
            else:
                val = request.form.get(key)

            just = request.form.get(f"{key}_just", "").strip()

            if item.required and ((item.type == "checkboxes" and not val) or (item.type != "checkboxes" and not val)):
                flash(f'Item {idx:02d} "{item.text}" é obrigatório.', "error")
                return redirect(url_for("checklist_mobile"))

            if item.type == "sim_nao_na" and item.require_justif_no and val == "Não" and not just:
                flash(f'Item {idx:02d} "{item.text}" requer justificativa quando "Não".', "error")
                return redirect(url_for("checklist_mobile"))

            respostas[f"{idx:02d} - {item.text}"] = {
                "tipo": item.type,
                "resposta": val,
                "justificativa": just or None
            }

        files = request.files.getlist("fotos")
        photos = save_photos(files) if files else []

        # =====================================================
        # 🔥 CORRIGIDO: DATA DE ENVIO SEM UTC
        # =====================================================
        raw = {
            "items": respostas,
            "photos": photos,
            "tecnico": tech,
            "veiculo": vehicle_id,
            "km": km,
            "data_envio": agora().strftime("%d/%m/%Y %H:%M"),
        }

        # =====================================================
        # 🔥 CORRIGIDO: NÃO USAR datetime.utcnow()
        # =====================================================
        checklist = Checklist(
            vehicle_id=vehicle_id,
            technician=tech,
            date=agora(),
            km=km,
            status="OK",
            notes="Checklist via web",
            raw_json=json.dumps(raw, ensure_ascii=False),
        )
        db.session.add(checklist)

        # Atualiza KM APENAS se maior
        if v and km > (v.km or 0):
            v.km = km

        db.session.commit()

        try:
            generate_checklist_pdf(checklist, raw)
        except Exception as e:
            print("⚠️ Erro gerando PDF:", e)

        registrar_log(f"Checklist criado para veículo ID={vehicle_id} por {tech}")
        flash("✅ Checklist enviado com sucesso!", "success")
        success = True

    return render_template("checklist_mobile.html", vehicles=vehicles, items=items_qs, success=success)




# ----------------- PERFIL -----------------
@app.get("/perfil")
@login_required
def perfil():
    return render_template("perfil.html", user=current_user)

@app.post("/perfil/alterar-senha")
@login_required
def perfil_alterar_senha():
    current_password = (request.form.get("current_password") or "").strip()
    new_password = (request.form.get("new_password") or "").strip()
    confirm_password = (request.form.get("confirm_password") or "").strip()

    if not current_password or not new_password or not confirm_password:
        flash("Preencha todos os campos.", "error")
        return redirect(request.referrer or url_for("perfil"))

    # ⚠️ Ajuste o nome do campo conforme seu model (ex: password_hash)
    if not check_password_hash(current_user.password_hash, current_password):
        flash("Senha atual incorreta.", "error")
        return redirect(request.referrer or url_for("perfil"))

    if new_password != confirm_password:
        flash("A confirmação não confere.", "error")
        return redirect(request.referrer or url_for("perfil"))

    if len(new_password) < 6:
        flash("A nova senha deve ter no mínimo 6 caracteres.", "error")
        return redirect(request.referrer or url_for("perfil"))

    current_user.password_hash = generate_password_hash(new_password)
    db.session.commit()

    flash("Senha alterada com sucesso!", "success")
    return redirect(request.referrer or url_for("perfil"))



# ----------------- LOGS DO SISTEMA (ADMIN) -----------------
@app.route("/logs")
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


@app.route("/vistorias")
@supervisor_allowed
def vistorias_list():
    periodo = request.args.get("periodo", "")
    veiculo_id = (request.args.get("veiculo") or "").strip()
    status = (request.args.get("status") or "").strip()  # ok | avarias | ""

    dt_inicio, dt_fim = parse_periodo(periodo)

    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()

    q = Vistoria.query

    if veiculo_id.isdigit():
        q = q.filter(Vistoria.vehicle_id == int(veiculo_id))

    if status in ("ok", "avarias"):
        q = q.filter(Vistoria.status_geral == status)

    if dt_inicio and dt_fim:
        q = q.filter(Vistoria.created_at >= dt_inicio, Vistoria.created_at <= dt_fim)

    registros = q.order_by(Vistoria.id.desc()).limit(80).all()

    return render_template(
        "vistorias_list.html",
        veiculos=veiculos,
        registros=registros,
        periodo=periodo
    )


@app.route("/vistorias/nova", methods=["GET", "POST"])
@supervisor_allowed
def vistorias_nova():
    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()

    ITENS = [
        "para_choque_dianteiro",
        "para_choque_traseiro",
        "lateral_esquerda",
        "lateral_direita",
        "capo",
        "teto",
        "porta_malas",
        "retrovisores",
        "farois_lanternas",
        "vidros_parabrisa",
        "pneus",
        "calotas",
    ]

    if request.method == "POST":
        vehicle_id = (request.form.get("vehicle_id") or "").strip()
        km = (request.form.get("km") or "").strip()
        turno = request.form.get("turno", "fim")
        local = (request.form.get("local") or "").strip() or None
        observacoes = (request.form.get("observacoes") or "").strip() or None

        if not vehicle_id.isdigit():
            flash("Selecione um veículo válido.", "error")
            return render_template("vistorias_nova.html", veiculos=veiculos)

        # 1) Status dos itens
        campos_status = {k: (request.form.get(k) or "ok") for k in ITENS}

        # 2) Observações por item
        campos_obs = {}
        for k in ITENS:
            obs_val = (request.form.get(f"obs_{k}") or "").strip()
            campos_obs[f"obs_{k}"] = obs_val or None

        # 3) Status geral automático
        status_geral = "avarias" if any(v == "avaria" for v in campos_status.values()) else "ok"

        # 4) Cria vistoria
        v = Vistoria(
            vehicle_id=int(vehicle_id),
            km=int(km) if km.isdigit() else None,
            turno=turno,
            local=local,
            status_geral=status_geral,
            observacoes=observacoes,
            created_by=current_user.id if getattr(current_user, "is_authenticated", False) else None,
            **campos_status,
            **campos_obs,
        )

        db.session.add(v)
        db.session.flush()  # garante v.id

        # 5) Pasta de upload (garante)
        VISTORIAS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

        # 6) Fotos por item (MULTIPLE)
        saved = 0
        rejected = 0

        for k in ITENS:
            # ✅ bate com o name do input: foto_<item>[]
            files = request.files.getlist(f"foto_{k}[]")
            if not files:
                continue

            for file in files:
                if not file or not file.filename:
                    continue

                if not allowed_file(file.filename):
                    rejected += 1
                    continue

                ext = os.path.splitext(file.filename)[1].lower()
                filename = f"vistoria_{v.id}_{k}_{uuid.uuid4().hex}{ext}"
                path = VISTORIAS_UPLOAD_DIR / filename

                try:
                    file.save(str(path))
                    db.session.add(VistoriaFoto(
                        vistoria_id=v.id,
                        filename=filename,
                        item_key=k
                    ))
                    saved += 1
                except Exception as e:
                    print("Erro salvando foto:", k, e)
                    rejected += 1

        db.session.commit()

        if rejected:
            flash(f"Vistoria registrada. Fotos salvas: {saved}. Rejeitadas: {rejected}", "success")
        else:
            flash(f"Vistoria registrada. Fotos salvas: {saved}", "success")

        return redirect(url_for("vistorias_list", open_id=v.id))

    return render_template("vistorias_nova.html", veiculos=veiculos)


# ----------------- ROTAS: COMUNICAÇÕES (AVISOS) -----------------
@app.route("/avisos")
@login_required
def avisos():
    notifications = Announcement.query.order_by(Announcement.created_at.desc()).all()
    # Adicionando manuais para evitar UndefinedError no template
    manuais = {
        'admin_supervisor': '',
        'tecnico_manutencao': ''
    }
    return render_template("avisos.html", notifications=notifications, manuais=manuais)

@app.route("/avisos/novo", methods=["POST"])
@supervisor_allowed
def avisos_novo():
    title = request.form.get("title")
    message = request.form.get("message")
    category = request.form.get("category", "Geral")
    
    if title and message:
        a = Announcement(
            title=title,
            message=message,
            category=category,
            created_by=current_user.id
        )
        db.session.add(a)
        db.session.commit()
        flash("Comunicado enviado com sucesso!", "success")
    else:
        flash("Título e mensagem são obrigatórios.", "error")
        
    return redirect(url_for("avisos"))

@app.route("/avisos/excluir/<int:aid>", methods=["POST"])
@supervisor_allowed
def avisos_excluir(aid):
    a = Announcement.query.get_or_404(aid)
    db.session.delete(a)
    db.session.commit()
    flash("Comunicado excluído.", "success")
    return redirect(url_for("avisos"))


@app.route("/rfo")
@supervisor_allowed
def rfo_list():
    return render_template("rfo_list.html")

@app.route("/geradores")
@supervisor_allowed
def geradores():
    return render_template("geradores.html")



@app.route("/vistorias/<int:vistoria_id>")
@supervisor_allowed
def vistorias_detail(vistoria_id):
    v = Vistoria.query.get_or_404(vistoria_id)

    fotos_por_item = defaultdict(list)
    for f in v.fotos:
        if f.item_key:
            fotos_por_item[f.item_key].append(f)

    if request.args.get("format") == "json":
        ITENS_INFO = [
            ('para_choque_dianteiro', 'Para-choque dianteiro'),
            ('para_choque_traseiro', 'Para-choque traseiro'),
            ('lateral_esquerda', 'Lateral esquerda'),
            ('lateral_direita', 'Lateral direita'),
            ('capo', 'Capô'),
            ('teto', 'Teto'),
            ('porta_malas', 'Porta-malas'),
            ('retrovisores', 'Retrovisores'),
            ('farois_lanternas', 'Faróis/Lanternas'),
            ('vidros_parabrisa', 'Vidros/Para-brisa'),
            ('pneus', 'Pneus'),
            ('calotas', 'Calotas')
        ]
        
        serialized_items = []
        for key, label in ITENS_INFO:
            serialized_items.append({
                "key": key,
                "label": label,
                "status": getattr(v, key, "ok"),
                "obs": getattr(v, f"obs_{key}", None) or "",
                "fotos": [f.filename for f in fotos_por_item[key]]
            })
            
        return jsonify({
            "id": v.id,
            "created_at": v.created_at.strftime('%d/%m/%Y %H:%M'),
            "plate": v.vehicle.plate if v.vehicle else "-",
            "km": v.km,
            "turno": v.turno,
            "local": v.local or "",
            "status_geral": v.status_geral,
            "observacoes": v.observacoes or "",
            "items": serialized_items,
            "fotos_gerais": [f.filename for f in v.fotos]
        })

    return render_template(
        "vistorias_detail.html",
        v=v,
        fotos_por_item=fotos_por_item
    )


# ----------------- EXECUÇÃO -----------------
# ===============================
# 🎓 MÓDULO: LMS (TREINAMENTOS)
# ===============================

# ----------------- ROTAS: LMS (TREINAMENTOS) -----------------
@app.route("/treinamentos/mobile")
@login_required
def treinamentos_mobile():
    return render_template("treinamentos_mobile.html")

@app.route("/treinamentos/admin")
@supervisor_allowed
def treinamentos_admin():
    return render_template("treinamentos_admin.html")

@app.route("/treinamentos/gerir")
@supervisor_allowed
def treinamentos_gerir():
    return render_template("treinamentos_gerir.html")

@app.route("/api/training/list")
@login_required
def api_training_list():
    try:
        courses = Training.query.order_by(Training.created_at.desc()).all()
        return json.dumps([{
            "id": c.id,
            "title": c.title,
            "description": c.description,
            "allow_retake": c.allow_retake,
            "badge": {
                "name": c.badge.name,
                "icon": c.badge.icon,
                "color": c.badge.color
            } if c.badge else None,
            "module_count": len(c.modules)
        } for c in courses])
    except Exception as e:
        return json.dumps({"error": str(e)}), 500

@app.route("/api/training/save", methods=["POST"])
@supervisor_allowed
def api_training_save():
    try:
        data = request.json
        course_id = data.get("id")
        
        if course_id:
            course = Course.query.get(course_id)
        else:
            course = Course()
            db.session.add(course)
        
        course.title = data.get("title")
        course.description = data.get("description")
        course.allow_retake = data.get("allow_retake", True)
        
        # Gestão de Badge
        badge_data = data.get("badge")
        if badge_data:
            if not course.badge:
                course.badge = Badge(course_id=course.id)
            course.badge.name = badge_data.get("name")
            course.badge.icon = badge_data.get("icon")
            course.badge.color = badge_data.get("color")
        
        db.session.commit()
        return json.dumps({"status": "ok", "id": course.id})
    except Exception as e:
        db.session.rollback()
        return json.dumps({"error": str(e)}), 500

@app.route("/api/training/submit", methods=["POST"])
@login_required
def api_training_submit():
    try:
        data = request.json
        course_id = data.get("course_id")
        answers = data.get("answers") # list of {question_id, answer_index}
        
        # Lógica de correção e atribuição de Badge
        # ... (simplificada para restauro)
        return json.dumps({"status": "ok", "score": 100})
    except Exception as e:
        return json.dumps({"error": str(e)}), 500

@app.route("/api/badges/list")
@login_required
def api_badges_list():
    try:
        user_badges = Badge.query.join(Attempt).filter(Attempt.user_id == current_user.id, Attempt.score >= 70).all()
        return json.dumps([{
            "name": b.name,
            "icon": b.icon,
            "color": b.color,
            "earned_at": "Recente"
        } for b in user_badges])
    except Exception as e:
        return json.dumps({"error": str(e)}), 500

if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(host="0.0.0.0", port=5001, debug=True)

# ============================================
# 📡 MÓDULO GPS ISOLADO (TK103)
# ============================================

class GPSDevice(db.Model):
    __tablename__ = "gps_device"
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), unique=True, nullable=False)
    
    # ✅ Conectividade (M2M)
    iccid = db.Column(db.String(30)) # ID do Chip
    phone_number = db.Column(db.String(20)) # Número do Chip
    provider = db.Column(db.String(50)) # Vivo, Tim, Claro, etc.
    
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), unique=True)
    vehicle = db.relationship("Vehicle", backref=db.backref("gps_device", uselist=False))
    
    model = db.Column(db.String(50), default="TK103")
    is_active = db.Column(db.Boolean, default=True)
    
    # ✅ Status de Operação
    last_seen = db.Column(db.DateTime)
    created_at = db.Column(db.DateTime, default=agora)

class GPSLog(db.Model):
    __tablename__ = "gps_log"
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), nullable=False, index=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=True)
    lat = db.Column(db.Float)
    lon = db.Column(db.Float)
    speed = db.Column(db.Float)
    angle = db.Column(db.Float)
    ignition = db.Column(db.Boolean)
    timestamp = db.Column(db.DateTime, default=agora)
    raw_data = db.Column(db.Text)

class GPSGeofence(db.Model):
    __tablename__ = "gps_geofence"
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), unique=True, nullable=False)
    lat = db.Column(db.Float, nullable=False)
    lon = db.Column(db.Float, nullable=False)
    radius = db.Column(db.Float, default=500.0) # raio em metros
    is_active = db.Column(db.Boolean, default=True)

class GPSAlert(db.Model):
    __tablename__ = "gps_alert"
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), nullable=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), nullable=False)
    alert_type = db.Column(db.String(50), nullable=False) # SPEED_LIMIT, IGNITION_OFF_HOURS, GEOFENCE_EXIT
    description = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=agora)
    is_dismissed = db.Column(db.Boolean, default=False)

@app.route("/tracking")
@login_required
def tracking():
    if not current_user.has_permission("frota"):
        abort(403)
    return render_template("tracking.html")

@app.route("/monitoramento/aparelhos", methods=["GET", "POST"])
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

@app.route("/monitoramento/historico")
@supervisor_allowed
def monitoramento_historico():
    veiculos = Vehicle.query.filter_by(status="ATIVO").all()
    v_id = request.args.get("vehicle_id")
    data_ini = request.args.get("data_ini")
    data_fim = request.args.get("data_fim")
    
    logs = []
    if v_id and data_ini and data_fim:
        logs = GPSLog.query.filter(
            GPSLog.vehicle_id == v_id,
            GPSLog.timestamp >= data_ini,
            GPSLog.timestamp <= data_fim
        ).order_by(GPSLog.timestamp.asc()).all()

    return render_template("monitoramento_historico.html", veiculos=veiculos, logs=logs)

@app.route("/monitoramento/config", methods=["GET", "POST"])
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

@app.route("/api/gps/send_command", methods=["POST"])
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

@app.route("/api/gps/geofence", methods=["GET", "POST"])
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

@app.route("/api/gps/alerts", methods=["GET"])
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

@app.route("/api/gps/alerts/dismiss/<int:alert_id>", methods=["POST"])
@login_required
def api_gps_alerts_dismiss(alert_id):
    alert = GPSAlert.query.get(alert_id)
    if not alert:
        return jsonify({"success": False, "error": "Alerta não encontrado."}), 404
        
    alert.is_dismissed = True
    db.session.commit()
    return jsonify({"success": True, "message": "Alerta dispensado com sucesso!"})

@app.route("/api/gps/simulator/tick", methods=["POST"])
@login_required
def api_gps_simulator_tick():
    db.session.commit()  # Evita cache de sessão do SQLAlchemy entre workers
    config = SystemConfig.query.first()
    if not config or not config.simulator_active:
        return jsonify({"success": False, "message": "O Simulador GPRS está desativado globalmente."})

    devices = GPSDevice.query.all()
    associated_devices = [d for d in devices if d.vehicle_id]
    if not associated_devices:
        vehicle = Vehicle.query.filter_by(status="ATIVO").first()
        if not vehicle:
            vehicle = Vehicle(
                plate="SIM-9999",
                brand="Chevrolet",
                model="Tracker",
                year=2024,
                color="Preto",
                chassis="9BW12345678901234",
                renavam="12345678901",
                status="ATIVO"
            )
            db.session.add(vehicle)
            db.session.commit()
        mock_device = GPSDevice(
            imei="999999999999999",
            iccid="8955123456789012345F",
            phone_number="21999999999",
            provider="Vivo M2M",
            vehicle_id=vehicle.id
        )
        db.session.add(mock_device)
        db.session.commit()
        associated_devices = [mock_device]
    
    devices = associated_devices
    
    # Rota simulada por Seropédica (BR-465 / Próximo à UFRRJ)
    ROUTE_COORDINATES = [
        (-22.7686, -43.7061, 0, True),    # Entrada da UFRRJ, Ignição Ligada
        (-22.7712, -43.7085, 35, True),   # 35 km/h, Ignição Ligada
        (-22.7745, -43.7112, 55, True),   # 55 km/h, Ignição Ligada
        (-22.7788, -43.7145, 95, True),   # 95 km/h (Alerta de Excesso!), Ignição Ligada
        (-22.7831, -43.7178, 60, True),   # 60 km/h, Ignição Ligada
        (-22.7874, -43.7211, 45, True),   # 45 km/h, Ignição Ligada
        (-22.7917, -43.7244, 0, False)    # Centro de Seropédica, Ignição Desligada
    ]
    
    simulated_count = 0
    for device in devices:
        if not device.vehicle_id:
            continue
            
        log_count = GPSLog.query.filter_by(imei=device.imei).count()
        lat, lon, speed, ignition = ROUTE_COORDINATES[log_count % len(ROUTE_COORDINATES)]
        
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

@app.route("/monitoramento/relatorio/pdf")
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

@app.route("/api/gps/current")
@login_required
def api_gps_current():
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
            "map_color": v.map_color or "#10b981"
        }
        results.append(data)
    return jsonify({"vehicles": results})

@app.route("/api/gps/gateway", methods=["POST"])
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
