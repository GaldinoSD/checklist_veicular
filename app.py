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
    flash, send_from_directory, abort
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager, login_user, login_required, logout_user,
    current_user, UserMixin
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

from sqlalchemy import text  # para migrações leves no PostgreSQL

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
# ========================
from datetime import timedelta

@app.template_filter("br_datetime")
def br_datetime(value):
    """Formata datetime já salvo no horário do Brasil (sem mexer em fuso)."""
    if not value:
        return ""
    try:
        return value.strftime("%d/%m/%Y %H:%M")
    except Exception:
        return str(value)


# ----------------- MODELOS -----------------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # legado
    is_admin_legacy = db.Column("is_admin", db.Boolean, default=False)

    # novo campo
    role = db.Column(db.String(20), default=None)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

    @property
    def is_admin(self):
        if self.role is None:
            return bool(self.is_admin_legacy)
        return self.role == "admin"

    @property
    def is_supervisor(self):
        return self.role == "supervisor"

    @property
    def is_tech(self):
        if self.role is None and not self.is_admin_legacy:
            return True
        return self.role == "tech"

    @property
    def is_manutencao(self):
        return self.role == "manutencao"


class Vehicle(db.Model):
    __tablename__ = "vehicle"
    id = db.Column(db.Integer, primary_key=True)
    plate = db.Column(db.String(20), unique=True, nullable=False)
    brand = db.Column(db.String(80))
    model = db.Column(db.String(80))
    year = db.Column(db.Integer)
    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="ATIVO")
    type = db.Column(db.String(20), default="carro")  # tipo: carro / moto / caminhão etc.

class VehicleMov(db.Model):
    __tablename__ = "vehicle_mov"

    id = db.Column(db.Integer, primary_key=True)

    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref="movimentos")

    # "saida" ou "entrada"
    tipo = db.Column(db.String(10), nullable=False)

    km = db.Column(db.Integer, nullable=False, default=0)
    responsavel = db.Column(db.String(120), nullable=False)
    obs = db.Column(db.Text)

    # horário BR (sem tzinfo) usando sua função agora()
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
    order = db.Column(db.Integer, default=0)
    text = db.Column(db.String(255), nullable=False)
    required = db.Column(db.Boolean, default=True)
    require_justif_no = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(50), default="texto_curto")
    options = db.Column(db.Text)


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
        # campos em checklist_item
        text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS type VARCHAR(50) DEFAULT \'texto_curto\''),
        text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS options TEXT'),
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

        flash("Usuário ou senha inválidos.", "error")

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

    # -----------------------
    # 📅 FILTRO DE PERÍODO
    # -----------------------
    periodo = request.args.get("periodo", "")
    dt_inicio = None
    dt_fim = None

    if periodo and " - " in periodo:
        try:
            inicio_str, fim_str = periodo.split(" - ")
            dt_inicio = datetime.strptime(inicio_str.strip(), "%Y-%m-%d")
            dt_fim = datetime.strptime(fim_str.strip(), "%Y-%m-%d")

            # Ajusta fim para o final do dia
            dt_fim = dt_fim.replace(hour=23, minute=59, second=59)

        except Exception as e:
            print("Erro período dashboard:", e)

    # -----------------------
    # 🚗 FILTRO POR VEÍCULO
    # -----------------------
    veiculo_id = request.args.get("veiculo", "").strip()
    veiculo_id_int = None
    if veiculo_id:
        try:
            veiculo_id_int = int(veiculo_id)
        except Exception:
            veiculo_id_int = None

    # lista de veículos pro select do template
    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()

    # -----------------------
    # 🔢 DADOS GERAIS
    # (pode ser geral ou filtrado - aqui deixei geral)
    # -----------------------
    total_veiculos = Vehicle.query.count()
    total_checklists = Checklist.query.count()
    total_relatorios = count_files(RELATORIOS_DIR)

    lr = list_reports()
    ultimo_relatorio = lr[0]["name"] if lr else "—"

    # -----------------------
    # 📄 CHECKLISTS RECENTES (com filtros)
    # -----------------------
    query_checklists = Checklist.query

    if veiculo_id_int:
        query_checklists = query_checklists.filter(Checklist.vehicle_id == veiculo_id_int)

    if dt_inicio and dt_fim:
        query_checklists = query_checklists.filter(
            Checklist.date >= dt_inicio,
            Checklist.date <= dt_fim
        )

    recentes = query_checklists.order_by(Checklist.date.desc()).limit(5).all()

    # -----------------------
    # 🚗 ALERTAS DE REVISÃO (com filtro veículo)
    # -----------------------
    alerts = []

    veiculos_para_alerta = veiculos
    if veiculo_id_int:
        veiculos_para_alerta = [v for v in veiculos if v.id == veiculo_id_int]

    for v in veiculos_para_alerta:
        alert, next_rev, remaining = km_alert(v.km or 0)
        if alert:
            alerts.append({
                "plate": v.plate,
                "km": v.km or 0,
                "next_rev": next_rev,
                "remaining": remaining
            })

    # -----------------------
    # 📊 KM SEMANAL
    # -----------------------
    # Se sua função aceitar vehicle_id, use assim:
    # labels, values = weekly_km_series(WEEKS_WINDOW, vehicle_id=veiculo_id_int)
    #
    # Se NÃO aceitar, mantém do jeito atual (geral):
    labels, values = weekly_km_series(WEEKS_WINDOW)

    # -----------------------
    # ⚠️ AVARIAS (com filtros)
    # -----------------------
    query_avarias = AvariaOS.query

    if veiculo_id_int:
        query_avarias = query_avarias.filter(AvariaOS.vehicle_id == veiculo_id_int)

    if dt_inicio and dt_fim:
        print("Aplicando filtro:", dt_inicio, "→", dt_fim)
        query_avarias = query_avarias.filter(
            AvariaOS.data_abertura >= dt_inicio,
            AvariaOS.data_abertura <= dt_fim
        )

    total_avarias = query_avarias.count()
    avarias_pendentes = query_avarias.filter_by(status="aberta").count()
    avarias_finalizadas = query_avarias.filter_by(status="finalizada").count()

    valor_total_gasto = query_avarias.with_entities(
        db.func.sum(AvariaOS.valor_gasto)
    ).scalar() or 0

    recentes_avarias = query_avarias.order_by(AvariaOS.id.desc()).limit(5).all()

    # -----------------------
    # RETORNO
    # -----------------------
    return render_template(
        "dashboard.html",

        periodo=periodo,
        veiculos=veiculos,  # <-- necessário pro select
        veiculo_selecionado=veiculo_id,  # opcional (se quiser usar no template)

        total_veiculos=total_veiculos,
        total_checklists=total_checklists,
        total_relatorios=total_relatorios,
        ultimo_relatorio=ultimo_relatorio,

        recentes=recentes,

        alerts=alerts,
        rev_interval=REV_INTERVAL,
        rev_margin=REV_ALERT_MARGIN,

        wk_labels=labels,
        wk_values=values,

        total_avarias=total_avarias,
        avarias_pendentes=avarias_pendentes,
        avarias_finalizadas=avarias_finalizadas,
        valor_total_gasto=valor_total_gasto,
        recentes_avarias=recentes_avarias
    )

# ----------------- USUÁRIOS (admin) -----------------
@app.route("/usuarios")
@admin_required
def users():
    items = User.query.order_by(User.username.asc()).all()
    return render_template("users.html", items=items)


@app.route("/usuarios/novo", methods=["POST"])
@admin_required
def users_new():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "").strip()
    role = request.form.get("role", "tech").strip().lower()

    if not username or not password:
        flash("Usuário e senha obrigatórios.", "error")
        return redirect(url_for("users"))

    if role not in {"admin", "supervisor", "tech", "manutencao"}:
        flash("Papel inválido.", "error")
        return redirect(url_for("users"))

    if User.query.filter_by(username=username).first():
        flash("Usuário já existe.", "error")
        return redirect(url_for("users"))

    u = User(username=username, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()

    registrar_log(f"Usuário criado: {username} ({role})")
    flash("Usuário cadastrado.", "success")
    return redirect(url_for("users"))


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




@app.route("/usuarios/<int:uid>/papel", methods=["POST"])
@admin_required
def users_role(uid):
    u = User.query.get_or_404(uid)
    role = request.form.get("role", "tech").strip().lower()

    if role not in {"admin", "supervisor", "tech", "manutencao"}:
        flash("Papel inválido.", "error")
        return redirect(url_for("users"))

    u.role = role
    db.session.commit()

    registrar_log(f"Papel alterado: {u.username} -> {role}")
    flash("Papel atualizado.", "success")
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
    q = request.args.get("q", "").strip().lower()
    query = Vehicle.query

    if q:
        query = query.filter(
            db.or_(
                Vehicle.plate.ilike(f"%{q}%"),
                Vehicle.brand.ilike(f"%{q}%"),
                Vehicle.model.ilike(f"%{q}%"),
            )
        )

    veiculos = query.order_by(Vehicle.plate.asc()).all()

    # garantir valor padrão caso venha nulo
    for v in veiculos:
        if not v.type:
            v.type = "carro"

    return render_template("vehicles.html", veiculos=veiculos, q=q)


@app.route("/veiculos/novo", methods=["POST"])
@login_required
def vehicle_new():
    if not current_user.is_admin:
        abort(403)

    plate = (request.form.get("plate") or "").upper().strip()
    brand = (request.form.get("brand") or "").strip()
    model = (request.form.get("model") or "").strip()
    year_raw = request.form.get("year")
    km_raw = request.form.get("km")
    type_ = (request.form.get("type") or "carro").strip().lower()
    status = request.form.get("status", "ATIVO")

    if not plate:
        flash("Placa é obrigatória.", "error")
        return redirect(url_for("vehicles"))

    if Vehicle.query.filter_by(plate=plate).first():
        flash("Já existe um veículo com essa placa.", "error")
        return redirect(url_for("vehicles"))

    year = int(year_raw) if year_raw and year_raw.isdigit() else None
    km = int(km_raw) if km_raw and km_raw.isdigit() else 0

    v = Vehicle(
        plate=plate,
        brand=brand,
        model=model,
        year=year,
        km=km,
        status=status,
        type=type_,
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
    old = v.status
    v.status = request.form.get("status", v.status)
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

    v.brand = (request.form.get("brand") or "").strip()
    v.model = (request.form.get("model") or "").strip()

    year_raw = request.form.get("year")
    km_raw = request.form.get("km")
    type_raw = (request.form.get("type") or "carro").strip().lower()
    status_raw = (request.form.get("status") or "ativo").strip().lower()

    v.year = int(year_raw) if year_raw and year_raw.isdigit() else None
    v.km = int(km_raw) if km_raw and km_raw.isdigit() else v.km
    v.type = type_raw
    v.status = status_raw

    db.session.commit()

    registrar_log(f"Veículo editado: {v.plate} (status={status_raw})")
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
    # GET: 1 linha = SAÍDA + CHEGADA (para r.saida / r.chegada)
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



    # ==========================
    # GET: carregar tela com dados reais
    # ==========================
    vehicles = Vehicle.query.order_by(Vehicle.plate.asc()).all()

    registros = (
        VehicleMov.query
        .order_by(VehicleMov.data_hora.desc())
        .limit(200)
        .all()
    )

    # marca quais SAÍDAS ainda não têm chegada
    saida_ids = [r.id for r in registros if r.tipo == "saida"]
    entradas = set(
        x.saida_id for x in VehicleMov.query.filter(
            VehicleMov.tipo == "entrada",
            VehicleMov.saida_id.in_(saida_ids)
        ).all()
    )

    for r in registros:
        r.pode_registrar_chegada = (r.tipo == "saida" and r.id not in entradas)

    return render_template(
        "controle_veiculos.html",
        page_title="Controle de Entrada e Saída",
        vehicles=vehicles,
        registros=registros
    )



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
                responsavel_id=request.form.get("responsavel_id"),
                gravidade=request.form.get("gravidade"),
                descricao=request.form.get("descricao"),
                km=request.form.get("km"),
                status="aberta"
            )
            db.session.add(nova)
            db.session.commit()
            registrar_log(f"Avaria criada para veículo ID={nova.vehicle_id}")
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
                registrar_log(f"O.S finalizada (admin/supervisor): ID={os_finalizar.id}")

            return redirect(url_for("avarias_registro"))

    # GET — listar avarias
    ordens = AvariaOS.query.order_by(AvariaOS.id.desc()).all()
    veiculos = Vehicle.query.all()
    colaboradores = User.query.all()

    return render_template(
        "avarias_registro.html",
        ordens=ordens,
        veiculos=veiculos,
        colaboradores=colaboradores
    )


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
                registrar_log(f"O.S finalizada (manutenção): ID={os_finalizar.id}")

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
    return render_template("reports.html", items=list_reports())


@app.route("/relatorios/download/<path:nome>")
@supervisor_allowed
def report_download(nome):
    return send_from_directory(RELATORIOS_DIR, nome, as_attachment=True)


@app.route("/relatorios/excluir/<path:nome>", methods=["POST"])
@login_required
def report_delete(nome):
    if not current_user.is_admin:
        abort(403)

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

        return redirect(url_for("vistorias_detail", vistoria_id=v.id))

    return render_template("vistorias_nova.html", veiculos=veiculos)




@app.route("/vistorias/<int:vistoria_id>")
@supervisor_allowed
def vistorias_detail(vistoria_id):
    v = Vistoria.query.get_or_404(vistoria_id)

    fotos_por_item = defaultdict(list)
    for f in v.fotos:
        if f.item_key:
            fotos_por_item[f.item_key].append(f)

    return render_template(
        "vistorias_detail.html",
        v=v,
        fotos_por_item=fotos_por_item
    )


# ----------------- EXECUÇÃO -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
