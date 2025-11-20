# -*- coding: utf-8 -*-
"""
Painel de Gerenciamento de Frota – app.py (versão com papéis: admin/supervisor/tech)

- Modelos: User / Vehicle / Checklist / ChecklistItem / Log
- Papel do usuário em 'User.role' (admin/supervisor/tech)
- Decoradores: @admin_required, @supervisor_allowed
- Login unificado com redirecionamento por papel
- Dashboard (admin+supervisor)
- Veículos (admin+supervisor; supervisor readonly)
- Usuários (apenas admin)
- Checklists + geração de PDF
- Relatórios (admin+supervisor; exclusão só admin)
- Perfil (troca de senha para técnico)
- Logs de sistema (admin): login, logout, CRUD geral
"""

import os, json, uuid, sqlite3
from pathlib import Path
from datetime import datetime, timedelta
from functools import wraps
from collections import defaultdict

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

# PDF
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import mm
from reportlab.lib import colors
from reportlab.platypus import (
    Table, TableStyle, SimpleDocTemplate,
    Paragraph, Spacer, Image as RLImage
)
from reportlab.lib.styles import getSampleStyleSheet

# Imagem (upload)
from PIL import Image

# ----------------- CONFIG BÁSICA -----------------
BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
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
app.config["SQLALCHEMY_DATABASE_URI"] = f"sqlite:///{DB_PATH}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["MAX_CONTENT_LENGTH"] = 32 * 1024 * 1024  # 32MB uploads

db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = "login"


# ----------------- MODELOS -----------------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)

    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)

    # campo legado
    is_admin_legacy = db.Column("is_admin", db.Boolean, default=False)

    # novo campo de papel
    # valores: "admin", "supervisor", "tech"
    role = db.Column(db.String(20), default=None)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

    @property
    def is_admin(self) -> bool:
        if self.role is None:
            return bool(self.is_admin_legacy)
        return self.role == "admin"

    @property
    def is_supervisor(self) -> bool:
        return self.role == "supervisor"

    @property
    def is_tech(self) -> bool:
        if self.role is None and not self.is_admin_legacy:
            return True
        return self.role == "tech"


class Vehicle(db.Model):
    __tablename__ = "vehicle"
    id = db.Column(db.Integer, primary_key=True)
    plate = db.Column(db.String(20), unique=True, nullable=False)
    brand = db.Column(db.String(80))
    model = db.Column(db.String(80))
    year = db.Column(db.Integer)
    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(20), default="ATIVO")  # ATIVO, INATIVO, MANUTENCAO


class Checklist(db.Model):
    __tablename__ = "checklist"
    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'))
    vehicle = db.relationship('Vehicle', backref='checklists')
    technician = db.Column(db.String(120))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(40), default="OK")
    notes = db.Column(db.Text)
    raw_json = db.Column(db.Text)  # itens + fotos


class ChecklistItem(db.Model):
    __tablename__ = "checklist_item"
    id = db.Column(db.Integer, primary_key=True)
    order = db.Column(db.Integer, default=0)
    text = db.Column(db.String(255), nullable=False)
    required = db.Column(db.Boolean, default=True)
    require_justif_no = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(50), default="texto_curto")  # texto_curto, paragrafo, numero, data, sim_nao_na, dropdown, radio, checkboxes
    options = db.Column(db.Text)  # opções separadas por vírgula


class Log(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), nullable=False)
    acao = db.Column(db.String(255), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ----------------- MIGRAÇÃO LEVE (SQLite) -----------------
def column_exists(table: str, column: str) -> bool:
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute(f"PRAGMA table_info({table});")
        cols = [r[1] for r in cur.fetchall()]
        return column in cols
    finally:
        con.close()


def migrate_db():
    # já existe db.create_all() fora – aqui só ajustes extras
    # Garantir colunas em checklist_item
    con = sqlite3.connect(DB_PATH)
    cur = con.cursor()
    try:
        cur.execute("PRAGMA table_info(checklist_item);")
        cols = [r[1] for r in cur.fetchall()]
        if "type" not in cols:
            cur.execute("ALTER TABLE checklist_item ADD COLUMN type TEXT DEFAULT 'texto_curto';")
        if "options" not in cols:
            cur.execute("ALTER TABLE checklist_item ADD COLUMN options TEXT;")
        con.commit()
    except Exception:
        pass
    finally:
        con.close()

    # Garantir coluna role em user
    if not column_exists("user", "role"):
        con2 = sqlite3.connect(DB_PATH)
        cur2 = con2.cursor()
        try:
            cur2.execute("ALTER TABLE user ADD COLUMN role TEXT;")
            con2.commit()
        except Exception:
            pass
        finally:
            con2.close()

    # Migrar valores legados para role (apenas se user.role for NULL)
    with app.app_context():
        users = User.query.all()
        changed = False
        for u in users:
            if u.role is None:
                if bool(u.is_admin_legacy):
                    u.role = "admin"
                else:
                    if u.username.lower().startswith("supervisor"):
                        u.role = "supervisor"
                    else:
                        u.role = "tech"
                changed = True
        if changed:
            db.session.commit()


# ----------------- SEED DEFAULTS -----------------
DEFAULT_ITEMS = [
    ("Pneus (calibragem/estado)", "sim_nao_na"),
    ("Luzes frontais (farol/alto/baixo)", "sim_nao_na"),
    ("Luzes traseiras (freio/placa)", "sim_nao_na"),
    ("Setas e alerta", "sim_nao_na"),
    ("Extintor (validade)", "sim_nao_na"),
    ("Painel sem avisos críticos", "sim_nao_na"),
    ("Documentação do veículo", "sim_nao_na"),
    ("Observações gerais", "paragrafo"),
]


def seed_defaults():
    # Usuários padrão
    if not User.query.filter_by(username="admin").first():
        u = User(username="admin", role="admin")
        u.set_password("admin")
        db.session.add(u)

    if not User.query.filter_by(username="supervisor").first():
        u = User(username="supervisor", role="supervisor")
        u.set_password("1234")
        db.session.add(u)

    if not User.query.filter_by(username="tecnico").first():
        u = User(username="tecnico", role="tech")
        u.set_password("1234")
        db.session.add(u)

    # Itens de checklist padrão
    if ChecklistItem.query.count() == 0:
        for idx, (txt, typ) in enumerate(DEFAULT_ITEMS, start=1):
            db.session.add(
                ChecklistItem(
                    order=idx,
                    text=txt,
                    required=True,
                    require_justif_no=("Luzes" in txt),
                    type=typ,
                    options=None
                )
            )
    db.session.commit()


with app.app_context():
    # cria TODAS as tabelas (incluindo Log) antes de mexer em qualquer coisa
    db.create_all()
    migrate_db()
    seed_defaults()


# ----------------- LOG DE SISTEMA -----------------
def registrar_log(acao: str):
    """Grava a ação feita por um usuário no sistema."""
    try:
        usuario = current_user.username if current_user.is_authenticated else "Sistema"
        novo = Log(usuario=usuario, acao=acao)
        db.session.add(novo)
        db.session.commit()
    except Exception as e:
        print(f"⚠️ Erro ao registrar log: {e}")


# ----------------- HELPERS -----------------
def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if not current_user.is_admin:
            flash("Acesso restrito ao administrador.", "error")
            if current_user.is_supervisor:
                return redirect(url_for("dashboard"))
            else:
                return redirect(url_for("checklist_mobile"))
        return view(*args, **kwargs)
    return wrapper


def supervisor_allowed(view):
    """Permite Admin e Supervisor. Técnicos são barrados."""
    @wraps(view)
    def wrapper(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("login"))
        if current_user.is_admin or current_user.is_supervisor:
            return view(*args, **kwargs)
        flash("Acesso restrito a supervisor/administrador.", "error")
        return redirect(url_for("checklist_mobile"))
    return wrapper


@app.context_processor
def inject_role_flags():
    return dict(
        ROLE_ADMIN=(current_user.is_authenticated and current_user.is_admin),
        ROLE_SUPERVISOR=(current_user.is_authenticated and current_user.is_supervisor),
        ROLE_TECH=(current_user.is_authenticated and current_user.is_tech)
    )


def count_files(dirpath: Path):
    try:
        return len([f for f in dirpath.iterdir() if f.is_file()])
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
    rows = Checklist.query.all()
    per_week_vehicle = {}
    for c in rows:
        wk = iso_week(c.date)
        key = (wk, c.vehicle_id)
        if key not in per_week_vehicle:
            per_week_vehicle[key] = [c.km, c.km]
        else:
            lo, hi = per_week_vehicle[key]
            per_week_vehicle[key] = [min(lo, c.km), max(hi, c.km)]
    weekly = defaultdict(int)
    for (wk, vid), (lo, hi) in per_week_vehicle.items():
        if hi >= lo:
            weekly[wk] += (hi - lo)
    weeks = []
    for i in range(weeks_back - 1, -1, -1):
        dt = end - timedelta(weeks=i)
        monday = dt - timedelta(days=dt.weekday())
        weeks.append(iso_week(monday + timedelta(days=3)))
    labels = weeks
    values = [weekly.get(wk, 0) for wk in weeks]
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


def generate_checklist_pdf(checklist_obj: 'Checklist', raw: dict) -> str:
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

    # Informações principais
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


# ----------------- LOGIN UNIFICADO -----------------
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").strip()
        u = User.query.filter_by(username=username).first()
        if u and u.check_password(password):
            login_user(u)
            registrar_log(f"Login efetuado: {u.username}")

            if u.is_admin or u.is_supervisor:
                return redirect(url_for("dashboard"))
            else:
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
        return redirect(url_for("checklist_mobile"))
    return redirect(url_for("login"))


# ----------------- DASHBOARD (admin+supervisor) -----------------
@app.route("/dashboard")
@supervisor_allowed
def dashboard():
    total_veiculos = Vehicle.query.count()
    total_checklists = Checklist.query.count()
    total_relatorios = count_files(RELATORIOS_DIR)

    lr = list_reports()
    ultimo_relatorio = lr[0]["name"] if lr else "—"

    recentes = Checklist.query.order_by(Checklist.date.desc()).limit(5).all()
    veiculos = Vehicle.query.all()
    alerts = []
    for v in veiculos:
        alert, next_rev, remaining = km_alert(v.km or 0)
        if alert:
            alerts.append({
                "plate": v.plate,
                "km": v.km or 0,
                "next_rev": next_rev,
                "remaining": remaining
            })

    labels, values = weekly_km_series(WEEKS_WINDOW)

    return render_template(
        "dashboard.html",
        total_veiculos=total_veiculos,
        total_checklists=total_checklists,
        total_relatorios=total_relatorios,
        ultimo_relatorio=ultimo_relatorio,
        recentes=recentes,
        alerts=alerts,
        rev_interval=REV_INTERVAL,
        rev_margin=REV_ALERT_MARGIN,
        wk_labels=labels,
        wk_values=values
    )


# ----------------- USUÁRIOS (apenas admin) -----------------
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

    if role not in {"admin", "supervisor", "tech"}:
        flash("Papel inválido.", "error")
        return redirect(url_for("users"))

    if User.query.filter_by(username=username).first():
        flash("Nome de usuário já existe.", "error")
        return redirect(url_for("users"))

    u = User(username=username, role=role)
    u.set_password(password)
    db.session.add(u)
    db.session.commit()
    registrar_log(f"Usuário criado: {username} (papel={role})")
    flash("Usuário criado.", "success")
    return redirect(url_for("users"))


@app.route("/usuarios/<int:uid>/senha", methods=["POST"])
@admin_required
def users_pwd(uid):
    u = User.query.get_or_404(uid)
    pwd = request.form.get("password", "").strip()
    if not pwd:
        flash("Senha inválida.", "error")
        return redirect(url_for("users"))
    u.set_password(pwd)
    db.session.commit()
    registrar_log(f"Senha alterada para usuário: {u.username}")
    flash("Senha atualizada.", "success")
    return redirect(url_for("users"))


@app.route("/usuarios/<int:uid>/papel", methods=["POST"])
@admin_required
def users_role(uid):
    u = User.query.get_or_404(uid)
    role = request.form.get("role", "tech").strip().lower()
    if role not in {"admin", "supervisor", "tech"}:
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
        flash("Você não pode se excluir.", "error")
        return redirect(url_for("users"))
    u = User.query.get_or_404(uid)
    nome = u.username
    db.session.delete(u)
    db.session.commit()
    registrar_log(f"Usuário excluído: {nome}")
    flash("Usuário excluído.", "success")
    return redirect(url_for("users"))




# ----------------- VEÍCULOS (admin+supervisor; supervisor readonly) -----------------
def ensure_vehicle_type_column():
    db_path = str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).replace("sqlite:///", "")
    if not db_path or not os.path.exists(db_path):
        return
    try:
        con = sqlite3.connect(db_path)
        cur = con.cursor()
        cur.execute("PRAGMA table_info(vehicle);")
        cols = [r[1] for r in cur.fetchall()]
        if "type" not in cols:
            print("🆕 Adicionando coluna 'type' à tabela vehicle...")
            cur.execute("ALTER TABLE vehicle ADD COLUMN type TEXT DEFAULT 'carro';")
            con.commit()
        con.close()
    except Exception as e:
        print(f"⚠️ Erro ao garantir coluna 'type': {e}")


@app.route("/veiculos")
@supervisor_allowed
def vehicles():
    ensure_vehicle_type_column()
    q = request.args.get("q", "").strip().lower()
    query = Vehicle.query
    if q:
        query = query.filter(
            db.or_(
                Vehicle.plate.ilike(f"%{q}%"),
                Vehicle.brand.ilike(f"%{q}%"),
                Vehicle.model.ilike(f"%{q}%")
            )
        )
    veiculos = query.order_by(Vehicle.plate.asc()).all()

    db_path = str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).replace("sqlite:///", "")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    try:
        tipos = dict(cur.execute("SELECT id, type FROM vehicle").fetchall())
    except Exception:
        tipos = {}
    finally:
        con.close()

    for v in veiculos:
        v.type = tipos.get(v.id, "carro")

    return render_template("vehicles.html", veiculos=veiculos, q=q)


@app.route("/veiculos/novo", methods=["POST"])
@login_required
def vehicle_new():
    if not current_user.is_admin:
        abort(403)

    ensure_vehicle_type_column()

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
    )

    db.session.add(v)
    db.session.commit()

    db_path = str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).replace("sqlite:///", "")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("UPDATE vehicle SET type = ? WHERE id = ?", (type_, v.id))
    con.commit()
    con.close()

    registrar_log(f"Veículo criado: {plate} ({brand} {model}, tipo={type_})")
    flash(f"Veículo {plate} cadastrado com sucesso!", "success")
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
    registrar_log(f"Status do veículo {v.plate} alterado: {old} -> {v.status}")
    flash(f"Status do veículo {v.plate} atualizado para {v.status}.", "success")
    return redirect(url_for("vehicles"))


@app.route("/veiculos/<int:vid>/editar", methods=["POST"])
@login_required
def vehicle_edit(vid):
    if not current_user.is_admin:
        abort(403)

    ensure_vehicle_type_column()

    v = Vehicle.query.get_or_404(vid)
    v.brand = (request.form.get("brand") or "").strip()
    v.model = (request.form.get("model") or "").strip()
    year_raw = request.form.get("year")
    km_raw = request.form.get("km")
    type_raw = (request.form.get("type") or "carro").strip().lower()

    v.year = int(year_raw) if year_raw and year_raw.isdigit() else None
    v.km = int(km_raw) if km_raw and km_raw.isdigit() else (v.km or 0)
    db.session.commit()

    db_path = str(app.config.get("SQLALCHEMY_DATABASE_URI", "")).replace("sqlite:///", "")
    con = sqlite3.connect(db_path)
    cur = con.cursor()
    cur.execute("UPDATE vehicle SET type = ? WHERE id = ?", (type_raw, v.id))
    con.commit()
    con.close()

    registrar_log(f"Veículo editado: {v.plate} (tipo={type_raw})")
    flash(f"Veículo {v.plate} atualizado com sucesso!", "success")
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
    flash(f"Veículo {plate} excluído com sucesso!", "success")
    return redirect(url_for("vehicles"))


# ----------------- CHECKLISTS (admin e supervisor: leitura; admin: ações) -----------------
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
                Checklist.status.ilike(f"%{q}%")
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
                    km=int(j.get("km", 0))
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
    registrar_log(f"Importação de checklists: {count} arquivo(s) JSON")
    flash(f"Importação concluída: {count} checklist(s).", "success")
    return redirect(url_for("checklists"))


# ----------------- RELATÓRIOS (admin+supervisor; exclusão só admin) -----------------
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
        flash("Relatório excluído.", "success")
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
    flash("Relatório enviado.", "success")
    return redirect(url_for("reports"))


# ----------------- CONFIGURAÇÃO DO CHECKLIST (apenas admin) -----------------
@app.route("/config-checklist")
@admin_required
def config_checklist():
    items = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    return render_template("config_checklist.html", items=items)


@app.route("/config-checklist/novo", methods=["POST"])
@admin_required
def config_checklist_new():
    text = request.form.get("text", "").strip()
    required = request.form.get("required") == "on"
    require_justif_no = request.form.get("require_justif_no") == "on"
    typ = request.form.get("type", "texto_curto")
    opts_raw = request.form.get("options", "").strip()

    if opts_raw:
        opts_list = [o.strip() for o in opts_raw.splitlines() if o.strip()]
        opts = ",".join(opts_list) if opts_list else None
    else:
        opts = None

    if not text:
        flash("Texto é obrigatório.", "error")
        return redirect(url_for("config_checklist"))

    last = db.session.query(db.func.max(ChecklistItem.order)).scalar() or 0
    db.session.add(
        ChecklistItem(
            order=last + 1,
            text=text,
            required=required,
            require_justif_no=require_justif_no,
            type=typ,
            options=opts,
        )
    )
    db.session.commit()
    registrar_log(f"Item de checklist adicionado: {text}")
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

    opts_raw = request.form.get("options", "").strip()
    if opts_raw:
        opts_list = [o.strip() for o in opts_raw.splitlines() if o.strip()]
        it.options = ",".join(opts_list) if opts_list else None
    else:
        it.options = None

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
    registrar_log(f"Ordem de item de checklist movida: {it.text} (id={iid}, dir={direction})")
    flash("Ordem atualizada.", "success")
    return redirect(url_for("config_checklist"))


# ----------------- CHECKLIST TÉCNICO (sem GPS) -----------------
@app.route("/checklist", methods=["GET", "POST"])
@login_required
def checklist_mobile():
    vehicles = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    items_qs = ChecklistItem.query.order_by(ChecklistItem.order.asc()).all()
    success = False

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

        respostas = {}
        for idx, item in enumerate(items_qs, start=1):
            key = f"item{idx}"
            val = request.form.getlist(key) if item.type == "checkboxes" else request.form.get(key)
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

        raw = {
            "items": respostas,
            "photos": photos,
            "tecnico": tech,
            "veiculo": vehicle_id,
            "km": km,
            "data_envio": datetime.now().strftime("%d/%m/%Y %H:%M")
        }

        checklist = Checklist(
            vehicle_id=vehicle_id,
            technician=tech,
            date=datetime.utcnow(),
            km=km,
            status="OK",
            notes="Checklist via web",
            raw_json=json.dumps(raw, ensure_ascii=False)
        )
        db.session.add(checklist)

        v = Vehicle.query.get(vehicle_id)
        if v and km and int(km) > (v.km or 0):
            v.km = int(km)

        db.session.commit()

        try:
            generate_checklist_pdf(checklist, raw)
        except Exception as e:
            print("⚠️ Erro gerando PDF:", e)

        registrar_log(f"Checklist criado para veículo ID={vehicle_id} por {tech}")
        flash("✅ Checklist enviado com sucesso!", "success")
        success = True

    return render_template("checklist_mobile.html", vehicles=vehicles, items=items_qs, success=success)


# ----------------- PERFIL TÉCNICO: alterar senha -----------------
@app.route("/perfil", methods=["GET", "POST"])
@login_required
def perfil():
    if current_user.is_admin or current_user.is_supervisor:
        flash("Apenas técnicos usam esta página de perfil.", "info")
        return redirect(url_for("dashboard"))

    if request.method == "POST":
        nova_senha = request.form.get("nova_senha", "").strip()
        confirma = request.form.get("confirma", "").strip()

        if not nova_senha or not confirma:
            flash("Preencha ambos os campos de senha.", "error")
            return redirect(url_for("perfil"))

        if nova_senha != confirma:
            flash("As senhas não coincidem.", "error")
            return redirect(url_for("perfil"))

        current_user.set_password(nova_senha)
        db.session.commit()
        registrar_log(f"Técnico alterou a própria senha: {current_user.username}")
        flash("Senha atualizada com sucesso!", "success")
        return redirect(url_for("checklist_mobile"))

    return render_template("perfil.html", user=current_user)


# ----------------- LOGS DO SISTEMA (somente admin) -----------------
@app.route("/logs")
@login_required
@admin_required
def logs():
    registros = Log.query.order_by(Log.data_hora.desc()).all()
    return render_template("logs.html", registros=registros)


# ----------------- EXECUÇÃO -----------------
if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
