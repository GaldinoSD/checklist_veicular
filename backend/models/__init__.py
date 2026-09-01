# -*- coding: utf-8 -*-
import json
from datetime import datetime, timedelta
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash
from backend import db
from backend.config import TZ

def agora():
    """Retorna horário real do Brasil sem tzinfo (compatível com SQLite e Postgres)."""
    return datetime.now(TZ).replace(tzinfo=None)

# ----------------- MODELOS -----------------
class User(UserMixin, db.Model):
    __tablename__ = "user"
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    full_name = db.Column(db.String(150), nullable=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin_legacy = db.Column("is_admin", db.Boolean, default=False)
    role = db.Column(db.String(20), default=None)
    email = db.Column(db.String(120))
    phone = db.Column(db.String(20))
    telegram_chat_id = db.Column(db.String(100))
    permissions = db.Column(db.Text) # JSON string
    last_login = db.Column(db.DateTime, nullable=True)
    last_seen = db.Column(db.DateTime, nullable=True)
    last_ip = db.Column(db.String(45), nullable=True)

    def set_password(self, pwd: str):
        self.password_hash = generate_password_hash(pwd)

    def check_password(self, pwd: str) -> bool:
        return check_password_hash(self.password_hash, pwd)

    @property
    def display_name(self):
        return self.full_name if self.full_name else self.username

    @property
    def is_online(self):
        if not self.last_seen:
            return False
        from backend.utils import agora
        diff = (agora() - self.last_seen).total_seconds()
        return 0 <= diff <= 300

    @property
    def is_admin(self):
        if self.role == "admin":
            return True
        return bool(self.is_admin_legacy)

    def has_permission(self, perm):
        if self.is_admin:
            return True
            
        # Normalização do nome da permissão para simplificar checagem de role-based defaults
        raw_perm = perm[5:] if perm.startswith("perm_") else perm

        # Role-based defaults (garante que as abas básicas apareçam por perfil mesmo se permissions estiver vazio)
        if raw_perm in ("treinamentos_mobile", "perm_treinamentos_mobile"):
            return True
        if self.role == "manutencao" and raw_perm == "manutencao_os":
            return True
        if self.role == "tech" and raw_perm in ("checklist_mobile", "treinamentos_mobile"):
            return True
        if self.role == "supervisor" and raw_perm in ("frota", "gestao_mapas"):
            return True

        if not self.permissions:
            return False
        try:
            p = json.loads(self.permissions)
            # Tenta com o nome exato (ex: 'perm_dashboard' ou 'dashboard')
            if p.get(perm, False):
                return True
            # Tenta com o prefixo 'perm_' se não foi passado com ele
            if not perm.startswith("perm_"):
                if p.get(f"perm_{perm}", False):
                    return True
            else:
                # Tenta sem o prefixo 'perm_' se foi passado com ele
                if p.get(raw_perm, False):
                    return True
            return False
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


@db.event.listens_for(User, "before_insert")
@db.event.listens_for(User, "before_update")
def _user_normalize_username(mapper, connection, target):
    if target.username and isinstance(target.username, str):
        target.username = target.username.upper()

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
    driver = db.relationship('User', foreign_keys=[driver_id], backref=db.backref('driven_vehicles'))
    map_icon = db.Column(db.String(50), default="fa-location-arrow")
    map_color = db.Column(db.String(20), default="#10b981")

    # 1 ficha de informações por veículo
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

    # Campos
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
    updated_at = db.Column(db.DateTime, default=lambda: agora(), onupdate=lambda: agora())


class VehicleMov(db.Model):
    __tablename__ = "vehicle_mov"

    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref=db.backref("movimentos", lazy=True))

    tipo = db.Column(db.String(10), nullable=False) # "saida" ou "entrada"
    km = db.Column(db.Integer, nullable=False, default=0)
    responsavel = db.Column(db.String(120), nullable=False)
    obs = db.Column(db.Text)
    data_hora = db.Column(db.DateTime, default=lambda: agora())

    saida_id = db.Column(db.Integer, db.ForeignKey("vehicle_mov.id"), nullable=True)
    saida_ref = db.relationship("VehicleMov", remote_side=[id], uselist=False)


class Checklist(db.Model):
    __tablename__ = "checklist"

    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"))
    vehicle = db.relationship("Vehicle", backref="checklists")
    technician = db.Column(db.String(120))
    date = db.Column(db.DateTime, default=lambda: agora())
    km = db.Column(db.Integer, default=0)
    status = db.Column(db.String(40), default="OK")
    notes = db.Column(db.Text)
    raw_json = db.Column(db.Text)
    signature = db.Column(db.String(255), nullable=True)


class ChecklistItem(db.Model):
    __tablename__ = "checklist_item"
    id = db.Column(db.Integer, primary_key=True)
    order = db.Column(db.Integer)
    text = db.Column(db.String(255), nullable=False)
    required = db.Column(db.Boolean, default=True)
    require_justif_no = db.Column(db.Boolean, default=False)
    type = db.Column(db.String(50), default="texto_curto")
    options = db.Column(db.Text)
    # Tipo de veículo ao qual este item pertence: carro | moto | caminhao | van
    vehicle_type = db.Column(db.String(20), default="carro")


class Announcement(db.Model):
    __tablename__ = "announcement"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    target_type = db.Column(db.String(50))  # internal, external, company, all, user
    target_id = db.Column(db.Integer)        # ID da empresa se target_type == company
    target_role = db.Column(db.String(50), nullable=True) # admin, supervisor, tech, manutencao
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=True)
    user = db.relationship("User", foreign_keys=[user_id], backref="targeted_announcements")
    category = db.Column(db.String(50), default="geral")  # geral, treinamento, escala, sistema
    whatsapp_status = db.Column(db.String(100), default="desativado")  # enviado, sem_telefone, desativado, falha
    expires_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=agora)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    reads = db.relationship("AnnouncementRead", backref="announcement", cascade="all, delete-orphan", lazy="dynamic")

    @property
    def message(self):
        return self.content

    @message.setter
    def message(self, value):
        self.content = value


class AnnouncementRead(db.Model):
    __tablename__ = "announcement_read"
    id = db.Column(db.Integer, primary_key=True)
    announcement_id = db.Column(db.Integer, db.ForeignKey("announcement.id"))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    read_at = db.Column(db.DateTime, default=agora)


class Manual(db.Model):
    __tablename__ = "manual"
    id = db.Column(db.Integer, primary_key=True)
    role_group = db.Column(db.String(50), unique=True, nullable=False)  # 'admin_supervisor', 'manutencao', 'tech'
    content = db.Column(db.Text, nullable=False)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)


class ToolCategory(db.Model):
    __tablename__ = "tool_category"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=agora)


class Tool(db.Model):
    __tablename__ = "tool"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    category = db.Column(db.String(50), nullable=True)
    is_active = db.Column(db.Boolean, default=True)
    created_at = db.Column(db.DateTime, default=agora)


class UserToolInspection(db.Model):
    __tablename__ = "user_tool_inspection"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), unique=True, nullable=False)
    user = db.relationship("User", backref=db.backref("tool_inspection", uselist=False, cascade="all, delete-orphan"))
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)
    notes = db.Column(db.Text)
    is_locked = db.Column(db.Boolean, default=True, nullable=False)
    signature = db.Column(db.String(255), nullable=True)


class UserToolStatus(db.Model):
    __tablename__ = "user_tool_status"
    id = db.Column(db.Integer, primary_key=True)
    inspection_id = db.Column(db.Integer, db.ForeignKey("user_tool_inspection.id", ondelete="CASCADE"), nullable=False)
    inspection = db.relationship("UserToolInspection", backref=db.backref("statuses", lazy=True, cascade="all, delete-orphan"))
    tool_id = db.Column(db.Integer, db.ForeignKey("tool.id", ondelete="CASCADE"), nullable=False)
    tool = db.relationship("Tool")
    status = db.Column(db.String(20), nullable=False)  # possui, nao_possui
    sub_status = db.Column(db.String(20), nullable=False)  # bom, ruim, nao_recebi, perdi
    damage_description = db.Column(db.Text)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)
    is_editable = db.Column(db.Boolean, default=False, nullable=False)


class ToolSuggestion(db.Model):
    __tablename__ = "tool_suggestion"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User", backref=db.backref("tool_suggestions", lazy=True, cascade="all, delete-orphan"))
    name = db.Column(db.String(100), nullable=False)
    purchase_link = db.Column(db.String(500), nullable=True)
    utility = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=agora)


class Training(db.Model):
    __tablename__ = "training"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    responsible_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    participants_json = db.Column(db.Text)
    date_planned = db.Column(db.Date)
    status = db.Column(db.String(20))
    obs = db.Column(db.Text)


class TrainingCourse(db.Model):
    __tablename__ = "training_course"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    category = db.Column(db.String(100))
    passing_grade = db.Column(db.Integer)
    is_mandatory = db.Column(db.Boolean)
    is_published = db.Column(db.Boolean)
    deadline = db.Column(db.Date)
    created_by_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=agora)
    badge_name = db.Column(db.String(100), default='Certificado')
    badge_icon = db.Column(db.String(50), default='fa-award')
    badge_color = db.Column(db.String(20), default='#0d9488')
    allow_retake = db.Column(db.Boolean, default=False)
    course_type = db.Column(db.String(50), default="lms")
    difficulty_level = db.Column(db.String(50), default="intermediario")
    workload_hours = db.Column(db.Float, default=1.0)
    xp_reward = db.Column(db.Integer, default=100)
    target_team_ids = db.Column(db.String(255), default="")
    cert_title = db.Column(db.String(500), default='CERTIFICADO DE CAPACITAÇÃO TÉCNICA')
    cert_subtitle = db.Column(db.Text, default='concluiu com aproveitamento e total conformidade técnica o treinamento operacional de:')
    cert_style = db.Column(db.String(100), default='classic')
    cert_signature_role = db.Column(db.String(255), default='Coordenação Técnica & Operações')
    cert_issuer_name = db.Column(db.String(255), default='')
    cert_validity_months = db.Column(db.Integer, default=0)
    cert_logo_path = db.Column(db.Text, default='')
    cert_company_name = db.Column(db.String(255), default='')
    cert_legal_text = db.Column(db.Text, default='Válido exclusivamente para fins de capacitação interna e procedimentos operacionais da empresa.')
    cert_standard = db.Column(db.String(500), default='Norma Interna de Qualidade & Procedimento Operacional Padrão')

    modules = db.relationship("TrainingModule", backref="course", cascade="all, delete-orphan", lazy=True, order_by="TrainingModule.order")
    questions = db.relationship("TrainingQuestion", backref="course", cascade="all, delete-orphan", lazy=True, order_by="TrainingQuestion.order")
    assignments = db.relationship("TrainingAssignment", backref="course", cascade="all, delete-orphan", lazy=True)


class TrainingModule(db.Model):
    __tablename__ = "training_module"
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("training_course.id", ondelete="CASCADE"), nullable=False)
    title = db.Column(db.String(200), nullable=False)
    content = db.Column(db.Text, nullable=False)
    order = db.Column(db.Integer, default=0)
    image_path = db.Column(db.String(255), nullable=True)
    video_path = db.Column(db.String(255), nullable=True)
    video_url = db.Column(db.String(500), nullable=True)
    attachment_path = db.Column(db.String(255), nullable=True)
    duration_minutes = db.Column(db.Integer, default=10)


class TrainingQuestion(db.Model):
    __tablename__ = "training_question"
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("training_course.id", ondelete="CASCADE"), nullable=False)
    question_text = db.Column(db.Text, nullable=False)
    option_a = db.Column(db.String(255), nullable=False)
    option_b = db.Column(db.String(255), nullable=False)
    option_c = db.Column(db.String(255), nullable=False)
    option_d = db.Column(db.String(255), nullable=False)
    correct_option = db.Column(db.String(1), nullable=False)
    explanation = db.Column(db.Text, nullable=True)
    difficulty = db.Column(db.String(50), default="medio")
    order = db.Column(db.Integer, default=0)


class TrainingAssignment(db.Model):
    __tablename__ = "training_assignment"
    id = db.Column(db.Integer, primary_key=True)
    course_id = db.Column(db.Integer, db.ForeignKey("training_course.id", ondelete="CASCADE"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    status = db.Column(db.String(20), default="pendente") # pendente, em_andamento, aprovado, reprovado
    best_score = db.Column(db.Integer)
    modules_read = db.Column(db.Text) # list of module_ids marked read
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)

    attempts = db.relationship("TrainingAttempt", backref="assignment", cascade="all, delete-orphan", lazy=True, order_by="desc(TrainingAttempt.attempted_at)")
    user = db.relationship("User", backref=db.backref("assignments", cascade="all, delete-orphan"), lazy=True)


class TrainingAttempt(db.Model):
    __tablename__ = "training_attempt"
    id = db.Column(db.Integer, primary_key=True)
    assignment_id = db.Column(db.Integer, db.ForeignKey("training_assignment.id", ondelete="CASCADE"), nullable=False)
    score = db.Column(db.Integer, nullable=False)
    total_questions = db.Column(db.Integer, nullable=False)
    correct_answers = db.Column(db.Integer, nullable=False)
    answers_json = db.Column(db.Text)
    attempted_at = db.Column(db.DateTime, default=agora)


class Badge(db.Model):
    __tablename__ = "badge"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100))
    icon = db.Column(db.String(50))
    color = db.Column(db.String(20))
    description = db.Column(db.Text)


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
    show_on_calendar = db.Column(db.Boolean, default=False)


class CompletedActivity(db.Model):
    __tablename__ = "completed_activity"
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    responsible_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="SET NULL"), nullable=True)
    responsible = db.relationship("User", backref="completed_activities")
    date = db.Column(db.Date)
    fields_json = db.Column(db.Text)  # JSON: [{"label":"Serviço Realizado","value":"..."},...]
    obs = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=agora)


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
    status = db.Column(db.String(20), default="PENDENTE")


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
    trigger_days = db.Column(db.Integer, default=7)
    channels = db.Column(db.String(100), default="system,whatsapp")
    msg_system = db.Column(db.Text)
    msg_whatsapp = db.Column(db.Text)
    msg_telegram = db.Column(db.Text)
    msg_email = db.Column(db.Text)
    silence_days = db.Column(db.Integer, default=1)


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


class AvariaOS(db.Model):
    __tablename__ = "avaria_os"

    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref="avarias")

    responsavel_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
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
    foto = db.Column(db.String(255))


class Log(db.Model):
    __tablename__ = "log"
    id = db.Column(db.Integer, primary_key=True)
    usuario = db.Column(db.String(100), nullable=False)
    acao = db.Column(db.String(255), nullable=False)
    data_hora = db.Column(db.DateTime, default=datetime.utcnow)


class Vistoria(db.Model):
    __tablename__ = "vistorias"

    id = db.Column(db.Integer, primary_key=True)
    vehicle_id = db.Column(db.Integer, db.ForeignKey("vehicle.id"), nullable=False)
    vehicle = db.relationship("Vehicle", backref=db.backref("vistorias", lazy=True))

    created_at = db.Column(db.DateTime, default=agora, nullable=False)
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    created_by_user = db.relationship("User", foreign_keys=[created_by])
    km = db.Column(db.Integer, nullable=True)
    turno = db.Column(db.String(20), default="fim", nullable=False) # inicio | durante | fim
    local = db.Column(db.String(120), nullable=True)
    status_geral = db.Column(db.String(20), default="ok", nullable=False) # ok | avarias
    observacoes = db.Column(db.Text, nullable=True)

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


class VistoriaFoto(db.Model):
    __tablename__ = "vistorias_fotos"

    id = db.Column(db.Integer, primary_key=True)
    vistoria_id = db.Column(db.Integer, db.ForeignKey("vistorias.id"), nullable=False)
    vistoria = db.relationship(
        "Vistoria",
        backref=db.backref("fotos", cascade="all, delete-orphan", lazy=True)
    )
    filename = db.Column(db.String(255), nullable=False)
    item_key = db.Column(db.String(50), nullable=True, index=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)


class SystemConfig(db.Model):
    __tablename__ = "system_config"
    id = db.Column(db.Integer, primary_key=True)
    mode = db.Column(db.String(20), default="start_only")
    
    scale_start_date = db.Column(db.Date)
    scale_start_team_id = db.Column(db.Integer)
    scale_rotation_order = db.Column(db.String(255))
    
    speed_limit = db.Column(db.Integer, default=80)
    ignition_alert = db.Column(db.Boolean, default=True)
    update_frequency = db.Column(db.Integer, default=30)
    simulator_active = db.Column(db.Boolean, default=False)
    
    login_bg_desktop = db.Column(db.String(255))
    login_bg_mobile = db.Column(db.String(255))
    login_logo = db.Column(db.String(255))
    sidebar_logo = db.Column(db.String(255))
    pdf_logo = db.Column(db.String(255))
    pdf_footer = db.Column(db.Text)
    login_primary_color = db.Column(db.String(50), default="#10b981")
    powerbi_url = db.Column(db.String(500))
    login_logo_height = db.Column(db.Integer, default=120)
    sidebar_logo_height = db.Column(db.Integer, default=44)
    pdf_logo_height = db.Column(db.Integer, default=30)
    login_bg_zoom = db.Column(db.Integer, default=100)
    login_bg_blur = db.Column(db.Integer, default=0)
    login_bg_opacity = db.Column(db.Integer, default=15)

    # Background image sizing & positioning per device
    login_bg_size_desktop = db.Column(db.String(50), default="cover")
    login_bg_size_mobile = db.Column(db.String(50), default="cover")
    login_bg_position_desktop = db.Column(db.String(50), default="center")
    login_bg_position_mobile = db.Column(db.String(50), default="center")

    # Login card styling
    login_card_opacity = db.Column(db.Integer, default=60)
    login_card_blur = db.Column(db.Integer, default=12)
    login_card_radius = db.Column(db.Integer, default=16)

    # Login text customization
    login_title_text = db.Column(db.String(100), default="Acesso ao Sistema")
    login_subtitle_text = db.Column(db.String(150), default="")
    login_username_placeholder = db.Column(db.String(100), default="Digite seu usuário")
    login_password_placeholder = db.Column(db.String(100), default="Digite sua senha")
    login_btn_text = db.Column(db.String(50), default="Entrar")
    login_btn_radius = db.Column(db.Integer, default=12)
    login_btn_padding_y = db.Column(db.Integer, default=12)
    login_btn_font_size = db.Column(db.Integer, default=16)

    # Overlay color (hex)
    login_overlay_color = db.Column(db.String(20), default="#000000")

    # Secondary color for gradients
    login_secondary_color = db.Column(db.String(50), default="#064e3b")

    # Sidebar customization
    sidebar_bg_color = db.Column(db.String(50))
    sidebar_text_color = db.Column(db.String(50))

    # Custom favicon
    favicon_custom = db.Column(db.String(255))

    # Login card position
    login_card_position = db.Column(db.String(20), default="right")

    # Layout mode and Hero Banner customization for modern login
    login_layout_mode = db.Column(db.String(30), default="split")
    login_hero_title = db.Column(db.String(255), default="Gestão Inteligente de Frotas e Equipes")
    login_hero_subtitle = db.Column(db.Text, default="Controle total da sua operação, com mais eficiência, produtividade e segurança.")
    login_hero_bullets = db.Column(db.Text, default="Gestão completa de frotas e veículos|Controle de equipes e produtividade|Vistorias e checklists digitais em tempo real|Gestão de Ordens de Serviço (O.S.) e avarias|Monitoramento operacional e indicadores|Automação de processos e redução de custos")
    login_footer_text = db.Column(db.String(255), default="© 2026 Painel de Frota. Todos os direitos reservados.")




class WhatsAppConfig(db.Model):
    __tablename__ = "whatsapp_config"
    id = db.Column(db.Integer, primary_key=True)
    api_url = db.Column(db.String(255), default="https://api.evolution.com")
    apikey = db.Column(db.String(255), default="")
    instance_name = db.Column(db.String(100), default="checklist_instance")
    is_enabled = db.Column(db.Boolean, default=False)
    
    msg_checklist_fail = db.Column(db.Text, default="*Aviso de Checklist:* O técnico {tecnico} realizou um checklist no veículo {veiculo} ({placa}) com avarias/inconformidades.")
    msg_os_opened = db.Column(db.Text, default="*Nova O.S. Criada:* Uma nova Ordem de Serviço foi aberta para o veículo {veiculo} ({placa}) com gravidade {gravidade}. Descrição: {descricao}")
    msg_os_closed = db.Column(db.Text, default="*O.S. Finalizada:* A Ordem de Serviço #{id} para o veículo {veiculo} foi finalizada por {usuario}. Serviço: {servico}")
    msg_new_vistoria = db.Column(db.Text, default="*Nova Vistoria:* O supervisor registrou uma nova vistoria para o veículo {veiculo} ({placa}). Status geral: {status}")
    
    msg_scale_alert = db.Column(db.Text, default="*Aviso de Plantão:* Olá {usuario}, você está escalado para o plantão de {escala} no dia {data}.")
    msg_late_checklist = db.Column(db.Text, default="*Alerta de Checklist Pendente:* Olá {usuario}, você está de plantão hoje e ainda não preencheu o checklist do seu veículo.")
    msg_training_alert = db.Column(db.Text, default="*Lembrete de Treinamento LMS:* Olá {usuario}, lembramos que você tem o treinamento \"{curso}\" pendente no portal.")
    msg_os_overdue = db.Column(db.Text, default="*O.S. Atrasada:* Olá {usuario}, a Ordem de Serviço #{id} está pendente há mais de 7 dias.")
    msg_inactive_tech = db.Column(db.Text, default="*Lembrete de Inatividade:* Olá {usuario}, identificamos que você não realiza checklists há mais de 7 dias.")
    
    recipients = db.Column(db.Text, default="")


class TelegramConfig(db.Model):
    __tablename__ = "telegram_config"
    id = db.Column(db.Integer, primary_key=True)
    bot_token = db.Column(db.String(255))
    chat_id = db.Column(db.String(100))
    is_enabled = db.Column(db.Boolean, default=False)


class EmailConfig(db.Model):
    __tablename__ = "email_config"
    id = db.Column(db.Integer, primary_key=True)
    smtp_server = db.Column(db.String(255))
    smtp_port = db.Column(db.Integer, default=587)
    smtp_user = db.Column(db.String(255))
    smtp_password = db.Column(db.String(255))
    from_email = db.Column(db.String(255))
    use_ssl = db.Column(db.Boolean, default=False)
    is_enabled = db.Column(db.Boolean, default=False)


class CloudflareConfig(db.Model):
    __tablename__ = "cloudflare_config"
    id = db.Column(db.Integer, primary_key=True)
    bucket_name = db.Column(db.String(150))
    access_key_id = db.Column(db.String(255))
    secret_access_key = db.Column(db.String(255))
    account_id = db.Column(db.String(255))
    endpoint_url = db.Column(db.String(255))
    public_url = db.Column(db.String(255))
    is_enabled = db.Column(db.Boolean, default=False)


class TraccarConfig(db.Model):
    __tablename__ = "traccar_config"
    id = db.Column(db.Integer, primary_key=True)
    server_url = db.Column(db.String(255), default="http://localhost:8082")
    api_token = db.Column(db.String(255))
    username = db.Column(db.String(100))
    password = db.Column(db.String(255))
    is_enabled = db.Column(db.Boolean, default=False)


class MetabaseConfig(db.Model):
    __tablename__ = "metabase_config"
    id = db.Column(db.Integer, primary_key=True)
    embed_url = db.Column(db.String(500))
    secret_key = db.Column(db.String(255))
    is_enabled = db.Column(db.Boolean, default=False)


class WhatsAppLog(db.Model):
    __tablename__ = "whatsapp_log"
    id = db.Column(db.Integer, primary_key=True)
    phone = db.Column(db.String(20), nullable=False)
    message = db.Column(db.Text, nullable=False)
    status_code = db.Column(db.Integer, nullable=True)
    status_text = db.Column(db.String(50), default="SENT")  # SENT, ERROR
    sent_at = db.Column(db.DateTime, default=agora)


# ==============================================================================
# 🌐 MODELOS FTTH/FTTX — PLATAFORMA DE ENGENHARIA DE REDE ÓPTICA
# ==============================================================================

class NetworkNode(db.Model):
    """Elementos de infraestrutura georreferenciados no mapa FTTH."""
    __tablename__ = "network_node"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(50))  # Código interno (ex: POP-001, CTO-042)
    type = db.Column(db.String(50), nullable=False)
    # Types: post, ceo, cto, dio, rack, mini_rack, armario_outdoor,
    #        shelter, pop, torre, olt, onu, ont, switch, router,
    #        server, firewall, nobreak, battery_bank, converter
    lat = db.Column(db.Float, nullable=False)
    lng = db.Column(db.Float, nullable=False)
    status = db.Column(db.String(30), default="active")
    # Status: planned, deploying, active, maintenance, disabled
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    capacity = db.Column(db.String(100))
    observations = db.Column(db.Text)
    layer = db.Column(db.String(50), default="infrastructure")
    details = db.Column(db.Text)  # JSON flexível para dados extras
    photos = db.Column(db.Text)  # JSON array de paths de fotos
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)

    splitters = db.relationship("NetworkSplitter", backref="node", cascade="all, delete-orphan")
    equipment = db.relationship("NetworkEquipment", backref="node", cascade="all, delete-orphan")
    racks = db.relationship("NetworkRack", backref="node", cascade="all, delete-orphan")


class NetworkEquipment(db.Model):
    """Equipamentos ativos de rede (OLT, Switch, etc) instalados em nós."""
    __tablename__ = "network_equipment"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    code = db.Column(db.String(50))
    type = db.Column(db.String(50), nullable=False)
    # Types: olt, onu, ont, switch, router, server, firewall,
    #        nobreak, battery_bank, converter, patch_panel, pdu, organizer
    node_id = db.Column(db.Integer, db.ForeignKey("network_node.id", ondelete="CASCADE"))
    manufacturer = db.Column(db.String(100))
    model = db.Column(db.String(100))
    serial_number = db.Column(db.String(100))
    ports_total = db.Column(db.Integer, default=0)
    ports_used = db.Column(db.Integer, default=0)
    power_watts = db.Column(db.Float, default=0)
    status = db.Column(db.String(30), default="active")
    observations = db.Column(db.Text)
    details = db.Column(db.Text)  # JSON
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)


class NetworkSplitter(db.Model):
    """Splitters PLC com gestão de portas individuais."""
    __tablename__ = "network_splitter"

    id = db.Column(db.Integer, primary_key=True)
    node_id = db.Column(db.Integer, db.ForeignKey("network_node.id", ondelete="CASCADE"), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ratio = db.Column(db.String(20), nullable=False)
    # Ratios: 1x2, 1x4, 1x8, 1x16, 1x32, 1x64
    ports = db.Column(db.Text)  # JSON: [{port: 1, client: "...", signal_dbm: -19.5, status: "active"}, ...]
    details = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)


class NetworkEdge(db.Model):
    """Cabos e rotas ópticas entre nós da rede FTTH."""
    __tablename__ = "network_edge"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    type = db.Column(db.String(50), default="backbone")
    # Types: backbone, distribution, drop, underground, aerial
    source_node_id = db.Column(db.Integer, db.ForeignKey("network_node.id", ondelete="CASCADE"), nullable=False)
    target_node_id = db.Column(db.Integer, db.ForeignKey("network_node.id", ondelete="CASCADE"), nullable=False)
    path_coordinates = db.Column(db.Text)  # JSON: [[lat, lng], ...]
    fiber_count = db.Column(db.Integer, default=12)
    tube_count = db.Column(db.Integer, default=1)
    cable_model = db.Column(db.String(100))
    manufacturer = db.Column(db.String(100))
    distance_m = db.Column(db.Float, default=0)
    technical_reserve_m = db.Column(db.Float, default=0)
    color = db.Column(db.String(20), default="#6366f1")
    thickness = db.Column(db.Integer, default=3)
    status = db.Column(db.String(30), default="active")
    # Status: planned, deploying, active, maintenance, disabled
    layer = db.Column(db.String(50), default="cables")
    details = db.Column(db.Text)  # JSON
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)

    source = db.relationship("NetworkNode", foreign_keys=[source_node_id])
    target = db.relationship("NetworkNode", foreign_keys=[target_node_id])


class NetworkRack(db.Model):
    """Racks físicos para montagem visual de equipamentos."""
    __tablename__ = "network_rack"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(150), nullable=False)
    node_id = db.Column(db.Integer, db.ForeignKey("network_node.id", ondelete="CASCADE"))
    total_units = db.Column(db.Integer, default=44)  # Total U's
    depth_mm = db.Column(db.Integer, default=600)
    width_mm = db.Column(db.Integer, default=600)
    location = db.Column(db.String(200))
    observations = db.Column(db.Text)
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)

    slots = db.relationship("NetworkRackSlot", backref="rack", cascade="all, delete-orphan")


class NetworkRackSlot(db.Model):
    """Slots ocupados no rack (posição U + equipamento)."""
    __tablename__ = "network_rack_slot"

    id = db.Column(db.Integer, primary_key=True)
    rack_id = db.Column(db.Integer, db.ForeignKey("network_rack.id", ondelete="CASCADE"), nullable=False)
    position_u = db.Column(db.Integer, nullable=False)  # Posição no rack (1-based)
    height_u = db.Column(db.Integer, default=1)  # Altura do equipamento em U's
    equipment_id = db.Column(db.Integer, db.ForeignKey("network_equipment.id", ondelete="SET NULL"))
    side = db.Column(db.String(10), default="front")  # front, back
    label = db.Column(db.String(100))
    created_at = db.Column(db.DateTime, default=agora)

    equipment = db.relationship("NetworkEquipment")


class NetworkLayer(db.Model):
    """Camadas personalizáveis do mapa para controle de visibilidade."""
    __tablename__ = "network_layer"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False, unique=True)
    display_name = db.Column(db.String(100))
    color = db.Column(db.String(20), default="#6366f1")
    icon = db.Column(db.String(50), default="fa-layer-group")
    visible = db.Column(db.Boolean, default=True)
    sort_order = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=agora)


class NetworkProject(db.Model):
    """Projetos de expansão e planejamento de rede."""
    __tablename__ = "network_project"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(30), default="planning")
    # Status: planning, approved, in_progress, completed, cancelled
    created_by = db.Column(db.Integer, db.ForeignKey("user.id"))
    created_at = db.Column(db.DateTime, default=agora)
    updated_at = db.Column(db.DateTime, default=agora, onupdate=agora)


class NetworkChangeLog(db.Model):
    """Histórico de alterações na rede para auditoria."""
    __tablename__ = "network_changelog"

    id = db.Column(db.Integer, primary_key=True)
    entity_type = db.Column(db.String(50), nullable=False)  # node, edge, splitter, equipment
    entity_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(20), nullable=False)  # created, updated, deleted
    entity_name = db.Column(db.String(150))
    old_data = db.Column(db.Text)  # JSON
    new_data = db.Column(db.Text)  # JSON
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"))
    user_name = db.Column(db.String(80))
    created_at = db.Column(db.DateTime, default=agora)


# Modelo GPSDevices e Logs (usados no gps_listener e monitoramento)
class GPSDevice(db.Model):
    __tablename__ = "gps_device"
    id = db.Column(db.Integer, primary_key=True)
    imei = db.Column(db.String(50), unique=True, nullable=False)
    iccid = db.Column(db.String(30)) # ID do Chip
    phone_number = db.Column(db.String(20)) # Número do Chip
    provider = db.Column(db.String(50)) # Vivo, Tim, Claro, etc.
    vehicle_id = db.Column(db.Integer, db.ForeignKey('vehicle.id'), unique=True)
    vehicle = db.relationship("Vehicle", backref=db.backref("gps_device", uselist=False))
    model = db.Column(db.String(50), default="TK103")
    is_active = db.Column(db.Boolean, default=True)
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
    vehicle = db.relationship("Vehicle", backref=db.backref("gps_alerts", lazy=True))
    alert_type = db.Column(db.String(50), nullable=False) # SPEED_LIMIT, IGNITION_OFF_HOURS, GEOFENCE_EXIT
    description = db.Column(db.String(255))
    latitude = db.Column(db.Float)
    longitude = db.Column(db.Float)
    timestamp = db.Column(db.DateTime, default=agora)
    is_dismissed = db.Column(db.Boolean, default=False)


class SystemRuleLog(db.Model):
    __tablename__ = "system_rule_logs"
    id = db.Column(db.Integer, primary_key=True)
    rule_slug = db.Column(db.String(50), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    channel = db.Column(db.String(20), nullable=False) # 'system', 'whatsapp', 'telegram', 'email'
    recipient = db.Column(db.String(255), nullable=False) # phone, email, chat_id, or "system"
    message = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default="SENT") # 'SENT', 'FAILED', 'FAILED_RETRY'
    error_message = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=agora)
    retry_count = db.Column(db.Integer, default=0)

    # Relationships
    user = db.relationship("User", backref="rule_logs")


# ==========================================
# 📂 MÓDULO: GESTÃO DE DOCUMENTOS TÉCNICOS
# ==========================================

class DocCategory(db.Model):
    __tablename__ = "doc_category"
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), unique=True, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: agora())


class TechnicalDocument(db.Model):
    __tablename__ = "technical_document"
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id", ondelete="CASCADE"), nullable=False)
    user = db.relationship("User", backref=db.backref("technical_documents", lazy=True, cascade="all, delete-orphan"))

    name = db.Column(db.String(150), nullable=False)
    category_id = db.Column(db.Integer, db.ForeignKey("doc_category.id", ondelete="RESTRICT"), nullable=False)
    category = db.relationship("DocCategory", backref="documents")

    doc_type = db.Column(db.String(50)) # e.g. CNH, RG, contrato, etc.
    description = db.Column(db.Text)
    date_issued = db.Column(db.Date, nullable=True)
    date_expired = db.Column(db.Date, nullable=True)
    issuer = db.Column(db.String(150))
    notes = db.Column(db.Text)

    is_required = db.Column(db.Boolean, default=False)
    is_active = db.Column(db.Boolean, default=True)

    created_at = db.Column(db.DateTime, default=lambda: agora())
    updated_at = db.Column(db.DateTime, default=lambda: agora(), onupdate=lambda: agora())


class DocumentFile(db.Model):
    __tablename__ = "document_file"
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("technical_document.id", ondelete="CASCADE"), nullable=False)
    document = db.relationship("TechnicalDocument", backref=db.backref("files", lazy=True, cascade="all, delete-orphan"))

    filename = db.Column(db.String(255), nullable=False)
    file_path = db.Column(db.String(512), nullable=False)
    uploaded_at = db.Column(db.DateTime, default=lambda: agora())


class DocumentHistory(db.Model):
    __tablename__ = "document_history"
    id = db.Column(db.Integer, primary_key=True)
    document_id = db.Column(db.Integer, db.ForeignKey("technical_document.id", ondelete="CASCADE"), nullable=True)
    document = db.relationship("TechnicalDocument")

    operator_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    operator = db.relationship("User")

    action = db.Column(db.String(50), nullable=False) # "created", "edited", "deleted"
    details = db.Column(db.Text) # Descrição JSON ou texto plano
    created_at = db.Column(db.DateTime, default=lambda: agora())


