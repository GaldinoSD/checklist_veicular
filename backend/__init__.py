# -*- coding: utf-8 -*-
import os
import sys
import secrets
from flask import Flask, session, request, abort, redirect, url_for, flash, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, current_user
from backend.config import Config, BASE_DIR

db = SQLAlchemy()
login_manager = LoginManager()
login_manager.login_view = "login"  # Embora usemos GlobalBlueprint, definimos o login view

def create_app():
    # Detecta se está em ambiente de teste
    is_testing = False
    if os.getenv("TESTING") == "true":
        is_testing = True
    elif "pytest" in sys.modules or "unittest" in sys.modules:
        is_testing = True
    else:
        for arg in sys.argv:
            if "pytest" in arg or "unittest" in arg or "tox" in arg or "test_lms" in arg:
                is_testing = True
                break

    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "frontend" / "templates"),
        static_folder=str(BASE_DIR / "frontend" / "static")
    )
    
    # Configurações do app
    app.config.from_object(Config)
    
    # 🛡️ SECRET_KEY robusta
    _secret = os.getenv("SECRET_KEY", "")
    if not _secret or _secret == "altere-esta-chave":
        if not is_testing:
            print("⚠️  AVISO CRÍTICO: SECRET_KEY não configurada ou usando valor padrão inseguro!")
        import secrets as _s
        _secret = _s.token_urlsafe(64)
    app.config["SECRET_KEY"] = _secret

    if is_testing:
        app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///:memory:"
        app.config["TESTING"] = True
        app.testing = True

    # Inicializa as extensões
    db.init_app(app)
    login_manager.init_app(app)

    # ==========================================
    # 🛡️ CABEÇALHOS DE SEGURANÇA
    # ==========================================
    @app.after_request
    def add_security_headers(response):
        response.headers['X-Frame-Options'] = 'SAMEORIGIN'
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        return response

    # ==========================================
    # 🛡️ PROTEÇÃO CONTRA CSRF (SYNCHRONIZER TOKEN PATTERN)
    # ==========================================
    @app.context_processor
    def inject_csrf_token():
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
        return dict(csrf_token=session["csrf_token"])

    @app.before_request
    def verify_csrf():
        if app.testing:
            return
            
        if "csrf_token" not in session:
            session["csrf_token"] = secrets.token_hex(32)
            
        if request.method in ("POST", "PUT", "PATCH", "DELETE"):
            if request.path == "/api/gps/gateway":
                return
                
            token = request.form.get("csrf_token") or request.headers.get("X-CSRFToken")
            session_token = session.get("csrf_token")
            
            if not session_token or not token or token != session_token:
                abort(400, description="CSRF token missing or invalid.")

    # ==========================================
    # FILTROS DE TEMPLATE JINJA2
    # ==========================================
    from backend.config import TZ
    from backend.models import SystemConfig
    from backend.utils import agora, br_datetime
    
    app.template_filter("br_datetime")(br_datetime)

    import re
    from markupsafe import Markup, escape

    @app.template_filter('urlize_custom')
    def urlize_custom_filter(s):
        if not s:
            return ""
        s_escaped = str(escape(s))
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
        return Markup(url_pattern.sub(replace, s_escaped))

    @app.template_filter('time_until')
    def time_until_filter(dt):
        if not dt:
            return ""
        diff = dt - agora()
        seconds = diff.total_seconds()
        if seconds <= 0:
            return "Expirado"
        days = int(seconds // 86400)
        if days > 0:
            return f"Expira em {days}d"
        hours = int((seconds % 86400) // 3600)
        if hours > 0:
            return f"Expira em {hours}h"
        minutes = int((seconds % 3600) // 60)
        return f"Expira em {minutes}min"

    # Context Processor para Flags de Perfis no Layout
    @app.context_processor
    def inject_role_flags():
        config = SystemConfig.query.first()
        return dict(
            ROLE_ADMIN=(current_user.is_authenticated and current_user.is_admin),
            ROLE_SUPERVISOR=(current_user.is_authenticated and current_user.is_supervisor),
            ROLE_TECH=(current_user.is_authenticated and current_user.is_tech),
            ROLE_MANUTENCAO=(current_user.is_authenticated and current_user.is_manutencao),
            sys_config=config
        )

    # ==========================================
    # USER LOADER PARA FLASK-LOGIN
    # ==========================================
    from backend.models import User
    
    @login_manager.user_loader
    def load_user(uid):
        return User.query.get(int(uid))

    # ==========================================
    # REGISTRO DE BLUEPRINTS
    # ==========================================
    from backend.blueprints.auth import auth_bp
    from backend.blueprints.fleet import fleet_bp
    from backend.blueprints.technical import technical_bp
    from backend.blueprints.network import network_bp
    from backend.blueprints.whatsapp import whatsapp_bp

    app.register_blueprint(auth_bp)
    app.register_blueprint(fleet_bp)
    app.register_blueprint(technical_bp)
    app.register_blueprint(network_bp)
    app.register_blueprint(whatsapp_bp)

    # ==========================================
    # INICIALIZAÇÃO DE BANCO E SCHEMA
    # ==========================================
    from sqlalchemy import text
    from backend.models import ChecklistItem, WhatsAppConfig

    def ensure_min_schema():
        """Garante as migrações leves no PostgreSQL."""
        stmts = [
            text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS role VARCHAR(20)'),
            text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS type VARCHAR(20) DEFAULT \'carro\''),
            text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS driver_id INTEGER REFERENCES "user"(id)'),
            text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS map_icon VARCHAR(50) DEFAULT \'fa-location-arrow\''),
            text('ALTER TABLE vehicle ADD COLUMN IF NOT EXISTS map_color VARCHAR(20) DEFAULT \'#10b981\''),
            text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS type VARCHAR(50) DEFAULT \'texto_curto\''),
            text('ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS options TEXT'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS speed_limit INTEGER DEFAULT 80'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS ignition_alert BOOLEAN DEFAULT TRUE'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS update_frequency INTEGER DEFAULT 30'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS simulator_active BOOLEAN DEFAULT FALSE'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_bg_desktop VARCHAR(255)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_bg_mobile VARCHAR(255)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_logo VARCHAR(255)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS sidebar_logo VARCHAR(255)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS pdf_logo VARCHAR(255)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS pdf_footer TEXT'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS powerbi_url VARCHAR(500)'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_logo_height INTEGER DEFAULT 120'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS sidebar_logo_height INTEGER DEFAULT 44'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS pdf_logo_height INTEGER DEFAULT 30'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_bg_zoom INTEGER DEFAULT 100'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_bg_blur INTEGER DEFAULT 0'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_bg_opacity INTEGER DEFAULT 15'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_btn_padding_y INTEGER DEFAULT 12'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_btn_font_size INTEGER DEFAULT 16'),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_subtitle_text VARCHAR(150) DEFAULT \'\''),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_username_placeholder VARCHAR(100) DEFAULT \'Digite seu usuário\''),
            text('ALTER TABLE system_config ADD COLUMN IF NOT EXISTS login_password_placeholder VARCHAR(100) DEFAULT \'Digite sua senha\''),
            text('ALTER TABLE announcement ADD COLUMN IF NOT EXISTS target_role VARCHAR(50)'),
            text('ALTER TABLE announcement ADD COLUMN IF NOT EXISTS user_id INTEGER REFERENCES "user"(id) ON DELETE CASCADE'),
            text('ALTER TABLE announcement ADD COLUMN IF NOT EXISTS expires_at TIMESTAMP'),
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
            '''),
            text('''
                CREATE TABLE IF NOT EXISTS whatsapp_config (
                    id SERIAL PRIMARY KEY,
                    api_url VARCHAR(255) DEFAULT 'https://api.evolution.com',
                    apikey VARCHAR(255) DEFAULT '',
                    instance_name VARCHAR(100) DEFAULT 'checklist_instance',
                    is_enabled BOOLEAN DEFAULT FALSE,
                    msg_checklist_fail TEXT DEFAULT '*Aviso de Checklist:* O técnico {tecnico} realizou um checklist no veículo {veiculo} ({placa}) com avarias/inconformidades.',
                    msg_os_opened TEXT DEFAULT '*Nova O.S. Criada:* Uma nova Ordem de Serviço foi aberta para o veículo {veiculo} ({placa}) com gravidade {gravidade}. Descrição: {descricao}',
                    msg_os_closed TEXT DEFAULT '*O.S. Finalizada:* A Ordem de Serviço #{id} para o veículo {veiculo} foi finalizada por {usuario}. Serviço: {servico}',
                    msg_new_vistoria TEXT DEFAULT '*Nova Vistoria:* O supervisor registrou uma nova vistoria para o veículo {veiculo} ({placa}). Status geral: {status}',
                    recipients TEXT DEFAULT ''
                )
            '''),
            text("ALTER TABLE whatsapp_config ADD COLUMN IF NOT EXISTS msg_scale_alert TEXT DEFAULT '*Aviso de Plantão:* Olá {usuario}, você está escalado para o plantão de {escala} no dia {data}.'"),
            text("ALTER TABLE whatsapp_config ADD COLUMN IF NOT EXISTS msg_late_checklist TEXT DEFAULT '*Alerta de Checklist Pendente:* Olá {usuario}, você está de plantão hoje e ainda não preencheu o checklist do seu veículo.'"),
            text("ALTER TABLE whatsapp_config ADD COLUMN IF NOT EXISTS msg_training_alert TEXT DEFAULT '*Lembrete de Treinamento LMS:* Olá {usuario}, lembramos que você tem o treinamento \"{curso}\" pendente no portal.'"),
            text("ALTER TABLE whatsapp_config ADD COLUMN IF NOT EXISTS msg_os_overdue TEXT DEFAULT '*O.S. Atrasada:* Olá {usuario}, a Ordem de Serviço #{id} está pendente há mais de 7 dias.'"),
            text("ALTER TABLE whatsapp_config ADD COLUMN IF NOT EXISTS msg_inactive_tech TEXT DEFAULT '*Lembrete de Inatividade:* Olá {usuario}, identificamos que você não realiza checklists há mais de 7 dias.'"),
            text('ALTER TABLE avaria_os ADD COLUMN IF NOT EXISTS foto VARCHAR(255)'),
            text('ALTER TABLE training_module ADD COLUMN IF NOT EXISTS image_path VARCHAR(255)'),
            text('ALTER TABLE training_module ADD COLUMN IF NOT EXISTS video_path VARCHAR(255)'),
            text('''
                CREATE TABLE IF NOT EXISTS network_node (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(100) NOT NULL,
                    type VARCHAR(50) NOT NULL,
                    lat FLOAT NOT NULL,
                    lng FLOAT NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''),
            text('''
                CREATE TABLE IF NOT EXISTS network_splitter (
                    id SERIAL PRIMARY KEY,
                    node_id INTEGER NOT NULL REFERENCES network_node(id) ON DELETE CASCADE,
                    name VARCHAR(100) NOT NULL,
                    ratio VARCHAR(20) NOT NULL,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''),
            text('''
                CREATE TABLE IF NOT EXISTS network_edge (
                    id SERIAL PRIMARY KEY,
                    name VARCHAR(150) NOT NULL,
                    type VARCHAR(50) DEFAULT 'cable_fo',
                    source_node_id INTEGER NOT NULL REFERENCES network_node(id) ON DELETE CASCADE,
                    target_node_id INTEGER NOT NULL REFERENCES network_node(id) ON DELETE CASCADE,
                    path_coordinates TEXT,
                    details TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            '''),
            text('ALTER TABLE training_course ADD COLUMN IF NOT EXISTS course_type VARCHAR(50) DEFAULT \'lms\''),
            text('ALTER TABLE user_tool_inspection ADD COLUMN IF NOT EXISTS is_locked BOOLEAN DEFAULT true'),
            text('ALTER TABLE user_tool_status ADD COLUMN IF NOT EXISTS is_editable BOOLEAN DEFAULT false'),
            text('ALTER TABLE user_tool_inspection ADD COLUMN IF NOT EXISTS signature VARCHAR(255)'),
            text('ALTER TABLE checklist ADD COLUMN IF NOT EXISTS signature VARCHAR(255)'),
            text("ALTER TABLE checklist_item ADD COLUMN IF NOT EXISTS vehicle_type VARCHAR(20) DEFAULT 'carro'"),
            text('ALTER TABLE "user" ADD COLUMN IF NOT EXISTS telegram_chat_id VARCHAR(100)'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS trigger_days INTEGER DEFAULT 7'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS channels VARCHAR(100) DEFAULT \'system,whatsapp\''),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS msg_system TEXT'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS msg_whatsapp TEXT'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS msg_telegram TEXT'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS msg_email TEXT'),
            text('''
                CREATE TABLE IF NOT EXISTS telegram_config (
                    id SERIAL PRIMARY KEY,
                    bot_token VARCHAR(255) DEFAULT '',
                    chat_id VARCHAR(100) DEFAULT '',
                    is_enabled BOOLEAN DEFAULT FALSE
                )
            '''),
            text('''
                CREATE TABLE IF NOT EXISTS email_config (
                    id SERIAL PRIMARY KEY,
                    smtp_server VARCHAR(255) DEFAULT '',
                    smtp_port INTEGER DEFAULT 587,
                    smtp_user VARCHAR(255) DEFAULT '',
                    smtp_password VARCHAR(255) DEFAULT '',
                    from_email VARCHAR(255) DEFAULT '',
                    use_ssl BOOLEAN DEFAULT FALSE,
                    is_enabled BOOLEAN DEFAULT FALSE
                )
            '''),
            text('ALTER TABLE email_config ADD COLUMN IF NOT EXISTS use_ssl BOOLEAN DEFAULT FALSE'),
            text('ALTER TABLE system_rule ADD COLUMN IF NOT EXISTS silence_days INTEGER DEFAULT 1'),
            text('''
                CREATE TABLE IF NOT EXISTS system_rule_logs (
                    id SERIAL PRIMARY KEY,
                    rule_slug VARCHAR(50) NOT NULL,
                    user_id INTEGER,
                    channel VARCHAR(20) NOT NULL,
                    recipient VARCHAR(255) NOT NULL,
                    message TEXT NOT NULL,
                    status VARCHAR(20) DEFAULT 'SENT',
                    error_message TEXT,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    retry_count INTEGER DEFAULT 0
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

        # Migração automática dos templates legados de WhatsApp para as regras de SystemRule correspondentes
        try:
            from backend.models import SystemRule, WhatsAppConfig
            w_config = WhatsAppConfig.query.first()
            if w_config:
                mapping = {
                    "scale_alert": w_config.msg_scale_alert,
                    "late_checklist": w_config.msg_late_checklist,
                    "training_alert": w_config.msg_training_alert,
                    "os_alert": w_config.msg_os_overdue,
                    "os_sla": w_config.msg_os_overdue,
                    "inactive_tech_alert": w_config.msg_inactive_tech
                }
                for slug, template in mapping.items():
                    rule = SystemRule.query.filter_by(slug=slug).first()
                    if rule and template and not rule.msg_whatsapp:
                        rule.msg_whatsapp = template
                db.session.commit()
        except Exception as e:
            print("⚠️ Erro ao migrar templates de WhatsApp para as regras:", e)
            db.session.rollback()
 
    # Itens padrão por tipo de veículo
    DEFAULT_ITEMS_CARRO = [
        ("Pneus (calibragem/estado)", "sim_nao_na"),
        ("Luzes frontais", "sim_nao_na"),
        ("Luzes traseiras", "sim_nao_na"),
        ("Setas e alerta", "sim_nao_na"),
        ("Extintor (validade)", "sim_nao_na"),
        ("Painel sem avisos críticos", "sim_nao_na"),
        ("Documentação do veículo", "sim_nao_na"),
        ("Observações gerais", "paragrafo"),
    ]

    DEFAULT_ITEMS_MOTO = [
        ("Pneus (calibragem/estado)", "sim_nao_na"),
        ("Luzes frontais e traseiras", "sim_nao_na"),
        ("Setas e alerta", "sim_nao_na"),
        ("Freios (dianteiro/traseiro)", "sim_nao_na"),
        ("Nível de óleo do motor", "sim_nao_na"),
        ("Corrente (tensão/lubrificação)", "sim_nao_na"),
        ("Documentação da moto", "sim_nao_na"),
        ("EPI utilizado (capacete/luvas)", "sim_nao_na"),
        ("Observações gerais", "paragrafo"),
    ]

    DEFAULT_ITEMS_CAMINHAO = [
        ("Pneus (calibragem/estado/step)", "sim_nao_na"),
        ("Luzes frontais", "sim_nao_na"),
        ("Luzes traseiras e de freio", "sim_nao_na"),
        ("Setas e alerta", "sim_nao_na"),
        ("Extintor (validade)", "sim_nao_na"),
        ("Nível de óleo do motor", "sim_nao_na"),
        ("Nível de água do radiador", "sim_nao_na"),
        ("Freios (sistema de ar)", "sim_nao_na"),
        ("Tacógrafo", "sim_nao_na"),
        ("Documentação do veículo", "sim_nao_na"),
        ("Carga fixada adequadamente", "sim_nao_na"),
        ("Observações gerais", "paragrafo"),
    ]

    DEFAULT_ITEMS_VAN = [
        ("Pneus (calibragem/estado)", "sim_nao_na"),
        ("Luzes frontais", "sim_nao_na"),
        ("Luzes traseiras", "sim_nao_na"),
        ("Setas e alerta", "sim_nao_na"),
        ("Extintor (validade)", "sim_nao_na"),
        ("Painel sem avisos críticos", "sim_nao_na"),
        ("Portas e travas funcionando", "sim_nao_na"),
        ("Documentação do veículo", "sim_nao_na"),
        ("Observações gerais", "paragrafo"),
    ]

    def seed_defaults():
        if not User.query.filter_by(username="ADMIN").first():
            _admin_pwd = secrets.token_urlsafe(16)
            u = User(username="admin", role="admin")
            u.set_password(_admin_pwd)
            db.session.add(u)
            print("="*60)
            print("🔐 ADMIN CRIADO COM SENHA ALEATÓRIA")
            print(f"   Usuário: admin")
            print(f"   Senha:   {_admin_pwd}")
            print("   ⚠️  ANOTE ESTA SENHA! Ela não será exibida novamente.")
            print("   Altere-a após o primeiro login.")
            print("="*60)
 
        if SystemConfig.query.count() == 0:
            db.session.add(SystemConfig(mode="start_only"))
 
        if WhatsAppConfig.query.count() == 0:
            db.session.add(WhatsAppConfig())
 
        # Seed itens por tipo de veículo (apenas se ainda não existir nenhum)
        seeds = [
            ("carro",    DEFAULT_ITEMS_CARRO),
            ("moto",     DEFAULT_ITEMS_MOTO),
            ("caminhao", DEFAULT_ITEMS_CAMINHAO),
            ("van",      DEFAULT_ITEMS_VAN),
        ]
        for vtype, items_list in seeds:
            if ChecklistItem.query.filter_by(vehicle_type=vtype).count() == 0:
                for i, (txt, typ) in enumerate(items_list, start=1):
                    db.session.add(ChecklistItem(order=i, text=txt, type=typ, vehicle_type=vtype))
 
        try:
            from backend.models import Tool
            Tool.query.update({Tool.is_active: True})
        except Exception as e:
            print("⚠️ Erro ao ativar ferramentas em seed_defaults:", e)

        db.session.commit()
 
    with app.app_context():
        try:
            db.create_all()
            if not is_testing:
                ensure_min_schema()
            seed_defaults()
        except Exception as startup_err:
            print("⚠️ Erro na inicialização concorrente do banco de dados:", startup_err)
            db.session.rollback()

    if not is_testing:
        try:
            from backend.scheduler import start_audit_scheduler
            start_audit_scheduler(app)
        except Exception as sched_err:
            print("⚠️ Erro ao iniciar scheduler de auditoria automática:", sched_err)

    return app


