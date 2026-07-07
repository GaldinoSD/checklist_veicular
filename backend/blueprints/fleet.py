# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
fleet_bp = GlobalBlueprint("fleet", __name__)

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
    UPLOAD_DIR, LOGO_PATH, LAYOUT_UPLOAD_DIR, INBOX_DIR, RELATORIOS_DIR,
    BASE_DIR
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
    agora, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts, parse_periodo,
    make_premium_pdf, allowed_file, br_datetime
)




# ----------------- VEÍCULOS (admin + supervisor) -----------------
@fleet_bp.route("/veiculos")
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




@fleet_bp.route("/veiculos/novo", methods=["POST"])
@login_required
def vehicle_new():
    if not current_user.is_admin and not current_user.has_permission("veiculos") and not current_user.has_permission("controle_veiculos"):
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




@fleet_bp.route("/veiculos/<int:vid>/status", methods=["POST"])
@login_required
def vehicle_status(vid):
    if not current_user.is_admin and not current_user.has_permission("veiculos") and not current_user.has_permission("controle_veiculos"):
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




@fleet_bp.route("/veiculos/<int:vid>/editar", methods=["POST"])
@login_required
def vehicle_edit(vid):
    if not current_user.is_admin and not current_user.has_permission("veiculos") and not current_user.has_permission("controle_veiculos"):
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




@fleet_bp.route("/veiculos/<int:vid>/excluir", methods=["POST"])
@login_required
def vehicle_delete(vid):
    if not current_user.is_admin and not current_user.has_permission("veiculos") and not current_user.has_permission("controle_veiculos"):
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
@fleet_bp.route("/veiculos/<int:vid>/info", methods=["POST"])
@login_required
def vehicle_info_save(vid):
    if not current_user.is_admin and not current_user.has_permission("veiculos") and not current_user.has_permission("controle_veiculos"):
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
@fleet_bp.route("/controle-veiculos", methods=["GET", "POST"])
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



@fleet_bp.route("/controle-veiculos/deletar/<int:mov_id>", methods=["POST"])
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



def safe_float(val):
    if not val:
        return None
    if isinstance(val, str):
        val = val.strip()
        if not val:
            return None
        val = val.replace("R$", "").replace(" ", "")
        if "," in val:
            if "." in val:
                val = val.replace(".", "")
            val = val.replace(",", ".")
    try:
        return float(val)
    except ValueError:
        return None



# ----------------- AVARIAS / ORDENS DE SERVIÇO -----------------
@fleet_bp.route("/avarias/registro", methods=["GET", "POST"])
@supervisor_allowed
def avarias_registro():
    if request.method == "POST":
        acao = request.form.get("acao")

        # CRIAR NOVA AVARIA
        if acao == "nova":
            import uuid
            foto_file = request.files.get("foto")
            saved_filename = None
            if foto_file and allowed_file(foto_file.filename):
                ext = os.path.splitext(foto_file.filename.lower())[1]
                saved_filename = f"avaria_{uuid.uuid4().hex}{ext}"
                foto_file.save(AVARIAS_UPLOAD_DIR / saved_filename)

            nova = AvariaOS(
                vehicle_id=request.form.get("veiculo_id"),
                # ✅ NÃO VEM MAIS DO FORM - define automático
                responsavel_id=current_user.id,  # ou None, se você quiser sem responsável
                gravidade=request.form.get("gravidade"),
                descricao=request.form.get("descricao"),
                km=request.form.get("km"),
                status="aberta",
                foto=saved_filename,
                data_abertura=agora()
            )
            db.session.add(nova)
            db.session.commit()
            
            # WhatsApp Nova OS
            try:
                w_config = WhatsAppConfig.query.first()
                if w_config and w_config.is_enabled:
                    v = Vehicle.query.get(nova.vehicle_id)
                    veiculo_txt = f"{v.brand} {v.model}" if v else f"ID {nova.vehicle_id}"
                    placa_txt = v.plate if v else ""
                    tpl = w_config.msg_os_opened
                    msg = tpl.format(
                        veiculo=veiculo_txt,
                        placa=placa_txt,
                        gravidade=nova.gravidade or "Média",
                        descricao=nova.descricao
                    )
                    send_whatsapp_message(msg)
            except Exception as whatsapp_err:
                print("⚠️ Erro ao disparar whatsapp para nova OS:", whatsapp_err)

            registrar_log(f"Avaria criada para veículo ID={nova.vehicle_id} (por {current_user.username})")
            return redirect(url_for("avarias_registro"))

        # FINALIZAR O.S (admin/supervisor)
        if acao == "finalizar":
            os_id = request.form.get("os_id")
            os_finalizar = AvariaOS.query.get(os_id)

            if os_finalizar:
                os_finalizar.valor_gasto = safe_float(request.form.get("valor"))
                os_finalizar.pecas_trocadas = request.form.get("pecas")
                os_finalizar.servico_realizado = request.form.get("servico")
                os_finalizar.status = "finalizada"
                os_finalizar.data_fechamento = agora()
                
                # Sume com o comunicado de O.S atrasada da Central de Notificações
                ann_title = f"⚠️ O.S. Atrasada: #{os_finalizar.id}"
                anns = Announcement.query.filter_by(title=ann_title).all()
                for ann in anns:
                    AnnouncementRead.query.filter_by(announcement_id=ann.id).delete()
                    db.session.delete(ann)
                
                db.session.commit()

                # Whatsapp OS finalizada
                try:
                    w_config = WhatsAppConfig.query.first()
                    if w_config and w_config.is_enabled:
                        v = os_finalizar.vehicle
                        veiculo_txt = f"{v.brand} {v.model}" if v else f"ID {os_finalizar.vehicle_id}"
                        tpl = w_config.msg_os_closed
                        msg = tpl.format(
                            id=os_finalizar.id,
                            veiculo=veiculo_txt,
                            usuario=current_user.username,
                            servico=os_finalizar.servico_realizado or "Manutenção concluída"
                        )
                        send_whatsapp_message(msg)
                except Exception as whatsapp_err:
                    print("⚠️ Erro ao disparar whatsapp para OS finalizada:", whatsapp_err)

                registrar_log(f"O.S finalizada (admin/supervisor): ID={os_finalizar.id} (por {current_user.username})")

            return redirect(url_for("avarias_registro"))

    # GET — listar avarias e calcular estatísticas
    q = request.args.get("q", "").strip()
    status_filter = request.args.get("status", "").strip()
    gravidade_filter = request.args.get("gravidade", "").strip()

    query = AvariaOS.query.join(Vehicle).outerjoin(User, AvariaOS.responsavel_id == User.id)

    if q:
        query = query.filter(
            db.or_(
                Vehicle.plate.ilike(f"%{q}%"),
                Vehicle.model.ilike(f"%{q}%"),
                Vehicle.brand.ilike(f"%{q}%"),
                User.username.ilike(f"%{q}%"),
                AvariaOS.descricao.ilike(f"%{q}%")
            )
        )
    if status_filter:
        query = query.filter(AvariaOS.status == status_filter)
    if gravidade_filter:
        query = query.filter(AvariaOS.gravidade == gravidade_filter)

    ordens = query.order_by(AvariaOS.id.desc()).all()
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



@fleet_bp.route("/avarias/excluir/<int:avaria_id>", methods=["POST"])
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




@fleet_bp.route("/avarias/<int:avaria_id>/pdf", methods=["GET"])
@supervisor_allowed
def avaria_pdf(avaria_id):
    import io
    from flask import send_file
    
    os_detail = AvariaOS.query.get_or_404(avaria_id)
    buffer = io.BytesIO()

    # Formatar data de abertura e fechamento usando br_datetime
    data_abertura_str = br_datetime(os_detail.data_abertura)
    data_fechamento_str = br_datetime(os_detail.data_fechamento)
    
    # Metadados
    metadata = {
        "ID": f"OS-{os_detail.id}",  # Ajustado para seguir o padrão com hífen (ex: OS-21)
        "ID O.S.": f"OS-{os_detail.id}",
        "Veículo": f"{os_detail.vehicle.brand} {os_detail.vehicle.model} ({os_detail.vehicle.plate})" if os_detail.vehicle else "N/A",
        "Gravidade": (os_detail.gravidade or "baixa").upper(),
        "KM Registro": f"{os_detail.km or 0} KM",
        "Responsável": os_detail.responsavel.username if os_detail.responsavel else "N/A",
        "Status": os_detail.status.upper()
    }

    content = [
        ("Descrição da Avaria", os_detail.descricao or "Sem descrição"),
        ("Peças Trocadas", os_detail.pecas_trocadas or "Nenhuma peça trocada"),
        ("Serviço Realizado", os_detail.servico_realizado or "Nenhum serviço registrado"),
        ("Valor Gasto", f"R$ {os_detail.valor_gasto:.2f}" if os_detail.valor_gasto is not None else "R$ 0,00"),
        ("Data de Abertura", data_abertura_str),
        ("Data de Fechamento", data_fechamento_str)
    ]

    # Carregar imagem do dano
    image_paths = []
    if os_detail.foto:
        p_path = AVARIAS_UPLOAD_DIR / os_detail.foto
        if p_path.exists():
            image_paths.append(p_path)

    make_premium_pdf(buffer, f"Ordem de Serviço OS-{os_detail.id}", metadata, content, image_paths=image_paths)
    buffer.seek(0)
    
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"ordem_servico_os-{os_detail.id}.pdf"
    )




# ----------------- TELA DA MANUTENÇÃO (SOMENTE MANUTENÇÃO) -----------------
@fleet_bp.route("/manutencao/os", methods=["GET", "POST"])
@manutencao_only
def manutencao_os():
    if request.method == "POST":
        acao = request.form.get("acao")

        # manutenção só FINALIZA O.S, não cria
        if acao == "finalizar":
            os_id = request.form.get("os_id")
            os_finalizar = AvariaOS.query.get(os_id)

            if os_finalizar:
                os_finalizar.valor_gasto = safe_float(request.form.get("valor"))
                os_finalizar.pecas_trocadas = request.form.get("pecas")
                os_finalizar.servico_realizado = request.form.get("servico")
                os_finalizar.status = "finalizada"
                os_finalizar.data_fechamento = agora()
                
                # Sume com o comunicado de O.S atrasada da Central de Notificações
                ann_title = f"⚠️ O.S. Atrasada: #{os_finalizar.id}"
                anns = Announcement.query.filter_by(title=ann_title).all()
                for ann in anns:
                    AnnouncementRead.query.filter_by(announcement_id=ann.id).delete()
                    db.session.delete(ann)
                
                db.session.commit()

                # Whatsapp OS finalizada
                try:
                    w_config = WhatsAppConfig.query.first()
                    if w_config and w_config.is_enabled:
                        v = os_finalizar.vehicle
                        veiculo_txt = f"{v.brand} {v.model}" if v else f"ID {os_finalizar.vehicle_id}"
                        tpl = w_config.msg_os_closed
                        msg = tpl.format(
                            id=os_finalizar.id,
                            veiculo=veiculo_txt,
                            usuario=current_user.username,
                            servico=os_finalizar.servico_realizado or "Manutenção concluída"
                        )
                        send_whatsapp_message(msg)
                except Exception as whatsapp_err:
                    print("⚠️ Erro ao disparar whatsapp para OS finalizada:", whatsapp_err)

                registrar_log(f"O.S finalizada (manutenção): ID={os_finalizar.id} (por {current_user.username})")

            return redirect(url_for("manutencao_os"))

        elif acao == "registrar_direto":
            vehicle_id = request.form.get("vehicle_id")
            gravidade = request.form.get("gravidade", "baixa")
            descricao = request.form.get("descricao", "Serviço direto sem O.S. aberta")
            km = request.form.get("km")
            valor = request.form.get("valor")
            pecas = request.form.get("pecas")
            servico = request.form.get("servico")

            if vehicle_id:
                new_os = AvariaOS(
                    vehicle_id=int(vehicle_id),
                    responsavel_id=current_user.id,
                    gravidade=gravidade,
                    descricao=descricao,
                    km=int(km) if km else None,
                    valor_gasto=safe_float(valor),
                    pecas_trocadas=pecas,
                    servico_realizado=servico,
                    status="finalizada",
                    data_abertura=agora(),
                    data_fechamento=agora()
                )
                db.session.add(new_os)
                db.session.commit()

                # Whatsapp OS finalizada direta
                try:
                    w_config = WhatsAppConfig.query.first()
                    if w_config and w_config.is_enabled:
                        v = new_os.vehicle
                        veiculo_txt = f"{v.brand} {v.model}" if v else f"ID {new_os.vehicle_id}"
                        tpl = w_config.msg_os_closed
                        msg = tpl.format(
                            id=new_os.id,
                            veiculo=veiculo_txt,
                            usuario=current_user.username,
                            servico=new_os.servico_realizado or "Manutenção concluída"
                        )
                        send_whatsapp_message(msg)
                except Exception as whatsapp_err:
                    print("⚠️ Erro ao disparar whatsapp para OS registrada direta:", whatsapp_err)

                registrar_log(f"O.S finalizada direta (manutenção): ID={new_os.id} (por {current_user.username})")
                flash("✅ Serviço registrado com sucesso!", "success")

            return redirect(url_for("manutencao_os"))

    ordens = AvariaOS.query.order_by(AvariaOS.id.desc()).all()
    veiculos = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    return render_template("manutencao_os.html", ordens=ordens, veiculos=veiculos)





# ----------------- IMPORTAÇÃO DE CHECKLISTS -----------------
@fleet_bp.route("/checklists/importar", methods=["POST"])
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
@fleet_bp.route("/relatorios")
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



@fleet_bp.route("/relatorios/gerar", methods=["POST"])
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
        topMargin=45 * mm,
        bottomMargin=40 * mm
    )

    elements = []

    # Informações do Veículo & Período
    meta_info = [
        ["Veículo / Modelo", f"{v.brand or ''} {v.model or ''} ({v.year or 'N/A'})"],
        ["Placa", v.plate],
        ["KM Atual", f"{v.km or 0} KM"],
        ["Período", f"{start_date.strftime('%d/%m/%Y')} até {end_date.strftime('%d/%m/%Y')}"]
    ]
    meta_table = Table(meta_info, colWidths=[50 * mm, 130 * mm])
    meta_table.setStyle(TableStyle([
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CCCCCC")),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F8FAFC")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("PADDING", (0, 0), (-1, -1), 6),
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
    elements.append(Spacer(1, 10))
    elements.append(Paragraph("----------------------------------------------------------------------------------------------------------------------------------", styles["TableText"]))
    elements.append(Spacer(1, 5))
    elements.append(Paragraph("<font color='#666666'>Relatório emitido pela plataforma de Checklist Veicular. Todos os dados são auditados e protegidos.</font>", styles["TableText"]))

    def draw_background(c, doc_obj):
        width, height = A4
        
        # Dynamic layout configuration from SystemConfig
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
            
        pdf_rodape_linhas = custom_rodape_linhas if custom_rodape_linhas is not None else [
            "ADAPT LINK SERVIÇOS EM COMUNICAÇÃO MULTIMÍDIA EIRELI",
            "CNPJ: 08.980.148/0001-41       Inscr. Est.: 78.342.480",
            "Rua Waldir Pedro de Medeiros, 253 – São Miguel – Seropédica – RJ",
            "CEP: 23.893-725",
            "Tel.: (21) 3812-5900 / (21) 2682-7822",
            "WWW.ADAPTLINK.COM.BR",
        ]
        
        # 1. Cabeçalho / Logotipo
        if logo_path and os.path.exists(logo_path):
            try:
                from reportlab.lib.utils import ImageReader
                logo = ImageReader(logo_path)
                pdf_h = config.pdf_logo_height or 30
                pdf_w = pdf_h * 2.4
                c.drawImage(logo, 20, height - 22.5 - pdf_h, width=pdf_w, height=pdf_h, preserveAspectRatio=True, mask="auto")
            except Exception as e:
                print("⚠️ Erro ao carregar logo no header frota:", e)

        # 2. Título Centralizado
        c.setFont("Helvetica-Bold", 14)
        c.setFillColor(colors.HexColor("#0F172A"))
        c.drawCentredString(width / 2, height - 40, "RELATÓRIO CONSOLIDADO DE FROTA")
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
        c.drawRightString(width - 25, height - 75, f"Placa: {v.plate}")

        # 5. Rodapé Institucional AdaptLink
        c.setStrokeColor(colors.HexColor("#E2E8F0"))
        c.setLineWidth(0.8)
        c.line(25, 90, width - 25, 90)
        
        c.setFont("Helvetica", 7)
        c.setFillColor(colors.HexColor("#475569"))
        y_footer = 75
        for linha in pdf_rodape_linhas:
            c.drawCentredString(width / 2, y_footer, linha)
            y_footer -= 9
        
        # Paginação
        c.setFont("Helvetica-Oblique", 8)
        c.drawRightString(width - 25, 30, f"Página {c.getPageNumber()}")

    try:
        doc.build(elements, onFirstPage=draw_background, onLaterPages=draw_background)
        registrar_log(f"Relatório Consolidado de Frota gerado: {filename} (Veículo: {v.plate})")
        flash("✅ Relatório consolidado gerado com sucesso!", "success")
    except Exception as e:
        registrar_log(f"Erro ao gerar Relatório Consolidado: {str(e)}")
        flash("❌ Erro ao compilar o arquivo PDF do relatório.", "error")

    return redirect(url_for("reports"))



@fleet_bp.route("/relatorios/download/<nome>")
@supervisor_allowed
def report_download(nome):
    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    return send_from_directory(str(REPORTS_DIR), nome)



@fleet_bp.route("/relatorios/excluir/<nome>", methods=["POST"])
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




@fleet_bp.route("/relatorios/upload", methods=["POST"])
@login_required
def report_upload():
    if not current_user.is_admin and not current_user.has_permission("relatorios"):
        abort(403)

    f = request.files.get("arquivo")
    if not f or f.filename == "":
        flash("Selecione um arquivo.", "error")
        return redirect(url_for("reports"))

    # Validar extensão do arquivo - Apenas PDF é permitido por motivos de segurança (evitar RCE/HTML XSS)
    ext = os.path.splitext(f.filename.lower())[1]
    if ext != ".pdf":
        flash("Formato de arquivo inválido. Apenas relatórios em PDF (.pdf) são permitidos.", "error")
        return redirect(url_for("reports"))

    name = secure_filename(f.filename)

    REPORTS_DIR = Path("/var/www/checklist_veicular/static/reports")
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    f.save(REPORTS_DIR / name)

    registrar_log(f"Relatório enviado: {name}")
    flash("Relatório enviado!", "success")
    return redirect(url_for("reports"))




# ----------------- LISTAGEM / DETALHE DE CHECKLISTS -----------------
@fleet_bp.route("/checklists")
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




@fleet_bp.route("/checklists/<int:cid>")
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



@fleet_bp.route("/api/checklists/<int:cid>")
@supervisor_allowed
def api_checklist_detail(cid):
    c = Checklist.query.get_or_404(cid)
    try:
        data = json.loads(c.raw_json) if c.raw_json else {}
    except Exception:
        data = {}

    return jsonify({
        "id": c.id,
        "date": c.date.strftime("%d/%m/%Y %H:%M"),
        "plate": c.vehicle.plate if c.vehicle else "-",
        "technician": c.technician or "-",
        "km": c.km,
        "status": c.status,
        "notes": c.notes,
        "photos": data.get("photos", []),
        "items": data.get("items", {})
    })



@fleet_bp.route("/checklists/<int:cid>/pdf")
@supervisor_allowed
def checklist_pdf_download(cid):
    import io
    from flask import send_file
    
    c = Checklist.query.get_or_404(cid)
    try:
        raw = json.loads(c.raw_json) if c.raw_json else {}
    except Exception:
        raw = {}
        
    pdf_path_str = generate_checklist_pdf(c, raw)
    
    return send_file(
        pdf_path_str,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"checklist_{c.id}_{c.technician}.pdf"
    )



@fleet_bp.route("/checklists/<int:cid>/excluir", methods=["POST"])
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
@fleet_bp.route("/config-checklist")
@admin_required
def config_checklist():
    items_carro   = ChecklistItem.query.filter_by(vehicle_type="carro").order_by(ChecklistItem.order.asc()).all()
    items_moto    = ChecklistItem.query.filter_by(vehicle_type="moto").order_by(ChecklistItem.order.asc()).all()
    items_caminhao = ChecklistItem.query.filter_by(vehicle_type="caminhao").order_by(ChecklistItem.order.asc()).all()
    items_van     = ChecklistItem.query.filter_by(vehicle_type="van").order_by(ChecklistItem.order.asc()).all()
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(mode="start_only")
        db.session.add(config)
        db.session.commit()
    return render_template(
        "config_checklist.html",
        items_carro=items_carro,
        items_moto=items_moto,
        items_caminhao=items_caminhao,
        items_van=items_van,
        config=config
    )




@fleet_bp.route("/config-checklist/mode", methods=["POST"])
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




@fleet_bp.route("/config-checklist/novo", methods=["POST"])
@admin_required
def config_checklist_new():
    text_ = request.form.get("text", "").strip()
    required = request.form.get("required") == "on"
    require_justif_no = request.form.get("require_justif_no") == "on"
    typ = request.form.get("type", "texto_curto")
    opts_raw = (request.form.get("options") or "").strip()
    vehicle_type = request.form.get("vehicle_type", "carro")

    allowed_vtypes = {"carro", "moto", "caminhao", "van"}
    if vehicle_type not in allowed_vtypes:
        vehicle_type = "carro"

    if not text_:
        flash("Texto é obrigatório.", "error")
        return redirect(url_for("config_checklist") + f"#{vehicle_type}")

    opts = opts_raw or None

    last = db.session.query(db.func.max(ChecklistItem.order)).filter(
        ChecklistItem.vehicle_type == vehicle_type
    ).scalar() or 0
    db.session.add(
        ChecklistItem(
            order=last + 1,
            text=text_,
            required=required,
            require_justif_no=require_justif_no,
            type=typ,
            options=opts,
            vehicle_type=vehicle_type,
        )
    )
    db.session.commit()

    registrar_log(f"Item de checklist adicionado ({vehicle_type}): {text_}")
    flash("Item adicionado.", "success")
    return redirect(url_for("config_checklist") + f"#{vehicle_type}")




@fleet_bp.route("/config-checklist/<int:iid>/editar", methods=["POST"])
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
    return redirect(url_for("config_checklist") + f"#{it.vehicle_type}")




@fleet_bp.route("/config-checklist/<int:iid>/excluir", methods=["POST"])
@admin_required
def config_checklist_del(iid):
    it = ChecklistItem.query.get_or_404(iid)
    texto = it.text
    vtype = it.vehicle_type

    db.session.delete(it)
    db.session.commit()

    # reajustar ordem
    items = ChecklistItem.query.filter_by(vehicle_type=vtype).order_by(ChecklistItem.order.asc()).all()
    for idx, x in enumerate(items, start=1):
        x.order = idx
    db.session.commit()

    registrar_log(f"Item de checklist excluído: {texto} (id={iid})")
    flash("Item excluído.", "success")
    return redirect(url_for("config_checklist") + f"#{vtype}")




@fleet_bp.route("/config-checklist/<int:iid>/mover", methods=["POST"])
@admin_required
def config_checklist_move(iid):
    direction = request.form.get("dir", "up")
    it = ChecklistItem.query.get_or_404(iid)
    vtype = it.vehicle_type

    items = ChecklistItem.query.filter_by(vehicle_type=vtype).order_by(ChecklistItem.order.asc()).all()
    pos = items.index(it)

    if direction == "up" and pos > 0:
        items[pos].order, items[pos - 1].order = items[pos - 1].order, items[pos].order
    elif direction == "down" and pos < len(items) - 1:
        items[pos].order, items[pos + 1].order = items[pos + 1].order, items[pos].order

    db.session.commit()

    registrar_log(f"Item de checklist movido: {it.text} (id={iid}, dir={direction})")
    flash("Ordem atualizada.", "success")
    return redirect(url_for("config_checklist") + f"#{vtype}")




@fleet_bp.route("/config-checklist/reordenar", methods=["POST"])
@admin_required
def config_checklist_reorder():
    data = request.get_json() or {}
    ids = data.get("ids", [])

    if not ids:
        return jsonify({"success": False, "message": "Nenhum ID enviado."}), 400

    try:
        # Atualiza a ordem de cada item enviado sequencialmente
        for idx, iid in enumerate(ids, start=1):
            it = ChecklistItem.query.get(int(iid))
            if it:
                it.order = idx
        db.session.commit()
        return jsonify({"success": True})
    except Exception as e:
        db.session.rollback()
        return jsonify({"success": False, "message": str(e)}), 500




# ----------------- CONFIGURAÇÃO DE LAYOUT DO SISTEMA -----------------
@fleet_bp.route("/configuracoes/layout", methods=["GET", "POST"])
@admin_required
def config_layout():
    config = SystemConfig.query.first()
    if not config:
        config = SystemConfig(mode="start_only")
        db.session.add(config)
        db.session.commit()

    if request.method == "POST":
        # Processar pdf_footer
        config.pdf_footer = request.form.get("pdf_footer", "").strip() or None

        # Processar powerbi_url
        config.powerbi_url = request.form.get("powerbi_url", "").strip() or None

        # Processar login_primary_color
        color = request.form.get("login_primary_color", "").strip()
        if color:
            if not color.startswith("#") or len(color) not in {4, 7}:
                flash("Cor primária inválida. Use um formato hexadecimal (ex: #10b981).", "error")
                return redirect(url_for("config_layout"))
            config.login_primary_color = color

        # Processar tamanhos de imagens e filtros
        try:
            config.login_logo_height = int(request.form.get("login_logo_height", "120") or "120")
            config.sidebar_logo_height = int(request.form.get("sidebar_logo_height", "44") or "44")
            config.pdf_logo_height = int(request.form.get("pdf_logo_height", "30") or "30")
            config.login_bg_zoom = int(request.form.get("login_bg_zoom", "100") or "100")
            config.login_bg_blur = int(request.form.get("login_bg_blur", "0") or "0")
            config.login_bg_opacity = int(request.form.get("login_bg_opacity", "15") or "15")
            config.login_card_opacity = int(request.form.get("login_card_opacity", "60") or "60")
            config.login_card_blur = int(request.form.get("login_card_blur", "12") or "12")
            config.login_card_radius = int(request.form.get("login_card_radius", "16") or "16")
            config.login_btn_radius = int(request.form.get("login_btn_radius", "12") or "12")
            config.login_btn_padding_y = int(request.form.get("login_btn_padding_y", "12") or "12")
            config.login_btn_font_size = int(request.form.get("login_btn_font_size", "16") or "16")
        except ValueError:
            flash("Valores de configuração de imagem inválidos. Por favor, insira números inteiros.", "error")
            return redirect(url_for("config_layout"))

        # Processar campos de texto do login
        title_text = request.form.get("login_title_text", "").strip()
        if title_text:
            config.login_title_text = title_text[:100]
        
        subtitle_text = request.form.get("login_subtitle_text", "").strip()
        config.login_subtitle_text = subtitle_text[:150]

        username_placeholder = request.form.get("login_username_placeholder", "").strip()
        config.login_username_placeholder = username_placeholder[:100] if username_placeholder else "Digite seu usuário"

        password_placeholder = request.form.get("login_password_placeholder", "").strip()
        config.login_password_placeholder = password_placeholder[:100] if password_placeholder else "Digite sua senha"

        btn_text = request.form.get("login_btn_text", "").strip()
        if btn_text:
            config.login_btn_text = btn_text[:50]

        # Processar background size e position por dispositivo
        allowed_sizes = {"cover", "contain", "auto", "100% 100%", "100% auto", "auto 100%"}
        allowed_positions = {"center", "top", "bottom", "left", "right", "top left", "top right", "bottom left", "bottom right"}
        
        bg_size_desktop = request.form.get("login_bg_size_desktop", "cover").strip()
        if bg_size_desktop in allowed_sizes:
            config.login_bg_size_desktop = bg_size_desktop
        
        bg_size_mobile = request.form.get("login_bg_size_mobile", "cover").strip()
        if bg_size_mobile in allowed_sizes:
            config.login_bg_size_mobile = bg_size_mobile

        bg_pos_desktop = request.form.get("login_bg_position_desktop", "center").strip()
        if bg_pos_desktop in allowed_positions:
            config.login_bg_position_desktop = bg_pos_desktop

        bg_pos_mobile = request.form.get("login_bg_position_mobile", "center").strip()
        if bg_pos_mobile in allowed_positions:
            config.login_bg_position_mobile = bg_pos_mobile

        # Processar overlay color
        overlay_color = request.form.get("login_overlay_color", "").strip()
        if overlay_color and overlay_color.startswith("#"):
            config.login_overlay_color = overlay_color

        # Processar secondary color
        secondary_color = request.form.get("login_secondary_color", "").strip()
        if secondary_color and secondary_color.startswith("#"):
            config.login_secondary_color = secondary_color

        # Processar sidebar colors
        sb_bg = request.form.get("sidebar_bg_color", "").strip()
        config.sidebar_bg_color = sb_bg if sb_bg and sb_bg.startswith("#") else None
        sb_text = request.form.get("sidebar_text_color", "").strip()
        config.sidebar_text_color = sb_text if sb_text and sb_text.startswith("#") else None

        # Processar posição do card
        allowed_card_positions = {"left", "left-center", "center", "right-center", "right"}
        card_pos = request.form.get("login_card_position", "right").strip()
        if card_pos in allowed_card_positions:
            config.login_card_position = card_pos

        # Processar uploads

        ALLOWED_LAYOUT_EXT = {".png", ".jpg", ".jpeg", ".webp", ".svg", ".ico"}
        fields = ["login_bg_desktop", "login_bg_mobile", "login_logo", "sidebar_logo", "pdf_logo", "favicon_custom"]

        for field in fields:
            file = request.files.get(field)
            if file and file.filename != "":
                ext = os.path.splitext(file.filename.lower())[1]
                if ext not in ALLOWED_LAYOUT_EXT:
                    flash(f"Extensão inválida para o campo {field}. Use PNG, JPG, JPEG, WEBP ou SVG.", "error")
                    return redirect(url_for("config_layout"))

                # Deleta o arquivo antigo se houver
                old_val = getattr(config, field)
                if old_val:
                    try:
                        old_p = LAYOUT_UPLOAD_DIR / old_val
                        if old_p.exists():
                            old_p.unlink()
                    except Exception as e:
                        print(f"⚠️ Erro deletando arquivo antigo {old_val}: {e}")

                # Cria nome seguro e salva
                fname = f"layout_{field}_{uuid.uuid4().hex[:8]}{ext}"
                file.save(LAYOUT_UPLOAD_DIR / fname)
                setattr(config, field, fname)

        db.session.commit()
        registrar_log("Configurações de layout atualizadas.")
        flash("Configurações de layout salvas com sucesso!", "success")
        return redirect(url_for("config_layout"))

    return render_template("layout_config.html", config=config)




@fleet_bp.route("/configuracoes/layout/reset/<field>", methods=["POST"])
@admin_required
def reset_layout_field(field):
    config = SystemConfig.query.first()
    if not config:
        flash("Nenhuma configuração encontrada.", "error")
        return redirect(url_for("config_layout"))

    allowed_fields = {
        "login_bg_desktop", "login_bg_mobile", "login_logo", "sidebar_logo", "pdf_logo",
        "pdf_footer", "login_primary_color", "powerbi_url", "login_logo_height",
        "sidebar_logo_height", "pdf_logo_height", "login_bg_zoom", "login_bg_blur",
        "login_bg_opacity", "login_bg_size_desktop", "login_bg_size_mobile",
        "login_bg_position_desktop", "login_bg_position_mobile", "login_card_opacity",
        "login_card_blur", "login_card_radius", "login_title_text", "login_btn_text",
        "login_btn_radius", "login_overlay_color", "login_secondary_color",
        "sidebar_bg_color", "sidebar_text_color", "favicon_custom", "login_card_position",
        "login_btn_padding_y", "login_btn_font_size", "login_subtitle_text",
        "login_username_placeholder", "login_password_placeholder",
    }
    if field not in allowed_fields:
        flash("Campo inválido.", "error")
        return redirect(url_for("config_layout"))

    # Map fields to their default values for simple resets
    simple_defaults = {
        "login_primary_color": "#10b981",
        "login_logo_height": 120,
        "sidebar_logo_height": 44,
        "pdf_logo_height": 30,
        "login_bg_zoom": 100,
        "login_bg_blur": 0,
        "login_bg_opacity": 15,
        "login_card_opacity": 60,
        "login_card_blur": 12,
        "login_card_radius": 16,
        "login_btn_radius": 12,
        "login_btn_padding_y": 12,
        "login_btn_font_size": 16,
        "login_bg_size_desktop": "cover",
        "login_bg_size_mobile": "cover",
        "login_bg_position_desktop": "center",
        "login_bg_position_mobile": "center",
        "login_title_text": "Acesso ao Sistema",
        "login_subtitle_text": "",
        "login_username_placeholder": "Digite seu usuário",
        "login_password_placeholder": "Digite sua senha",
        "login_btn_text": "Entrar",
        "login_overlay_color": "#000000",
        "login_secondary_color": "#064e3b",
        "login_card_position": "right",
    }

    if field in simple_defaults:
        default_val = simple_defaults[field]
        current_val = getattr(config, field)
        if current_val != default_val:
            setattr(config, field, default_val)
            db.session.commit()
            registrar_log(f"Configuração de layout restaurada para o padrão: {field}")
            flash("A configuração foi restaurada para o padrão com sucesso.", "success")
        else:
            flash("Esta configuração já está usando o padrão.", "info")
        return redirect(url_for("config_layout"))

    # Nullable fields (set to None to reset)
    nullable_fields = {"sidebar_bg_color", "sidebar_text_color"}
    if field in nullable_fields:
        setattr(config, field, None)
        db.session.commit()
        registrar_log(f"Configuração de layout restaurada para o padrão: {field}")
        flash("A configuração foi restaurada para o padrão com sucesso.", "success")
        return redirect(url_for("config_layout"))

    # File-based and text-based fields
    val = getattr(config, field)
    if val or (field == "pdf_footer" and config.pdf_footer is not None) or (field == "powerbi_url" and config.powerbi_url is not None):
        # If it's an image file, delete physically
        if field not in {"pdf_footer", "powerbi_url"}:
            try:
                p = LAYOUT_UPLOAD_DIR / val
                if p.exists():
                    p.unlink()
            except Exception as e:
                print(f"⚠️ Erro ao deletar arquivo de reset: {e}")
        setattr(config, field, None)
        db.session.commit()
        registrar_log(f"Configuração de layout restaurada para o padrão: {field}")
        flash("A configuração foi restaurada para o padrão com sucesso.", "success")
    else:
        flash("Esta configuração já está usando o padrão.", "info")

    return redirect(url_for("config_layout"))





@fleet_bp.route("/configuracoes/layout/test-pdf")
@admin_required
def test_layout_pdf():
    import io
    from flask import send_file

    config = SystemConfig.query.first()
    buffer = io.BytesIO()

    metadata = {
        "ID": "TST-9999",
        "Ambiente": "Homologação de Layout",
        "Emitente": current_user.username,
        "Data": agora().strftime("%d/%m/%Y %H:%M")
    }

    content_table_data = [
        ["Imagem de Fundo Desktop", ("Customizado: " + config.login_bg_desktop) if (config and config.login_bg_desktop) else "Asset Padrão (img.png)"],
        ["Imagem de Fundo Mobile", ("Customizado: " + config.login_bg_mobile) if (config and config.login_bg_mobile) else "Asset Padrão (imgmbl.png)"],
        ["Logo da Tela de Login", ("Customizado: " + config.login_logo) if (config and config.login_logo) else "Asset Padrão (logo.png)"],
        ["Logo do Sidebar (Menu)", ("Customizado: " + config.sidebar_logo) if (config and config.sidebar_logo) else "Asset Padrão (imgsidebar.png)"],
        ["Logo dos PDFs", ("Customizado: " + config.pdf_logo) if (config and config.pdf_logo) else "Asset Padrão (logo.png)"],
        ["Rodapé dos PDFs", ("Customizado: " + config.pdf_footer.replace('\n', ' | ')) if (config and config.pdf_footer) else "Não configurado - AdaptLink Padrão"]
    ]

    make_premium_pdf(
        buffer=buffer,
        title="RELATÓRIO DE HOMOLOGAÇÃO DE LAYOUT",
        metadata=metadata,
        content_table_data=content_table_data
    )

    buffer.seek(0)
    return send_file(
        buffer,
        mimetype="application/pdf",
        as_attachment=False,
        download_name="homologacao_layout.pdf"
    )




@fleet_bp.route("/configuracoes/layout/preview")
@admin_required
def preview_layout():
    config = SystemConfig.query.first()
    return render_template("login.html", sys_config=config, is_preview=True)


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

    dt_brt = checklist_obj.date.astimezone(BRT) if checklist_obj.date.tzinfo is not None else checklist_obj.date
    dt_str = dt_brt.strftime("%Y-%m-%d_%Hh%M")
    now_brt_str = datetime.datetime.now(BRT).strftime("%d/%m/%Y %H:%M")

    filename = f"checklist_{safe_user}_{plate}_{dt_str}.pdf"
    out_path = RELATORIOS_DIR / filename

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodyJustify", parent=styles["Normal"], fontSize=7, leading=9))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading3"], spaceBefore=5, spaceAfter=2,
                              textColor=colors.HexColor("#1F3C78"), fontSize=9, leading=11))

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

    # Dynamic layout configuration from SystemConfig
    config = SystemConfig.query.first()
    
    logo_path_custom = None
    if config and config.pdf_logo:
        custom_p = LAYOUT_UPLOAD_DIR / config.pdf_logo
        if custom_p.exists():
            logo_path_custom = str(custom_p)
            
    pdf_logo_path = logo_path_custom if logo_path_custom else (str(LOGO_PATH) if LOGO_PATH.exists() else None)

    custom_rodape_linhas = None
    if config and config.pdf_footer:
        custom_rodape_linhas = [linha.strip() for linha in config.pdf_footer.splitlines() if linha.strip()]
        
    pdf_rodape_linhas = custom_rodape_linhas if custom_rodape_linhas is not None else RODAPE_LINHAS

    def header_footer_factory(titulo: str, subtitulo: str):
        def _on_page(c, doc):
            width, height = A4
            if pdf_logo_path:
                try:
                    pdf_h = config.pdf_logo_height or 30
                    pdf_w = pdf_h * 2.36
                    c.drawImage(pdf_logo_path, 15*mm, height - 13*mm - pdf_h, pdf_w, pdf_h,
                                preserveAspectRatio=True, mask="auto")
                except Exception:
                    pass
            c.setStrokeColor(AZUL)
            c.setLineWidth(1.0)
            c.line(12*mm, height-27*mm, width-12*mm, height-27*mm)
            c.setFont("Helvetica-Bold", 12)
            c.setFillColor(AZUL)
            c.drawCentredString(width/2, height-14*mm, titulo)
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.black)
            c.drawCentredString(width/2, height-20*mm, subtitulo)
            c.setFont("Helvetica", 7)
            c.setFillColor(CINZA_TEXTO)
            c.drawString(12*mm, height-31*mm, f"Emitido em: {now_brt_str}")
            c.drawRightString(width-12*mm, height-31*mm, f"Doc Ref: CK-{checklist_obj.id}")

            footer_line_y = 20*mm
            c.setStrokeColor(colors.HexColor("#BBBBBB"))
            c.setLineWidth(0.8)
            c.line(12*mm, footer_line_y, width-12*mm, footer_line_y)
            c.setFont("Helvetica", 6.5)
            c.setFillColor(colors.HexColor("#6E6E6E"))
            y = 16*mm
            for linha in pdf_rodape_linhas:
                c.drawCentredString(width/2, y, linha)
                y -= 2.6*mm
            c.setFont("Helvetica-Oblique", 6.5)
            c.drawRightString(width-12*mm, 5*mm, f"Página {c.getPageNumber()}")
        return _on_page

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=34 * mm,
        bottomMargin=23 * mm
    )

    elements = []

    # Cabeçalho / meta
    elements.append(Paragraph("<b>Informações do Checklist</b>", styles["SectionTitle"]))
    meta_data = [
        ["Técnico:", checklist_obj.technician or "-", "Placa:", plate],
        ["Veículo:", f"{checklist_obj.vehicle.brand or ''} {checklist_obj.vehicle.model or ''}".strip(), "KM:", str(checklist_obj.km)],
        ["Data:", dt_brt.strftime("%d/%m/%Y %H:%M"), "Status:", checklist_obj.status],
    ]

    t = Table(meta_data, colWidths=[22 * mm, 71 * mm, 22 * mm, 71 * mm])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#707070")),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.0),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.0),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F4F4")),
        ("BACKGROUND", (2, 0), (2, -1), colors.HexColor("#F4F4F4")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -1), "Helvetica-Bold"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 2))

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

    tbl = Table(data_tbl, colWidths=[100 * mm, 30 * mm, 56 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("FONTSIZE", (0, 0), (-1, -1), 7),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 0.8),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.8),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 2))

    photos = raw.get("photos", [])
    photo_elements = []
    if photos:
        for p in photos[:6]:
            try:
                img_path = BASE_DIR / p.lstrip("/")
                if not img_path.exists():
                    img_path = BASE_DIR / "static" / Path(p).name
                img = RLImage(str(img_path), width=40 * mm, height=30 * mm)
                photo_elements.append(img)
            except Exception:
                continue

    if photo_elements:
        elements.append(Paragraph("<b>Fotos Registradas</b>", styles["SectionTitle"]))
        photo_rows = []
        for i in range(0, len(photo_elements), 3):
            row = photo_elements[i:i+3]
            while len(row) < 3:
                row.append("")
            photo_rows.append(row)
        
        t_photos = Table(photo_rows, colWidths=[62 * mm, 62 * mm, 62 * mm])
        t_photos.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 1.5),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ]))
        elements.append(t_photos)
        elements.append(Spacer(1, 2))

    elements.append(Paragraph("<b>Assinatura do Técnico</b>", styles["SectionTitle"]))
    
    sig_cell = []
    if checklist_obj.signature:
        sig_path = BASE_DIR / "static" / "assinaturas" / checklist_obj.signature
        if sig_path.exists():
            try:
                sig_img = RLImage(str(sig_path), width=50 * mm, height=14 * mm)
                sig_img.hAlign = 'LEFT'
                sig_cell.append(sig_img)
            except Exception as e:
                print("Erro ao renderizar assinatura em PDF do checklist veicular:", e)
                
    sig_table_data = []
    if sig_cell:
        sig_table_data.append(sig_cell)
    else:
        sig_table_data.append([Spacer(1, 8 * mm)])
        
    sig_table_data.append([Paragraph("____________________________________________", styles["BodyJustify"])])
    sig_table_data.append([Paragraph(f"<b>Técnico:</b> {checklist_obj.technician or '-'}", styles["BodyJustify"])])
    sig_table_data.append([Paragraph(f"<b>Data/Hora:</b> {dt_brt.strftime('%d/%m/%Y %H:%M')}", styles["BodyJustify"])])
    
    sig_table = Table(sig_table_data, colWidths=[186 * mm])
    sig_table.setStyle(TableStyle([
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("LEFTPADDING", (0, 0), (-1, -1), 0),
        ("RIGHTPADDING", (0, 0), (-1, -1), 0),
        ("TOPPADDING", (0, 0), (-1, -1), 0.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 0.5),
    ]))
    elements.append(sig_table)

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


def get_part_status(v, group_key, sub_key=None):
    group_val = getattr(v, group_key, "ok")
    if group_val != "avaria":
        return "ok"
    obs = getattr(v, f"obs_{group_key}", "") or ""
    if obs.startswith("[parts:"):
        end_idx = obs.find("]")
        if end_idx != -1:
            parts_str = obs[7:end_idx]
            active_subs = [p.strip() for p in parts_str.split(",") if p.strip()]
            if sub_key:
                return "avaria" if sub_key in active_subs else "ok"
    return "avaria"

def render_motorcycle_drawing(v: Vistoria) -> Image.Image:
    from PIL import ImageDraw
    
    def get_bezier_points(p0, p1, p2, p3, num_points=15):
        pts = []
        for i in range(num_points + 1):
            t = i / num_points
            x = (1-t)**3 * p0[0] + 3*(1-t)**2 * t * p1[0] + 3*(1-t) * t**2 * p2[0] + t**3 * p3[0]
            y = (1-t)**3 * p0[1] + 3*(1-t)**2 * t * p1[1] + 3*(1-t) * t**2 * p2[1] + t**3 * p3[1]
            pts.append((x, y))
        return pts

    S = 3
    img = Image.new("RGBA", (200 * S, 400 * S), "#FFFFFF")
    draw = ImageDraw.Draw(img)
    
    def scale_pts(pts):
        return [(x * S, y * S) for x, y in pts]

    def get_colors(group_key, sub_key=None):
        status = get_part_status(v, group_key, sub_key)
        if status == "avaria":
            return (252, 230, 194, 255), (245, 158, 11, 255)
        else:
            return (236, 250, 245, 255), (16, 185, 129, 255)

    def get_glass_colors(sub):
        status = get_part_status(v, "vidros_parabrisa", sub)
        if status == "avaria":
            return (252, 230, 194, 255), (245, 158, 11, 255)
        else:
            return (175, 228, 252, 255), (2, 132, 199, 255)

    def get_light_colors(sub, default_color):
        status = get_part_status(v, "farois_lanternas", sub)
        if status == "avaria":
            return (245, 158, 11, 255)
        else:
            return default_color

    def get_mirror_colors(sub):
        status = get_part_status(v, "retrovisores", sub)
        if status == "avaria":
            return (245, 158, 11, 255)
        else:
            return (71, 85, 105, 255)

    # 1. Pneus
    for sub, (x, y, w, h) in [("de", (91, 40, 18, 42)), ("te", (91, 290, 18, 48))]:
        bg, border = get_colors("pneus", sub)
        box = [x * S, y * S, (x + w) * S, (y + h) * S]
        draw.rounded_rectangle(box, radius=4 * S, fill=bg, outline=border, width=int(1.5 * S))

    # 2. Rodas
    for sub, (cx, cy) in [("de", (100, 61)), ("te", (100, 314))]:
        bg, border = get_colors("calotas", sub)
        r = 5
        box = [(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S]
        draw.ellipse(box, fill=bg, outline=border, width=int(1 * S))

    # 3. Chassi
    draw.polygon(scale_pts([(96, 61), (104, 61), (104, 314), (96, 314)]), fill=(226, 232, 240, 255), outline=(71, 85, 105, 255), width=int(1.5 * S))

    # 4. Laterais
    bg, border = get_colors("lateral_esquerda")
    pts = get_bezier_points((90, 130), (80, 180), (80, 230), (90, 280))
    draw.line(scale_pts(pts), fill=border, width=int(5 * S), joint="round")

    bg, border = get_colors("lateral_direita")
    pts = get_bezier_points((110, 130), (120, 180), (120, 230), (110, 280))
    draw.line(scale_pts(pts), fill=border, width=int(5 * S), joint="round")

    # 5. Tanque
    bg, border = get_colors("capo")
    pts = get_bezier_points((88, 120), (88, 95), (112, 95), (112, 120)) + [(114, 175)] + get_bezier_points((114, 175), (114, 190), (86, 190), (86, 175))
    draw.polygon(scale_pts(pts), fill=bg, outline=border, width=int(1.5 * S))

    # 6. Assento
    bg, border = get_colors("teto")
    pts = [(88, 185), (112, 185), (110, 245), (90, 245)]
    draw.polygon(scale_pts(pts), fill=bg, outline=border, width=int(1.5 * S))

    # 7. Baú
    bg, border = get_colors("porta_malas")
    box = [78 * S, 250 * S, (78 + 44) * S, (250 + 36) * S]
    draw.rounded_rectangle(box, radius=4 * S, fill=bg, outline=border, width=int(1.5 * S))

    # 8. Guidão
    bg, border = get_colors("para_choque_dianteiro")
    draw.line(scale_pts([(60, 90), (140, 90)]), fill=border, width=int(6 * S), joint="round")

    # 9. Relação
    bg, border = get_colors("para_choque_traseiro")
    draw.line(scale_pts([(88, 280), (88, 325)]), fill=border, width=int(5 * S), joint="round")

    # 10. Escapamento
    bg, border = get_glass_colors("diant")
    box = [114 * S, 255 * S, (114 + 8) * S, (255 + 60) * S]
    draw.rectangle(box, fill=bg, outline=border, width=int(1 * S))

    # 11. Faróis / Lanternas
    c_fe = get_light_colors("fe", (253, 224, 71, 255))
    pts = get_bezier_points((94, 36), (100, 32), (100, 32), (106, 36))
    draw.line(scale_pts(pts), fill=c_fe, width=int(4 * S), joint="round")

    c_le = get_light_colors("le", (239, 68, 68, 255))
    pts = get_bezier_points((94, 336), (100, 340), (100, 340), (106, 336))
    draw.line(scale_pts(pts), fill=c_le, width=int(4 * S), joint="round")

    # 12. Retrovisores
    c_esq = get_mirror_colors("esq")
    pts = get_bezier_points((70, 90), (60, 76), (55, 76), (65, 70))
    draw.line(scale_pts(pts), fill=c_esq, width=int(2.5 * S), joint="round")

    c_dir = get_mirror_colors("dir")
    pts = get_bezier_points((130, 90), (140, 76), (145, 76), (135, 70))
    draw.line(scale_pts(pts), fill=c_dir, width=int(2.5 * S), joint="round")

    return img

def render_vehicle_drawing(v: Vistoria) -> Image.Image:
    if v.vehicle and v.vehicle.type == 'moto':
        return render_motorcycle_drawing(v)
        
    from PIL import ImageDraw
    
    def get_bezier_points(p0, p1, p2, p3, num_points=15):
        pts = []
        for i in range(num_points + 1):
            t = i / num_points
            x = (1-t)**3 * p0[0] + 3*(1-t)**2 * t * p1[0] + 3*(1-t) * t**2 * p2[0] + t**3 * p3[0]
            y = (1-t)**3 * p0[1] + 3*(1-t)**2 * t * p1[1] + 3*(1-t) * t**2 * p2[1] + t**3 * p3[1]
            pts.append((x, y))
        return pts

    def get_quad_bezier_points(p0, p1, p2, num_points=10):
        pts = []
        for i in range(num_points + 1):
            t = i / num_points
            x = (1-t)**2 * p0[0] + 2*(1-t)*t * p1[0] + t**2 * p2[0]
            y = (1-t)**2 * p0[1] + 2*(1-t)*t * p1[1] + t**2 * p2[1]
            pts.append((x, y))
        return pts

    S = 3
    img = Image.new("RGBA", (200 * S, 400 * S), "#FFFFFF")
    draw = ImageDraw.Draw(img)
    
    def scale_pts(pts):
        return [(x * S, y * S) for x, y in pts]

    def get_colors(group_key, sub_key=None):
        status = get_part_status(v, group_key, sub_key)
        if status == "avaria":
            return (252, 230, 194, 255), (245, 158, 11, 255)
        else:
            return (236, 250, 245, 255), (16, 185, 129, 255)

    def get_glass_colors(sub):
        status = get_part_status(v, "vidros_parabrisa", sub)
        if status == "avaria":
            return (252, 230, 194, 255), (245, 158, 11, 255)
        else:
            return (175, 228, 252, 255), (2, 132, 199, 255)

    def get_light_colors(sub, default_color):
        status = get_part_status(v, "farois_lanternas", sub)
        if status == "avaria":
            return (245, 158, 11, 255)
        else:
            return default_color

    def get_mirror_colors(sub):
        status = get_part_status(v, "retrovisores", sub)
        if status == "avaria":
            return (245, 158, 11, 255)
        else:
            return (71, 85, 105, 255)

    # 1. Pneus
    for sub, (x, y, w, h) in [
        ("de", (15, 80, 22, 46)),
        ("dd", (163, 80, 22, 46)),
        ("te", (15, 274, 22, 46)),
        ("td", (163, 274, 22, 46))
    ]:
        bg, border = get_colors("pneus", sub)
        box = [x * S, y * S, (x + w) * S, (y + h) * S]
        draw.rounded_rectangle(box, radius=6 * S, fill=bg, outline=border, width=int(1.5 * S))

    # 2. Calotas
    for sub, (cx, cy) in [("de", (26, 103)), ("dd", (174, 103)), ("te", (26, 297)), ("td", (174, 297))]:
        bg, border = get_colors("calotas", sub)
        r = 7
        box = [(cx - r) * S, (cy - r) * S, (cx + r) * S, (cy + r) * S]
        draw.ellipse(box, fill=bg, outline=border, width=int(1 * S))

    # 3. Laterais
    bg, border = get_colors("lateral_esquerda")
    pts = get_bezier_points((35, 75), (30, 150), (30, 250), (35, 325))
    draw.line(scale_pts(pts), fill=border, width=int(6 * S), joint="round")
    
    bg, border = get_colors("lateral_direita")
    pts = get_bezier_points((165, 75), (170, 150), (170, 250), (165, 325))
    draw.line(scale_pts(pts), fill=border, width=int(6 * S), joint="round")

    # 4. Chassi
    chassi_pts = (
        get_bezier_points((35, 75), (35, 55), (50, 45), (100, 45)) +
        get_bezier_points((100, 45), (150, 45), (165, 55), (165, 75)) +
        [(165, 325)] +
        get_bezier_points((165, 325), (165, 345), (150, 355), (100, 355)) +
        get_bezier_points((100, 355), (50, 355), (35, 345), (35, 325))
    )
    draw.polygon(scale_pts(chassi_pts), fill=(226, 232, 240, 255), outline=(71, 85, 105, 255), width=int(2 * S))

    # 5. Capô
    bg, border = get_colors("capo")
    capo_pts = (
        get_bezier_points((37, 75), (37, 57), (50, 47), (100, 47)) +
        get_bezier_points((100, 47), (150, 47), (163, 57), (163, 75)) +
        [(163, 130), (37, 130)]
    )
    draw.polygon(scale_pts(capo_pts), fill=bg, outline=border, width=int(1.5 * S))

    # 6. Teto
    bg, border = get_colors("teto")
    box = [37 * S, 145 * S, (37 + 126) * S, (145 + 125) * S]
    draw.rounded_rectangle(box, radius=8 * S, fill=bg, outline=border, width=int(1.5 * S))

    # 7. Porta-malas
    bg, border = get_colors("porta_malas")
    porta_malas_pts = (
        [(37, 285), (163, 285), (163, 325)] +
        get_bezier_points((163, 325), (163, 343), (150, 353), (100, 353)) +
        get_bezier_points((100, 353), (50, 353), (37, 343), (37, 325))
    )
    draw.polygon(scale_pts(porta_malas_pts), fill=bg, outline=border, width=int(1.5 * S))

    # 8. Para-choques
    bg, border = get_colors("para_choque_dianteiro")
    pts = get_bezier_points((45, 46), (60, 41), (140, 41), (155, 46))
    draw.line(scale_pts(pts), fill=border, width=int(7 * S), joint="round")
    
    bg, border = get_colors("para_choque_traseiro")
    pts = get_bezier_points((45, 354), (60, 359), (140, 359), (155, 354))
    draw.line(scale_pts(pts), fill=border, width=int(7 * S), joint="round")

    # 9. Vidros
    bg, border = get_glass_colors("diant")
    pts = [(44, 140), (156, 140), (146, 125), (54, 125)]
    draw.polygon(scale_pts(pts), fill=bg, outline=border, width=int(1 * S))
    
    bg, border = get_glass_colors("tras")
    pts = [(44, 275), (156, 275), (148, 285), (52, 285)]
    draw.polygon(scale_pts(pts), fill=bg, outline=border, width=int(1 * S))

    for sub, (x, y, w, h) in [
        ("vlde", (34, 148, 4, 56)),
        ("vldd", (162, 148, 4, 56)),
        ("vlte", (34, 211, 4, 56)),
        ("vltd", (162, 211, 4, 56))
    ]:
        bg, border = get_glass_colors(sub)
        box = [x * S, y * S, (x + w) * S, (y + h) * S]
        draw.rectangle(box, fill=bg, outline=border, width=int(1 * S))

    # 10. Faróis / Lanternas
    c_fe = get_light_colors("fe", (253, 224, 71, 255))
    pts = get_quad_bezier_points((38, 65), (48, 65), (48, 55))
    draw.line(scale_pts(pts), fill=c_fe, width=int(4 * S), joint="round")
    
    c_fd = get_light_colors("fd", (253, 224, 71, 255))
    pts = get_quad_bezier_points((162, 65), (152, 65), (152, 55))
    draw.line(scale_pts(pts), fill=c_fd, width=int(4 * S), joint="round")

    c_le = get_light_colors("le", (239, 68, 68, 255))
    pts = get_quad_bezier_points((38, 345), (48, 345), (48, 351))
    draw.line(scale_pts(pts), fill=c_le, width=int(4 * S), joint="round")
    
    c_ld = get_light_colors("ld", (239, 68, 68, 255))
    pts = get_quad_bezier_points((162, 345), (152, 345), (152, 351))
    draw.line(scale_pts(pts), fill=c_ld, width=int(4 * S), joint="round")

    # 11. Retrovisores
    c_esq = get_mirror_colors("esq")
    pts = get_bezier_points((28, 135), (20, 135), (20, 145), (28, 145))
    draw.line(scale_pts(pts), fill=c_esq, width=int(4 * S), joint="round")
    
    c_dir = get_mirror_colors("dir")
    pts = get_bezier_points((172, 135), (180, 135), (180, 145), (172, 145))
    draw.line(scale_pts(pts), fill=c_dir, width=int(4 * S), joint="round")

    return img

def generate_vistoria_pdf(vistoria_obj: Vistoria) -> str:
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
    plate = vistoria_obj.vehicle.plate if vistoria_obj.vehicle else "SEM_PLACA"
    safe_user = (vistoria_obj.created_by_user.username if vistoria_obj.created_by_user else "supervisor").replace(" ", "_")

    dt_brt = vistoria_obj.created_at.astimezone(BRT) if vistoria_obj.created_at.tzinfo is not None else vistoria_obj.created_at
    dt_str = dt_brt.strftime("%Y-%m-%d_%Hh%M")
    now_brt_str = datetime.datetime.now(BRT).strftime("%d/%m/%Y %H:%M")

    filename = f"relatorio_vistoria_{safe_user}_{plate}_{dt_str}.pdf"
    out_path = RELATORIOS_DIR / filename

    styles = getSampleStyleSheet()
    styles.add(ParagraphStyle(name="BodyJustify", parent=styles["Normal"], fontSize=7.5, leading=9.5))
    styles.add(ParagraphStyle(name="SectionTitle", parent=styles["Heading3"], spaceBefore=6, spaceAfter=3,
                               textColor=colors.HexColor("#1F3C78"), fontSize=9.5, leading=11.5))

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

    config = SystemConfig.query.first()
    
    logo_path_custom = None
    if config and config.pdf_logo:
        custom_p = LAYOUT_UPLOAD_DIR / config.pdf_logo
        if custom_p.exists():
            logo_path_custom = str(custom_p)
            
    pdf_logo_path = logo_path_custom if logo_path_custom else (str(LOGO_PATH) if LOGO_PATH.exists() else None)

    custom_rodape_linhas = None
    if config and config.pdf_footer:
        custom_rodape_linhas = [linha.strip() for linha in config.pdf_footer.splitlines() if linha.strip()]
        
    pdf_rodape_linhas = custom_rodape_linhas if custom_rodape_linhas is not None else RODAPE_LINHAS

    def header_footer_factory(titulo: str, subtitulo: str):
        def _on_page(c, doc):
            width, height = A4
            if pdf_logo_path:
                try:
                    pdf_h = config.pdf_logo_height or 30
                    pdf_w = pdf_h * 2.36
                    c.drawImage(pdf_logo_path, 15*mm, height - 13*mm - pdf_h, pdf_w, pdf_h,
                                preserveAspectRatio=True, mask="auto")
                except Exception:
                    pass
            c.setStrokeColor(AZUL)
            c.setLineWidth(1.0)
            c.line(12*mm, height-27*mm, width-12*mm, height-27*mm)
            c.setFont("Helvetica-Bold", 12)
            c.setFillColor(AZUL)
            c.drawCentredString(width/2, height-14*mm, titulo)
            c.setFont("Helvetica", 9)
            c.setFillColor(colors.black)
            c.drawCentredString(width/2, height-20*mm, subtitulo)
            c.setFont("Helvetica", 7)
            c.setFillColor(CINZA_TEXTO)
            c.drawString(12*mm, height-31*mm, f"Emitido em: {now_brt_str}")
            c.drawRightString(width-12*mm, height-31*mm, f"Doc Ref: CK-{vistoria_obj.id}")

            footer_line_y = 20*mm
            c.setStrokeColor(colors.HexColor("#BBBBBB"))
            c.setLineWidth(0.8)
            c.line(12*mm, footer_line_y, width-12*mm, footer_line_y)
            c.setFont("Helvetica", 6.5)
            c.setFillColor(colors.HexColor("#6E6E6E"))
            y = 16*mm
            for linha in pdf_rodape_linhas:
                c.drawCentredString(width/2, y, linha)
                y -= 2.6*mm
            c.setFont("Helvetica-Oblique", 6.5)
            c.drawRightString(width-12*mm, 5*mm, f"Página {c.getPageNumber()}")
        return _on_page

    doc = SimpleDocTemplate(
        str(out_path),
        pagesize=A4,
        rightMargin=12 * mm,
        leftMargin=12 * mm,
        topMargin=34 * mm,
        bottomMargin=23 * mm
    )

    elements = []

    # 1. Informações da Vistoria
    elements.append(Paragraph("<b>Informações da Vistoria</b>", styles["SectionTitle"]))
    
    status_text = "Com avarias" if vistoria_obj.status_geral == "avarias" else "OK"
    turno_formatted = "Início do Expediente" if vistoria_obj.turno == "inicio" else ("Durante Expediente" if vistoria_obj.turno == "durante" else "Fim do Expediente")
    
    meta_data = [
        ["Vistoria ID:", f"#{vistoria_obj.id}", "Supervisor/Técnico:", vistoria_obj.created_by_user.username if vistoria_obj.created_by_user else "-"],
        ["Veículo:", f"{vistoria_obj.vehicle.brand or ''} {vistoria_obj.vehicle.model or ''}".strip(), "Placa:", plate],
        ["KM:", str(vistoria_obj.km or "-"), "Turno:", turno_formatted],
        ["Data:", dt_brt.strftime("%d/%m/%Y %H:%M"), "Status Geral:", status_text],
        ["Local:", vistoria_obj.local or "-", "", ""]
    ]

    t = Table(meta_data, colWidths=[24 * mm, 69 * mm, 30 * mm, 63 * mm])
    t.setStyle(TableStyle([
        ("BOX", (0, 0), (-1, -1), 0.8, colors.HexColor("#707070")),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("SPAN", (1, 4), (3, 4)),
        ("FONTSIZE", (0, 0), (-1, -1), 7.5),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.5),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F4F4F4")),
        ("BACKGROUND", (2, 0), (2, -2), colors.HexColor("#F4F4F4")),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTNAME", (2, 0), (2, -2), "Helvetica-Bold"),
    ]))
    elements.append(t)
    elements.append(Spacer(1, 4))

    # 2. Mapa Visual e Observações Gerais
    img_temp_path = None
    map_image = None
    try:
        img_temp_path = RELATORIOS_DIR / f"temp_vehicle_vistoria_{vistoria_obj.id}.png"
        img_pil = render_vehicle_drawing(vistoria_obj)
        img_pil.save(str(img_temp_path), "PNG")
        map_image = RLImage(str(img_temp_path), width=45 * mm, height=90 * mm)
        map_image.hAlign = 'CENTER'
    except Exception as e:
        print("⚠️ Erro ao renderizar imagem do veículo no PDF:", e)

    obs_text = vistoria_obj.observacoes or "Nenhuma observação geral registrada."
    obs_style = ParagraphStyle(
        name="ObsStyle",
        parent=styles["Normal"],
        fontSize=8,
        leading=11,
        textColor=colors.HexColor("#333333")
    )
    obs_p = Paragraph(f"<b>Observações Gerais:</b><br/>{obs_text}", obs_style)
    
    if map_image:
        map_table_data = [[map_image, obs_p]]
        map_table = Table(map_table_data, colWidths=[55 * mm, 131 * mm])
        map_table.setStyle(TableStyle([
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ALIGN", (0, 0), (0, 0), "CENTER"),
            ("LEFTPADDING", (0, 0), (-1, -1), 0),
            ("RIGHTPADDING", (0, 0), (-1, -1), 0),
            ("TOPPADDING", (0, 0), (-1, -1), 4),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
        ]))
        elements.append(map_table)
    else:
        elements.append(obs_p)
    elements.append(Spacer(1, 4))

    # 3. Itens Avaliados
    elements.append(Paragraph("<b>Detalhamento dos Itens Avaliados</b>", styles["SectionTitle"]))
    data_tbl = [["Item", "Status", "Detalhamento da Avaria / Observação"]]
    
    is_moto = (vistoria_obj.vehicle and vistoria_obj.vehicle.type == 'moto')
    if is_moto:
        ITENS_INFO = [
            ('para_choque_dianteiro', 'Guidão e Manetes'),
            ('para_choque_traseiro', 'Relação (Corrente/Coroa)'),
            ('lateral_esquerda', 'Lateral esquerda'),
            ('lateral_direita', 'Lateral direita'),
            ('capo', 'Tanque de Combustível'),
            ('teto', 'Assento / Banco'),
            ('porta_malas', 'Baú / Bauleto'),
            ('retrovisores', 'Retrovisores'),
            ('farois_lanternas', 'Farol / Lanterna'),
            ('vidros_parabrisa', 'Escapamento / Motor'),
            ('pneus', 'Pneus (Dianteiro/Traseiro)'),
            ('calotas', 'Rodas / Raios')
        ]
    else:
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

    def format_item_details(v, key, label):
        val = getattr(v, key, "ok")
        if val != "avaria":
            return "OK", "-"
        obs = getattr(v, f"obs_{key}", "") or ""
        clean_obs = obs
        sub_desc = ""
        if obs.startswith("[parts:"):
            end_idx = obs.find("]")
            if end_idx != -1:
                parts_str = obs[7:end_idx]
                clean_obs = obs[end_idx+1:].strip()
                if is_moto:
                    sub_labels = {
                        "de": "Dianteiro",
                        "te": "Traseiro",
                        "fe": "Farol (Dianteiro)",
                        "le": "Lanterna (Traseiro)",
                        "esq": "Esquerdo",
                        "dir": "Direito"
                    }
                else:
                    sub_labels = {
                        "de": "Dianteiro Esquerdo (DE)", "dd": "Dianteiro Direito (DD)",
                        "te": "Traseiro Esquerdo (TE)", "td": "Traseiro Direito (TD)",
                        "diant": "Dianteiro", "tras": "Traseiro",
                        "fe": "Farol Esquerdo", "fd": "Farol Direito",
                        "le": "Lanterna Esquerda", "ld": "Lanterna Direita",
                        "esq": "Esquerdo", "dir": "Direito",
                        "vlde": "Vidro Lat. Diant. Esq.", "vldd": "Vidro Lat. Diant. Dir.",
                        "vlte": "Vidro Lat. Tras. Esq.", "vltd": "Vidro Lat. Tras. Dir."
                    }
                subs = [p.strip() for p in parts_str.split(",") if p.strip()]
                sub_names = [sub_labels.get(s, s) for s in subs]
                if sub_names:
                    sub_desc = f"Partes: {', '.join(sub_names)}."
        
        final_obs = ""
        if sub_desc:
            final_obs += sub_desc
        if clean_obs:
            if final_obs:
                final_obs += " Obs: "
            final_obs += clean_obs
        if not final_obs:
            final_obs = "-"
        return "Avaria", final_obs

    for key, label in ITENS_INFO:
        status, details = format_item_details(vistoria_obj, key, label)
        
        if status == "Avaria":
            status_para = Paragraph("<b>⚠️ AVARIA</b>", ParagraphStyle(name="AvariaStatus", parent=styles["BodyJustify"], textColor=colors.HexColor("#D97706")))
        else:
            status_para = Paragraph("✅ OK", ParagraphStyle(name="OkStatus", parent=styles["BodyJustify"], textColor=colors.HexColor("#059669")))

        data_tbl.append([
            Paragraph(label, styles["BodyJustify"]),
            status_para,
            Paragraph(details, styles["BodyJustify"])
        ])

    tbl = Table(data_tbl, colWidths=[55 * mm, 30 * mm, 101 * mm])
    tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#D9E2F3")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.black),
        ("GRID", (0, 0), (-1, -1), 0.6, colors.HexColor("#707070")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 1.2),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 1.2),
        ("ROWBACKGROUNDS", (0, 1), (-1, -1), [colors.white, colors.HexColor("#F5F5F5")]),
    ]))
    elements.append(tbl)
    elements.append(Spacer(1, 4))

    # 4. Fotos Registradas
    photo_elements = []
    if vistoria_obj.fotos:
        for f in vistoria_obj.fotos[:6]:
            try:
                img_path = VISTORIAS_UPLOAD_DIR / f.filename
                if img_path.exists():
                    img = RLImage(str(img_path), width=40 * mm, height=30 * mm)
                    photo_elements.append(img)
            except Exception:
                continue

    if photo_elements:
        elements.append(Paragraph("<b>Fotos Registradas</b>", styles["SectionTitle"]))
        photo_rows = []
        for i in range(0, len(photo_elements), 3):
            row = photo_elements[i:i+3]
            while len(row) < 3:
                row.append("")
            photo_rows.append(row)
        
        t_photos = Table(photo_rows, colWidths=[62 * mm, 62 * mm, 62 * mm])
        t_photos.setStyle(TableStyle([
            ("ALIGN", (0, 0), (-1, -1), "CENTER"),
            ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
            ("TOPPADDING", (0, 0), (-1, -1), 2),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 2),
        ]))
        elements.append(t_photos)
        elements.append(Spacer(1, 4))

    doc.build(
        elements,
        onFirstPage=header_footer_factory(
            "RELATÓRIO DE VISTORIA VEICULAR",
            f"Veículo: {plate}  |  Supervisor: {vistoria_obj.created_by_user.username if vistoria_obj.created_by_user else '-'}",
        ),
        onLaterPages=header_footer_factory(
            "RELATÓRIO DE VISTORIA VEICULAR",
            f"Veículo: {plate}  |  Supervisor: {vistoria_obj.created_by_user.username if vistoria_obj.created_by_user else '-'}",
        )
    )

    if img_temp_path and img_temp_path.exists():
        try:
            img_temp_path.unlink()
        except Exception:
            pass

    return str(out_path)

@fleet_bp.route("/vistorias/<int:vistoria_id>/pdf")
@supervisor_allowed
def vistoria_pdf_download(vistoria_id):
    from flask import send_file
    
    v = Vistoria.query.get_or_404(vistoria_id)
    try:
        pdf_path_str = generate_vistoria_pdf(v)
    except Exception as e:
        registrar_log(f"Erro ao gerar PDF da vistoria #{vistoria_id}: {str(e)}")
        flash("❌ Erro interno ao compilar o PDF.", "error")
        return redirect(url_for("vistorias_list"))
        
    return send_file(
        pdf_path_str,
        mimetype="application/pdf",
        as_attachment=False,
        download_name=f"vistoria_{v.id}_{v.vehicle.plate if v.vehicle else 'sem_placa'}.pdf"
    )


# ----------------- API: TIPO DO VEÍCULO -----------------
@fleet_bp.route("/api/vehicle/<int:vid>/type")
@login_required
def api_vehicle_type(vid):
    """Retorna o tipo do veículo em JSON para uso no frontend."""
    from flask import jsonify
    v = Vehicle.query.get_or_404(vid)
    return jsonify({"type": v.type or "carro"})


# ----------------- CHECKLIST TÉCNICO (MODO) -----------------
@fleet_bp.route("/checklist", methods=["GET", "POST"])
@login_required
def checklist_mobile():
    vehicles = Vehicle.query.order_by(Vehicle.plate.asc()).all()
    # Carrega itens de todos os tipos para o template (o JS filtra na tela)
    items_by_type = {
        "carro":    ChecklistItem.query.filter_by(vehicle_type="carro").order_by(ChecklistItem.order.asc()).all(),
        "moto":     ChecklistItem.query.filter_by(vehicle_type="moto").order_by(ChecklistItem.order.asc()).all(),
        "caminhao": ChecklistItem.query.filter_by(vehicle_type="caminhao").order_by(ChecklistItem.order.asc()).all(),
        "van":      ChecklistItem.query.filter_by(vehicle_type="van").order_by(ChecklistItem.order.asc()).all(),
    }
    # items_qs usado no POST (filtrado pelo tipo do veículo submetido)
    items_qs = []
    success = request.args.get("success") == "true"

    config = SystemConfig.query.first()
    mode = config.mode if config else "start_only"

    # se desativado, não permite nem GET nem POST
    if mode == "disabled":
        flash("Checklist desativado pelo supervisor.", "error")
        return render_template(
            "checklist_mobile.html",
            vehicles=[],
            items_by_type={"carro":[], "moto":[], "caminhao":[], "van":[]},
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

        # Detecta o tipo do veículo e carrega apenas os itens correspondentes
        v = Vehicle.query.get(vehicle_id)
        v_type = (v.type or "carro") if v else "carro"
        items_qs = ChecklistItem.query.filter_by(vehicle_type=v_type).order_by(ChecklistItem.order.asc()).all()

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

        # 🔍 VALIDAÇÃO DE KM (v já foi obtido para detectar o tipo)
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
        has_just = False
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

            if just:
                has_just = True

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
                sig_filename = f"sig_veiculo_{tech}_{uuid4().hex[:8]}.png"
                with open(sig_dir / sig_filename, "wb") as f:
                    f.write(data)
            except Exception as e:
                print("Erro ao salvar assinatura de veículo:", e)

        # =====================================================
        # 🔥 CORRIGIDO: NÃO USAR datetime.utcnow()
        # =====================================================
        checklist = Checklist(
            vehicle_id=vehicle_id,
            technician=tech,
            date=agora(),
            km=km,
            status="Com Avaria" if has_just else "OK",
            notes="Checklist via web",
            raw_json=json.dumps(raw, ensure_ascii=False),
            signature=sig_filename
        )
        db.session.add(checklist)

        # Atualiza KM APENAS se maior
        if v and km > (v.km or 0):
            v.km = km

        db.session.commit()

        # Verifica se o checklist tem inconformidades
        has_fail = False
        fail_items = []
        for item_name, item_data in respostas.items():
            if isinstance(item_data, dict) and item_data.get("resposta") == "Não":
                has_fail = True
                fail_items.append(item_name.split(" - ")[-1])
        
        if has_fail:
            try:
                w_config = WhatsAppConfig.query.first()
                if w_config and w_config.is_enabled:
                    tpl = w_config.msg_checklist_fail
                    veiculo_txt = f"{v.brand} {v.model}" if v else f"ID {vehicle_id}"
                    placa_txt = v.plate if v else ""
                    
                    msg = tpl.format(
                        tecnico=tech,
                        veiculo=veiculo_txt,
                        placa=placa_txt
                    )
                    msg += f"\n*Itens com inconformidade:* {', '.join(fail_items)}"
                    send_whatsapp_message(msg)
            except Exception as whatsapp_err:
                print("⚠️ Erro ao disparar whatsapp para checklist:", whatsapp_err)

        try:
            generate_checklist_pdf(checklist, raw)
        except Exception as e:
            print("⚠️ Erro gerando PDF:", e)

        registrar_log(f"Checklist criado para veículo ID={vehicle_id} por {tech}")
        flash("✅ Checklist enviado com sucesso!", "success")
        return redirect(url_for("checklist_mobile", success="true"))

    return render_template("checklist_mobile.html", vehicles=vehicles, items_by_type=items_by_type, success=success)




# ----------------- PERFIL -----------------
@fleet_bp.get("/perfil")
@login_required
def perfil():
    return render_template("perfil.html", user=current_user)

@fleet_bp.post("/perfil/alterar-senha")
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




@fleet_bp.route("/vistorias")
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




@fleet_bp.route("/vistorias/nova", methods=["GET", "POST"])
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

        # WhatsApp Vistoria
        try:
            w_config = WhatsAppConfig.query.first()
            if w_config and w_config.is_enabled:
                veh = Vehicle.query.get(int(vehicle_id))
                veiculo_txt = f"{veh.brand} {veh.model}" if veh else f"ID {vehicle_id}"
                placa_txt = veh.plate if veh else ""
                
                tpl = w_config.msg_new_vistoria
                msg = tpl.format(
                    veiculo=veiculo_txt,
                    placa=placa_txt,
                    status=status_geral.upper()
                )
                send_whatsapp_message(msg)
        except Exception as whatsapp_err:
            print("⚠️ Erro ao disparar whatsapp para nova vistoria:", whatsapp_err)

        if rejected:
            flash(f"Vistoria registrada. Fotos salvas: {saved}. Rejeitadas: {rejected}", "success")
        else:
            flash(f"Vistoria registrada. Fotos salvas: {saved}", "success")

        return redirect(url_for("vistorias_list", open_id=v.id))

    return render_template("vistorias_nova.html", veiculos=veiculos)





@fleet_bp.route("/vistorias/<int:vistoria_id>")
@supervisor_allowed
def vistorias_detail(vistoria_id):
    v = Vistoria.query.get_or_404(vistoria_id)

    fotos_por_item = defaultdict(list)
    for f in v.fotos:
        if f.item_key:
            fotos_por_item[f.item_key].append(f)

    if request.args.get("format") == "json":
        is_moto = (v.vehicle and v.vehicle.type == 'moto')
        if is_moto:
            ITENS_INFO = [
                ('para_choque_dianteiro', 'Guidão e Manetes'),
                ('para_choque_traseiro', 'Relação (Corrente/Coroa)'),
                ('lateral_esquerda', 'Lateral esquerda'),
                ('lateral_direita', 'Lateral direita'),
                ('capo', 'Tanque de Combustível'),
                ('teto', 'Assento / Banco'),
                ('porta_malas', 'Baú / Bauleto'),
                ('retrovisores', 'Retrovisores'),
                ('farois_lanternas', 'Farol / Lanterna'),
                ('vidros_parabrisa', 'Escapamento / Motor'),
                ('pneus', 'Pneus (Dianteiro/Traseiro)'),
                ('calotas', 'Rodas / Raios')
            ]
        else:
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
                "fotos": [f.filename for f in fotos_por_item[key]],
                "fotos_info": [{"id": f.id, "filename": f.filename} for f in fotos_por_item[key]]
            })
            
        return jsonify({
            "id": v.id,
            "created_at": v.created_at.strftime('%d/%m/%Y %H:%M'),
            "plate": v.vehicle.plate if v.vehicle else "-",
            "vehicle_type": v.vehicle.type if v.vehicle else "carro",
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


@fleet_bp.route("/vistorias/<int:vistoria_id>/editar", methods=["GET", "POST"])
@supervisor_allowed
def vistorias_editar(vistoria_id):
    v = Vistoria.query.get_or_404(vistoria_id)
    if request.method == "GET":
        return redirect(url_for("vistorias_list", open_id=v.id, edit="true"))

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
            return redirect(url_for("vistorias_list", open_id=v.id, edit="true"))

        # 1) Excluir fotos marcadas para exclusão
        delete_photo_ids = request.form.getlist("delete_photos[]")
        for f_id_str in delete_photo_ids:
            if f_id_str.isdigit():
                f_id = int(f_id_str)
                foto_obj = VistoriaFoto.query.filter_by(id=f_id, vistoria_id=v.id).first()
                if foto_obj:
                    if foto_obj.filename:
                        filepath = VISTORIAS_UPLOAD_DIR / foto_obj.filename
                        if filepath.exists():
                            try:
                                filepath.unlink()
                            except Exception as unlink_err:
                                print(f"Erro ao deletar arquivo de foto {filepath}: {unlink_err}")
                    db.session.delete(foto_obj)

        # 2) Atualizar status e observações dos itens
        campos_status = {k: (request.form.get(k) or "ok") for k in ITENS}
        for k in ITENS:
            setattr(v, k, campos_status[k])
            obs_val = (request.form.get(f"obs_{k}") or "").strip()
            setattr(v, f"obs_{k}", obs_val or None)

        # 3) Processar novas fotos
        VISTORIAS_UPLOAD_DIR.mkdir(parents=True, exist_ok=True)
        saved = 0
        rejected = 0

        for k in ITENS:
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
                    print("Erro salvando nova foto na edição:", k, e)
                    rejected += 1

        # 4) Atualizar dados principais
        v.vehicle_id = int(vehicle_id)
        v.km = int(km) if km.isdigit() else None
        v.turno = turno
        v.local = local
        v.observacoes = observacoes

        # 5) Recalcular status geral automático
        v.status_geral = "avarias" if any(getattr(v, k) == "avaria" for k in ITENS) else "ok"

        try:
            db.session.commit()
            registrar_log(f"Vistoria editada: ID {v.id} (Veículo: {v.vehicle.plate if v.vehicle else 'N/A'})")
            if rejected:
                flash(f"Vistoria atualizada. Fotos novas salvas: {saved}. Rejeitadas: {rejected}", "success")
            else:
                flash("Vistoria atualizada com sucesso.", "success")
            return redirect(url_for("vistorias_list", open_id=v.id))
        except Exception as e:
            db.session.rollback()
            registrar_log(f"Vistoria: ERRO AO EDITAR id={v.id}: {str(e)}")
            flash(f"Erro ao salvar alterações da vistoria: {e}", "error")
            return redirect(url_for("vistorias_list", open_id=v.id, edit="true"))

    return redirect(url_for("vistorias_list", open_id=v.id, edit="true"))


@fleet_bp.route("/vistorias/<int:vistoria_id>/excluir", methods=["POST"])
@supervisor_allowed
def vistorias_excluir(vistoria_id):
    v = Vistoria.query.get_or_404(vistoria_id)
    try:
        # Save vehicle plate info before deletion to prevent unbound lazy-load error after commit
        plate = v.vehicle.plate if v.vehicle else "N/A"
        
        # Delete physical photo files associated with the vistoria
        for f in v.fotos:
            if f.filename:
                filepath = VISTORIAS_UPLOAD_DIR / f.filename
                if filepath.exists():
                    filepath.unlink()
        
        # Deleting vistoria also cascades to VistoriaFoto due to cascade="all, delete-orphan"
        db.session.delete(v)
        db.session.commit()
        registrar_log(f"Vistoria excluída: ID {vistoria_id} (Veículo: {plate})")
        flash("Vistoria excluída com sucesso.", "success")
    except Exception as e:
        db.session.rollback()
        registrar_log(f"Vistoria: ERRO AO EXCLUIR id={vistoria_id}: {str(e)}")
        flash(f"Erro ao excluir vistoria: {e}", "error")
    return redirect(url_for("vistorias_list"))
