# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
network_bp = GlobalBlueprint("network", __name__)

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
    agora, registrar_log, send_whatsapp_message, admin_required,
    supervisor_allowed, manutencao_only, count_files, list_reports,
    km_alert, iso_week, weekly_km_series, save_photos, _check_rate_limit,
    _record_attempt, _clear_attempts, _cleanup_old_attempts
)




# ==============================================================================
# 🌐 VISTAS E API REST: SISTEMA DE MAPAS E REDE DE FIBRA ÓPTICA 🌐
# ==============================================================================
@network_bp.route("/mapa-rede")
@login_required
def mapa_rede():
    if not current_user.has_permission("gestao_mapas"):
        abort(403)
    return render_template("mapa_rede.html")




@network_bp.route("/rede-registros")
@login_required
def rede_registros():
    if not current_user.has_permission("gestao_mapas"):
        abort(403)

    nodes = NetworkNode.query.order_by(NetworkNode.id).all()
    edges = NetworkEdge.query.order_by(NetworkEdge.id).all()

    nodes_list = []
    for node in nodes:
        node_splitters = []
        for s in node.splitters:
            node_splitters.append({
                "id": s.id,
                "name": s.name,
                "ratio": s.ratio,
                "details": json.loads(s.details) if s.details else {}
            })
        nodes_list.append({
            "id": node.id,
            "name": node.name,
            "type": node.type,
            "lat": node.lat,
            "lng": node.lng,
            "details": json.loads(node.details) if node.details else {},
            "splitters": node_splitters,
            "created_at": node.created_at.strftime("%d/%m/%Y %H:%M") if node.created_at else None
        })

    edges_list = []
    for edge in edges:
        source = next((n for n in nodes_list if n["id"] == edge.source_node_id), None)
        target = next((n for n in nodes_list if n["id"] == edge.target_node_id), None)
        edges_list.append({
            "id": edge.id,
            "name": edge.name,
            "type": edge.type,
            "source_node_id": edge.source_node_id,
            "target_node_id": edge.target_node_id,
            "source_name": source["name"] if source else "N/A",
            "target_name": target["name"] if target else "N/A",
            "path_coordinates": json.loads(edge.path_coordinates) if edge.path_coordinates else [],
            "details": json.loads(edge.details) if edge.details else {},
            "created_at": edge.created_at.strftime("%d/%m/%Y %H:%M") if edge.created_at else None
        })

    return render_template("rede_registros.html",
                           nodes_json=json.dumps(nodes_list),
                           edges_json=json.dumps(edges_list))




# API: GET Nodes
@network_bp.route("/api/network/nodes", methods=["GET"])
@login_required
def get_network_nodes():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    nodes = NetworkNode.query.order_by(NetworkNode.id).all()
    result = []
    for node in nodes:
        node_splitters = []
        for s in node.splitters:
            node_splitters.append({
                "id": s.id,
                "name": s.name,
                "ratio": s.ratio,
                "details": json.loads(s.details) if s.details else {}
            })
        result.append({
            "id": node.id,
            "name": node.name,
            "type": node.type,
            "lat": node.lat,
            "lng": node.lng,
            "details": json.loads(node.details) if node.details else {},
            "splitters": node_splitters
        })
    return jsonify({"success": True, "nodes": result})




# API: POST Node
@network_bp.route("/api/network/nodes", methods=["POST"])
@login_required
def create_network_node():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    node_type = data.get("type", "").strip()
    lat = data.get("lat")
    lng = data.get("lng")
    details = data.get("details", {})

    if not name or not node_type or lat is None or lng is None:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    node = NetworkNode(
        name=name,
        type=node_type,
        lat=float(lat),
        lng=float(lng),
        details=json.dumps(details)
    )
    db.session.add(node)
    db.session.commit()
    return jsonify({"success": True, "node": {
        "id": node.id,
        "name": node.name,
        "type": node.type,
        "lat": node.lat,
        "lng": node.lng,
        "details": details,
        "splitters": []
    }})




# API: PUT Node
@network_bp.route("/api/network/nodes/<int:id>", methods=["PUT"])
@login_required
def update_network_node(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    data = request.get_json() or {}
    
    if "name" in data:
        node.name = data["name"].strip()
    if "lat" in data:
        node.lat = float(data["lat"])
    if "lng" in data:
        node.lng = float(data["lng"])
    if "details" in data:
        node.details = json.dumps(data["details"])
        
    db.session.commit()
    return jsonify({"success": True, "message": "Node updated successfully"})




# API: DELETE Node
@network_bp.route("/api/network/nodes/<int:id>", methods=["DELETE"])
@login_required
def delete_network_node(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    
    # Cascade delete cables connecting to this node
    edges = NetworkEdge.query.filter(
        (NetworkEdge.source_node_id == id) | (NetworkEdge.target_node_id == id)
    ).all()
    for edge in edges:
        db.session.delete(edge)
        
    db.session.delete(node)
    db.session.commit()
    return jsonify({"success": True, "message": "Node deleted successfully"})




# API: GET Edges
@network_bp.route("/api/network/edges", methods=["GET"])
@login_required
def get_network_edges():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edges = NetworkEdge.query.all()
    result = []
    for edge in edges:
        result.append({
            "id": edge.id,
            "name": edge.name,
            "type": edge.type,
            "source_node_id": edge.source_node_id,
            "target_node_id": edge.target_node_id,
            "path_coordinates": json.loads(edge.path_coordinates) if edge.path_coordinates else [],
            "details": json.loads(edge.details) if edge.details else {}
        })
    return jsonify({"success": True, "edges": result})




# API: POST Edge
@network_bp.route("/api/network/edges", methods=["POST"])
@login_required
def create_network_edge():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    edge_type = data.get("type", "cable_fo").strip()
    source_node_id = data.get("source_node_id")
    target_node_id = data.get("target_node_id")
    path_coordinates = data.get("path_coordinates", [])
    details = data.get("details", {})

    if not name or source_node_id is None or target_node_id is None:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    edge = NetworkEdge(
        name=name,
        type=edge_type,
        source_node_id=int(source_node_id),
        target_node_id=int(target_node_id),
        path_coordinates=json.dumps(path_coordinates),
        details=json.dumps(details)
    )
    db.session.add(edge)
    db.session.commit()
    return jsonify({"success": True, "edge": {
        "id": edge.id,
        "name": edge.name,
        "type": edge.type,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "path_coordinates": path_coordinates,
        "details": details
    }})




# API: PUT Edge
@network_bp.route("/api/network/edges/<int:id>", methods=["PUT"])
@login_required
def update_network_edge(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edge = NetworkEdge.query.get_or_404(id)
    data = request.get_json() or {}
    
    if "name" in data:
        edge.name = data["name"].strip()
    if "type" in data:
        edge.type = data["type"].strip()
    if "path_coordinates" in data:
        edge.path_coordinates = json.dumps(data["path_coordinates"])
    if "details" in data:
        edge.details = json.dumps(data["details"])
        
    db.session.commit()
    return jsonify({"success": True, "message": "Edge updated successfully"})




# API: DELETE Edge
@network_bp.route("/api/network/edges/<int:id>", methods=["DELETE"])
@login_required
def delete_network_edge(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edge = NetworkEdge.query.get_or_404(id)
    db.session.delete(edge)
    db.session.commit()
    return jsonify({"success": True, "message": "Edge deleted successfully"})




# API: POST Splitter
@network_bp.route("/api/network/splitters", methods=["POST"])
@login_required
def create_network_splitter():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    node_id = data.get("node_id")
    name = data.get("name", "").strip()
    ratio = data.get("ratio", "1x8").strip()
    details = data.get("details", {})

    if node_id is None or not name:
        return jsonify({"success": False, "error": "Missing required fields"}), 400

    splitter = NetworkSplitter(
        node_id=int(node_id),
        name=name,
        ratio=ratio,
        details=json.dumps(details)
    )
    db.session.add(splitter)
    db.session.commit()
    return jsonify({"success": True, "splitter": {
        "id": splitter.id,
        "node_id": splitter.node_id,
        "name": splitter.name,
        "ratio": splitter.ratio,
        "details": details
    }})




# API: DELETE Splitter
@network_bp.route("/api/network/splitters/<int:id>", methods=["DELETE"])
@login_required
def delete_network_splitter(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    splitter = NetworkSplitter.query.get_or_404(id)
    db.session.delete(splitter)
    db.session.commit()
    return jsonify({"success": True, "message": "Splitter deleted successfully"})
