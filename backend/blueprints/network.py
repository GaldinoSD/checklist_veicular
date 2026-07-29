# -*- coding: utf-8 -*-
from backend.utils import GlobalBlueprint
network_bp = GlobalBlueprint("network", __name__)

import os, json, uuid, pytz
from datetime import datetime
from pathlib import Path

from flask import render_template, request, abort, jsonify, current_app
from flask_login import login_required, current_user
from werkzeug.utils import secure_filename
from sqlalchemy import func

from backend import db
from backend.config import TZ, UPLOAD_DIR
from backend.models import (
    NetworkNode, NetworkSplitter, NetworkEdge, NetworkEquipment,
    NetworkRack, NetworkRackSlot, NetworkLayer, NetworkProject,
    NetworkChangeLog
)
from backend.utils import agora


# ==============================================================================
# HELPERS
# ==============================================================================
NETWORK_PHOTOS_DIR = os.path.join(UPLOAD_DIR, "network_photos")
os.makedirs(NETWORK_PHOTOS_DIR, exist_ok=True)


def _log_change(entity_type, entity_id, action, entity_name="", old_data=None, new_data=None):
    """Registra alteração no histórico de rede."""
    entry = NetworkChangeLog(
        entity_type=entity_type,
        entity_id=entity_id,
        action=action,
        entity_name=entity_name,
        old_data=json.dumps(old_data) if old_data else None,
        new_data=json.dumps(new_data) if new_data else None,
        user_id=current_user.id if current_user.is_authenticated else None,
        user_name=current_user.username if current_user.is_authenticated else "system"
    )
    db.session.add(entry)


def _node_to_dict(node):
    """Serializa um nó para JSON."""
    splitters_list = []
    for s in node.splitters:
        splitters_list.append({
            "id": s.id, "name": s.name, "ratio": s.ratio,
            "ports": json.loads(s.ports) if s.ports else [],
            "details": json.loads(s.details) if s.details else {}
        })
    equip_list = []
    for e in node.equipment:
        equip_list.append({
            "id": e.id, "name": e.name, "code": e.code, "type": e.type,
            "manufacturer": e.manufacturer, "model": e.model,
            "serial_number": e.serial_number,
            "ports_total": e.ports_total, "ports_used": e.ports_used,
            "power_watts": e.power_watts, "status": e.status,
            "observations": e.observations,
            "details": json.loads(e.details) if e.details else {}
        })
    return {
        "id": node.id, "name": node.name, "code": node.code,
        "type": node.type, "lat": node.lat, "lng": node.lng,
        "status": node.status, "manufacturer": node.manufacturer,
        "model": node.model, "capacity": node.capacity,
        "observations": node.observations, "layer": node.layer,
        "details": json.loads(node.details) if node.details else {},
        "photos": json.loads(node.photos) if node.photos else [],
        "splitters": splitters_list,
        "equipment": equip_list,
        "created_at": node.created_at.strftime("%d/%m/%Y %H:%M") if node.created_at else None
    }


def _edge_to_dict(edge):
    """Serializa um cabo para JSON."""
    return {
        "id": edge.id, "name": edge.name, "type": edge.type,
        "source_node_id": edge.source_node_id,
        "target_node_id": edge.target_node_id,
        "path_coordinates": json.loads(edge.path_coordinates) if edge.path_coordinates else [],
        "fiber_count": edge.fiber_count, "tube_count": edge.tube_count,
        "cable_model": edge.cable_model, "manufacturer": edge.manufacturer,
        "distance_m": edge.distance_m,
        "technical_reserve_m": edge.technical_reserve_m,
        "color": edge.color, "thickness": edge.thickness,
        "status": edge.status, "layer": edge.layer,
        "details": json.loads(edge.details) if edge.details else {},
        "created_at": edge.created_at.strftime("%d/%m/%Y %H:%M") if edge.created_at else None
    }


def _ensure_default_layers():
    """Cria camadas padrão se não existirem."""
    defaults = [
        ("backbone", "Backbone", "#ef4444", "fa-bolt", 1),
        ("distribution", "Distribuição", "#f59e0b", "fa-code-branch", 2),
        ("drop", "Drop/Derivação", "#06b6d4", "fa-plug", 3),
        ("infrastructure", "Infraestrutura", "#64748b", "fa-city", 4),
        ("ctos", "CTOs / NAPs", "#22c55e", "fa-box", 5),
        ("ceos", "CEOs / Emendas", "#eab308", "fa-circle-nodes", 6),
        ("pops", "POPs", "#f97316", "fa-building", 7),
        ("equipment", "Equipamentos", "#8b5cf6", "fa-server", 8),
        ("cables", "Cabos", "#6366f1", "fa-bezier-curve", 9),
        ("projects", "Projetos", "#ec4899", "fa-drafting-compass", 10),
    ]
    for name, display, color, icon, order in defaults:
        if not NetworkLayer.query.filter_by(name=name).first():
            db.session.add(NetworkLayer(
                name=name, display_name=display, color=color,
                icon=icon, sort_order=order
            ))
    db.session.commit()


# ==============================================================================
# 🌐 VIEWS: PÁGINAS HTML
# ==============================================================================
@network_bp.route("/mapa-rede")
@login_required
def mapa_rede():
    if not current_user.has_permission("gestao_mapas"):
        abort(403)
    _ensure_default_layers()
    return render_template("mapa_rede.html")


@network_bp.route("/rede-registros")
@login_required
def rede_registros():
    if not current_user.has_permission("gestao_mapas"):
        abort(403)
    nodes = NetworkNode.query.order_by(NetworkNode.id).all()
    edges = NetworkEdge.query.order_by(NetworkEdge.id).all()
    nodes_list = [_node_to_dict(n) for n in nodes]
    edges_list = []
    for edge in edges:
        ed = _edge_to_dict(edge)
        src = next((n for n in nodes_list if n["id"] == edge.source_node_id), None)
        tgt = next((n for n in nodes_list if n["id"] == edge.target_node_id), None)
        ed["source_name"] = src["name"] if src else "N/A"
        ed["target_name"] = tgt["name"] if tgt else "N/A"
        edges_list.append(ed)
    return render_template("rede_registros.html",
                           nodes_json=json.dumps(nodes_list),
                           edges_json=json.dumps(edges_list))


# ==============================================================================
# 🔌 API REST: NODES (Infraestrutura)
# ==============================================================================
@network_bp.route("/api/network/nodes", methods=["GET"])
@login_required
def get_network_nodes():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    layer = request.args.get("layer")
    ntype = request.args.get("type")
    status = request.args.get("status")
    q = NetworkNode.query
    if layer:
        q = q.filter_by(layer=layer)
    if ntype:
        q = q.filter_by(type=ntype)
    if status:
        q = q.filter_by(status=status)
    nodes = q.order_by(NetworkNode.id).all()
    return jsonify({"success": True, "nodes": [_node_to_dict(n) for n in nodes]})


def _req_json():
    data = request.get_json(force=True, silent=True)
    if not data and request.data:
        try:
            data = json.loads(request.data.decode('utf-8'))
        except Exception:
            data = {}
    return data or {}


@network_bp.route("/api/network/nodes", methods=["POST"])
@login_required
def create_network_node():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = _req_json()
    name = data.get("name", "").strip()
    node_type = data.get("type", "").strip()
    lat = data.get("lat")
    lng = data.get("lng")
    if not name or not node_type or lat is None or lng is None:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    node = NetworkNode(
        name=name, code=data.get("code", "").strip() or None,
        type=node_type, lat=float(lat), lng=float(lng),
        status=data.get("status", "active"),
        manufacturer=data.get("manufacturer", "").strip() or None,
        model=data.get("model", "").strip() or None,
        capacity=data.get("capacity", "").strip() or None,
        observations=data.get("observations", "").strip() or None,
        layer=data.get("layer", "infrastructure"),
        details=json.dumps(data.get("details", {})),
        created_by=current_user.id
    )
    db.session.add(node)
    db.session.flush()
    _log_change("node", node.id, "created", node.name)
    db.session.commit()
    return jsonify({"success": True, "node": _node_to_dict(node)})


@network_bp.route("/api/network/nodes/<int:id>", methods=["PUT"])
@login_required
def update_network_node(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    data = _req_json()
    old_name = node.name
    for field in ["name", "code", "status", "manufacturer", "model", "capacity", "observations", "layer"]:
        if field in data:
            val = data[field]
            setattr(node, field, val.strip() if isinstance(val, str) else val)
    if "lat" in data:
        node.lat = float(data["lat"])
    if "lng" in data:
        node.lng = float(data["lng"])
    if "details" in data:
        node.details = json.dumps(data["details"])
    _log_change("node", node.id, "updated", old_name)
    db.session.commit()
    return jsonify({"success": True, "node": _node_to_dict(node)})


@network_bp.route("/api/network/nodes/<int:id>", methods=["DELETE"])
@login_required
def delete_network_node(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    _log_change("node", node.id, "deleted", node.name)
    edges = NetworkEdge.query.filter(
        (NetworkEdge.source_node_id == id) | (NetworkEdge.target_node_id == id)
    ).all()
    for edge in edges:
        db.session.delete(edge)
    db.session.delete(node)
    db.session.commit()
    return jsonify({"success": True})


@network_bp.route("/api/network/nodes/<int:id>/fusions", methods=["POST", "PUT"])
@login_required
def save_node_fusions(id):
    """Salva a matriz de fusões de fibra em uma CEO, CTO, DIO ou POP."""
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    data = _req_json()
    fusions = data.get("fusions", [])

    details = json.loads(node.details) if node.details else {}
    details["fusions"] = fusions
    node.details = json.dumps(details)

    _log_change("node", node.id, "updated_fusions", node.name)
    db.session.commit()
    return jsonify({"success": True, "fusions": fusions})


@network_bp.route("/api/network/nodes/<int:id>/connections", methods=["POST", "PUT"])
@login_required
def save_node_connections(id):
    """Salva o mapeamento de interligação OLT <-> DIO <-> Fibra <-> Equipamento."""
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    data = _req_json()
    connections = data.get("connections", [])

    details = json.loads(node.details) if node.details else {}
    details["connections"] = connections
    node.details = json.dumps(details)

    _log_change("node", node.id, "updated_connections", node.name)
    db.session.commit()
    return jsonify({"success": True, "connections": connections})


# ==============================================================================
# ⚡ API REST: EDGES (Cabos/Rotas Ópticas)
# ==============================================================================
@network_bp.route("/api/network/edges", methods=["GET"])
@login_required
def get_network_edges():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edges = NetworkEdge.query.order_by(NetworkEdge.id).all()
    return jsonify({"success": True, "edges": [_edge_to_dict(e) for e in edges]})


@network_bp.route("/api/network/edges", methods=["POST"])
@login_required
def create_network_edge():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = _req_json()
    name = data.get("name", "").strip()
    source_id = data.get("source_node_id")
    target_id = data.get("target_node_id")
    if not name or source_id is None or target_id is None:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    edge = NetworkEdge(
        name=name, type=data.get("type", "backbone"),
        source_node_id=int(source_id), target_node_id=int(target_id),
        path_coordinates=json.dumps(data.get("path_coordinates", [])),
        fiber_count=int(data.get("fiber_count", 12)),
        tube_count=int(data.get("tube_count", 1)),
        cable_model=data.get("cable_model", "").strip() or None,
        manufacturer=data.get("manufacturer", "").strip() or None,
        distance_m=float(data.get("distance_m", 0)),
        technical_reserve_m=float(data.get("technical_reserve_m", 0)),
        color=data.get("color", "#6366f1"),
        thickness=int(data.get("thickness", 3)),
        status=data.get("status", "active"),
        layer=data.get("layer", "cables"),
        details=json.dumps(data.get("details", {}))
    )
    db.session.add(edge)
    db.session.flush()
    _log_change("edge", edge.id, "created", edge.name)
    db.session.commit()
    return jsonify({"success": True, "edge": _edge_to_dict(edge)})


@network_bp.route("/api/network/edges/<int:id>", methods=["PUT"])
@login_required
def update_network_edge(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edge = NetworkEdge.query.get_or_404(id)
    data = _req_json()
    for field in ["name", "type", "cable_model", "manufacturer", "color", "status", "layer"]:
        if field in data:
            val = data[field]
            setattr(edge, field, val.strip() if isinstance(val, str) else val)
    for field in ["fiber_count", "tube_count", "thickness"]:
        if field in data:
            setattr(edge, field, int(data[field]))
    for field in ["distance_m", "technical_reserve_m"]:
        if field in data:
            setattr(edge, field, float(data[field]))
    if "path_coordinates" in data:
        edge.path_coordinates = json.dumps(data["path_coordinates"])
    if "details" in data:
        edge.details = json.dumps(data["details"])
    if "source_node_id" in data:
        edge.source_node_id = int(data["source_node_id"])
    if "target_node_id" in data:
        edge.target_node_id = int(data["target_node_id"])
    _log_change("edge", edge.id, "updated", edge.name)
    db.session.commit()
    return jsonify({"success": True, "edge": _edge_to_dict(edge)})


@network_bp.route("/api/network/edges/<int:id>", methods=["DELETE"])
@login_required
def delete_network_edge(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    edge = NetworkEdge.query.get_or_404(id)
    _log_change("edge", edge.id, "deleted", edge.name)
    db.session.delete(edge)
    db.session.commit()
    return jsonify({"success": True})


# ==============================================================================
# 🔀 API REST: SPLITTERS
# ==============================================================================
@network_bp.route("/api/network/splitters", methods=["POST"])
@login_required
def create_network_splitter():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    node_id = data.get("node_id")
    name = data.get("name", "").strip()
    ratio = data.get("ratio", "1x8").strip()
    if node_id is None or not name:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    # Gera portas iniciais baseado no ratio
    output_count = int(ratio.split("x")[1]) if "x" in ratio else 8
    initial_ports = [{"port": i+1, "client": "", "signal_dbm": 0, "status": "free"} for i in range(output_count)]
    splitter = NetworkSplitter(
        node_id=int(node_id), name=name, ratio=ratio,
        ports=json.dumps(initial_ports),
        details=json.dumps(data.get("details", {}))
    )
    db.session.add(splitter)
    db.session.flush()
    _log_change("splitter", splitter.id, "created", splitter.name)
    db.session.commit()
    return jsonify({"success": True, "splitter": {
        "id": splitter.id, "node_id": splitter.node_id,
        "name": splitter.name, "ratio": splitter.ratio,
        "ports": initial_ports,
        "details": json.loads(splitter.details) if splitter.details else {}
    }})


@network_bp.route("/api/network/splitters/<int:id>", methods=["PUT"])
@login_required
def update_network_splitter(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    splitter = NetworkSplitter.query.get_or_404(id)
    data = request.get_json() or {}
    if "name" in data:
        splitter.name = data["name"].strip()
    if "ratio" in data:
        splitter.ratio = data["ratio"].strip()
    if "ports" in data:
        splitter.ports = json.dumps(data["ports"])
    if "details" in data:
        splitter.details = json.dumps(data["details"])
    _log_change("splitter", splitter.id, "updated", splitter.name)
    db.session.commit()
    return jsonify({"success": True})


@network_bp.route("/api/network/splitters/<int:id>", methods=["DELETE"])
@login_required
def delete_network_splitter(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    splitter = NetworkSplitter.query.get_or_404(id)
    _log_change("splitter", splitter.id, "deleted", splitter.name)
    db.session.delete(splitter)
    db.session.commit()
    return jsonify({"success": True})


# ==============================================================================
# 🖥️ API REST: EQUIPMENT
# ==============================================================================
@network_bp.route("/api/network/equipment", methods=["GET"])
@login_required
def get_network_equipment():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    items = NetworkEquipment.query.order_by(NetworkEquipment.id).all()
    result = []
    for e in items:
        result.append({
            "id": e.id, "name": e.name, "code": e.code, "type": e.type,
            "node_id": e.node_id, "manufacturer": e.manufacturer,
            "model": e.model, "serial_number": e.serial_number,
            "ports_total": e.ports_total, "ports_used": e.ports_used,
            "power_watts": e.power_watts, "status": e.status,
            "observations": e.observations,
            "details": json.loads(e.details) if e.details else {}
        })
    return jsonify({"success": True, "equipment": result})


@network_bp.route("/api/network/equipment", methods=["POST"])
@login_required
def create_network_equipment():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    data = request.get_json() or {}
    name = data.get("name", "").strip()
    eq_type = data.get("type", "").strip()
    if not name or not eq_type:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    equip = NetworkEquipment(
        name=name, code=data.get("code", "").strip() or None,
        type=eq_type,
        node_id=int(data["node_id"]) if data.get("node_id") else None,
        manufacturer=data.get("manufacturer", "").strip() or None,
        model=data.get("model", "").strip() or None,
        serial_number=data.get("serial_number", "").strip() or None,
        ports_total=int(data.get("ports_total", 0)),
        ports_used=int(data.get("ports_used", 0)),
        power_watts=float(data.get("power_watts", 0)),
        status=data.get("status", "active"),
        observations=data.get("observations", "").strip() or None,
        details=json.dumps(data.get("details", {}))
    )
    db.session.add(equip)
    db.session.flush()
    _log_change("equipment", equip.id, "created", equip.name)
    db.session.commit()
    return jsonify({"success": True, "equipment": {
        "id": equip.id, "name": equip.name, "type": equip.type
    }})


@network_bp.route("/api/network/equipment/<int:id>", methods=["PUT"])
@login_required
def update_network_equipment(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    equip = NetworkEquipment.query.get_or_404(id)
    data = request.get_json() or {}
    for field in ["name", "code", "type", "manufacturer", "model", "serial_number", "status", "observations"]:
        if field in data:
            val = data[field]
            setattr(equip, field, val.strip() if isinstance(val, str) else val)
    for field in ["ports_total", "ports_used"]:
        if field in data:
            setattr(equip, field, int(data[field]))
    if "power_watts" in data:
        equip.power_watts = float(data["power_watts"])
    if "node_id" in data:
        equip.node_id = int(data["node_id"]) if data["node_id"] else None
    if "details" in data:
        equip.details = json.dumps(data["details"])
    _log_change("equipment", equip.id, "updated", equip.name)
    db.session.commit()
    return jsonify({"success": True})


@network_bp.route("/api/network/equipment/<int:id>", methods=["DELETE"])
@login_required
def delete_network_equipment(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    equip = NetworkEquipment.query.get_or_404(id)
    _log_change("equipment", equip.id, "deleted", equip.name)
    db.session.delete(equip)
    db.session.commit()
    return jsonify({"success": True})


# ==============================================================================
# 🗂️ API REST: LAYERS (Camadas)
# ==============================================================================
@network_bp.route("/api/network/layers", methods=["GET"])
@login_required
def get_network_layers():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    _ensure_default_layers()
    layers = NetworkLayer.query.order_by(NetworkLayer.sort_order).all()
    return jsonify({"success": True, "layers": [{
        "id": l.id, "name": l.name, "display_name": l.display_name,
        "color": l.color, "icon": l.icon, "visible": l.visible,
        "sort_order": l.sort_order
    } for l in layers]})


@network_bp.route("/api/network/layers/<int:id>", methods=["PUT"])
@login_required
def update_network_layer(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    layer = NetworkLayer.query.get_or_404(id)
    data = request.get_json() or {}
    if "visible" in data:
        layer.visible = bool(data["visible"])
    if "display_name" in data:
        layer.display_name = data["display_name"].strip()
    if "color" in data:
        layer.color = data["color"].strip()
    db.session.commit()
    return jsonify({"success": True})


# ==============================================================================
# 📊 API REST: DASHBOARD & STATS
# ==============================================================================
@network_bp.route("/api/network/dashboard", methods=["GET"])
@login_required
def get_network_dashboard():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403

    total_nodes = NetworkNode.query.count()
    nodes_by_type = db.session.query(
        NetworkNode.type, func.count(NetworkNode.id)
    ).group_by(NetworkNode.type).all()
    nodes_by_status = db.session.query(
        NetworkNode.status, func.count(NetworkNode.id)
    ).group_by(NetworkNode.status).all()

    total_edges = NetworkEdge.query.count()
    total_distance = db.session.query(func.sum(NetworkEdge.distance_m)).scalar() or 0
    total_fibers = db.session.query(func.sum(NetworkEdge.fiber_count)).scalar() or 0
    edges_by_type = db.session.query(
        NetworkEdge.type, func.count(NetworkEdge.id)
    ).group_by(NetworkEdge.type).all()
    edges_by_status = db.session.query(
        NetworkEdge.status, func.count(NetworkEdge.id)
    ).group_by(NetworkEdge.status).all()

    total_splitters = NetworkSplitter.query.count()
    total_equipment = NetworkEquipment.query.count()
    total_racks = NetworkRack.query.count()

    # Ocupação de splitters
    all_splitters = NetworkSplitter.query.all()
    total_ports = 0
    used_ports = 0
    for s in all_splitters:
        ports = json.loads(s.ports) if s.ports else []
        total_ports += len(ports)
        used_ports += len([p for p in ports if p.get("status") == "active"])

    # Ocupação de equipamentos (portas)
    equip_ports_total = db.session.query(func.sum(NetworkEquipment.ports_total)).scalar() or 0
    equip_ports_used = db.session.query(func.sum(NetworkEquipment.ports_used)).scalar() or 0
    equip_power = db.session.query(func.sum(NetworkEquipment.power_watts)).scalar() or 0

    return jsonify({
        "success": True,
        "dashboard": {
            "total_nodes": total_nodes,
            "nodes_by_type": {t: c for t, c in nodes_by_type},
            "nodes_by_status": {s: c for s, c in nodes_by_status},
            "total_edges": total_edges,
            "total_distance_km": round(total_distance / 1000, 2),
            "total_fibers": total_fibers,
            "edges_by_type": {t: c for t, c in edges_by_type},
            "edges_by_status": {s: c for s, c in edges_by_status},
            "total_splitters": total_splitters,
            "splitter_ports_total": total_ports,
            "splitter_ports_used": used_ports,
            "splitter_occupancy_pct": round((used_ports / total_ports * 100) if total_ports > 0 else 0, 1),
            "total_equipment": total_equipment,
            "equipment_ports_total": equip_ports_total,
            "equipment_ports_used": equip_ports_used,
            "equipment_power_watts": round(equip_power, 1),
            "total_racks": total_racks,
        }
    })


# ==============================================================================
# 📜 API REST: CHANGELOG
# ==============================================================================
@network_bp.route("/api/network/changelog", methods=["GET"])
@login_required
def get_network_changelog():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    limit = request.args.get("limit", 50, type=int)
    logs = NetworkChangeLog.query.order_by(NetworkChangeLog.created_at.desc()).limit(limit).all()
    return jsonify({"success": True, "changelog": [{
        "id": l.id, "entity_type": l.entity_type,
        "entity_id": l.entity_id, "action": l.action,
        "entity_name": l.entity_name,
        "user_name": l.user_name,
        "created_at": l.created_at.strftime("%d/%m/%Y %H:%M") if l.created_at else None
    } for l in logs]})


# ==============================================================================
# 🔍 API REST: SEARCH
# ==============================================================================
@network_bp.route("/api/network/search", methods=["GET"])
@login_required
def search_network():
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    q = request.args.get("q", "").strip()
    if not q or len(q) < 2:
        return jsonify({"success": True, "results": []})
    search_term = f"%{q}%"
    nodes = NetworkNode.query.filter(
        (NetworkNode.name.ilike(search_term)) |
        (NetworkNode.code.ilike(search_term))
    ).limit(20).all()
    edges = NetworkEdge.query.filter(
        NetworkEdge.name.ilike(search_term)
    ).limit(10).all()
    results = []
    for n in nodes:
        results.append({
            "type": "node", "id": n.id, "name": n.name,
            "subtype": n.type, "lat": n.lat, "lng": n.lng
        })
    for e in edges:
        results.append({
            "type": "edge", "id": e.id, "name": e.name,
            "subtype": e.type
        })
    return jsonify({"success": True, "results": results})


# ==============================================================================
# 📷 API REST: UPLOAD FOTOS
# ==============================================================================
@network_bp.route("/api/network/nodes/<int:id>/photo", methods=["POST"])
@login_required
def upload_node_photo(id):
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403
    node = NetworkNode.query.get_or_404(id)
    if "photo" not in request.files:
        return jsonify({"success": False, "error": "No file uploaded"}), 400
    photo = request.files["photo"]
    if photo.filename == "":
        return jsonify({"success": False, "error": "Empty filename"}), 400
    ext = photo.filename.rsplit(".", 1)[-1].lower() if "." in photo.filename else ""
    if ext not in ("jpg", "jpeg", "png", "webp"):
        return jsonify({"success": False, "error": "Invalid file type"}), 400
    filename = f"node_{id}_{uuid.uuid4().hex[:8]}.{ext}"
    filepath = os.path.join(NETWORK_PHOTOS_DIR, filename)
    photo.save(filepath)
    photos = json.loads(node.photos) if node.photos else []
    photos.append(f"/static/uploads/network_photos/{filename}")
    node.photos = json.dumps(photos)
    db.session.commit()
    return jsonify({"success": True, "photo_url": photos[-1]})


# ==============================================================================
# 📤 API REST: EXPORTAÇÃO (GeoJSON, KML, CSV)
# ==============================================================================
@network_bp.route("/api/network/export/geojson", methods=["GET"])
@login_required
def export_geojson():
    """Exporta toda a rede no padrão GeoJSON (compatível com QGIS, ArcGIS, Google Maps)."""
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403

    nodes = NetworkNode.query.all()
    edges = NetworkEdge.query.all()

    features = []

    # Features dos Nós (Point)
    for n in nodes:
        features.append({
            "type": "Feature",
            "geometry": {
                "type": "Point",
                "coordinates": [n.lng, n.lat]
            },
            "properties": {
                "id": n.id, "name": n.name, "code": n.code or "",
                "type": n.type, "status": n.status,
                "manufacturer": n.manufacturer or "", "model": n.model or "",
                "capacity": n.capacity or "", "layer": n.layer
            }
        })

    # Features dos Cabos (LineString)
    for e in edges:
        coords = json.loads(e.path_coordinates) if e.path_coordinates else []
        # Converter [lat, lng] para GeoJSON [lng, lat]
        geojson_coords = [[c[1], c[0]] for c in coords if len(c) >= 2]
        if len(geojson_coords) >= 2:
            features.append({
                "type": "Feature",
                "geometry": {
                    "type": "LineString",
                    "coordinates": geojson_coords
                },
                "properties": {
                    "id": e.id, "name": e.name, "type": e.type,
                    "fiber_count": e.fiber_count, "tube_count": e.tube_count,
                    "distance_m": e.distance_m, "status": e.status,
                    "color": e.color
                }
            })

    geojson_data = {
        "type": "FeatureCollection",
        "name": "Rede_FTTH_Export",
        "features": features
    }

    return current_app.response_class(
        response=json.dumps(geojson_data, ensure_ascii=False, indent=2),
        status=200,
        mimetype="application/json",
        headers={"Content-Disposition": f"attachment;filename=rede_ftth_geojson_{datetime.now().strftime('%d_%m_%Y')}.json"}
    )


@network_bp.route("/api/network/export/kml", methods=["GET"])
@login_required
def export_kml():
    """Exporta a rede no formato KML para o Google Earth."""
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403

    nodes = NetworkNode.query.all()
    edges = NetworkEdge.query.all()

    kml = ['<?xml version="1.0" encoding="UTF-8"?>']
    kml.append('<kml xmlns="http://www.opengis.net/kml/2.2">')
    kml.append('<Document><name>Rede FTTH/FTTX</name>')

    # Estilos de linhas por tipo de cabo
    kml.append('<Style id="backbone"><LineStyle><color>ff4444ef</color><width>5</width></LineStyle></Style>')
    kml.append('<Style id="distribution"><LineStyle><color>ff0b9ef5</color><width>3</width></LineStyle></Style>')
    kml.append('<Style id="drop"><LineStyle><color>ffd4b606</color><width>2</width></LineStyle></Style>')

    # Nós
    kml.append('<Folder><name>Elementos de Infraestrutura</name>')
    for n in nodes:
        kml.append('<Placemark>')
        kml.append(f'<name>{n.name} ({n.type.upper()})</name>')
        kml.append(f'<description><![CDATA[Código: {n.code or "N/A"}<br>Status: {n.status}<br>Modelo: {n.model or "N/A"}]]></description>')
        kml.append(f'<Point><coordinates>{n.lng},{n.lat},0</coordinates></Point>')
        kml.append('</Placemark>')
    kml.append('</Folder>')

    # Cabos
    kml.append('<Folder><name>Cabos de Fibra Óptica</name>')
    for e in edges:
        coords = json.loads(e.path_coordinates) if e.path_coordinates else []
        if len(coords) >= 2:
            kml.append('<Placemark>')
            kml.append(f'<name>{e.name} ({e.fiber_count} FO)</name>')
            kml.append(f'<styleUrl>#{e.type}</styleUrl>')
            coord_str = ' '.join([f"{c[1]},{c[0]},0" for c in coords])
            kml.append(f'<LineString><coordinates>{coord_str}</coordinates></LineString>')
            kml.append('</Placemark>')
    kml.append('</Folder>')

    kml.append('</Document></kml>')
    kml_content = '\n'.join(kml)

    return current_app.response_class(
        response=kml_content,
        status=200,
        mimetype="application/vnd.google-earth.kml+xml",
        headers={"Content-Disposition": f"attachment;filename=rede_ftth_{datetime.now().strftime('%d_%m_%Y')}.kml"}
    )


# ==============================================================================
# 💡 API REST: OPTICAL POWER BUDGET (Orçamento de Potência)
# ==============================================================================
@network_bp.route("/api/network/power-budget", methods=["POST"])
@login_required
def calculate_power_budget():
    """Calcula atenuação teórica da fibra (dB) entre dois pontos ou em um caminho de splitters."""
    if not current_user.has_permission("gestao_mapas"):
        return jsonify({"error": "Unauthorized"}), 403

    data = request.get_json(force=True, silent=True) or {}
    distance_km = float(data.get("distance_km", 0))
    fusion_count = int(data.get("fusion_count", 0))
    connector_count = int(data.get("connector_count", 0))
    splitters = data.get("splitters", [])  # lista ex: ['1x8', '1x16']
    wavelength = data.get("wavelength", "1490nm")  # 1310nm, 1490nm, 1550nm

    # Coeficientes de atenuação padrão ITU-T G.652.D
    attenuation_per_km = 0.35 if wavelength == "1310nm" else (0.21 if wavelength == "1550nm" else 0.25)  # 1490nm default = 0.25 dB/km
    fusion_loss_db = 0.05  # Perda média por fusão
    connector_loss_db = 0.3  # Perda por conector SC/APC

    # Perda por splitter PLC
    splitter_losses = {
        "1x2": 3.7, "1x4": 7.2, "1x8": 10.5,
        "1x16": 13.8, "1x32": 17.0, "1x64": 20.5
    }

    total_fiber_loss = distance_km * attenuation_per_km
    total_fusion_loss = fusion_count * fusion_loss_db
    total_connector_loss = connector_count * connector_loss_db
    total_splitter_loss = sum(splitter_losses.get(s, 10.5) for s in splitters)

    margin_db = 3.0  # Margem de segurança de engenharia
    total_attenuation = total_fiber_loss + total_fusion_loss + total_connector_loss + total_splitter_loss + margin_db

    # Potência típica de saída OLT GPON = +3.0 dBm
    olt_power_dbm = 3.0
    rx_power_dbm = olt_power_dbm - total_attenuation
    status = "EXCELLENT" if rx_power_dbm >= -20 else ("GOOD" if rx_power_dbm >= -25 else ("WARNING" if rx_power_dbm >= -28 else "CRITICAL"))

    return jsonify({
        "success": True,
        "power_budget": {
            "distance_km": distance_km,
            "wavelength": wavelength,
            "fiber_loss_db": round(total_fiber_loss, 2),
            "fusion_loss_db": round(total_fusion_loss, 2),
            "connector_loss_db": round(total_connector_loss, 2),
            "splitter_loss_db": round(total_splitter_loss, 2),
            "safety_margin_db": margin_db,
            "total_attenuation_db": round(total_attenuation, 2),
            "estimated_tx_power_dbm": olt_power_dbm,
            "estimated_rx_power_dbm": round(rx_power_dbm, 2),
            "status": status
        }
    })

