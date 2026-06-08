"""
AI Firewall Policy Intelligence System
api/routes/threats.py — Threat Intelligence APIs
"""

import json
import os
from flask import Blueprint, jsonify, current_app

threats_bp = Blueprint("threats", __name__, url_prefix="/api")


# ── GET threat intelligence data ───────────────────────────────────
@threats_bp.route("/threats", methods=["GET"])
def get_threats():
    data_dir    = current_app.config["DATA_DIR"]
    threat_path = os.path.join(data_dir, "threat_intel.json")
    try:
        if not os.path.exists(threat_path):
            return jsonify({"error": "Threat intelligence file not found"}), 404
        with open(threat_path, "r") as f:
            data = json.load(f)
        return jsonify({
            "threats": data,
            "count"  : len(data) if isinstance(data, list) else 1
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── GET network topology ───────────────────────────────────────────
@threats_bp.route("/topology", methods=["GET"])
def get_topology():
    data_dir      = current_app.config["DATA_DIR"]
    topology_path = os.path.join(data_dir, "network_topology.json")
    try:
        if not os.path.exists(topology_path):
            return jsonify({"error": "Topology file not found"}), 404
        with open(topology_path, "r") as f:
            data = json.load(f)
        return jsonify({
            "topology": data
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


# ── GET API health check ───────────────────────────────────────────
@threats_bp.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status"   : "ok",
        "message"  : "AI Firewall API running",
        "endpoints": [
            "POST   /api/analyze",
            "GET    /api/reports",
            "POST   /api/reports",
            "GET    /api/reports/<index>",
            "DELETE /api/reports/<index>",
            "GET    /api/threats",
            "GET    /api/topology",
            "GET    /api/health",
        ]
    }), 200