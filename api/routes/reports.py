"""
AI Firewall Policy Intelligence System
api/routes/reports.py — GET/POST/DELETE /api/reports
"""

import json
import os
from flask import Blueprint, request, jsonify, current_app

reports_bp = Blueprint("reports", __name__, url_prefix="/api")


def load_reports(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return []


def save_reports(path, reports):
    with open(path, "w") as f:
        json.dump(reports, f, indent=2)


# ── GET all reports ────────────────────────────────────────────────
@reports_bp.route("/reports", methods=["GET"])
def get_reports():

    path = current_app.config["REPORTS_PATH"]
    reports = load_reports(path)

    return jsonify({
        "reports": reports,
        "count": len(reports)
    }), 200


# ── POST save a report ─────────────────────────────────────────────
@reports_bp.route("/reports", methods=["POST"])
def save_report():

    path = current_app.config["REPORTS_PATH"]
    data = request.get_json() or {}

    reports = load_reports(path)

    reports.insert(0, data)

    save_reports(path, reports)

    return jsonify({
        "message": "Report saved",
        "count": len(reports)
    }), 201


# ── DELETE a report by index ───────────────────────────────────────
@reports_bp.route("/reports/<int:index>", methods=["DELETE"])
def delete_report(index):

    path = current_app.config["REPORTS_PATH"]
    reports = load_reports(path)

    if index < 0 or index >= len(reports):
        return jsonify({"error": "Report not found"}), 404

    deleted = reports.pop(index)

    save_reports(path, reports)

    return jsonify({
        "message": "Report deleted",
        "deleted": deleted
    }), 200


# ── GET single report ──────────────────────────────────────────────
@reports_bp.route("/reports/<int:index>", methods=["GET"])
def get_report(index):

    path = current_app.config["REPORTS_PATH"]
    reports = load_reports(path)

    if index < 0 or index >= len(reports):
        return jsonify({"error": "Report not found"}), 404

    return jsonify(reports[index]), 200