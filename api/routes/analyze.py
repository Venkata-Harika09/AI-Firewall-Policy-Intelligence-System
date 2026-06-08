"""
AI Firewall Policy Intelligence System
api/routes/analyze.py — POST /api/analyze
"""

from flask import Blueprint, request, jsonify, current_app

# Blueprint with API prefix
analyze_bp = Blueprint("analyze", __name__, url_prefix="/api")


@analyze_bp.route("/analyze", methods=["POST"])
def analyze():
    try:
        # ── Get policy text from request ───────────────────────────
        data = request.get_json() or {}
        policy = data.get("policy", "").strip()

        if not policy:
            return jsonify({"error": "Policy text is required"}), 400

        # ── Get engines from app config ────────────────────────────
        E = current_app.config["ENGINES"]
        existing_rules = current_app.config["EXISTING_RULES"]

        # ── Stage 1: Preprocessing ─────────────────────────────────
        processed = E["preprocessor"].preprocess(policy)

        # ── Stage 2: Intent Classification ─────────────────────────
        clf_result = E["classifier"].predict(policy)
        intent = clf_result["prediction"]

        # ── Stage 3: Rule Generation ───────────────────────────────
        rule_output = E["generator"].generate(policy, intent)
        entities = rule_output.get("extracted_entities", {})

        rule_struct = {
            "policy_id": len(existing_rules) + 1,
            "policy_text": policy,
            "intent": intent,
            "protocol": entities.get("protocol"),
            "port": entities.get("port"),
            "source_ip": entities.get("source_ip", "any"),
            "destination_ip": entities.get("destination_ip", "any"),
            "direction": entities.get("direction", "incoming"),
            "priority": len(existing_rules) + 1,
            "is_malicious_ip": entities.get("is_malicious_ip", False),
            "asset_sensitivity": entities.get("asset_sensitivity", "medium"),
            "exposure_type": entities.get("exposure_type", "public"),
            "time_constraint": entities.get("time_constraint"),
        }

        # ── Stage 4: Conflict Detection ────────────────────────────
        conflicts = E["detector"].check_rule(rule_struct, existing_rules)

        # ── Stage 5: Rule Ordering ─────────────────────────────────
        ordering_info = E["ordering"].suggest_priority(rule_struct, existing_rules)

        # ── Stage 6: Rule Optimization ─────────────────────────────
        optimization = E["optimizer"].check_rule(rule_struct, existing_rules)

        # ── Stage 7: Zero Trust Validation ─────────────────────────
        zt_result = E["zero_trust"].validate_rule(rule_struct, existing_rules)

        # ── Stage 8: Threat Intelligence ───────────────────────────
        threat_result = E["threat_intel"].check(rule_struct)
        rule_struct["threat_match"] = threat_result.get("matched", False)

        # ── Stage 9: CVSS Risk Score ───────────────────────────────
        risk_result = E["risk_scorer"].score(rule_struct, threat_result)

        # ── Stage 10: ML Risk Prediction ───────────────────────────
        ml_result = E["ml_scorer"].predict(rule_struct)

        # ── Stage 11: Attack Simulation ────────────────────────────
        sim_result = E["simulator"].simulate_attack(rule_struct)

        # ── Stage 12: Attack Surface ───────────────────────────────
        surface_result = E["surface_engine"].score_rule(rule_struct, sim_result)

        # ── Stage 13: Self Healing ─────────────────────────────────
        healing_result = E["healer"].recommend(
            rule_struct,
            risk_result["risk_score"],
            threat_result
        )

        # ── Stage 14: Explainability ───────────────────────────────
        explanation = E["explainer"].explain(
            rule_struct,
            risk_result,
            threat_result,
            sim_result,
            healing_result
        )

        # ── Add to existing rules ──────────────────────────────────
        existing_rules.append(rule_struct)

        # ── Build response ─────────────────────────────────────────
        response = {

            # Rule
            "policy": policy,
            "iptables": rule_output.get("iptables_rule", ""),
            "intent": intent,
            "port": rule_struct["port"],
            "protocol": rule_struct["protocol"],
            "source_ip": rule_struct["source_ip"],

            # Risk
            "risk_score": risk_result["risk_score"],
            "risk_level": risk_result["risk_level"],
            "risk_vector": risk_result.get("risk_vector", ""),

            # ML Risk
            "ml_score": ml_result.get("risk_score", 0),
            "ml_level": ml_result.get("risk_level", "Unknown"),
            "ml_confidence": ml_result.get("confidence", 0),
            "ml_model": ml_result.get("model", "GradientBoosting"),

            # Conflicts
            "conflicts": conflicts.get("conflicts", []),
            "conflict_count": conflicts.get("conflict_count", 0),

            # Zero Trust
            "zero_trust_score": zt_result.get("new_score", 100),
            "zero_trust_level": zt_result.get("level", "GOOD"),
            "zero_trust_violations": zt_result.get("violations", []),

            # Threat Intelligence
            "threat_matched": threat_result.get("matched", False),
            "threat_alerts": threat_result.get("alerts", []),
            "alert_count": threat_result.get("alert_count", 0),

            # Simulation
            "sim_paths": sim_result.get("paths_found", 0),
            "sim_targets": len(sim_result.get("target_reached", [])),
            "sim_level": sim_result.get("simulation_level", "LOW"),
            "sim_lateral": len(sim_result.get("lateral_movement", [])),
            "sim_reachable": sim_result.get("reachable_nodes", []),
            "attack_paths": [
                t.get("path", [])
                for t in sim_result.get("target_reached", [])
            ],

            # Attack Surface
            "surface_score": surface_result.get("surface_score", 0),
            "surface_level": surface_result.get("level", "None"),

            # Self Healing
            "healing_count": healing_result.get("rec_count", 0),
            "healing_priority": healing_result.get("priority", "None"),
            "healing_summary": healing_result.get("summary", ""),
            "healings": healing_result.get("recommendations", []),
            "healed_rule": healing_result.get("healed_rule", {}),

            # Explainability
            "explanation": explanation.get("narrative", ""),
            "rule_explanation": explanation.get("rule", ""),
            "risk_explanation": explanation.get("risk", ""),
            "sim_explanation": explanation.get("simulation", ""),
            "heal_explanation": explanation.get("healing", ""),
            "confidence_score": explanation.get("confidence", 0.5),
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500