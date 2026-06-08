"""
AI Firewall Policy Intelligence System
core/main.py

Milestone 1  → NLP + Intent + Rule Generation
Milestone 2  → Conflict Detection + Optimization + Zero Trust
Milestone 3  → Threat Intelligence + CVSS Risk + ML Risk Prediction
Milestone 4  → Attack Simulation + Attack Surface + Self Healing + Explainability
"""

import sys
import os

# ───────────────────────────────────────────────
# Add project root directory to path
# ───────────────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

DATA_DIR = os.path.join(BASE_DIR, "data")

# ───────────────────────────────────────────────
# Milestone 1 Modules
# ───────────────────────────────────────────────
from nlp.preprocessing import TextPreprocessor
from nlp.intent_classifier import IntentClassifier
from firewall.rule_generator import RuleGenerator

# ───────────────────────────────────────────────
# Milestone 2 Modules
# ───────────────────────────────────────────────
from firewall.conflict_detector import ConflictDetector
from firewall.rule_ordering import RuleOrderingEngine
from firewall.rule_optimizer import RuleOptimizer
from firewall.zero_trust_validator import ZeroTrustValidator

# ───────────────────────────────────────────────
# Milestone 3 Modules
# ───────────────────────────────────────────────
from risk.threat_intel import ThreatIntelligence
from risk.risk_scorer import RiskScorer
from risk.risk_ml import RiskMLScorer

# ───────────────────────────────────────────────
# Milestone 4 Modules
# ───────────────────────────────────────────────
from simulation.policy_simulator import PolicySimulator
from simulation.attack_surface import AttackSurfaceCalculator
from simulation.self_healing import SelfHealingEngine
from simulation.explainability import ExplainabilityEngine


if __name__ == "__main__":

    # ───────────────────────────────────────────
    # Initialize Engines
    # ───────────────────────────────────────────
    preprocessor = TextPreprocessor()
    classifier   = IntentClassifier()
    generator    = RuleGenerator()

    detector   = ConflictDetector()
    ordering   = RuleOrderingEngine()
    optimizer  = RuleOptimizer()
    zero_trust = ZeroTrustValidator()

    threat_intel = ThreatIntelligence()
    risk_scorer  = RiskScorer()
    ml_scorer    = RiskMLScorer()

    # Milestone 4 Engines
    simulator      = PolicySimulator(os.path.join(DATA_DIR,"network_topology.json"))
    surface_engine = AttackSurfaceCalculator()
    healer         = SelfHealingEngine()
    explainer      = ExplainabilityEngine()

    existing_rules = []

    # ───────────────────────────────────────────
    # Dataset Path
    # ───────────────────────────────────────────
    FIREWALL_DATASET = os.path.join(DATA_DIR, "unified_firewall_dataset.csv")

    print("Training models...\n")

    classifier.train(FIREWALL_DATASET)
    ml_scorer.train(FIREWALL_DATASET)

    print("\n🛡 AI FIREWALL POLICY ENGINE READY")
    print("=" * 65)

    # ───────────────────────────────────────────
    # Interactive Loop
    # ───────────────────────────────────────────
    while True:

        policy = input("\nEnter firewall policy (or type 'exit'): ").strip()

        if policy.lower() == "exit":
            print("Exiting AI Firewall Engine...")
            break

        if not policy:
            continue

        # ─────────────────────────────────────
        # 1️⃣ NLP Preprocessing
        # ─────────────────────────────────────
        processed = preprocessor.preprocess(policy)

        # ─────────────────────────────────────
        # 2️⃣ Intent Classification
        # ─────────────────────────────────────
        clf_result = classifier.predict(policy)
        intent = clf_result["prediction"]

        # ─────────────────────────────────────
        # 3️⃣ Firewall Rule Generation
        # ─────────────────────────────────────
        rule_output = generator.generate(policy, intent)
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

        # ─────────────────────────────────────
        # 4️⃣ Conflict Detection
        # ─────────────────────────────────────
        conflicts = detector.check_rule(rule_struct, existing_rules)

        # ─────────────────────────────────────
        # 5️⃣ Rule Ordering
        # ─────────────────────────────────────
        ordering_info = ordering.suggest_priority(rule_struct, existing_rules)

        # ─────────────────────────────────────
        # 6️⃣ Rule Optimization
        # ─────────────────────────────────────
        optimization = optimizer.check_rule(rule_struct, existing_rules)

        # ─────────────────────────────────────
        # 7️⃣ Zero Trust Validation
        # ─────────────────────────────────────
        zt_result = zero_trust.validate_rule(rule_struct, existing_rules)

        # ─────────────────────────────────────
        # 8️⃣ Threat Intelligence
        # ─────────────────────────────────────
        threat_result = threat_intel.check(rule_struct)
        rule_struct["threat_match"] = threat_result.get("matched", False)

        # ─────────────────────────────────────
        # 9️⃣ CVSS Risk Score
        # ─────────────────────────────────────
        risk_result = risk_scorer.score(rule_struct, threat_result)

        # ─────────────────────────────────────
        # 🔟 ML Risk Prediction
        # ─────────────────────────────────────
        ml_result = ml_scorer.predict(rule_struct)

        # ─────────────────────────────────────
        # 1️⃣1️⃣ Attack Simulation
        # ─────────────────────────────────────
        sim_result = simulator.simulate_attack(rule_struct)

        # ─────────────────────────────────────
        # 1️⃣2️⃣ Attack Surface Calculation
        # ─────────────────────────────────────
        surface_result = surface_engine.score_rule(rule_struct, sim_result)

        # ─────────────────────────────────────
        # 1️⃣3️⃣ Self-Healing Engine
        # ─────────────────────────────────────
        healing_result = healer.recommend(
            rule_struct,
            risk_result["risk_score"],
            threat_result
        )

        # ─────────────────────────────────────
        # 1️⃣4️⃣ Explainability Engine
        # ─────────────────────────────────────
        explanation = explainer.explain(
            rule_struct,
            risk_result,
            threat_result,
            sim_result,
            healing_result
        )

        existing_rules.append(rule_struct)

        # ─────────────────────────────────────
        # PRINT RESULTS
        # ─────────────────────────────────────

        print("\n" + "=" * 65)
        print("FIREWALL POLICY ANALYSIS RESULT")
        print("=" * 65)

        print("\n--- Generated Firewall Rule ---")
        print(rule_output.get("iptables_rule"))

        print("\n--- CVSS Risk Score ---")
        print("Risk Score :", risk_result["risk_score"])
        print("Risk Level :", risk_result["risk_level"])

        print("\n--- Attack Simulation ---")
        print("Paths Found :", sim_result["paths_found"])
        print("Targets Reached :", len(sim_result.get("target_reached", [])))
        print("Simulation Level :", sim_result.get("simulation_level"))

        print("\n--- Attack Surface ---")
        print("Surface Score :", surface_result["surface_score"])
        print("Surface Level :", surface_result["level"])

        print("\n--- Self Healing ---")
        print(healing_result["summary"])

        print("\n--- Explainability ---")
        print("Rule Explanation :", explanation["rule"])
        print("Risk Explanation :", explanation["risk"])
        print("Narrative        :", explanation["narrative"])
        print("Confidence       :", explanation["confidence"])

        print("\n" + "=" * 65)