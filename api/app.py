"""
AI Firewall Policy Intelligence System
api/app.py — Flask Backend Entry Point
"""

import sys
import os
import logging
from flask import Flask, jsonify
from flask_cors import CORS
from dotenv import load_dotenv

load_dotenv()

# ── Logging setup ─────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("AI-Firewall")

# ── Add project root to path ──────────────────────────────────────
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.append(BASE_DIR)

# ── Initialize Flask ──────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

logger.info("Loading AI Firewall modules...")

# ── Import AI modules ─────────────────────────────────────────────
from nlp.preprocessing       import TextPreprocessor
from nlp.intent_classifier   import IntentClassifier
from firewall.rule_generator import RuleGenerator

from firewall.conflict_detector    import ConflictDetector
from firewall.rule_ordering import RuleOrderingEngine
from firewall.rule_optimizer       import RuleOptimizer
from firewall.zero_trust_validator import ZeroTrustValidator

from risk.threat_intel import ThreatIntelligence
from risk.risk_scorer  import RiskScorer
from risk.risk_ml      import RiskMLScorer

from simulation.policy_simulator import PolicySimulator
from simulation.attack_surface   import AttackSurfaceCalculator
from simulation.self_healing     import SelfHealingEngine
from simulation.explainability   import ExplainabilityEngine

# ── Paths ─────────────────────────────────────────────────────────
DATA_DIR      = os.path.join(BASE_DIR, "data")
DATASET_PATH  = os.path.join(DATA_DIR, "unified_firewall_dataset.csv")
TOPOLOGY_PATH = os.path.join(DATA_DIR, "network_topology.json")
REPORTS_PATH  = os.path.join(DATA_DIR, "reports.json")

# Ensure data directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# ── Instantiate AI Engines ───────────────────────────────────────
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

simulator      = PolicySimulator(TOPOLOGY_PATH)
surface_engine = AttackSurfaceCalculator()
healer         = SelfHealingEngine()
explainer      = ExplainabilityEngine()

# ── Train ML Models ──────────────────────────────────────────────
logger.info("Training models...")

classifier.train(DATASET_PATH)
ml_scorer.train(DATASET_PATH)

logger.info("✅ All AI modules ready!")

# ── Shared state ─────────────────────────────────────────────────
existing_rules = []

# ── Store engines in app config ──────────────────────────────────
app.config["ENGINES"] = {
    "preprocessor": preprocessor,
    "classifier": classifier,
    "generator": generator,
    "detector": detector,
    "ordering": ordering,
    "optimizer": optimizer,
    "zero_trust": zero_trust,
    "threat_intel": threat_intel,
    "risk_scorer": risk_scorer,
    "ml_scorer": ml_scorer,
    "simulator": simulator,
    "surface_engine": surface_engine,
    "healer": healer,
    "explainer": explainer,
}

app.config["EXISTING_RULES"] = existing_rules
app.config["REPORTS_PATH"]   = REPORTS_PATH
app.config["DATA_DIR"]       = DATA_DIR

# ── Register API routes ──────────────────────────────────────────
from api.routes.analyze import analyze_bp
from api.routes.reports import reports_bp
from api.routes.threats import threats_bp

app.register_blueprint(analyze_bp)
app.register_blueprint(reports_bp)
app.register_blueprint(threats_bp)

# ── Global Health Check ──────────────────────────────────────────
@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "message": "AI Firewall Policy Intelligence API running",
        "modules": [
            "NLP Engine",
            "Firewall Rule Engine",
            "Conflict Detection",
            "Risk Scoring",
            "Threat Intelligence",
            "Attack Simulation",
            "Self-Healing",
            "Explainability"
        ]
    })

# ── Run server ───────────────────────────────────────────────────
if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=5000,
        debug=True
    )