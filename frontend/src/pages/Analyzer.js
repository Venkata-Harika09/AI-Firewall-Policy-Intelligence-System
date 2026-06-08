// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Analyzer.js
// ================================================================

import React, { useState } from "react";
import StatCard, { MiniStat } from "../components/StatCard";
import RiskGauge              from "../components/RiskGauge";
import HealingCard            from "../components/HealingCard";
import PolicyInput            from "../components/PolicyInput";
import { AnalyzingLoader }    from "../components/Loader";
import { analyzePolicy, riskColor, riskBadgeClass, riskIcon, simColor } from "../services/api";

// ================================================================
// ANALYZER PAGE
// ================================================================
export default function Analyzer({ onAddReport }) {
  const [result,  setResult]  = useState(null);
  const [loading, setLoading] = useState(false);
  const [error,   setError]   = useState("");
  const [tab,     setTab]     = useState("overview");
  const [saved,   setSaved]   = useState(false);
  const [policy,  setPolicy]  = useState("");

  const TABS = ["overview", "simulation", "healing", "explain"];

  // ── Analyze ────────────────────────────────────────────────
  const handleAnalyze = async (policyText) => {
    if (!policyText.trim()) return;
    setPolicy(policyText);
    setLoading(true);
    setError("");
    setSaved(false);
    setTab("overview");
    try {
      const data = await analyzePolicy(policyText);
      setResult(data);
    } catch (err) {
      setError(
        err.response?.data?.error ||
        "Failed to connect to Flask backend. Make sure python api/app.py is running."
      );
    } finally {
      setLoading(false);
    }
  };

  // ── Save report ────────────────────────────────────────────
  const handleSave = () => {
    if (!result || saved) return;
    onAddReport({ ...result, policy, createdAt: new Date().toLocaleString() });
    setSaved(true);
  };

  return (
    <div
      style={{
        display:  "flex",
        height:   "100%",
        overflow: "hidden",
      }}
    >
      {/* ── Left panel ───────────────────────────────────── */}
      <div
        className="glass"
        style={{
          width:         290,
          flexShrink:    0,
          display:       "flex",
          flexDirection: "column",
          borderRight:   "1px solid #142240",
          overflow:      "hidden",
        }}
      >
        {/* Policy input */}
        <div
          style={{
            padding:      16,
            borderBottom: "1px solid #142240",
          }}
        >
          <PolicyInput
            onAnalyze={handleAnalyze}
            loading={loading}
          />
        </div>

        {/* Generated rule */}
        {result && (
          <div
            style={{
              padding:      14,
              borderBottom: "1px solid #142240",
            }}
          >
            <div className="section-label">GENERATED RULE</div>
            <div
              style={{
                background:   "#020810",
                borderRadius: 8,
                padding:      "10px 12px",
                fontFamily:   "'JetBrains Mono', monospace",
                fontSize:     10,
                color:        "#00D4FF",
                lineHeight:   1.7,
                wordBreak:    "break-all",
                border:       "1px solid #142240",
                marginBottom: 10,
              }}
            >
              {result.iptables || "—"}
            </div>

            {/* Intent + Port */}
            <div
              style={{
                display: "flex",
                gap:     8,
                marginBottom: 10,
              }}
            >
              <span
                style={{
                  fontSize:   9,
                  padding:    "2px 8px",
                  borderRadius: 4,
                  fontFamily: "'JetBrains Mono', monospace",
                  fontWeight: 700,
                  background: result.intent === "allow"
                    ? "rgba(255,136,0,0.12)"
                    : "rgba(0,230,118,0.12)",
                  border: `1px solid ${result.intent === "allow" ? "rgba(255,136,0,0.3)" : "rgba(0,230,118,0.3)"}`,
                  color: result.intent === "allow" ? "#FF8800" : "#00E676",
                }}
              >
                {result.intent?.toUpperCase()}
              </span>
              {result.port && (
                <span
                  style={{
                    fontSize:   9,
                    padding:    "2px 8px",
                    borderRadius: 4,
                    fontFamily: "'JetBrains Mono', monospace",
                    background: "rgba(0,212,255,0.08)",
                    border:     "1px solid rgba(0,212,255,0.2)",
                    color:      "#00D4FF",
                  }}
                >
                  PORT {result.port}
                </span>
              )}
            </div>

            {/* Save button */}
            <button
              onClick={handleSave}
              disabled={saved}
              style={{
                width:        "100%",
                padding:      "8px",
                borderRadius: 8,
                background:   saved
                  ? "rgba(0,230,118,0.08)"
                  : "rgba(0,212,255,0.06)",
                border:       `1px solid ${saved ? "rgba(0,230,118,0.3)" : "#142240"}`,
                color:        saved ? "#00E676" : "#3A5070",
                fontFamily:   "'JetBrains Mono', monospace",
                fontSize:     10,
                fontWeight:   700,
                letterSpacing: 1.5,
                cursor:       saved ? "default" : "pointer",
                transition:   "all 0.2s",
              }}
            >
              {saved ? "✓ SAVED TO REPORTS" : "+ SAVE TO REPORTS"}
            </button>
          </div>
        )}

        {/* Error */}
        {error && (
          <div
            style={{
              margin:       14,
              padding:      "10px 12px",
              borderRadius: 8,
              background:   "rgba(255,45,85,0.08)",
              border:       "1px solid rgba(255,45,85,0.25)",
              fontSize:     10,
              color:        "#FF2D55",
              fontFamily:   "'JetBrains Mono', monospace",
              lineHeight:   1.6,
            }}
          >
            ⚠ {error}
          </div>
        )}
      </div>

      {/* ── Right panel ──────────────────────────────────── */}
      <div
        style={{
          flex:      1,
          display:   "flex",
          flexDirection: "column",
          overflow:  "hidden",
        }}
      >
        {/* Loading state */}
        {loading && (
          <div style={{ flex: 1 }}>
            <AnalyzingLoader />
          </div>
        )}

        {/* Empty state */}
        {!loading && !result && (
          <div
            style={{
              flex:           1,
              display:        "flex",
              flexDirection:  "column",
              alignItems:     "center",
              justifyContent: "center",
              gap:            16,
              opacity:        0.5,
            }}
          >
            <div style={{ fontSize: 48 }}>🛡️</div>
            <div
              style={{
                fontFamily:    "'Orbitron', monospace",
                fontSize:      16,
                color:         "#00D4FF",
                letterSpacing: 4,
              }}
            >
              AI FIREWALL
            </div>
            <div
              style={{
                fontSize:      11,
                color:         "#3A5070",
                letterSpacing: 2,
                textAlign:     "center",
                fontFamily:    "'JetBrains Mono', monospace",
                lineHeight:    2,
              }}
            >
              ENTER A POLICY TO BEGIN ANALYSIS
              <br />
              M1 → M2 → M3 → M4
            </div>
          </div>
        )}

        {/* Results */}
        {!loading && result && (
          <div
            style={{
              flex:      1,
              display:   "flex",
              flexDirection: "column",
              overflow:  "hidden",
              padding:   "16px 20px",
            }}
          >
            {/* Rule bar */}
            <div
              className="glass scanline-wrap"
              style={{
                borderRadius:  10,
                padding:       "10px 16px",
                marginBottom:  14,
                display:       "flex",
                alignItems:    "center",
                gap:           12,
                flexShrink:    0,
              }}
            >
              <div
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize:   11,
                  color:      "#00D4FF",
                  flex:       1,
                  overflow:   "hidden",
                  textOverflow: "ellipsis",
                  whiteSpace: "nowrap",
                }}
              >
                {result.iptables}
              </div>
              <span
                className={riskBadgeClass(result.risk_level)}
                style={{ whiteSpace: "nowrap" }}
              >
                {riskIcon(result.risk_level)} {result.risk_level?.toUpperCase()}
              </span>
            </div>

            {/* Tabs */}
            <div
              style={{
                display:      "flex",
                borderBottom: "1px solid #142240",
                marginBottom: 16,
                flexShrink:   0,
              }}
            >
              {TABS.map((t) => (
                <button
                  key={t}
                  className={`tab-btn ${tab === t ? "tab-active" : ""}`}
                  onClick={() => setTab(t)}
                >
                  {t.toUpperCase()}
                </button>
              ))}
            </div>

            {/* Tab content */}
            <div style={{ flex: 1, overflowY: "auto" }}>

              {/* ── OVERVIEW ── */}
              {tab === "overview" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

                  {/* Score cards */}
                  <div
                    style={{
                      display:             "grid",
                      gridTemplateColumns: "repeat(4, 1fr)",
                      gap:                 10,
                    }}
                  >
                    <StatCard
                      label="CVSS RISK"
                      value={result.risk_score}
                      sub={result.risk_level}
                      color={riskColor(result.risk_level)}
                      delay={0}
                    />
                    <StatCard
                      label="ML SCORE"
                      value={result.ml_score || 0}
                      sub={`${result.ml_confidence || 0}% conf`}
                      color={riskColor(result.ml_level)}
                      delay={60}
                    />
                    <StatCard
                      label="SURFACE"
                      value={result.surface_score}
                      sub={result.surface_level}
                      color={riskColor(result.surface_level)}
                      delay={120}
                    />
                    <StatCard
                      label="ZERO TRUST"
                      value={result.zero_trust_score || 100}
                      sub={result.zero_trust_level}
                      color="#00D4FF"
                      delay={180}
                    />
                  </div>

                  {/* Gauge + Threats + Zero Trust */}
                  <div
                    style={{
                      display:             "grid",
                      gridTemplateColumns: "200px 1fr 1fr",
                      gap:                 12,
                    }}
                  >
                    {/* Gauge */}
                    <div
                      className="glass"
                      style={{
                        borderRadius: 12,
                        padding:      16,
                        display:      "flex",
                        alignItems:   "center",
                        justifyContent: "center",
                      }}
                    >
                      <RiskGauge
                        score={result.risk_score}
                        level={result.risk_level}
                        size={170}
                      />
                    </div>

                    {/* Threat alerts */}
                    <div
                      className="glass"
                      style={{ borderRadius: 12, padding: 16 }}
                    >
                      <div className="section-label">THREAT INTELLIGENCE</div>
                      {!result.threat_alerts?.length ? (
                        <div
                          style={{
                            color:      "#00E676",
                            fontSize:   11,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          ✓ No threats detected
                        </div>
                      ) : (
                        result.threat_alerts.map((t, i) => (
                          <div
                            key={i}
                            style={{
                              display:      "flex",
                              gap:          10,
                              marginBottom: 10,
                              paddingBottom: 10,
                              borderBottom: i < result.threat_alerts.length - 1
                                ? "1px solid #142240"
                                : "none",
                            }}
                          >
                            <span
                              className={riskBadgeClass(
                                t.severity === "CRITICAL" ? "Critical" :
                                t.severity === "HIGH"     ? "High"     : "Medium"
                              )}
                              style={{ height: "fit-content", flexShrink: 0 }}
                            >
                              {t.severity}
                            </span>
                            <span
                              style={{
                                fontSize:   10,
                                color:      "#B8D0EE",
                                lineHeight: 1.6,
                                fontFamily: "'JetBrains Mono', monospace",
                              }}
                            >
                              {t.description || t.desc || t.type}
                            </span>
                          </div>
                        ))
                      )}
                    </div>

                    {/* Zero Trust */}
                    <div
                      className="glass"
                      style={{ borderRadius: 12, padding: 16 }}
                    >
                      <div className="section-label">ZERO TRUST</div>

                      {/* Score bars */}
                      <div
                        style={{
                          display:      "flex",
                          gap:          12,
                          marginBottom: 14,
                        }}
                      >
                        {[
                          { label: "BASE",  val: 100 },
                          { label: "AFTER", val: result.zero_trust_score || 100 },
                        ].map(({ label, val }) => (
                          <div key={label} style={{ flex: 1 }}>
                            <div
                              style={{
                                fontSize:   8,
                                color:      "#3A5070",
                                fontFamily: "'JetBrains Mono', monospace",
                                letterSpacing: 1.5,
                                marginBottom: 4,
                              }}
                            >
                              {label}
                            </div>
                            <div
                              style={{
                                fontFamily: "'Orbitron', monospace",
                                fontSize:   20,
                                fontWeight: 900,
                                color:      "#00D4FF",
                                marginBottom: 4,
                              }}
                            >
                              {val}
                            </div>
                            <div className="progress-track">
                              <div
                                className="progress-fill"
                                style={{
                                  width:      `${val}%`,
                                  background: "linear-gradient(90deg,#00D4FF,#00A8CC)",
                                }}
                              />
                            </div>
                          </div>
                        ))}
                      </div>

                      {/* Violations */}
                      {result.zero_trust_violations?.map((v, i) => (
                        <div
                          key={i}
                          style={{
                            fontSize:     10,
                            color:        riskColor(
                              v.severity === "CRITICAL" ? "Critical" : "High"
                            ),
                            borderLeft:   `3px solid ${riskColor(
                              v.severity === "CRITICAL" ? "Critical" : "High"
                            )}`,
                            paddingLeft:  8,
                            marginTop:    6,
                            lineHeight:   1.6,
                            fontFamily:   "'JetBrains Mono', monospace",
                          }}
                        >
                          {v.description || v.desc}
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Risk vector */}
                  <div
                    className="glass"
                    style={{ borderRadius: 10, padding: "12px 16px" }}
                  >
                    <div className="section-label">RISK VECTOR</div>
                    <div
                      style={{
                        fontFamily: "'JetBrains Mono', monospace",
                        fontSize:   11,
                        color:      "#00D4FF",
                        letterSpacing: 1,
                        wordBreak:  "break-all",
                      }}
                    >
                      {result.risk_vector || "—"}
                    </div>
                  </div>
                </div>
              )}

              {/* ── SIMULATION ── */}
              {tab === "simulation" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>
                  <div
                    style={{
                      display:             "grid",
                      gridTemplateColumns: "repeat(4, 1fr)",
                      gap:                 10,
                    }}
                  >
                    <StatCard
                      label="PATHS FOUND"
                      value={result.sim_paths}
                      color={result.sim_paths > 100 ? "#FF2D55" : "#FFD000"}
                      decimals={0}
                      delay={0}
                    />
                    <StatCard
                      label="TARGETS HIT"
                      value={result.sim_targets}
                      color={result.sim_targets > 0 ? "#FF2D55" : "#00E676"}
                      decimals={0}
                      delay={60}
                    />
                    <StatCard
                      label="LATERAL MOVES"
                      value={result.sim_lateral}
                      color={result.sim_lateral > 2 ? "#FF8800" : "#FFD000"}
                      decimals={0}
                      delay={120}
                    />
                    <StatCard
                      label="SIM LEVEL"
                      value={result.sim_level}
                      color={simColor(result.sim_level)}
                      decimals={0}
                      delay={180}
                    />
                  </div>

                  {/* Sim explanation */}
                  <div
                    className="glass"
                    style={{ borderRadius: 10, padding: "12px 16px" }}
                  >
                    <div className="section-label">SIMULATION RESULT</div>
                    <div
                      style={{
                        fontSize:   12,
                        color:      "#B8D0EE",
                        lineHeight: 1.8,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {result.sim_explanation || "No simulation data."}
                    </div>
                  </div>

                  {/* Attack paths */}
                  {result.attack_paths?.length > 0 && (
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">ATTACK PATHS</div>
                      <div
                        style={{
                          display:   "flex",
                          flexWrap:  "wrap",
                          gap:       8,
                        }}
                      >
                        {result.attack_paths.slice(0, 6).map((path, i) => (
                          <div
                            key={i}
                            style={{
                              background:   "rgba(255,45,85,0.06)",
                              border:       "1px solid rgba(255,45,85,0.2)",
                              borderRadius: 8,
                              padding:      "8px 12px",
                              fontSize:     10,
                              fontFamily:   "'JetBrains Mono', monospace",
                              animation:    `fadeUp 0.3s ease ${i * 50}ms both`,
                            }}
                          >
                            <span style={{ color: "#3A5070", marginRight: 8 }}>
                              PATH {i + 1}
                            </span>
                            {path.map((node, j) => (
                              <span key={j}>
                                <span
                                  style={{
                                    color: ["admin","database"].includes(node)
                                      ? "#FF2D55"
                                      : "#00D4FF",
                                    fontWeight: ["admin","database"].includes(node)
                                      ? 700 : 400,
                                  }}
                                >
                                  {node.toUpperCase()}
                                </span>
                                {j < path.length - 1 && (
                                  <span style={{ color: "#FF2D55", margin: "0 4px" }}>
                                    →
                                  </span>
                                )}
                              </span>
                            ))}
                            <span style={{ color: "#3A5070", marginLeft: 8 }}>
                              {path.length - 1} hops
                            </span>
                          </div>
                        ))}
                        {result.attack_paths.length > 6 && (
                          <div
                            style={{
                              fontSize:   10,
                              color:      "#3A5070",
                              fontFamily: "'JetBrains Mono', monospace",
                              padding:    "8px 12px",
                              alignSelf:  "center",
                            }}
                          >
                            +{result.attack_paths.length - 6} more paths...
                          </div>
                        )}
                      </div>
                    </div>
                  )}

                  {/* Reachable nodes */}
                  {result.sim_reachable?.length > 0 && (
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">REACHABLE ZONES</div>
                      <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                        {result.sim_reachable.map((node) => (
                          <span
                            key={node}
                            style={{
                              fontSize:     9,
                              padding:      "3px 10px",
                              borderRadius: 4,
                              fontFamily:   "'JetBrains Mono', monospace",
                              fontWeight:   700,
                              background:   ["admin","database"].includes(node)
                                ? "rgba(255,45,85,0.12)"
                                : "rgba(0,212,255,0.08)",
                              border: `1px solid ${
                                ["admin","database"].includes(node)
                                  ? "rgba(255,45,85,0.3)"
                                  : "rgba(0,212,255,0.2)"
                              }`,
                              color: ["admin","database"].includes(node)
                                ? "#FF2D55"
                                : "#00D4FF",
                            }}
                          >
                            {node.toUpperCase()}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}

              {/* ── HEALING ── */}
              {tab === "healing" && (
                <div>
                  {/* Summary */}
                  <div
                    className="glass"
                    style={{
                      borderRadius: 10,
                      padding:      "12px 16px",
                      marginBottom: 14,
                      display:      "flex",
                      alignItems:   "center",
                      gap:          12,
                    }}
                  >
                    <span style={{ fontSize: 24 }}>🔧</span>
                    <div>
                      <div
                        style={{
                          fontSize:   12,
                          color:      "#E8F4FF",
                          fontWeight: 700,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {result.healing_count} Recommendation(s) — Priority:{" "}
                        <span
                          style={{
                            color: riskColor(
                              result.healing_priority === "CRITICAL" ? "Critical" :
                              result.healing_priority === "HIGH"     ? "High"     : "Medium"
                            ),
                          }}
                        >
                          {result.healing_priority}
                        </span>
                      </div>
                      <div
                        style={{
                          fontSize:   9,
                          color:      "#3A5070",
                          marginTop:  4,
                          fontFamily: "'JetBrains Mono', monospace",
                          letterSpacing: 1.5,
                        }}
                      >
                        AUTO-GENERATED REMEDIATION ACTIONS
                      </div>
                    </div>
                  </div>

                  {/* Healing cards */}
                  {result.healings?.length === 0 ? (
                    <div
                      className="glass"
                      style={{
                        borderRadius: 10,
                        padding:      24,
                        textAlign:    "center",
                      }}
                    >
                      <div style={{ fontSize: 24, marginBottom: 8 }}>✅</div>
                      <div
                        style={{
                          color:      "#00E676",
                          fontSize:   12,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        No healing required — rule is safe
                      </div>
                    </div>
                  ) : (
                    result.healings?.map((h, i) => (
                      <HealingCard key={i} healing={h} index={i} />
                    ))
                  )}
                </div>
              )}

              {/* ── EXPLAIN ── */}
              {tab === "explain" && (
                <div style={{ display: "flex", flexDirection: "column", gap: 14 }}>

                  {/* Narrative */}
                  <div
                    className="glass"
                    style={{
                      borderRadius: 10,
                      padding:      18,
                      borderLeft:   "4px solid #00D4FF",
                    }}
                  >
                    <div className="section-label">📖 FULL NARRATIVE</div>
                    <div
                      style={{
                        fontSize:   12,
                        color:      "#B8D0EE",
                        lineHeight: 2,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {result.explanation || "—"}
                    </div>
                  </div>

                  {/* Rule + Risk explanations */}
                  <div
                    style={{
                      display:             "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap:                 12,
                    }}
                  >
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">RULE EXPLANATION</div>
                      <div
                        style={{
                          fontSize:   11,
                          color:      "#B8D0EE",
                          lineHeight: 1.8,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {result.rule_explanation || "—"}
                      </div>
                    </div>
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">RISK EXPLANATION</div>
                      <div
                        style={{
                          fontSize:   11,
                          color:      "#B8D0EE",
                          lineHeight: 1.8,
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        {result.risk_explanation || "—"}
                      </div>
                    </div>
                  </div>

                  {/* Confidence + ML */}
                  <div
                    style={{
                      display:             "grid",
                      gridTemplateColumns: "1fr 1fr",
                      gap:                 12,
                    }}
                  >
                    {/* Confidence */}
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">CONFIDENCE SCORE</div>
                      <div
                        style={{
                          fontFamily:  "'Orbitron', monospace",
                          fontSize:    36,
                          fontWeight:  900,
                          color:       "#00D4FF",
                          textShadow:  "0 0 20px rgba(0,212,255,0.5)",
                          marginBottom: 10,
                        }}
                      >
                        {((result.confidence_score || 0) * 100).toFixed(0)}%
                      </div>
                      <div className="progress-track">
                        <div
                          className="progress-fill"
                          style={{
                            width:      `${(result.confidence_score || 0) * 100}%`,
                            background: "linear-gradient(90deg,#00D4FF,#00A8CC)",
                          }}
                        />
                      </div>
                      <div
                        style={{
                          fontSize:      9,
                          color:         "#3A5070",
                          marginTop:     8,
                          fontFamily:    "'JetBrains Mono', monospace",
                          letterSpacing: 1,
                        }}
                      >
                        {result.confidence_score >= 1
                          ? "All analysis modules active"
                          : result.confidence_score >= 0.85
                          ? "High confidence"
                          : "Moderate confidence"}
                      </div>
                    </div>

                    {/* ML info */}
                    <div
                      className="glass"
                      style={{ borderRadius: 10, padding: 16 }}
                    >
                      <div className="section-label">ML MODEL INFO</div>
                      {[
                        { label: "MODEL",      value: result.ml_model    },
                        { label: "ML SCORE",   value: `${result.ml_score || 0}/10` },
                        { label: "CONFIDENCE", value: `${result.ml_confidence || 0}%` },
                        { label: "INTENT",     value: result.intent?.toUpperCase() },
                      ].map(({ label, value }) => (
                        <div
                          key={label}
                          style={{
                            display:       "flex",
                            justifyContent: "space-between",
                            padding:       "7px 0",
                            borderBottom:  "1px solid #142240",
                          }}
                        >
                          <span
                            style={{
                              fontSize:   9,
                              color:      "#3A5070",
                              fontFamily: "'JetBrains Mono', monospace",
                              letterSpacing: 1.5,
                            }}
                          >
                            {label}
                          </span>
                          <span
                            style={{
                              fontSize:   11,
                              color:      "#00D4FF",
                              fontFamily: "'JetBrains Mono', monospace",
                              fontWeight: 600,
                            }}
                          >
                            {value || "—"}
                          </span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}