// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/AttackGraph.js
// ================================================================

import React, { useState, useEffect, useRef } from "react";
import NetworkGraph        from "../components/NetworkGraph";
import { AnalyzingLoader } from "../components/Loader";
import {
  analyzePolicy,
  riskColor,
  riskBadgeClass,
  riskIcon,
  simColor,
} from "../services/api";

// ================================================================
// SCENARIOS
// ================================================================
const SCENARIOS = [
  {
    key:    "ssh",
    label:  "Allow SSH from any",
    policy: "Allow SSH from any",
    icon:   "🔴",
  },
  {
    key:    "https",
    label:  "Allow HTTPS from any",
    policy: "Allow HTTPS from any",
    icon:   "🟠",
  },
  {
    key:    "rdp",
    label:  "Deny RDP from internet",
    policy: "Deny RDP from internet",
    icon:   "🟢",
  },
  {
    key:    "mongodb",
    label:  "Allow MongoDB from any",
    policy: "Allow MongoDB from any",
    icon:   "🟠",
  },
  {
    key:    "all",
    label:  "Allow all traffic",
    policy: "Allow all traffic",
    icon:   "🔴",
  },
];

// ================================================================
// ATTACK GRAPH PAGE
// ================================================================
export default function AttackGraph() {
  const [activeKey,  setActiveKey]  = useState(null);
  const [result,     setResult]     = useState(null);
  const [loading,    setLoading]    = useState(false);
  const [error,      setError]      = useState("");
  const [healed,     setHealed]     = useState(false);
  const [animated,   setAnimated]   = useState(true);
  const [customPolicy, setCustomPolicy] = useState("");

  // ── Load scenario ──────────────────────────────────────────
  const loadScenario = async (policy, key = null) => {
    if (!policy.trim()) return;
    setLoading(true);
    setError("");
    setHealed(false);
    setActiveKey(key);
    try {
      const data = await analyzePolicy(policy);
      setResult(data);
    } catch (err) {
      setError(
        err.response?.data?.error ||
        "Failed to connect to Flask backend."
      );
    } finally {
      setLoading(false);
    }
  };

  return (
    <div
      style={{
        display:       "flex",
        height:        "100%",
        overflow:      "hidden",
        gap:           0,
      }}
    >

      {/* ── Left controls panel ──────────────────────────── */}
      <div
        className="glass"
        style={{
          width:         260,
          flexShrink:    0,
          display:       "flex",
          flexDirection: "column",
          borderRight:   "1px solid #142240",
          overflow:      "hidden",
        }}
      >
        {/* Header */}
        <div
          style={{
            padding:      "16px 14px",
            borderBottom: "1px solid #142240",
          }}
        >
          <div
            style={{
              fontFamily:    "'Orbitron', monospace",
              fontSize:      11,
              fontWeight:    900,
              color:         "#00D4FF",
              letterSpacing: 3,
              marginBottom:  4,
            }}
          >
            ⚡ ATTACK GRAPH
          </div>
          <div
            style={{
              fontSize:      8,
              color:         "#3A5070",
              fontFamily:    "'JetBrains Mono', monospace",
              letterSpacing: 2,
            }}
          >
            BFS NETWORK SIMULATION
          </div>
        </div>

        {/* Scenarios */}
        <div
          style={{
            padding:      "12px 10px",
            borderBottom: "1px solid #142240",
          }}
        >
          <div className="section-label">SCENARIOS</div>
          <div
            style={{
              display:       "flex",
              flexDirection: "column",
              gap:           4,
            }}
          >
            {SCENARIOS.map((s) => (
              <button
                key={s.key}
                onClick={() => loadScenario(s.policy, s.key)}
                disabled={loading}
                style={{
                  display:       "flex",
                  alignItems:    "center",
                  gap:           8,
                  padding:       "9px 12px",
                  borderRadius:  8,
                  border:        `1px solid ${
                    activeKey === s.key
                      ? "rgba(0,212,255,0.4)"
                      : "#142240"
                  }`,
                  background:    activeKey === s.key
                    ? "rgba(0,212,255,0.08)"
                    : "transparent",
                  color:         activeKey === s.key
                    ? "#00D4FF"
                    : "#3A5070",
                  fontSize:      10,
                  fontFamily:    "'JetBrains Mono', monospace",
                  cursor:        loading ? "not-allowed" : "pointer",
                  transition:    "all 0.2s",
                  textAlign:     "left",
                  width:         "100%",
                }}
              >
                <span style={{ fontSize: 12, flexShrink: 0 }}>{s.icon}</span>
                <span>{s.label}</span>
              </button>
            ))}
          </div>
        </div>

        {/* Custom policy */}
        <div
          style={{
            padding:      "12px 10px",
            borderBottom: "1px solid #142240",
          }}
        >
          <div className="section-label">CUSTOM POLICY</div>
          <textarea
            className="fw-input"
            value={customPolicy}
            onChange={(e) => setCustomPolicy(e.target.value)}
            onKeyDown={(e) => {
              if (e.key === "Enter" && !e.shiftKey) {
                e.preventDefault();
                loadScenario(customPolicy);
              }
            }}
            placeholder={"Allow SSH from any\nDeny RDP from internet"}
            rows={3}
            style={{ marginBottom: 8 }}
          />
          <button
            className="btn-primary"
            onClick={() => loadScenario(customPolicy)}
            disabled={loading || !customPolicy.trim()}
          >
            {loading ? "SIMULATING..." : "▶ RUN SIMULATION"}
          </button>
        </div>

        {/* Controls */}
        <div style={{ padding: "12px 10px" }}>
          <div className="section-label">CONTROLS</div>

          {/* Before / After */}
          {result && (
            <div style={{ marginBottom: 10 }}>
              <div
                style={{
                  fontSize:      8,
                  color:         "#3A5070",
                  fontFamily:    "'JetBrains Mono', monospace",
                  letterSpacing: 1.5,
                  marginBottom:  6,
                }}
              >
                VIEW MODE
              </div>
              <div
                style={{
                  display:      "flex",
                  background:   "#0B1628",
                  border:       "1px solid #142240",
                  borderRadius: 8,
                  overflow:     "hidden",
                }}
              >
                {[
                  { label: "BEFORE", active: !healed, color: "#FF2D55" },
                  { label: "AFTER",  active:  healed, color: "#00E676" },
                ].map(({ label, active, color }) => (
                  <button
                    key={label}
                    onClick={() => setHealed(label === "AFTER")}
                    style={{
                      flex:          1,
                      padding:       "8px 0",
                      background:    active ? `${color}15` : "transparent",
                      border:        "none",
                      color:         active ? color : "#3A5070",
                      fontSize:      10,
                      fontFamily:    "'JetBrains Mono', monospace",
                      fontWeight:    700,
                      letterSpacing: 2,
                      cursor:        "pointer",
                      transition:    "all 0.2s",
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Animation toggle */}
          <div
            style={{
              display:        "flex",
              alignItems:     "center",
              justifyContent: "space-between",
              marginBottom:   10,
            }}
          >
            <span
              style={{
                fontSize:   10,
                color:      "#3A5070",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              ANIMATION
            </span>
            <button
              onClick={() => setAnimated((a) => !a)}
              style={{
                padding:      "4px 12px",
                borderRadius: 6,
                border:       `1px solid ${animated ? "rgba(0,212,255,0.3)" : "#142240"}`,
                background:   animated ? "rgba(0,212,255,0.08)" : "transparent",
                color:        animated ? "#00D4FF" : "#3A5070",
                fontSize:     9,
                fontFamily:   "'JetBrains Mono', monospace",
                fontWeight:   700,
                cursor:       "pointer",
                transition:   "all 0.2s",
              }}
            >
              {animated ? "⏸ PAUSE" : "▶ PLAY"}
            </button>
          </div>
        </div>

        {/* Error */}
        {error && (
          <div
            style={{
              margin:       "0 10px",
              padding:      "8px 10px",
              borderRadius: 6,
              background:   "rgba(255,45,85,0.08)",
              border:       "1px solid rgba(255,45,85,0.2)",
              fontSize:     9,
              color:        "#FF2D55",
              fontFamily:   "'JetBrains Mono', monospace",
              lineHeight:   1.6,
            }}
          >
            ⚠ {error}
          </div>
        )}
      </div>

      {/* ── Main content ─────────────────────────────────── */}
      <div
        style={{
          flex:          1,
          display:       "flex",
          flexDirection: "column",
          overflow:      "hidden",
          padding:       "16px",
          gap:           12,
        }}
      >

        {/* Loading */}
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
              gap:            20,
              opacity:        0.5,
            }}
          >
            <div style={{ fontSize: 64 }}>🕸️</div>
            <div
              style={{
                fontFamily:    "'Orbitron', monospace",
                fontSize:      16,
                color:         "#00D4FF",
                letterSpacing: 4,
              }}
            >
              ATTACK GRAPH
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
              SELECT A SCENARIO OR ENTER A CUSTOM POLICY
              <br />
              TO VISUALIZE ATTACK PATHS
            </div>

            {/* Zone legend */}
            <div
              className="glass"
              style={{
                borderRadius: 12,
                padding:      "14px 20px",
                display:      "flex",
                gap:          20,
              }}
            >
              {[
                { zone: "INTERNET",  color: "rgba(0,100,160,0.6)"  },
                { zone: "DMZ",       color: "rgba(0,140,120,0.6)"  },
                { zone: "INTERNAL",  color: "rgba(0,80,200,0.6)"   },
                { zone: "ADMIN",     color: "rgba(200,40,40,0.6)"  },
                { zone: "DATABASE",  color: "rgba(140,40,200,0.6)" },
              ].map(({ zone, color }) => (
                <div
                  key={zone}
                  style={{
                    display:    "flex",
                    alignItems: "center",
                    gap:        6,
                  }}
                >
                  <div
                    style={{
                      width:        10,
                      height:       10,
                      borderRadius: 2,
                      background:   color,
                    }}
                  />
                  <span
                    style={{
                      fontSize:   8,
                      color:      "#3A5070",
                      fontFamily: "'JetBrains Mono', monospace",
                      letterSpacing: 1,
                    }}
                  >
                    {zone}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Results */}
        {!loading && result && (
          <>
            {/* Top info bar */}
            <div
              className="glass"
              style={{
                borderRadius: 10,
                padding:      "10px 16px",
                display:      "flex",
                alignItems:   "center",
                gap:          16,
                flexShrink:   0,
                flexWrap:     "wrap",
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

              <div
                style={{
                  display:    "flex",
                  gap:        10,
                  alignItems: "center",
                  flexShrink: 0,
                }}
              >
                {[
                  {
                    label: "RISK",
                    value: result.risk_score,
                    color: riskColor(result.risk_level),
                  },
                  {
                    label: "PATHS",
                    value: healed ? 0 : result.sim_paths,
                    color: result.sim_paths > 100 ? "#FF2D55" : "#FFD000",
                  },
                  {
                    label: "TARGETS",
                    value: healed ? 0 : result.sim_targets,
                    color: result.sim_targets > 0 ? "#FF2D55" : "#00E676",
                  },
                ].map(({ label, value, color }) => (
                  <div
                    key={label}
                    style={{ textAlign: "center" }}
                  >
                    <div
                      style={{
                        fontFamily: "'Orbitron', monospace",
                        fontSize:   16,
                        fontWeight: 900,
                        color,
                        textShadow: `0 0 8px ${color}66`,
                        lineHeight: 1,
                      }}
                    >
                      {value}
                    </div>
                    <div
                      style={{
                        fontSize:      7,
                        color:         "#3A5070",
                        fontFamily:    "'JetBrains Mono', monospace",
                        letterSpacing: 1.5,
                        marginTop:     2,
                      }}
                    >
                      {label}
                    </div>
                  </div>
                ))}

                <span className={riskBadgeClass(result.risk_level)}>
                  {riskIcon(result.risk_level)} {result.risk_level}
                </span>
              </div>
            </div>

            {/* Main graph */}
            <div
              className="glass"
              style={{
                borderRadius: 14,
                padding:      20,
                flex:         1,
                overflow:     "hidden",
                minHeight:    0,
              }}
            >
              <NetworkGraph
                result={result}
                showHealed={healed}
                animated={animated}
                height={320}
              />
            </div>

            {/* Bottom — attack paths + before/after */}
            <div
              style={{
                display:             "grid",
                gridTemplateColumns: "1fr 1fr",
                gap:                 12,
                flexShrink:          0,
              }}
            >
              {/* Attack paths */}
              <div
                className="glass"
                style={{ borderRadius: 10, padding: 14 }}
              >
                <div
                  className="section-label"
                  style={{
                    color:       healed ? "#00E676" : "#FF2D55",
                    marginBottom: 10,
                  }}
                >
                  {healed ? "✓ PATHS BLOCKED" : "⚡ TOP ATTACK PATHS"}
                </div>
                {healed ? (
                  <div
                    style={{
                      fontSize:   10,
                      color:      "#00E676",
                      fontFamily: "'JetBrains Mono', monospace",
                    }}
                  >
                    ✓ All attack paths eliminated by self-healing
                  </div>
                ) : (
                  <div
                    style={{
                      display:  "flex",
                      flexWrap: "wrap",
                      gap:      6,
                    }}
                  >
                    {result.attack_paths?.slice(0, 4).map((path, i) => (
                      <div
                        key={i}
                        style={{
                          background:   "rgba(255,45,85,0.05)",
                          border:       "1px solid rgba(255,45,85,0.15)",
                          borderRadius: 6,
                          padding:      "6px 10px",
                          fontSize:     9,
                          fontFamily:   "'JetBrains Mono', monospace",
                        }}
                      >
                        {path.map((node, j) => (
                          <span key={j}>
                            <span
                              style={{
                                color: ["admin","database"].includes(node)
                                  ? "#FF2D55"
                                  : "#00D4FF",
                              }}
                            >
                              {node.toUpperCase()}
                            </span>
                            {j < path.length - 1 && (
                              <span style={{ color: "#FF2D55", margin: "0 2px" }}>→</span>
                            )}
                          </span>
                        ))}
                      </div>
                    ))}
                    {!result.attack_paths?.length && (
                      <div
                        style={{
                          fontSize:   10,
                          color:      "#00E676",
                          fontFamily: "'JetBrains Mono', monospace",
                        }}
                      >
                        ✓ No attack paths found
                      </div>
                    )}
                  </div>
                )}
              </div>

              {/* Before vs After */}
              <div
                className="glass"
                style={{ borderRadius: 10, padding: 14 }}
              >
                <div className="section-label">BEFORE vs AFTER HEALING</div>
                {[
                  {
                    label:  "Risk Score",
                    before: result.risk_score,
                    after:  Math.max(1, result.risk_score - 4.5).toFixed(1),
                    max:    10,
                  },
                  {
                    label:  "Attack Paths",
                    before: Math.min(result.sim_paths, 200),
                    after:  0,
                    max:    200,
                  },
                  {
                    label:  "Surface Score",
                    before: result.surface_score,
                    after:  Math.max(0, result.surface_score - 4).toFixed(1),
                    max:    10,
                  },
                ].map(({ label, before, after, max }) => (
                  <div key={label} style={{ marginBottom: 10 }}>
                    <div
                      style={{
                        display:        "flex",
                        justifyContent: "space-between",
                        fontSize:       8,
                        color:          "#3A5070",
                        fontFamily:     "'JetBrains Mono', monospace",
                        marginBottom:   3,
                      }}
                    >
                      <span>{label}</span>
                      <span style={{ color: "#00E676" }}>
                        {before} → {after}
                      </span>
                    </div>
                    <div
                      className="progress-track"
                      style={{ marginBottom: 2 }}
                    >
                      <div
                        className="progress-fill"
                        style={{
                          width:      `${(before / max) * 100}%`,
                          background: "#FF2D55",
                        }}
                      />
                    </div>
                    <div className="progress-track">
                      <div
                        className="progress-fill"
                        style={{
                          width:      `${(after / max) * 100}%`,
                          background: "#00E676",
                        }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  );
}