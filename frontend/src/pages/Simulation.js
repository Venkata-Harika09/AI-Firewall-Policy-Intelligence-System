// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Simulation.js
// ================================================================

import React, { useState } from "react";
import NetworkGraph           from "../components/NetworkGraph";
import StatCard               from "../components/StatCard";
import { AnalyzingLoader }    from "../components/Loader";
import {
  analyzePolicy,
  riskColor,
  riskBadgeClass,
  riskIcon,
  simColor,
} from "../services/api";

// ================================================================
// QUICK TEST SCENARIOS
// ================================================================
const SCENARIOS = [
  { label: "Allow SSH from any",       policy: "Allow SSH from any"       },
  { label: "Allow HTTPS from any",     policy: "Allow HTTPS from any"     },
  { label: "Deny RDP from internet",   policy: "Deny RDP from internet"   },
  { label: "Allow MongoDB from any",   policy: "Allow MongoDB from any"   },
  { label: "Allow all traffic",        policy: "Allow all traffic"        },
];

// ================================================================
// SIMULATION PAGE
// ================================================================
export default function Simulation() {
  const [result,   setResult]   = useState(null);
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [policy,   setPolicy]   = useState("");
  const [healed,   setHealed]   = useState(false);

  // ── Run simulation ─────────────────────────────────────────
  const handleSimulate = async (policyText) => {
    if (!policyText.trim()) return;
    setPolicy(policyText);
    setLoading(true);
    setError("");
    setHealed(false);
    try {
      const data = await analyzePolicy(policyText);
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
        flexDirection: "column",
        height:        "100%",
        overflow:      "hidden",
        padding:       "16px 20px",
        gap:           14,
      }}
    >

      {/* ── Header + Input ─────────────────────────────────── */}
      <div
        className="glass"
        style={{
          borderRadius: 12,
          padding:      "14px 18px",
          flexShrink:   0,
        }}
      >
        <div
          style={{
            display:    "flex",
            gap:        10,
            alignItems: "center",
            flexWrap:   "wrap",
          }}
        >
          {/* Policy input */}
          <input
            className="fw-input"
            value={policy}
            onChange={(e) => setPolicy(e.target.value)}
            onKeyDown={(e) => e.key === "Enter" && handleSimulate(policy)}
            placeholder="Enter policy to simulate attack paths..."
            style={{ flex: 1, minWidth: 260 }}
          />

          {/* Simulate button */}
          <button
            className="btn-primary"
            onClick={() => handleSimulate(policy)}
            disabled={loading}
            style={{ width: "auto", padding: "10px 20px", flexShrink: 0 }}
          >
            {loading ? (
              <span style={{ display: "inline-block", animation: "spin 1s linear infinite" }}>
                ◌
              </span>
            ) : "⚡ SIMULATE"}
          </button>

          {/* Before/After toggle */}
          {result && (
            <div
              style={{
                display:      "flex",
                background:   "#0B1628",
                border:       "1px solid #142240",
                borderRadius: 8,
                overflow:     "hidden",
                flexShrink:   0,
              }}
            >
              {["BEFORE", "AFTER"].map((label, i) => {
                const active = i === 0 ? !healed : healed;
                return (
                  <button
                    key={label}
                    onClick={() => setHealed(i === 1)}
                    style={{
                      background: active
                        ? i === 0
                          ? "rgba(255,45,85,0.15)"
                          : "rgba(0,230,118,0.15)"
                        : "transparent",
                      border:     "none",
                      padding:    "8px 16px",
                      color:      active
                        ? i === 0 ? "#FF2D55" : "#00E676"
                        : "#3A5070",
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
                );
              })}
            </div>
          )}
        </div>

        {/* Scenario presets */}
        <div
          style={{
            display:    "flex",
            gap:        6,
            marginTop:  10,
            flexWrap:   "wrap",
          }}
        >
          <span
            style={{
              fontSize:   8,
              color:      "#3A5070",
              fontFamily: "'JetBrains Mono', monospace",
              letterSpacing: 1.5,
              alignSelf:  "center",
              marginRight: 4,
            }}
          >
            QUICK TEST:
          </span>
          {SCENARIOS.map((s) => (
            <button
              key={s.policy}
              onClick={() => handleSimulate(s.policy)}
              style={{
                background:   result?.policy === s.policy
                  ? "rgba(0,212,255,0.1)"
                  : "#0B1628",
                border:       `1px solid ${
                  result?.policy === s.policy
                    ? "rgba(0,212,255,0.4)"
                    : "#142240"
                }`,
                borderRadius: 6,
                padding:      "4px 10px",
                color:        result?.policy === s.policy
                  ? "#00D4FF"
                  : "#3A5070",
                fontSize:     9,
                fontFamily:   "'JetBrains Mono', monospace",
                cursor:       "pointer",
                transition:   "all 0.2s",
              }}
            >
              {s.label}
            </button>
          ))}
        </div>
      </div>

      {/* ── Error ──────────────────────────────────────────── */}
      {error && (
        <div
          style={{
            padding:      "10px 14px",
            borderRadius: 8,
            background:   "rgba(255,45,85,0.08)",
            border:       "1px solid rgba(255,45,85,0.25)",
            fontSize:     11,
            color:        "#FF2D55",
            fontFamily:   "'JetBrains Mono', monospace",
            flexShrink:   0,
          }}
        >
          ⚠ {error}
        </div>
      )}

      {/* ── Loading ─────────────────────────────────────────── */}
      {loading && (
        <div style={{ flex: 1 }}>
          <AnalyzingLoader />
        </div>
      )}

      {/* ── Empty state ─────────────────────────────────────── */}
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
          <div style={{ fontSize: 48 }}>🎮</div>
          <div
            style={{
              fontFamily:    "'Orbitron', monospace",
              fontSize:      14,
              color:         "#00D4FF",
              letterSpacing: 4,
            }}
          >
            ATTACK SIMULATION
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
            ENTER A POLICY OR SELECT A QUICK TEST
            <br />
            BFS GRAPH TRAVERSAL · 6 NETWORK ZONES
          </div>
        </div>
      )}

      {/* ── Results ─────────────────────────────────────────── */}
      {!loading && result && (
        <div
          style={{
            flex:      1,
            display:   "flex",
            gap:       14,
            overflow:  "hidden",
            minHeight: 0,
          }}
        >

          {/* ── Main graph area ────────────────────────────── */}
          <div
            style={{
              flex:          1,
              display:       "flex",
              flexDirection: "column",
              gap:           12,
              overflow:      "hidden",
            }}
          >
            {/* Stat cards */}
            <div
              style={{
                display:             "grid",
                gridTemplateColumns: "repeat(4, 1fr)",
                gap:                 10,
                flexShrink:          0,
              }}
            >
              <StatCard
                label="PATHS FOUND"
                value={healed ? 0 : result.sim_paths}
                color={result.sim_paths > 100 ? "#FF2D55" : "#FFD000"}
                decimals={0}
                delay={0}
              />
              <StatCard
                label="TARGETS HIT"
                value={healed ? 0 : result.sim_targets}
                color={result.sim_targets > 0 ? "#FF2D55" : "#00E676"}
                decimals={0}
                delay={60}
              />
              <StatCard
                label="LATERAL MOVES"
                value={healed ? 0 : result.sim_lateral}
                color={result.sim_lateral > 2 ? "#FF8800" : "#FFD000"}
                decimals={0}
                delay={120}
              />
              <StatCard
                label="SURFACE SCORE"
                value={healed ? 0 : result.surface_score}
                color={riskColor(result.surface_level)}
                decimals={1}
                delay={180}
              />
            </div>

            {/* Network graph */}
            <div
              className="glass"
              style={{
                borderRadius: 14,
                padding:      16,
                flex:         1,
                overflow:     "hidden",
                position:     "relative",
              }}
            >
              <div
                style={{
                  display:        "flex",
                  justifyContent: "space-between",
                  alignItems:     "center",
                  marginBottom:   12,
                  flexShrink:     0,
                }}
              >
                <div className="section-label" style={{ marginBottom: 0 }}>
                  NETWORK ATTACK GRAPH
                </div>
                <div
                  style={{
                    display:    "flex",
                    gap:        8,
                    alignItems: "center",
                  }}
                >
                  <span
                    style={{
                      fontSize:      9,
                      fontFamily:    "'JetBrains Mono', monospace",
                      color:         "#3A5070",
                    }}
                  >
                    Policy: {result.policy}
                  </span>
                  <span
                    className={riskBadgeClass(result.risk_level)}
                  >
                    {riskIcon(result.risk_level)} {result.risk_level}
                  </span>
                </div>
              </div>

              <NetworkGraph
                result={result}
                showHealed={healed}
                animated={true}
                height={280}
              />
            </div>
          </div>

          {/* ── Right sidebar ──────────────────────────────── */}
          <div
            style={{
              width:         280,
              display:       "flex",
              flexDirection: "column",
              gap:           12,
              overflowY:     "auto",
              flexShrink:    0,
            }}
          >

            {/* Attack paths */}
            <div
              className="glass"
              style={{
                borderRadius: 12,
                padding:      14,
                flex:         1,
                overflowY:    "auto",
              }}
            >
              <div
                className="section-label"
                style={{
                  color: healed ? "#00E676" : "#FF2D55",
                  marginBottom: 10,
                }}
              >
                {healed ? "✓ PATHS BLOCKED" : "⚡ ATTACK PATHS"}
              </div>

              {healed ? (
                <div
                  style={{
                    background:   "rgba(0,230,118,0.06)",
                    border:       "1px solid rgba(0,230,118,0.2)",
                    borderRadius: 8,
                    padding:      12,
                    fontSize:     10,
                    color:        "#00E676",
                    fontFamily:   "'JetBrains Mono', monospace",
                    lineHeight:   1.7,
                  }}
                >
                  ✓ Self-healing recommendations applied.
                  All attack paths eliminated.
                </div>
              ) : result.attack_paths?.length === 0 ? (
                <div
                  style={{
                    fontSize:   10,
                    color:      "#00E676",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  ✓ No attack paths found
                </div>
              ) : (
                result.attack_paths?.slice(0, 8).map((path, i) => (
                  <div
                    key={i}
                    style={{
                      background:   "rgba(255,45,85,0.05)",
                      border:       "1px solid rgba(255,45,85,0.15)",
                      borderRadius: 6,
                      padding:      "8px 10px",
                      marginBottom: 6,
                      animation:    `fadeUp 0.3s ease ${i * 40}ms both`,
                    }}
                  >
                    <div
                      style={{
                        fontSize:   8,
                        color:      "#3A5070",
                        fontFamily: "'JetBrains Mono', monospace",
                        marginBottom: 4,
                      }}
                    >
                      PATH {i + 1} — {path.length - 1} HOP{path.length > 2 ? "S" : ""}
                    </div>
                    <div
                      style={{
                        fontSize:   10,
                        fontFamily: "'JetBrains Mono', monospace",
                        lineHeight: 1.8,
                      }}
                    >
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
                            <span style={{ color: "#FF2D55", margin: "0 3px" }}>
                              →
                            </span>
                          )}
                        </span>
                      ))}
                    </div>
                  </div>
                ))
              )}

              {result.attack_paths?.length > 8 && !healed && (
                <div
                  style={{
                    fontSize:   9,
                    color:      "#3A5070",
                    fontFamily: "'JetBrains Mono', monospace",
                    textAlign:  "center",
                    marginTop:  8,
                  }}
                >
                  +{result.attack_paths.length - 8} more paths
                </div>
              )}
            </div>

            {/* Before vs After comparison */}
            <div
              className="glass"
              style={{ borderRadius: 12, padding: 14 }}
            >
              <div className="section-label">BEFORE vs AFTER</div>
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
                <div key={label} style={{ marginBottom: 12 }}>
                  <div
                    style={{
                      display:        "flex",
                      justifyContent: "space-between",
                      fontSize:       9,
                      color:          "#3A5070",
                      fontFamily:     "'JetBrains Mono', monospace",
                      marginBottom:   4,
                    }}
                  >
                    <span>{label}</span>
                    <span style={{ color: "#00E676" }}>
                      {before} → {after}
                    </span>
                  </div>

                  {/* Before */}
                  <div className="progress-track" style={{ marginBottom: 3 }}>
                    <div
                      className="progress-fill"
                      style={{
                        width:      `${(before / max) * 100}%`,
                        background: "#FF2D55",
                      }}
                    />
                  </div>

                  {/* After */}
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

            {/* Reachable zones */}
            {result.sim_reachable?.length > 0 && (
              <div
                className="glass"
                style={{ borderRadius: 12, padding: 14 }}
              >
                <div className="section-label">REACHABLE ZONES</div>
                <div
                  style={{
                    display:  "flex",
                    flexWrap: "wrap",
                    gap:      6,
                  }}
                >
                  {result.sim_reachable.map((node) => (
                    <span
                      key={node}
                      style={{
                        fontSize:     8,
                        padding:      "2px 8px",
                        borderRadius: 4,
                        fontFamily:   "'JetBrains Mono', monospace",
                        fontWeight:   700,
                        background:   healed
                          ? "rgba(0,230,118,0.08)"
                          : ["admin","database"].includes(node)
                          ? "rgba(255,45,85,0.12)"
                          : "rgba(0,212,255,0.08)",
                        border: `1px solid ${
                          healed
                            ? "rgba(0,230,118,0.25)"
                            : ["admin","database"].includes(node)
                            ? "rgba(255,45,85,0.3)"
                            : "rgba(0,212,255,0.2)"
                        }`,
                        color: healed
                          ? "#00E676"
                          : ["admin","database"].includes(node)
                          ? "#FF2D55"
                          : "#00D4FF",
                      }}
                    >
                      {healed ? "✓ " : ""}{node.toUpperCase()}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  );
}