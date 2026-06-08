// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Home.js
// ================================================================

import React, { useEffect, useRef } from "react";
import { useNavigate } from "react-router-dom";
import { Chart, registerables } from "chart.js";
import StatCard from "../components/StatCard";
import { riskColor, riskIcon, fmt } from "../services/api";

Chart.register(...registerables);

// ================================================================
// HOME PAGE
// ================================================================
export default function Home({ reports = [] }) {
  const navigate      = useNavigate();
  const donutRef      = useRef();
  const lineRef       = useRef();
  const donutChart    = useRef();
  const lineChart     = useRef();

  // ── Stats ───────────────────────────────────────────────────
  const total    = reports.length;
  const crits    = reports.filter((r) => r.risk_level === "Critical").length;
  const highs    = reports.filter((r) => r.risk_level === "High").length;
  const avgRisk  = total
    ? (reports.reduce((a, r) => a + (r.risk_score || 0), 0) / total).toFixed(1)
    : 0;
  const threats  = reports.filter((r) => r.threat_matched).length;
  const healed   = reports.filter((r) => r.healing_count > 0).length;

  // ── Donut chart ─────────────────────────────────────────────
  useEffect(() => {
    if (!donutRef.current) return;
    if (donutChart.current) donutChart.current.destroy();

    const dist = {
      Critical: reports.filter((r) => r.risk_level === "Critical").length,
      High:     reports.filter((r) => r.risk_level === "High").length,
      Medium:   reports.filter((r) => r.risk_level === "Medium").length,
      Low:      reports.filter((r) => r.risk_level === "Low").length,
    };

    donutChart.current = new Chart(donutRef.current, {
      type: "doughnut",
      data: {
        labels:   ["Critical", "High", "Medium", "Low"],
        datasets: [{
          data:            Object.values(dist),
          backgroundColor: [
            "rgba(255,45,85,0.8)",
            "rgba(255,136,0,0.8)",
            "rgba(255,208,0,0.8)",
            "rgba(0,230,118,0.8)",
          ],
          borderColor: ["#FF2D55","#FF8800","#FFD000","#00E676"],
          borderWidth:  2,
          hoverOffset:  8,
        }],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        cutout:              "70%",
        plugins: {
          legend: {
            position: "bottom",
            labels: {
              color:     "rgba(184,208,238,0.7)",
              font:      { size: 10, family: "JetBrains Mono" },
              boxWidth:  10,
              padding:   10,
            },
          },
          tooltip: {
            backgroundColor: "rgba(7,15,30,0.95)",
            borderColor:     "rgba(0,212,255,0.3)",
            borderWidth:     1,
            titleColor:      "#00D4FF",
            bodyColor:       "#B8D0EE",
          },
        },
      },
    });
  }, [reports]);

  // ── Line chart ──────────────────────────────────────────────
  useEffect(() => {
    if (!lineRef.current || reports.length < 2) return;
    if (lineChart.current) lineChart.current.destroy();

    const last8  = [...reports].reverse().slice(-8);
    const labels = last8.map((_, i) => `#${i + 1}`);
    const scores = last8.map((r) => r.risk_score || 0);

    lineChart.current = new Chart(lineRef.current, {
      type: "line",
      data: {
        labels,
        datasets: [{
          label:           "Risk Score",
          data:            scores,
          borderColor:     "#00D4FF",
          backgroundColor: "rgba(0,212,255,0.08)",
          borderWidth:     2,
          pointBackgroundColor: "#00D4FF",
          pointRadius:     4,
          pointHoverRadius: 6,
          fill:            true,
          tension:         0.4,
        }],
      },
      options: {
        responsive:          true,
        maintainAspectRatio: false,
        scales: {
          x: {
            grid:  { color: "rgba(20,34,64,0.8)" },
            ticks: { color: "rgba(184,208,238,0.5)", font: { size: 10, family: "JetBrains Mono" } },
          },
          y: {
            min:   0,
            max:   10,
            grid:  { color: "rgba(20,34,64,0.8)" },
            ticks: { color: "rgba(184,208,238,0.5)", font: { size: 10, family: "JetBrains Mono" } },
          },
        },
        plugins: {
          legend: { display: false },
          tooltip: {
            backgroundColor: "rgba(7,15,30,0.95)",
            borderColor:     "rgba(0,212,255,0.3)",
            borderWidth:     1,
            titleColor:      "#00D4FF",
            bodyColor:       "#B8D0EE",
          },
        },
      },
    });
  }, [reports]);

  // ── Pipeline stages ─────────────────────────────────────────
  const pipeline = [
    { stage: "M1 — NLP Pipeline",        status: "ACTIVE",  detail: "SVM 100% · 87.7% CV"         },
    { stage: "M2 — Rule Intelligence",   status: "ACTIVE",  detail: "Conflict + Zero Trust"        },
    { stage: "M3 — Risk Scoring",        status: "ACTIVE",  detail: "CVSS + GradientBoosting"      },
    { stage: "M4 — Attack Simulation",   status: "ACTIVE",  detail: "BFS Graph · 776 max paths"    },
    { stage: "Flask Backend",            status: "ACTIVE",  detail: "localhost:5000"               },
    { stage: "React Dashboard",          status: "ACTIVE",  detail: "localhost:3000"               },
  ];

  return (
    <div
      style={{
        padding:    "20px 24px",
        overflowY:  "auto",
        height:     "100%",
        display:    "flex",
        flexDirection: "column",
        gap:        16,
      }}
    >

      {/* ── Stat cards ─────────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap:                 14,
        }}
      >
        <StatCard
          icon="📋"
          label="RULES ANALYZED"
          value={total}
          sub="total policies"
          color="#00D4FF"
          decimals={0}
          delay={0}
          onClick={() => navigate("/reports")}
        />
        <StatCard
          icon="🔴"
          label="CRITICAL RULES"
          value={crits}
          sub="immediate action"
          color="#FF2D55"
          decimals={0}
          delay={80}
          onClick={() => navigate("/reports")}
        />
        <StatCard
          icon="⚡"
          label="AVG RISK SCORE"
          value={avgRisk}
          sub="out of 10"
          color={avgRisk >= 7 ? "#FF2D55" : avgRisk >= 5 ? "#FF8800" : "#00D4FF"}
          decimals={1}
          delay={160}
        />
        <StatCard
          icon="🛡️"
          label="THREATS MATCHED"
          value={threats}
          sub="malicious sources"
          color="#FFD000"
          decimals={0}
          delay={240}
          onClick={() => navigate("/threats")}
        />
      </div>

      {/* ── Middle row ─────────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "1fr 1.6fr 1fr",
          gap:                 14,
          flex:                1,
          minHeight:           0,
        }}
      >

        {/* Donut chart */}
        <div
          className="glass"
          style={{ borderRadius: 14, padding: 18 }}
        >
          <div className="section-label">RISK DISTRIBUTION</div>
          {total === 0 ? (
            <EmptyState message="Analyze rules to see distribution" />
          ) : (
            <div style={{ height: 200 }}>
              <canvas ref={donutRef} />
            </div>
          )}
        </div>

        {/* Line chart */}
        <div
          className="glass"
          style={{ borderRadius: 14, padding: 18 }}
        >
          <div className="section-label">RISK TREND</div>
          {reports.length < 2 ? (
            <EmptyState message="Analyze 2+ rules to see trend" />
          ) : (
            <div style={{ height: 200 }}>
              <canvas ref={lineRef} />
            </div>
          )}
        </div>

        {/* Recent activity */}
        <div
          className="glass"
          style={{
            borderRadius: 14,
            padding:      18,
            overflowY:    "auto",
          }}
        >
          <div className="section-label">RECENT ACTIVITY</div>
          {reports.length === 0 ? (
            <EmptyState message="No rules yet" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
              {reports.slice(0, 8).map((r, i) => (
                <div
                  key={r.id || i}
                  style={{
                    display:       "flex",
                    alignItems:    "center",
                    gap:           8,
                    padding:       "7px 0",
                    borderBottom:  i < 7 ? "1px solid #142240" : "none",
                    animation:     `fadeUp 0.3s ease ${i * 40}ms both`,
                    cursor:        "pointer",
                  }}
                  onClick={() => navigate("/reports")}
                >
                  <span style={{ fontSize: 12, flexShrink: 0 }}>
                    {riskIcon(r.risk_level)}
                  </span>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div
                      style={{
                        fontSize:      10,
                        color:         "#B8D0EE",
                        overflow:      "hidden",
                        textOverflow:  "ellipsis",
                        whiteSpace:    "nowrap",
                        fontFamily:    "'JetBrains Mono', monospace",
                      }}
                    >
                      {r.policy}
                    </div>
                    <div
                      style={{
                        fontSize:  8,
                        color:     "#3A5070",
                        marginTop: 2,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      {r.intent?.toUpperCase()} · Port {r.port || "ANY"}
                    </div>
                  </div>
                  <span
                    style={{
                      fontFamily: "'Orbitron', monospace",
                      fontSize:   11,
                      fontWeight: 900,
                      color:      riskColor(r.risk_level),
                      flexShrink: 0,
                    }}
                  >
                    {r.risk_score}
                  </span>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* ── Bottom row ─────────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "1fr 1fr",
          gap:                 14,
        }}
      >

        {/* Top riskiest rules */}
        <div
          className="glass"
          style={{ borderRadius: 14, padding: 18 }}
        >
          <div className="section-label">TOP RISKIEST RULES</div>
          {reports.length === 0 ? (
            <EmptyState message="Analyze rules to see rankings" />
          ) : (
            <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
              {[...reports]
                .sort((a, b) => b.risk_score - a.risk_score)
                .slice(0, 4)
                .map((r, i) => {
                  const color = riskColor(r.risk_level);
                  return (
                    <div
                      key={r.id || i}
                      style={{
                        display:       "flex",
                        alignItems:    "center",
                        gap:           12,
                        padding:       "10px 12px",
                        borderRadius:  8,
                        background:    `${color}08`,
                        border:        `1px solid ${color}22`,
                        animation:     `fadeUp 0.4s ease ${i * 60}ms both`,
                        cursor:        "pointer",
                      }}
                      onClick={() => navigate("/analyzer")}
                    >
                      <span
                        style={{
                          fontFamily: "'Orbitron', monospace",
                          fontSize:   12,
                          fontWeight: 900,
                          color,
                          minWidth:   24,
                        }}
                      >
                        #{i + 1}
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div
                          style={{
                            fontSize:     11,
                            color:        "#B8D0EE",
                            overflow:     "hidden",
                            textOverflow: "ellipsis",
                            whiteSpace:   "nowrap",
                            fontFamily:   "'JetBrains Mono', monospace",
                          }}
                        >
                          {r.policy}
                        </div>
                        <div
                          style={{
                            fontSize:  8,
                            color:     "#3A5070",
                            marginTop: 2,
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {r.sim_paths} paths · {r.healing_count} fixes
                        </div>
                      </div>
                      <span
                        style={{
                          fontFamily: "'Orbitron', monospace",
                          fontSize:   16,
                          fontWeight: 900,
                          color,
                          textShadow: `0 0 8px ${color}66`,
                        }}
                      >
                        {r.risk_score}
                      </span>
                    </div>
                  );
                })}
            </div>
          )}
        </div>

        {/* Pipeline status */}
        <div
          className="glass"
          style={{ borderRadius: 14, padding: 18 }}
        >
          <div className="section-label">PIPELINE STATUS</div>
          <div style={{ display: "flex", flexDirection: "column", gap: 2 }}>
            {pipeline.map((p, i) => (
              <div
                key={i}
                style={{
                  display:       "flex",
                  alignItems:    "center",
                  gap:           10,
                  padding:       "9px 0",
                  borderBottom:  i < pipeline.length - 1
                    ? "1px solid #142240"
                    : "none",
                  animation:     `fadeUp 0.3s ease ${i * 60}ms both`,
                }}
              >
                <div
                  className={`status-dot ${
                    p.status === "ACTIVE"  ? "status-active"  :
                    p.status === "PENDING" ? "status-pending" :
                    "status-error"
                  }`}
                />
                <span
                  style={{
                    flex:      1,
                    fontSize:  11,
                    color:     "#B8D0EE",
                    fontFamily:"'JetBrains Mono', monospace",
                  }}
                >
                  {p.stage}
                </span>
                <span
                  style={{
                    fontSize:   9,
                    color:      p.status === "ACTIVE" ? "#00E676" : "#FFD000",
                    fontFamily: "'JetBrains Mono', monospace",
                  }}
                >
                  {p.detail}
                </span>
              </div>
            ))}
          </div>

          {/* Summary stats */}
          <div
            style={{
              display:             "grid",
              gridTemplateColumns: "repeat(3, 1fr)",
              gap:                 8,
              marginTop:           14,
              paddingTop:          14,
              borderTop:           "1px solid #142240",
            }}
          >
            {[
              { label: "HIGH RULES",   value: highs,  color: "#FF8800" },
              { label: "HEALED",       value: healed, color: "#00E676" },
              { label: "THREATS",      value: threats, color: "#FFD000" },
            ].map(({ label, value, color }) => (
              <div
                key={label}
                style={{ textAlign: "center" }}
              >
                <div
                  style={{
                    fontFamily: "'Orbitron', monospace",
                    fontSize:   18,
                    fontWeight: 900,
                    color,
                    textShadow: `0 0 8px ${color}55`,
                  }}
                >
                  {value}
                </div>
                <div
                  style={{
                    fontSize:      8,
                    color:         "#3A5070",
                    fontFamily:    "'JetBrains Mono', monospace",
                    letterSpacing: 1,
                    marginTop:     2,
                  }}
                >
                  {label}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  );
}

// ================================================================
// EMPTY STATE
// ================================================================
function EmptyState({ message }) {
  return (
    <div
      style={{
        display:        "flex",
        alignItems:     "center",
        justifyContent: "center",
        height:         160,
        fontSize:       11,
        color:          "#3A5070",
        fontFamily:     "'JetBrains Mono', monospace",
        textAlign:      "center",
        letterSpacing:  1,
      }}
    >
      {message}
    </div>
  );
}