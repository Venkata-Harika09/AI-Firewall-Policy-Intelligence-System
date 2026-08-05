// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Reports.js
// ================================================================

import React, { useState, useRef } from "react";
import StatCard           from "../components/StatCard";
import { riskColor, riskBadgeClass, riskIcon, simColor } from "../services/api";

// ================================================================
// PDF EXPORT
// ================================================================
const exportReportPDF = (report) => {
  const content = `
AI FIREWALL POLICY INTELLIGENCE SYSTEM
Security Analysis Report
Generated: ${new Date().toLocaleString()}
${"=".repeat(60)}

POLICY ANALYZED
${report.policy}

GENERATED RULE
${report.iptables || "—"}

RISK ANALYSIS
CVSS Risk Score  : ${report.risk_score} / 10
Risk Level       : ${report.risk_level}
ML Score         : ${report.ml_score || 0} / 10
Surface Score    : ${report.surface_score} / 10
Zero Trust Score : ${report.zero_trust_score || 100}

ATTACK SIMULATION
Paths Found      : ${report.sim_paths}
Targets Reached  : ${report.sim_targets}
Lateral Moves    : ${report.sim_lateral}
Sim Level        : ${report.sim_level}

SELF HEALING (${report.healing_count} recommendations)
${report.healings?.map((h, i) =>
  `${i + 1}. [${h.priority}] ${h.type}\n   → ${h.suggested}\n   Impact: ${h.impact}`
).join("\n") || "No healing required"}

EXPLANATION
${report.explanation || "—"}

Risk Vector: ${report.risk_vector || "—"}
Confidence : ${((report.confidence_score || 0) * 100).toFixed(0)}%

${"=".repeat(60)}
AI Firewall — M1 NLP · M2 Rules · M3 Risk · M4 Simulation
  `.trim();

  const blob = new Blob([content], { type: "text/plain" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `firewall_report_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

// ================================================================
// EXPORT ALL CSV
// ================================================================
const exportAllCSV = (reports) => {
  const headers = [
    "Policy","Intent","Port","Risk Score","Risk Level",
    "ML Score","Surface Score","Sim Paths","Sim Level",
    "Healing Count","Confidence","Date",
  ];
  const rows = reports.map((r) => [
    `"${r.policy}"`, r.intent, r.port || "ANY",
    r.risk_score, r.risk_level, r.ml_score || 0,
    r.surface_score, r.sim_paths, r.sim_level,
    r.healing_count, `${((r.confidence_score||0)*100).toFixed(0)}%`,
    `"${r.createdAt || ""}"`,
  ]);
  const csv  = [headers, ...rows].map((r) => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `firewall_reports_${Date.now()}.csv`;
  a.click();
  URL.revokeObjectURL(url);
};

// ================================================================
// REPORTS PAGE
// ================================================================
export default function Reports({ reports = [] }) {
  const [search,   setSearch]   = useState("");
  const [filter,   setFilter]   = useState("ALL");
  const [sortBy,   setSortBy]   = useState("date");
  const [sortDir,  setSortDir]  = useState("desc");
  const [expanded, setExpanded] = useState(null);

  // ── Stats ───────────────────────────────────────────────────
  const total   = reports.length;
  const crits   = reports.filter((r) => r.risk_level === "Critical").length;
  const healed  = reports.filter((r) => r.healing_count > 0).length;
  const avgRisk = total
    ? (reports.reduce((a, r) => a + (r.risk_score || 0), 0) / total).toFixed(1)
    : 0;

  // ── Sort handler ────────────────────────────────────────────
  const handleSort = (col) => {
    if (sortBy === col) setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    else { setSortBy(col); setSortDir("desc"); }
  };

  const sortIcon = (col) =>
    sortBy === col ? (sortDir === "asc" ? " ↑" : " ↓") : "";

  // ── Filter + sort ───────────────────────────────────────────
  const filtered = reports
    .filter((r) => {
      const matchSearch =
        !search ||
        r.policy?.toLowerCase().includes(search.toLowerCase()) ||
        r.risk_level?.toLowerCase().includes(search.toLowerCase()) ||
        String(r.port || "").includes(search);
      const matchFilter = filter === "ALL" || r.risk_level === filter;
      return matchSearch && matchFilter;
    })
    .sort((a, b) => {
      let av, bv;
      if (sortBy === "risk_score")   { av = a.risk_score;  bv = b.risk_score;  }
      else if (sortBy === "sim_paths"){ av = a.sim_paths;   bv = b.sim_paths;   }
      else                            { av = a.id || 0;     bv = b.id || 0;     }
      return sortDir === "asc" ? av - bv : bv - av;
    });

  // ── Column header ───────────────────────────────────────────
  const Th = ({ col, children, width }) => (
    <th
      onClick={() => handleSort(col)}
      style={{
        cursor:        "pointer",
        userSelect:    "none",
        whiteSpace:    "nowrap",
        width,
        padding:       "10px 12px",
        background:    "#0B1628",
        color:         sortBy === col ? "#00D4FF" : "#3A5070",
        fontFamily:    "'JetBrains Mono', monospace",
        fontSize:      9,
        fontWeight:    700,
        letterSpacing: 2,
        textTransform: "uppercase",
        borderBottom:  "1px solid #142240",
        transition:    "color 0.2s",
      }}
    >
      {children}{sortIcon(col)}
    </th>
  );

  return (
    <div
      style={{
        padding:       "20px 24px",
        overflowY:     "auto",
        height:        "100%",
        display:       "flex",
        flexDirection: "column",
        gap:           16,
      }}
    >

      {/* ── Stat cards ───────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap:                 14,
        }}
      >
        <StatCard icon="📊" label="TOTAL REPORTS"    value={total}   sub="all analyzed"        color="#00D4FF" decimals={0} delay={0}   />
        <StatCard icon="🔴" label="CRITICAL FINDINGS" value={crits}   sub="immediate action"    color="#FF2D55" decimals={0} delay={80}  />
        <StatCard icon="⚡" label="AVG RISK SCORE"   value={avgRisk} sub="out of 10"            color="#FF8800" decimals={1} delay={160} />
        <StatCard icon="🔧" label="RULES HEALED"     value={healed}  sub="recommendations given" color="#00E676" decimals={0} delay={240} />
      </div>

      {/* ── Filters + Export ─────────────────────────────── */}
      <div
        style={{
          display:    "flex",
          gap:        10,
          alignItems: "center",
          flexWrap:   "wrap",
        }}
      >
        {/* Search */}
        <input
          className="fw-input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search policy, risk level, port..."
          style={{ flex: 1, minWidth: 220 }}
        />

        {/* Risk filters */}
        {["ALL","Critical","High","Medium","Low"].map((f) => (
          <button
            key={f}
            onClick={() => setFilter(f)}
            style={{
              padding:      "7px 14px",
              borderRadius: 8,
              border:       `1px solid ${
                filter === f
                  ? riskColor(f === "ALL" ? "Low" : f)
                  : "#142240"
              }`,
              background:   filter === f
                ? `${riskColor(f === "ALL" ? "Low" : f)}12`
                : "#0B1628",
              color:        filter === f
                ? riskColor(f === "ALL" ? "Low" : f)
                : "#3A5070",
              fontFamily:   "'JetBrains Mono', monospace",
              fontSize:     10,
              fontWeight:   700,
              letterSpacing: 1,
              cursor:       "pointer",
              transition:   "all 0.2s",
            }}
          >
            {f}
          </button>
        ))}

        {/* Export CSV */}
        {reports.length > 0 && (
          <button
            onClick={() => exportAllCSV(reports)}
            style={{
              padding:      "7px 14px",
              borderRadius: 8,
              border:       "1px solid rgba(0,212,255,0.3)",
              background:   "rgba(0,212,255,0.08)",
              color:        "#00D4FF",
              fontFamily:   "'JetBrains Mono', monospace",
              fontSize:     10,
              fontWeight:   700,
              cursor:       "pointer",
              transition:   "all 0.2s",
              whiteSpace:   "nowrap",
            }}
          >
            ⬇ Export All CSV
          </button>
        )}

        {/* Count */}
        <div
          style={{
            fontSize:   9,
            color:      "#3A5070",
            fontFamily: "'JetBrains Mono', monospace",
            whiteSpace: "nowrap",
          }}
        >
          {filtered.length} / {total} reports
        </div>
      </div>

      {/* ── Table ────────────────────────────────────────── */}
      <div
        className="glass"
        style={{ borderRadius: 14, overflow: "hidden", flex: 1 }}
      >
        {total === 0 ? (
          <div
            style={{
              display:        "flex",
              flexDirection:  "column",
              alignItems:     "center",
              justifyContent: "center",
              height:         300,
              gap:            14,
              opacity:        0.5,
            }}
          >
            <div style={{ fontSize: 48 }}>📊</div>
            <div
              style={{
                fontFamily:    "'Orbitron', monospace",
                fontSize:      14,
                color:         "#00D4FF",
                letterSpacing: 3,
              }}
            >
              NO REPORTS YET
            </div>
            <div
              style={{
                fontSize:      11,
                color:         "#3A5070",
                fontFamily:    "'JetBrains Mono', monospace",
                letterSpacing: 2,
              }}
            >
              ANALYZE RULES IN THE ANALYZER PAGE
            </div>
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table style={{ width: "100%", borderCollapse: "collapse" }}>
              <thead>
                <tr>
                  <th style={{ width:36, padding:"10px 12px", background:"#0B1628", color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", fontSize:9, letterSpacing:2, borderBottom:"1px solid #142240" }}>#</th>
                  <Th col="policy"     width={200}>POLICY</Th>
                  <Th col="intent"     width={70}>INTENT</Th>
                  <Th col="port"       width={60}>PORT</Th>
                  <Th col="risk_score" width={90}>RISK</Th>
                  <Th col="risk_level" width={90}>LEVEL</Th>
                  <Th col="sim_paths"  width={80}>PATHS</Th>
                  <Th col="sim_level"  width={90}>SIM</Th>
                  <th style={{ width:70, padding:"10px 12px", background:"#0B1628", color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", fontSize:9, letterSpacing:2, borderBottom:"1px solid #142240" }}>HEALED</th>
                  <th style={{ width:130, padding:"10px 12px", background:"#0B1628", color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", fontSize:9, letterSpacing:2, borderBottom:"1px solid #142240" }}>DATE</th>
                  <th style={{ width:90, padding:"10px 12px", background:"#0B1628", color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", fontSize:9, letterSpacing:2, borderBottom:"1px solid #142240" }}>REPORT</th>
                </tr>
              </thead>
              <tbody>
                {filtered.length === 0 ? (
                  <tr>
                    <td
                      colSpan={11}
                      style={{
                        padding:    40,
                        textAlign:  "center",
                        color:      "#3A5070",
                        fontSize:   11,
                        fontFamily: "'JetBrains Mono', monospace",
                      }}
                    >
                      No results match your filter
                    </td>
                  </tr>
                ) : (
                  filtered.map((r, i) => {
                    const isExpanded = expanded === i;
                    const rc         = riskColor(r.risk_level);
                    const sc         = simColor(r.sim_level);

                    return (
                      <React.Fragment key={r.id || i}>
                        {/* Main row */}
                        <tr
                          onClick={() => setExpanded(isExpanded ? null : i)}
                          style={{
                            cursor:     "pointer",
                            background: isExpanded
                              ? "rgba(0,212,255,0.04)"
                              : "transparent",
                            transition: "background 0.15s",
                            animation:  `fadeUp 0.3s ease ${i * 30}ms both`,
                          }}
                        >
                          {/* # */}
                          <td
                            style={{
                              padding:    "12px",
                              fontSize:   10,
                              color:      "#3A5070",
                              fontFamily: "'JetBrains Mono', monospace",
                              borderBottom: "1px solid #142240",
                            }}
                          >
                            {i + 1}
                          </td>

                          {/* Policy */}
                          <td
                            style={{
                              padding:      "12px",
                              fontSize:     11,
                              color:        "#E8F4FF",
                              fontFamily:   "'JetBrains Mono', monospace",
                              maxWidth:     200,
                              overflow:     "hidden",
                              textOverflow: "ellipsis",
                              whiteSpace:   "nowrap",
                              borderBottom: "1px solid #142240",
                            }}
                          >
                            {r.policy}
                          </td>

                          {/* Intent */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240" }}>
                            <span
                              style={{
                                fontSize:     9,
                                padding:      "2px 7px",
                                borderRadius: 4,
                                fontFamily:   "'JetBrains Mono', monospace",
                                fontWeight:   700,
                                background:   r.intent === "allow"
                                  ? "rgba(255,136,0,0.12)"
                                  : "rgba(0,230,118,0.12)",
                                border:       `1px solid ${r.intent === "allow" ? "rgba(255,136,0,0.3)" : "rgba(0,230,118,0.3)"}`,
                                color:        r.intent === "allow" ? "#FF8800" : "#00E676",
                              }}
                            >
                              {r.intent?.toUpperCase()}
                            </span>
                          </td>

                          {/* Port */}
                          <td
                            style={{
                              padding:    "12px",
                              fontSize:   11,
                              color:      "#00D4FF",
                              fontFamily: "'JetBrains Mono', monospace",
                              fontWeight: 600,
                              borderBottom: "1px solid #142240",
                            }}
                          >
                            {r.port || "ANY"}
                          </td>

                          {/* Risk Score */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240" }}>
                            <span
                              style={{
                                fontFamily: "'Orbitron', monospace",
                                fontSize:   13,
                                fontWeight: 900,
                                color:      rc,
                                textShadow: `0 0 8px ${rc}55`,
                              }}
                            >
                              {r.risk_score}
                            </span>
                          </td>

                          {/* Risk Level */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240" }}>
                            <span className={riskBadgeClass(r.risk_level)}>
                              {riskIcon(r.risk_level)} {r.risk_level}
                            </span>
                          </td>

                          {/* Sim Paths */}
                          <td
                            style={{
                              padding:    "12px",
                              fontSize:   11,
                              color:      r.sim_paths > 100 ? "#FF2D55" : "#B8D0EE",
                              fontFamily: "'JetBrains Mono', monospace",
                              fontWeight: r.sim_paths > 100 ? 700 : 400,
                              borderBottom: "1px solid #142240",
                            }}
                          >
                            {r.sim_paths}
                          </td>

                          {/* Sim Level */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240" }}>
                            <span
                              style={{
                                fontSize:      9,
                                padding:       "2px 7px",
                                borderRadius:  4,
                                fontFamily:    "'JetBrains Mono', monospace",
                                fontWeight:    700,
                                letterSpacing: 1,
                                background:    `${sc}12`,
                                border:        `1px solid ${sc}33`,
                                color:         sc,
                              }}
                            >
                              {r.sim_level}
                            </span>
                          </td>

                          {/* Healed */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240", textAlign:"center" }}>
                            {r.healing_count > 0 ? (
                              <span
                                style={{
                                  color:      "#00E676",
                                  fontSize:   12,
                                  fontWeight: 700,
                                }}
                              >
                                ✓ {r.healing_count}
                              </span>
                            ) : (
                              <span style={{ color:"#3A5070", fontSize:11 }}>—</span>
                            )}
                          </td>

                          {/* Date */}
                          <td
                            style={{
                              padding:    "12px",
                              fontSize:   9,
                              color:      "#3A5070",
                              fontFamily: "'JetBrains Mono', monospace",
                              borderBottom: "1px solid #142240",
                            }}
                          >
                            {r.createdAt || "—"}
                          </td>

                          {/* PDF button */}
                          <td style={{ padding:"12px", borderBottom:"1px solid #142240" }}>
                            <button
                              onClick={(e) => { e.stopPropagation(); exportReportPDF(r); }}
                              style={{
                                padding:      "4px 10px",
                                borderRadius: 5,
                                background:   "rgba(0,212,255,0.08)",
                                border:       "1px solid rgba(0,212,255,0.2)",
                                color:        "#00D4FF",
                                fontSize:     9,
                                fontFamily:   "'JetBrains Mono', monospace",
                                fontWeight:   700,
                                cursor:       "pointer",
                                transition:   "all 0.2s",
                                whiteSpace:   "nowrap",
                              }}
                            >
                              📄 Report
                            </button>
                          </td>
                        </tr>

                        {/* Expanded row */}
                        {isExpanded && (
                          <tr>
                            <td
                              colSpan={11}
                              style={{
                                padding:      0,
                                borderBottom: "1px solid #142240",
                              }}
                            >
                              <div
                                style={{
                                  padding:   16,
                                  background:"rgba(0,212,255,0.02)",
                                  borderTop: "1px solid rgba(0,212,255,0.1)",
                                }}
                              >
                                <div
                                  style={{
                                    display:             "grid",
                                    gridTemplateColumns: "1fr 1fr 1fr",
                                    gap:                 14,
                                  }}
                                >
                                  {/* Explanation */}
                                  <div>
                                    <div className="section-label">EXPLANATION</div>
                                    <div
                                      style={{
                                        fontSize:   10,
                                        color:      "#B8D0EE",
                                        lineHeight: 1.8,
                                        fontFamily: "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      {r.explanation || "—"}
                                    </div>
                                    <div
                                      style={{
                                        marginTop:  10,
                                        fontSize:   9,
                                        color:      "#3A5070",
                                        fontFamily: "'JetBrains Mono', monospace",
                                      }}
                                    >
                                      Confidence: {((r.confidence_score || 0) * 100).toFixed(0)}%
                                    </div>
                                  </div>

                                  {/* Healing recs */}
                                  <div>
                                    <div className="section-label">HEALING RECOMMENDATIONS</div>
                                    {r.healings?.length === 0 ? (
                                      <div style={{ fontSize:10, color:"#00E676", fontFamily:"'JetBrains Mono',monospace" }}>
                                        ✓ No healing required
                                      </div>
                                    ) : (
                                      r.healings?.slice(0, 3).map((h, j) => {
                                        const hc = riskColor(
                                          h.priority === "CRITICAL" ? "Critical" :
                                          h.priority === "HIGH"     ? "High"     : "Medium"
                                        );
                                        return (
                                          <div
                                            key={j}
                                            style={{
                                              borderLeft:   `3px solid ${hc}`,
                                              paddingLeft:  8,
                                              marginBottom: 8,
                                            }}
                                          >
                                            <div
                                              style={{
                                                fontSize:   9,
                                                color:      hc,
                                                fontFamily: "'JetBrains Mono', monospace",
                                                fontWeight: 700,
                                                marginBottom: 2,
                                              }}
                                            >
                                              {h.type}
                                            </div>
                                            <div
                                              style={{
                                                fontSize:   9,
                                                color:      "#B8D0EE",
                                                fontFamily: "'JetBrains Mono', monospace",
                                              }}
                                            >
                                              → {h.suggested}
                                            </div>
                                          </div>
                                        );
                                      })
                                    )}
                                  </div>

                                  {/* Attack paths */}
                                  <div>
                                    <div className="section-label">ATTACK PATHS</div>
                                    {r.attack_paths?.length === 0 ? (
                                      <div style={{ fontSize:10, color:"#00E676", fontFamily:"'JetBrains Mono',monospace" }}>
                                        ✓ No attack paths
                                      </div>
                                    ) : (
                                      r.attack_paths?.slice(0, 3).map((path, j) => (
                                        <div
                                          key={j}
                                          style={{
                                            fontSize:     9,
                                            fontFamily:   "'JetBrains Mono', monospace",
                                            color:        "#FF2D55",
                                            marginBottom: 6,
                                            lineHeight:   1.6,
                                          }}
                                        >
                                          {path.join(" → ")}
                                        </div>
                                      ))
                                    )}
                                    {r.attack_paths?.length > 3 && (
                                      <div
                                        style={{
                                          fontSize:   9,
                                          color:      "#3A5070",
                                          fontFamily: "'JetBrains Mono', monospace",
                                        }}
                                      >
                                        +{r.attack_paths.length - 3} more paths
                                      </div>
                                    )}

                                    {/* Mini stats */}
                                    <div
                                      style={{
                                        display:             "grid",
                                        gridTemplateColumns: "1fr 1fr",
                                        gap:                 8,
                                        marginTop:           12,
                                      }}
                                    >
                                      {[
                                        { label:"ML SCORE",   value:`${r.ml_score || 0}/10`,           color:"#00D4FF" },
                                        { label:"SURFACE",    value:`${r.surface_score}/10`,            color:riskColor(r.surface_level) },
                                        { label:"ZERO TRUST", value:`${r.zero_trust_score || 100}`,     color:"#00D4FF" },
                                        { label:"LATERAL",    value:`${r.sim_lateral || 0} moves`,      color:"#FF8800" },
                                      ].map(({ label, value, color }) => (
                                        <div
                                          key={label}
                                          style={{
                                            background:   "rgba(11,22,40,0.6)",
                                            borderRadius: 6,
                                            padding:      "6px 8px",
                                          }}
                                        >
                                          <div style={{ fontSize:7, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", letterSpacing:1.5, marginBottom:3 }}>
                                            {label}
                                          </div>
                                          <div style={{ fontSize:11, color, fontFamily:"'Orbitron',monospace", fontWeight:700 }}>
                                            {value}
                                          </div>
                                        </div>
                                      ))}
                                    </div>
                                  </div>
                                </div>
                              </div>
                            </td>
                          </tr>
                        )}
                      </React.Fragment>
                    );
                  })
                )}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}