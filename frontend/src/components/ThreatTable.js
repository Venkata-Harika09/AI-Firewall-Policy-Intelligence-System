// ================================================================
// AI Firewall Policy Intelligence System
// src/components/ThreatTable.js
// ================================================================

import React, { useState } from "react";

// ================================================================
// HELPERS
// ================================================================
const abuseColor = (score) => {
  if (score >= 80) return "#FF2D55";
  if (score >= 60) return "#FF8800";
  if (score >= 40) return "#FFD000";
  return "#00E676";
};

const statusStyle = (status) => ({
  BLOCKED: {
    background: "rgba(255,45,85,0.12)",
    border:     "1px solid rgba(255,45,85,0.35)",
    color:      "#FF2D55",
  },
  MONITOR: {
    background: "rgba(255,208,0,0.12)",
    border:     "1px solid rgba(255,208,0,0.35)",
    color:      "#FFD000",
  },
  ALLOWED: {
    background: "rgba(0,230,118,0.12)",
    border:     "1px solid rgba(0,230,118,0.35)",
    color:      "#00E676",
  },
}[status] || {
  background: "rgba(58,80,112,0.12)",
  border:     "1px solid rgba(58,80,112,0.35)",
  color:      "#3A5070",
});

// ================================================================
// THREAT TABLE — shows malicious IPs
// ================================================================
export default function ThreatTable({ threats = [] }) {
  const [sortBy,    setSortBy]    = useState("abuse_score");
  const [sortDir,   setSortDir]   = useState("desc");
  const [search,    setSearch]    = useState("");
  const [filterCat, setFilterCat] = useState("ALL");

  // ── Sort handler ─────────────────────────────────────────────
  const handleSort = (col) => {
    if (sortBy === col) {
      setSortDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortBy(col);
      setSortDir("desc");
    }
  };

  // ── Categories ───────────────────────────────────────────────
  const categories = [
    "ALL",
    ...new Set(threats.map((t) => t.category).filter(Boolean)),
  ];

  // ── Filter + sort ────────────────────────────────────────────
  const filtered = threats
    .filter((t) => {
      const matchSearch =
        !search ||
        t.ip?.toLowerCase().includes(search.toLowerCase()) ||
        t.category?.toLowerCase().includes(search.toLowerCase()) ||
        t.country?.toLowerCase().includes(search.toLowerCase());

      const matchCat =
        filterCat === "ALL" || t.category === filterCat;

      return matchSearch && matchCat;
    })
    .sort((a, b) => {
      const av = a[sortBy] ?? "";
      const bv = b[sortBy] ?? "";
      if (sortDir === "asc") return av > bv ? 1 : -1;
      return av < bv ? 1 : -1;
    });

  // ── Sort icon ────────────────────────────────────────────────
  const sortIcon = (col) =>
    sortBy === col ? (sortDir === "asc" ? " ↑" : " ↓") : "";

  // ── Column header ────────────────────────────────────────────
  const Th = ({ col, children }) => (
    <th
      onClick={() => handleSort(col)}
      style={{
        cursor:        "pointer",
        userSelect:    "none",
        whiteSpace:    "nowrap",
        padding:       "10px 14px",
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
      {children}
      {sortIcon(col)}
    </th>
  );

  return (
    <div>
      {/* ── Filters ─────────────────────────────────────────── */}
      <div
        style={{
          display:      "flex",
          gap:          10,
          marginBottom: 14,
          flexWrap:     "wrap",
          alignItems:   "center",
        }}
      >
        {/* Search */}
        <input
          className="fw-input"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search IP, category, country..."
          style={{ flex: 1, minWidth: 200, padding: "7px 12px" }}
        />

        {/* Category filter */}
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap" }}>
          {categories.map((cat) => (
            <button
              key={cat}
              onClick={() => setFilterCat(cat)}
              style={{
                padding:       "5px 12px",
                borderRadius:  6,
                border:        `1px solid ${filterCat === cat ? "#00D4FF" : "#142240"}`,
                background:    filterCat === cat
                  ? "rgba(0,212,255,0.1)"
                  : "#0B1628",
                color:         filterCat === cat ? "#00D4FF" : "#3A5070",
                fontFamily:    "'JetBrains Mono', monospace",
                fontSize:      9,
                fontWeight:    700,
                letterSpacing: 1,
                cursor:        "pointer",
                transition:    "all 0.2s",
              }}
            >
              {cat}
            </button>
          ))}
        </div>

        {/* Count */}
        <div
          style={{
            fontSize:   9,
            color:      "#3A5070",
            fontFamily: "'JetBrains Mono', monospace",
            whiteSpace: "nowrap",
          }}
        >
          {filtered.length} / {threats.length} entries
        </div>
      </div>

      {/* ── Table ───────────────────────────────────────────── */}
      <div
        className="glass"
        style={{ borderRadius: 12, overflow: "hidden" }}
      >
        {filtered.length === 0 ? (
          <div
            style={{
              padding:    40,
              textAlign:  "center",
              color:      "#3A5070",
              fontSize:   12,
              fontFamily: "'JetBrains Mono', monospace",
            }}
          >
            {threats.length === 0
              ? "No threat data available"
              : "No results match your filter"}
          </div>
        ) : (
          <div style={{ overflowX: "auto" }}>
            <table className="fw-table" style={{ minWidth: 600 }}>
              <thead>
                <tr>
                  <Th col="ip">IP / CIDR</Th>
                  <Th col="category">Category</Th>
                  <Th col="abuse_score">Abuse Score</Th>
                  <Th col="country">Country</Th>
                  <Th col="status">Status</Th>
                  <Th col="last_seen">Last Seen</Th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((t, i) => {
                  const abuse = t.abuse_score ?? 0;
                  const ac    = abuseColor(abuse);
                  const ss    = statusStyle(t.status);

                  return (
                    <tr
                      key={i}
                      style={{
                        animation: `fadeUp 0.3s ease ${i * 40}ms both`,
                      }}
                    >
                      {/* IP */}
                      <td>
                        <span
                          style={{
                            fontFamily: "'JetBrains Mono', monospace",
                            fontSize:   11,
                            color:      "#FF2D55",
                            fontWeight: 600,
                          }}
                        >
                          {t.ip || "—"}
                        </span>
                      </td>

                      {/* Category */}
                      <td>
                        <span
                          style={{
                            fontSize:      9,
                            padding:       "2px 8px",
                            borderRadius:  4,
                            background:    "rgba(0,212,255,0.08)",
                            border:        "1px solid rgba(0,212,255,0.2)",
                            color:         "#00D4FF",
                            fontFamily:    "'JetBrains Mono', monospace",
                            fontWeight:    600,
                            whiteSpace:    "nowrap",
                          }}
                        >
                          {t.category || "Unknown"}
                        </span>
                      </td>

                      {/* Abuse Score */}
                      <td>
                        <div
                          style={{
                            display:    "flex",
                            alignItems: "center",
                            gap:        8,
                          }}
                        >
                          {/* Bar */}
                          <div
                            className="progress-track"
                            style={{ width: 60, flexShrink: 0 }}
                          >
                            <div
                              className="progress-fill"
                              style={{
                                width:      `${abuse}%`,
                                background: ac,
                                boxShadow:  `0 0 4px ${ac}88`,
                              }}
                            />
                          </div>
                          {/* Number */}
                          <span
                            style={{
                              fontFamily: "'Orbitron', monospace",
                              fontSize:   11,
                              fontWeight: 700,
                              color:      ac,
                            }}
                          >
                            {abuse}
                          </span>
                        </div>
                      </td>

                      {/* Country */}
                      <td>
                        <span
                          style={{
                            fontSize:   11,
                            color:      "#B8D0EE",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {t.country || "—"}
                        </span>
                      </td>

                      {/* Status */}
                      <td>
                        <span
                          style={{
                            ...ss,
                            fontSize:      9,
                            padding:       "2px 8px",
                            borderRadius:  4,
                            fontFamily:    "'JetBrains Mono', monospace",
                            fontWeight:    700,
                            letterSpacing: 1,
                            whiteSpace:    "nowrap",
                          }}
                        >
                          {t.status || "UNKNOWN"}
                        </span>
                      </td>

                      {/* Last Seen */}
                      <td>
                        <span
                          style={{
                            fontSize:   10,
                            color:      "#3A5070",
                            fontFamily: "'JetBrains Mono', monospace",
                          }}
                        >
                          {t.last_seen || "—"}
                        </span>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  );
}

// ================================================================
// PORT RISK TABLE — shows dangerous ports
// ================================================================
export function PortRiskTable({ ports = [] }) {
  return (
    <div>
      <div className="section-label" style={{ marginBottom: 14 }}>
        HIGH-RISK PORTS
      </div>
      <div style={{ display: "flex", flexDirection: "column", gap: 8 }}>
        {ports.map((p, i) => {
          const risk  = parseFloat(p.risk_score || p.risk || 0);
          const color = risk >= 0.9
            ? "#FF2D55"
            : risk >= 0.8
            ? "#FF8800"
            : "#FFD000";

          return (
            <div
              key={i}
              className="glass"
              style={{
                borderRadius: 8,
                padding:      "10px 14px",
                display:      "flex",
                alignItems:   "center",
                gap:          12,
                animation:    `fadeUp 0.3s ease ${i * 40}ms both`,
              }}
            >
              {/* Port number */}
              <div
                style={{
                  fontFamily:    "'Orbitron', monospace",
                  fontSize:      13,
                  fontWeight:    900,
                  color:         "#00D4FF",
                  minWidth:      44,
                }}
              >
                {p.port}
              </div>

              {/* Service name */}
              <div
                style={{
                  fontSize:   11,
                  color:      "#B8D0EE",
                  flex:       1,
                  fontFamily: "'JetBrains Mono', monospace",
                }}
              >
                {p.service || p.name || "—"}
              </div>

              {/* Risk bar */}
              <div
                style={{
                  display:    "flex",
                  alignItems: "center",
                  gap:        8,
                  minWidth:   120,
                }}
              >
                <div
                  className="progress-track"
                  style={{ flex: 1 }}
                >
                  <div
                    className="progress-fill"
                    style={{
                      width:      `${risk * 100}%`,
                      background: color,
                      boxShadow:  `0 0 6px ${color}66`,
                    }}
                  />
                </div>
                <span
                  style={{
                    fontFamily: "'Orbitron', monospace",
                    fontSize:   11,
                    fontWeight: 700,
                    color,
                    minWidth:   32,
                    textAlign:  "right",
                  }}
                >
                  {risk.toFixed(2)}
                </span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}