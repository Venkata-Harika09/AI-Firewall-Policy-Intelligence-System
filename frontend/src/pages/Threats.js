// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Threats.js — Improved Version
// ================================================================

import React, { useState, useEffect, useCallback } from "react";
import ThreatTable, { PortRiskTable } from "../components/ThreatTable";
import StatCard                        from "../components/StatCard";
import { PageLoader }                  from "../components/Loader";
import { getThreats }                  from "../services/api";

// ================================================================
// FALLBACK DATA
// ================================================================
const FALLBACK_IPS = [
  { ip:"45.155.205.233", category:"Botnet C2",     abuse_score:95, country:"RU", status:"BLOCKED" },
  { ip:"198.51.100.25",  category:"Port Scanner",  abuse_score:78, country:"CN", status:"BLOCKED" },
  { ip:"203.0.113.45",   category:"Malware Host",  abuse_score:88, country:"NG", status:"BLOCKED" },
  { ip:"185.220.101.34", category:"TOR Exit Node", abuse_score:72, country:"DE", status:"MONITOR" },
  { ip:"91.108.4.0/22",  category:"CIDR Range",    abuse_score:65, country:"NL", status:"BLOCKED" },
  { ip:"5.188.206.0/24", category:"Spam Source",   abuse_score:70, country:"RU", status:"BLOCKED" },
];

const FALLBACK_PORTS = [
  { port:23,    service:"Telnet",         risk:0.95 },
  { port:2375,  service:"Docker API",     risk:0.95 },
  { port:6443,  service:"Kubernetes API", risk:0.90 },
  { port:445,   service:"SMB",            risk:0.85 },
  { port:3389,  service:"RDP",            risk:0.85 },
  { port:22,    service:"SSH",            risk:0.80 },
  { port:3306,  service:"MySQL",          risk:0.80 },
  { port:27017, service:"MongoDB",        risk:0.75 },
  { port:6379,  service:"Redis",          risk:0.75 },
  { port:9200,  service:"Elasticsearch",  risk:0.70 },
];

// ================================================================
// HELPERS
// ================================================================
const severityFromScore = (score) => {
  if (score >= 80) return "Critical";
  if (score >= 60) return "High";
  if (score >= 40) return "Medium";
  return "Low";
};

const exportJSON = (data) => {
  const blob = new Blob([JSON.stringify(data, null, 2)], { type: "application/json" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = "threat_intel.json";
  a.click();
  URL.revokeObjectURL(url);
};

const exportCSV = (data) => {
  const headers = ["IP","Category","Abuse Score","Country","Status"];
  const rows    = data.map((t) => [
    t.ip, t.category, t.abuse_score, t.country, t.status,
  ]);
  const csv = [headers, ...rows].map((r) => r.join(",")).join("\n");
  const blob = new Blob([csv], { type: "text/csv" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = "threat_intel.csv";
  a.click();
  URL.revokeObjectURL(url);
};

// ================================================================
// THREATS PAGE
// ================================================================
export default function Threats() {
  const [data,      setData]      = useState(null);
  const [loading,   setLoading]   = useState(true);
  const [refreshing,setRefreshing]= useState(false);
  const [isLive,    setIsLive]    = useState(false);
  const [lastSync,  setLastSync]  = useState("");
  const [error,     setError]     = useState("");

  // ── Fetch ─────────────────────────────────────────────────
  const fetchData = useCallback(async (isRefresh = false) => {
    if (isRefresh) setRefreshing(true);
    else           setLoading(true);
    setError("");
    try {
      const res = await getThreats();
      setData(res);
      setIsLive(true);
    } catch {
      setError("Using local threat database — Flask API unavailable.");
      setData({ threats: FALLBACK_IPS, count: FALLBACK_IPS.length });
      setIsLive(false);
    } finally {
      setLoading(false);
      setRefreshing(false);
      setLastSync(new Date().toLocaleTimeString());
    }
  }, []);

  // ── Initial load + auto refresh every 60s ─────────────────
  useEffect(() => {
    fetchData();
    const timer = setInterval(() => fetchData(true), 60000);
    return () => clearInterval(timer);
  }, [fetchData]);

  // ── Derived stats ──────────────────────────────────────────
  const ips      = data?.threats || FALLBACK_IPS;
  const blocked  = ips.filter((t) => t.status === "BLOCKED").length;
  const critical = ips.filter((t) => (t.abuse_score || 0) >= 80).length;
  const cidrs    = ips.filter((t) => t.ip?.includes("/")).length;

  // Severity distribution
  const severityDist = ips.reduce((acc, t) => {
    const s = severityFromScore(t.abuse_score || 0);
    acc[s]  = (acc[s] || 0) + 1;
    return acc;
  }, { Critical:0, High:0, Medium:0, Low:0 });

  // Category breakdown
  const categoryDist = ips.reduce((acc, t) => {
    const c = t.category || "Unknown";
    acc[c]  = (acc[c] || 0) + 1;
    return acc;
  }, {});

  // Country breakdown
  const countryDist = ips.reduce((acc, t) => {
    const c = t.country || "—";
    acc[c]  = (acc[c] || 0) + 1;
    return acc;
  }, {});

  // Most dangerous IP
  const topThreat = [...ips].sort((a, b) => (b.abuse_score || 0) - (a.abuse_score || 0))[0];

  if (loading) return <PageLoader message="LOADING THREAT INTELLIGENCE..." />;

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

      {/* ── Feed Status Bar ──────────────────────────────── */}
      <div
        style={{
          display:        "flex",
          alignItems:     "center",
          justifyContent: "space-between",
          padding:        "8px 14px",
          borderRadius:   8,
          background:     isLive
            ? "rgba(0,230,118,0.06)"
            : "rgba(255,208,0,0.06)",
          border: `1px solid ${isLive
            ? "rgba(0,230,118,0.2)"
            : "rgba(255,208,0,0.2)"}`,
        }}
      >
        {/* Status */}
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <div
            className={isLive ? "status-dot status-active" : "status-dot status-pending"}
          />
          <span
            style={{
              fontSize:      10,
              fontFamily:    "'JetBrains Mono', monospace",
              fontWeight:    700,
              letterSpacing: 1.5,
              color:         isLive ? "#00E676" : "#FFD000",
            }}
          >
            {isLive ? "🟢 LIVE FEED — Flask API Connected" : "🟡 OFFLINE — Using Local Database"}
          </span>
        </div>

        {/* Last sync + refresh */}
        <div style={{ display:"flex", alignItems:"center", gap:12 }}>
          {lastSync && (
            <div style={{ textAlign:"right" }}>
              <div style={{ fontSize:7, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", letterSpacing:1.5 }}>
                LAST SYNC
              </div>
              <div style={{ fontSize:10, color:"#B8D0EE", fontFamily:"'JetBrains Mono',monospace" }}>
                {lastSync}
              </div>
            </div>
          )}
          <button
            onClick={() => fetchData(true)}
            disabled={refreshing}
            style={{
              display:      "flex",
              alignItems:   "center",
              gap:          6,
              padding:      "6px 12px",
              borderRadius: 6,
              background:   "rgba(0,212,255,0.08)",
              border:       "1px solid rgba(0,212,255,0.25)",
              color:        "#00D4FF",
              fontSize:     10,
              fontFamily:   "'JetBrains Mono', monospace",
              fontWeight:   700,
              cursor:       refreshing ? "not-allowed" : "pointer",
              opacity:      refreshing ? 0.6 : 1,
              transition:   "all 0.2s",
            }}
          >
            <span style={{ display:"inline-block", animation: refreshing ? "spin 1s linear infinite" : "none" }}>
              🔄
            </span>
            {refreshing ? "REFRESHING..." : "Refresh Threat Feed"}
          </button>
        </div>
      </div>

      {/* ── Error ────────────────────────────────────────── */}
      {error && (
        <div
          style={{
            padding:      "8px 14px",
            borderRadius: 8,
            background:   "rgba(255,208,0,0.06)",
            border:       "1px solid rgba(255,208,0,0.2)",
            fontSize:     10,
            color:        "#FFD000",
            fontFamily:   "'JetBrains Mono', monospace",
          }}
        >
          ⚠ {error}
        </div>
      )}

      {/* ── Stat cards ───────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap:                 14,
        }}
      >
        <StatCard icon="🚫" label="MALICIOUS IPs"  value={ips.length}  sub="in database"    color="#FF2D55"  decimals={0} delay={0}   />
        <StatCard icon="🔴" label="BLOCKED"         value={blocked}     sub="active blocks"  color="#FF8800"  decimals={0} delay={80}  />
        <StatCard icon="⚡" label="HIGH ABUSE"      value={critical}    sub="score ≥ 80"     color="#FFD000"  decimals={0} delay={160} />
        <StatCard icon="🌐" label="CIDR RANGES"     value={cidrs}       sub="blocked ranges" color="#00D4FF"  decimals={0} delay={240} />
      </div>

      {/* ── Most dangerous IP ────────────────────────────── */}
      {topThreat && (
        <div
          className="glass glass-red"
          style={{
            borderRadius: 12,
            padding:      "14px 18px",
            display:      "flex",
            alignItems:   "center",
            gap:          16,
            flexShrink:   0,
            animation:    "fadeUp 0.5s ease both",
          }}
        >
          <div style={{ fontSize:28 }}>🔥</div>
          <div style={{ flex:1 }}>
            <div style={{ fontSize:9, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", letterSpacing:2, marginBottom:4 }}>
              MOST DANGEROUS THREAT
            </div>
            <div style={{ fontFamily:"'Orbitron',monospace", fontSize:16, fontWeight:900, color:"#FF2D55", marginBottom:2 }}>
              {topThreat.ip}
            </div>
            <div style={{ fontSize:10, color:"#B8D0EE", fontFamily:"'JetBrains Mono',monospace" }}>
              {topThreat.category} · {topThreat.country}
            </div>
          </div>
          <div style={{ textAlign:"center" }}>
            <div style={{ fontFamily:"'Orbitron',monospace", fontSize:28, fontWeight:900, color:"#FF2D55", textShadow:"0 0 20px #FF2D5566" }}>
              {topThreat.abuse_score}
            </div>
            <div style={{ fontSize:8, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace", letterSpacing:1.5 }}>
              ABUSE SCORE
            </div>
          </div>
          <div style={{ display:"flex", gap:8 }}>
            <button
              onClick={() => exportJSON(ips)}
              style={{
                padding:"6px 12px", borderRadius:6,
                background:"rgba(0,212,255,0.08)", border:"1px solid rgba(0,212,255,0.25)",
                color:"#00D4FF", fontSize:10, fontFamily:"'JetBrains Mono',monospace",
                fontWeight:700, cursor:"pointer", transition:"all 0.2s",
              }}
            >
              ⬇ Export JSON
            </button>
            <button
              onClick={() => exportCSV(ips)}
              style={{
                padding:"6px 12px", borderRadius:6,
                background:"rgba(0,230,118,0.08)", border:"1px solid rgba(0,230,118,0.25)",
                color:"#00E676", fontSize:10, fontFamily:"'JetBrains Mono',monospace",
                fontWeight:700, cursor:"pointer", transition:"all 0.2s",
              }}
            >
              ⬇ Export CSV
            </button>
          </div>
        </div>
      )}

      {/* ── Main content ─────────────────────────────────── */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "1fr 340px",
          gap:                 16,
          flex:                1,
          minHeight:           0,
        }}
      >
        {/* IP table */}
        <div style={{ display:"flex", flexDirection:"column", gap:12 }}>
          <div style={{ display:"flex", alignItems:"center", justifyContent:"space-between" }}>
            <div className="section-label" style={{ marginBottom:0 }}>MALICIOUS IP DATABASE</div>
            <div style={{ fontSize:9, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace" }}>
              {ips.length} entries · Last Sync: {lastSync || "—"}
            </div>
          </div>
          <ThreatTable threats={ips} />
        </div>

        {/* Right sidebar */}
        <div style={{ display:"flex", flexDirection:"column", gap:14, overflowY:"auto" }}>

          {/* Port risk */}
          <div className="glass" style={{ borderRadius:14, padding:16 }}>
            <PortRiskTable ports={FALLBACK_PORTS} />
          </div>

          {/* Severity distribution */}
          <div className="glass" style={{ borderRadius:14, padding:16 }}>
            <div className="section-label">THREAT SEVERITY DISTRIBUTION</div>
            {[
              { level:"Critical", color:"#FF2D55" },
              { level:"High",     color:"#FF8800" },
              { level:"Medium",   color:"#FFD000" },
              { level:"Low",      color:"#00E676" },
            ].map(({ level, color }) => (
              <div key={level} style={{ marginBottom:10 }}>
                <div style={{ display:"flex", justifyContent:"space-between", marginBottom:4 }}>
                  <span style={{ fontSize:9, color, fontFamily:"'JetBrains Mono',monospace", fontWeight:700 }}>
                    {level}
                  </span>
                  <span style={{ fontSize:10, color, fontFamily:"'Orbitron',monospace", fontWeight:700 }}>
                    {severityDist[level] || 0}
                  </span>
                </div>
                <div className="progress-track">
                  <div
                    className="progress-fill"
                    style={{
                      width:      `${((severityDist[level] || 0) / ips.length) * 100}%`,
                      background: color,
                      boxShadow:  `0 0 4px ${color}66`,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>

          {/* Country stats */}
          <div className="glass" style={{ borderRadius:14, padding:16 }}>
            <div className="section-label">COUNTRY STATISTICS</div>
            {Object.entries(countryDist)
              .sort((a, b) => b[1] - a[1])
              .map(([country, count], i) => (
                <div
                  key={country}
                  style={{
                    display:        "flex",
                    justifyContent: "space-between",
                    alignItems:     "center",
                    padding:        "7px 0",
                    borderBottom:   "1px solid #142240",
                    animation:      `fadeUp 0.3s ease ${i * 40}ms both`,
                  }}
                >
                  <span style={{ fontSize:10, color:"#B8D0EE", fontFamily:"'JetBrains Mono',monospace" }}>
                    {country}
                  </span>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div className="progress-track" style={{ width:50 }}>
                      <div
                        className="progress-fill"
                        style={{
                          width:      `${(count / ips.length) * 100}%`,
                          background: "#FF2D55",
                        }}
                      />
                    </div>
                    <span style={{ fontFamily:"'Orbitron',monospace", fontSize:11, fontWeight:700, color:"#FF2D55", minWidth:16, textAlign:"right" }}>
                      {count}
                    </span>
                  </div>
                </div>
              ))}
          </div>

          {/* Category breakdown */}
          <div className="glass" style={{ borderRadius:14, padding:16 }}>
            <div className="section-label">THREAT CATEGORIES</div>
            {Object.entries(categoryDist)
              .sort((a, b) => b[1] - a[1])
              .map(([cat, count], i) => (
                <div
                  key={cat}
                  style={{
                    display:        "flex",
                    justifyContent: "space-between",
                    alignItems:     "center",
                    padding:        "7px 0",
                    borderBottom:   "1px solid #142240",
                    animation:      `fadeUp 0.3s ease ${i * 40}ms both`,
                  }}
                >
                  <span style={{ fontSize:10, color:"#B8D0EE", fontFamily:"'JetBrains Mono',monospace" }}>
                    {cat}
                  </span>
                  <div style={{ display:"flex", alignItems:"center", gap:8 }}>
                    <div className="progress-track" style={{ width:50 }}>
                      <div className="progress-fill" style={{ width:`${(count/ips.length)*100}%`, background:"#00D4FF" }}/>
                    </div>
                    <span style={{ fontFamily:"'Orbitron',monospace", fontSize:11, fontWeight:700, color:"#00D4FF", minWidth:16, textAlign:"right" }}>
                      {count}
                    </span>
                  </div>
                </div>
              ))}
          </div>

        </div>
      </div>
    </div>
  );
}