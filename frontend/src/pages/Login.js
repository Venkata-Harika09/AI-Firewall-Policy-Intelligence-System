// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Login.js
// ================================================================

import React, { useState, useEffect } from "react";
import { useNavigate } from "react-router-dom";
import { checkHealth } from "../services/api";

// ================================================================
// LOGIN PAGE
// ================================================================
export default function Login({ onLogin }) {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [loading,  setLoading]  = useState(false);
  const [error,    setError]    = useState("");
  const [online,   setOnline]   = useState(null);
  const [dots,     setDots]     = useState("");
  const navigate = useNavigate();

  // ── Animated dots ──────────────────────────────────────────
  useEffect(() => {
    if (!loading) return;
    const id = setInterval(
      () => setDots((d) => (d.length < 3 ? d + "." : "")),
      400
    );
    return () => clearInterval(id);
  }, [loading]);

  // ── Backend status check ───────────────────────────────────
  useEffect(() => {
    const check = async () => {
      try {
        await checkHealth();
        setOnline(true);
      } catch {
        setOnline(false);
      }
    };
    check();
  }, []);

  // ── Handle login ───────────────────────────────────────────
  const handleLogin = async () => {
    if (!username.trim()) {
      setError("Please enter your Analyst ID");
      return;
    }
    setError("");
    setLoading(true);
    // Simulate auth delay
    setTimeout(() => {
      onLogin(username.trim());
      navigate("/home");
    }, 1500);
  };

  const handleKeyDown = (e) => {
    if (e.key === "Enter") handleLogin();
  };

  // ── Milestone badges ───────────────────────────────────────
  const milestones = [
    { label: "M1", desc: "NLP Pipeline",      icon: "🔤" },
    { label: "M2", desc: "Rule Intelligence",  icon: "⚙️"  },
    { label: "M3", desc: "Risk Scoring",       icon: "📊" },
    { label: "M4", desc: "Simulation",         icon: "🎮" },
  ];

  return (
    <div
      style={{
        height:          "100vh",
        width:           "100vw",
        background:      "#020810",
        display:         "flex",
        alignItems:      "center",
        justifyContent:  "center",
        position:        "relative",
        overflow:        "hidden",
        fontFamily:      "'Syne', sans-serif",
      }}
    >
      {/* ── Background grid ──────────────────────────────── */}
      <div
        className="grid-bg"
        style={{
          position:      "absolute",
          inset:         0,
          opacity:       0.04,
          pointerEvents: "none",
        }}
      />

      {/* ── Glow orbs ────────────────────────────────────── */}
      <div
        className="orb orb-cyan"
        style={{
          width:  500,
          height: 500,
          top:    "-10%",
          left:   "5%",
        }}
      />
      <div
        className="orb orb-red"
        style={{
          width:  400,
          height: 400,
          bottom: "10%",
          right:  "10%",
        }}
      />
      <div
        className="orb orb-cyan"
        style={{
          width:  300,
          height: 300,
          bottom: "20%",
          left:   "20%",
          opacity: 0.5,
        }}
      />

      {/* ── Main card ────────────────────────────────────── */}
      <div
        className="glass glass-cyan scanline-wrap"
        style={{
          width:         420,
          borderRadius:  20,
          padding:       "40px 36px",
          animation:     "fadeUp 0.7s ease",
          position:      "relative",
          zIndex:        1,
        }}
      >
        {/* Logo */}
        <div style={{ textAlign: "center", marginBottom: 32 }}>
          <div
            style={{
              fontSize:      48,
              marginBottom:  12,
              animation:     "float 4s ease-in-out infinite",
              display:       "inline-block",
            }}
          >
            ⚡
          </div>
          <div
            style={{
              fontFamily:    "'Orbitron', monospace",
              fontSize:      24,
              fontWeight:    900,
              color:         "#00D4FF",
              letterSpacing: 4,
              textShadow:    "0 0 20px rgba(0,212,255,0.4)",
              marginBottom:  6,
            }}
          >
            AI FIREWALL
          </div>
          <div
            style={{
              fontSize:      10,
              color:         "#3A5070",
              letterSpacing: 3,
              fontFamily:    "'JetBrains Mono', monospace",
            }}
          >
            POLICY INTELLIGENCE SYSTEM
          </div>
        </div>

        {/* Backend status */}
        <div
          style={{
            display:        "flex",
            alignItems:     "center",
            justifyContent: "center",
            gap:            6,
            marginBottom:   24,
            padding:        "6px 14px",
            borderRadius:   6,
            background:     online === null
              ? "rgba(58,80,112,0.1)"
              : online
              ? "rgba(0,230,118,0.08)"
              : "rgba(255,45,85,0.08)",
            border: `1px solid ${
              online === null
                ? "#142240"
                : online
                ? "rgba(0,230,118,0.25)"
                : "rgba(255,45,85,0.25)"
            }`,
          }}
        >
          <div
            className={
              online === null
                ? "status-dot status-pending"
                : online
                ? "status-dot status-active"
                : "status-dot status-error"
            }
          />
          <span
            style={{
              fontSize:      9,
              fontFamily:    "'JetBrains Mono', monospace",
              fontWeight:    700,
              letterSpacing: 1.5,
              color:         online === null
                ? "#3A5070"
                : online
                ? "#00E676"
                : "#FF2D55",
            }}
          >
            {online === null
              ? "CHECKING BACKEND..."
              : online
              ? "FLASK API ONLINE — READY"
              : "FLASK API OFFLINE — START python api/app.py"}
          </span>
        </div>

        {/* Inputs */}
        <div style={{ marginBottom: 14 }}>
          <div className="section-label" style={{ marginBottom: 6 }}>
            ANALYST ID
          </div>
          <input
            className="fw-input"
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Enter your analyst ID"
            autoFocus
          />
        </div>

        <div style={{ marginBottom: 20 }}>
          <div className="section-label" style={{ marginBottom: 6 }}>
            ACCESS TOKEN
          </div>
          <input
            className="fw-input"
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="••••••••••••"
          />
        </div>

        {/* Error */}
        {error && (
          <div
            style={{
              marginBottom:  14,
              padding:       "8px 12px",
              borderRadius:  6,
              background:    "rgba(255,45,85,0.08)",
              border:        "1px solid rgba(255,45,85,0.25)",
              fontSize:      11,
              color:         "#FF2D55",
              fontFamily:    "'JetBrains Mono', monospace",
            }}
          >
            ⚠ {error}
          </div>
        )}

        {/* Login button */}
        <button
          className="btn-primary"
          onClick={handleLogin}
          disabled={loading}
          style={{ marginBottom: 24 }}
        >
          {loading ? (
            <>
              <span
                style={{
                  display:   "inline-block",
                  animation: "spin 1s linear infinite",
                }}
              >
                ◌
              </span>
              AUTHENTICATING{dots}
            </>
          ) : (
            "▶  ENTER SOC DASHBOARD"
          )}
        </button>

        {/* Divider */}
        <div className="fw-divider" />

        {/* Milestone badges */}
        <div style={{ marginTop: 20 }}>
          <div
            className="section-label"
            style={{ textAlign: "center", marginBottom: 12 }}
          >
            ACTIVE MILESTONES
          </div>
          <div
            style={{
              display:             "grid",
              gridTemplateColumns: "repeat(4, 1fr)",
              gap:                 8,
            }}
          >
            {milestones.map((m, i) => (
              <div
                key={m.label}
                style={{
                  background:    "rgba(0,212,255,0.04)",
                  border:        "1px solid rgba(0,212,255,0.12)",
                  borderRadius:  8,
                  padding:       "8px 4px",
                  textAlign:     "center",
                  animation:     `fadeUp 0.4s ease ${i * 80}ms both`,
                }}
              >
                <div style={{ fontSize: 16, marginBottom: 4 }}>
                  {m.icon}
                </div>
                <div
                  style={{
                    fontFamily:    "'Orbitron', monospace",
                    fontSize:      9,
                    fontWeight:    700,
                    color:         "#00D4FF",
                    marginBottom:  2,
                  }}
                >
                  {m.label}
                </div>
                <div
                  style={{
                    fontSize:      7,
                    color:         "#3A5070",
                    fontFamily:    "'JetBrains Mono', monospace",
                    lineHeight:    1.3,
                  }}
                >
                  {m.desc}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Footer note */}
        <div
          style={{
            marginTop:  20,
            textAlign:  "center",
            fontSize:   9,
            color:      "#3A5070",
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: 1,
          }}
        >
          SVM 100% · GRADIENTBOOSTING 100% · 199 RULES
        </div>
      </div>
    </div>
  );
}