// ================================================================
// AI Firewall Policy Intelligence System
// src/components/Navbar.js
// ================================================================

import React, { useState, useEffect } from "react";
import { checkHealth } from "../services/api";

// ── Ticker messages ────────────────────────────────────────────
const TICKER_MSGS = [
  "🚨 SSH brute-force risk detected — port 22 exposed to internet",
  "🔥 MongoDB port 27017 — unauthenticated access possible",
  "⚠️ RDP port 3389 publicly accessible — ransomware risk",
  "🛡️ Self-healing applied — VPN restriction enforced",
  "🔴 CRITICAL: Allow SSH from any → Risk Score 9.8/10",
  "✅ Deny rule applied — attack surface reduced to 0",
  "⚡ BFS simulation: 776 attack paths discovered",
  "🎯 DATABASE node reachable in 2 hops from internet",
  "🤖 GradientBoosting model: 100% accuracy, 87.3% CV",
  "🔧 4 self-healing recommendations generated",
];

// ================================================================
// NAVBAR
// ================================================================
export default function Navbar({
  user,
  reports = [],
}) {
  const [online, setOnline] = useState(null);
  const [time, setTime] = useState(new Date());

  // ── Clock ──────────────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => {
      setTime(new Date());
    }, 1000);

    return () => clearInterval(id);
  }, []);

  // ── Backend health check ───────────────────────────────────
  useEffect(() => {
    const healthCheck = async () => {
      try {
        await checkHealth();
        setOnline(true);
      } catch {
        setOnline(false);
      }
    };

    healthCheck();

    const id = setInterval(
      healthCheck,
      30000
    );

    return () => clearInterval(id);
  }, []);

  // ── Safe reports handling ──────────────────────────────────
  const safeReports = reports || [];

  const critCount = safeReports.filter(
    (r) => r.risk_level === "Critical"
  ).length;

  const avgRisk = safeReports.length
    ? (
        safeReports.reduce(
          (sum, r) =>
            sum +
            (Number(r.risk_score) || 0),
          0
        ) / safeReports.length
      ).toFixed(1)
    : null;

  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        zIndex: 10,
      }}
    >
      {/* ==========================================================
          MAIN NAVBAR
      ========================================================== */}
      <div
        className="glass"
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          padding: "0 20px",
          height: 52,
          borderBottom: "1px solid #142240",
          borderRadius: 0,
          gap: 16,
        }}
      >
        {/* LEFT */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 12,
          }}
        >
          <div
            style={{
              fontFamily:
                "'Orbitron', monospace",
              fontSize: 11,
              fontWeight: 700,
              color: "#00D4FF",
              letterSpacing: 3,
            }}
          >
            AI FIREWALL
          </div>

          <div
            style={{
              width: 1,
              height: 16,
              background: "#142240",
            }}
          />

          <div
            style={{
              fontSize: 9,
              color: "#3A5070",
              fontFamily:
                "'JetBrains Mono', monospace",
              letterSpacing: 2,
            }}
          >
            POLICY INTELLIGENCE SYSTEM
          </div>
        </div>

        {/* CENTER STATS */}
        <div
          style={{
            display: "flex",
            gap: 20,
            alignItems: "center",
          }}
        >
          {[
            {
              label: "RULES",
              value: safeReports.length,
              color: "#00D4FF",
            },
            {
              label: "CRITICAL",
              value: critCount,
              color:
                critCount > 0
                  ? "#FF2D55"
                  : "#3A5070",
            },
            {
              label: "AVG RISK",
              value: avgRisk ?? "—",
              color:
                avgRisk >= 7
                  ? "#FF2D55"
                  : avgRisk >= 5
                  ? "#FF8800"
                  : "#00D4FF",
            },
          ].map(
            ({
              label,
              value,
              color,
            }) => (
              <div
                key={label}
                style={{
                  textAlign: "center",
                }}
              >
                <div
                  style={{
                    fontFamily:
                      "'Orbitron', monospace",
                    fontSize: 14,
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
                    fontSize: 7,
                    color: "#3A5070",
                    letterSpacing: 1.5,
                    fontFamily:
                      "'JetBrains Mono', monospace",
                    marginTop: 2,
                  }}
                >
                  {label}
                </div>
              </div>
            )
          )}
        </div>

        {/* RIGHT */}
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 16,
          }}
        >
          {/* API STATUS */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "4px 10px",
              background:
                online === null
                  ? "rgba(58,80,112,0.1)"
                  : online
                  ? "rgba(0,230,118,0.08)"
                  : "rgba(255,45,85,0.08)",

              border: `1px solid ${
                online === null
                  ? "#142240"
                  : online
                  ? "rgba(0,230,118,0.3)"
                  : "rgba(255,45,85,0.3)"
              }`,

              borderRadius: 6,
            }}
          >
            <div
              style={{
                width: 5,
                height: 5,
                borderRadius: "50%",
                background:
                  online === null
                    ? "#3A5070"
                    : online
                    ? "#00E676"
                    : "#FF2D55",

                boxShadow:
                  online === null
                    ? "none"
                    : online
                    ? "0 0 8px #00E676"
                    : "0 0 8px #FF2D55",
              }}
            />

            <span
              style={{
                fontSize: 9,
                fontFamily:
                  "'JetBrains Mono', monospace",
                fontWeight: 700,
                letterSpacing: 1,
                color:
                  online === null
                    ? "#3A5070"
                    : online
                    ? "#00E676"
                    : "#FF2D55",
              }}
            >
              {online === null
                ? "CHECKING"
                : online
                ? "API ONLINE"
                : "API OFFLINE"}
            </span>
          </div>

          {/* CLOCK */}
          <div
            style={{
              fontFamily:
                "'JetBrains Mono', monospace",
              fontSize: 11,
              color: "#3A5070",
              letterSpacing: 1,
            }}
          >
            {time.toLocaleTimeString()}
          </div>

          {/* USER */}
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 6,
              padding: "4px 10px",
              background:
                "rgba(0,212,255,0.06)",
              border:
                "1px solid rgba(0,212,255,0.2)",
              borderRadius: 6,
            }}
          >
            <div
              style={{
                width: 20,
                height: 20,
                borderRadius: "50%",
                background:
                  "rgba(0,212,255,0.15)",
                border:
                  "1px solid rgba(0,212,255,0.3)",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                fontSize: 10,
                fontWeight: 700,
                color: "#00D4FF",
              }}
            >
              {user?.[0]?.toUpperCase() ||
                "A"}
            </div>

            <span
              style={{
                fontSize: 11,
                color: "#B8D0EE",
                fontFamily:
                  "'JetBrains Mono', monospace",
              }}
            >
              {user || "Analyst"}
            </span>
          </div>
        </div>
      </div>

      {/* ==========================================================
          THREAT TICKER
      ========================================================== */}
      <div
        style={{
          background:
            "rgba(255,45,85,0.05)",
          borderBottom:
            "1px solid rgba(255,45,85,0.15)",
          padding: "5px 0",
          overflow: "hidden",
          position: "relative",
          height: 28,
          display: "flex",
          alignItems: "center",
        }}
      >
        <div
          style={{
            position: "absolute",
            left: 12,
            zIndex: 3,
            fontSize: 8,
            fontFamily:
              "'JetBrains Mono', monospace",
            fontWeight: 700,
            color: "#FF2D55",
            letterSpacing: 1.5,
            background: "#020810",
            padding: "2px 6px",
            borderRadius: 3,
          }}
        >
          LIVE
        </div>

        <div
          style={{
            display: "flex",
            whiteSpace: "nowrap",
            animation:
              "ticker 40s linear infinite",
            paddingLeft: 60,
          }}
        >
          {[...TICKER_MSGS, ...TICKER_MSGS].map(
            (msg, i) => (
              <span
                key={i}
                style={{
                  fontSize: 10,
                  color:
                    i % 2 === 0
                      ? "#FF2D55"
                      : "#B8D0EE",
                  fontFamily:
                    "'JetBrains Mono', monospace",
                  padding: "0 40px",
                  opacity: 0.85,
                }}
              >
                {msg}
              </span>
            )
          )}
        </div>
      </div>
    </div>
  );
}