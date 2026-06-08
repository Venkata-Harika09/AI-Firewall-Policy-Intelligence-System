// ================================================================
// AI Firewall Policy Intelligence System
// src/components/HealingCard.js
// ================================================================

import React, { useState } from "react";

// ── Severity color mapping ─────────────────────────────────────
const SEVERITY_COLORS = {
  CRITICAL: {
    color: "#FF2D55",
    bg: "rgba(255,45,85,0.08)",
    border: "rgba(255,45,85,0.3)",
    glow: "rgba(255,45,85,0.4)",
  },
  HIGH: {
    color: "#FF8800",
    bg: "rgba(255,136,0,0.08)",
    border: "rgba(255,136,0,0.3)",
    glow: "rgba(255,136,0,0.4)",
  },
  MEDIUM: {
    color: "#FFD600",
    bg: "rgba(255,214,0,0.08)",
    border: "rgba(255,214,0,0.3)",
    glow: "rgba(255,214,0,0.3)",
  },
  LOW: {
    color: "#00E676",
    bg: "rgba(0,230,118,0.08)",
    border: "rgba(0,230,118,0.3)",
    glow: "rgba(0,230,118,0.3)",
  },
  INFO: {
    color: "#00D4FF",
    bg: "rgba(0,212,255,0.08)",
    border: "rgba(0,212,255,0.3)",
    glow: "rgba(0,212,255,0.3)",
  },
};

// ── Severity icons ─────────────────────────────────────────────
const SEVERITY_ICONS = {
  CRITICAL: "⚠",
  HIGH: "▲",
  MEDIUM: "◆",
  LOW: "●",
  INFO: "ℹ",
};

// ================================================================
// HEALING CARD
// ================================================================
export default function HealingCard({
  recommendation,
  index = 0,
  onApply,
}) {
  const [expanded, setExpanded] = useState(false);
  const [applied, setApplied] = useState(false);
  const [copied, setCopied] = useState(false);

  // ── Safe destructuring with defaults ──────────────────────
  const {
    title = "Security Recommendation",
    description = "No description available",
    severity = "INFO",
    suggested_rule = "",
    reason = "",
    impact = "",
    category = "GENERAL",
  } = recommendation || {};

  const sev =
    SEVERITY_COLORS[severity?.toUpperCase()] ||
    SEVERITY_COLORS.INFO;

  const icon =
    SEVERITY_ICONS[severity?.toUpperCase()] || "●";

  // ── Apply handler ─────────────────────────────────────────
  const handleApply = () => {
    setApplied(true);
    if (onApply) {
      onApply(recommendation);
    }
  };

  // ── Copy rule to clipboard ────────────────────────────────
  const handleCopy = async () => {
    if (!suggested_rule) return;
    try {
      await navigator.clipboard.writeText(suggested_rule);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch (err) {
      console.error("Copy failed:", err);
    }
  };

  return (
    <div
      className="glass"
      style={{
        background: "rgba(2,8,16,0.6)",
        border: `1px solid ${sev.border}`,
        borderLeft: `3px solid ${sev.color}`,
        borderRadius: 8,
        padding: 16,
        display: "flex",
        flexDirection: "column",
        gap: 12,
        transition: "all 0.2s ease",
        position: "relative",
        overflow: "hidden",
      }}
      onMouseEnter={(e) => {
        e.currentTarget.style.boxShadow = `0 0 20px ${sev.glow}`;
      }}
      onMouseLeave={(e) => {
        e.currentTarget.style.boxShadow = "none";
      }}
    >
      {/* Applied overlay indicator */}
      {applied && (
        <div
          style={{
            position: "absolute",
            top: 8,
            right: 8,
            padding: "3px 8px",
            background: "rgba(0,230,118,0.15)",
            border: "1px solid rgba(0,230,118,0.4)",
            borderRadius: 4,
            fontSize: 8,
            fontFamily: "'JetBrains Mono', monospace",
            color: "#00E676",
            fontWeight: 700,
            letterSpacing: 1.5,
          }}
        >
          ✓ APPLIED
        </div>
      )}

      {/* ==========================================================
          HEADER
      ========================================================== */}
      <div
        style={{
          display: "flex",
          alignItems: "flex-start",
          gap: 12,
        }}
      >
        {/* Index badge */}
        <div
          style={{
            minWidth: 28,
            height: 28,
            borderRadius: 6,
            background: sev.bg,
            border: `1px solid ${sev.border}`,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            fontSize: 11,
            fontFamily: "'Orbitron', monospace",
            fontWeight: 900,
            color: sev.color,
          }}
        >
          {String(index + 1).padStart(2, "0")}
        </div>

        {/* Title + meta */}
        <div style={{ flex: 1, minWidth: 0 }}>
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 8,
              marginBottom: 4,
              flexWrap: "wrap",
            }}
          >
            <span
              style={{
                fontSize: 12,
                color: sev.color,
                fontWeight: 700,
              }}
            >
              {icon}
            </span>

            <span
              style={{
                fontSize: 13,
                color: "#B8D0EE",
                fontFamily: "'JetBrains Mono', monospace",
                fontWeight: 700,
              }}
            >
              {title}
            </span>
          </div>

          {/* Badges */}
          <div
            style={{
              display: "flex",
              gap: 6,
              alignItems: "center",
              flexWrap: "wrap",
            }}
          >
            <span
              style={{
                fontSize: 8,
                fontFamily: "'JetBrains Mono', monospace",
                color: sev.color,
                background: sev.bg,
                border: `1px solid ${sev.border}`,
                padding: "2px 6px",
                borderRadius: 3,
                letterSpacing: 1.5,
                fontWeight: 700,
              }}
            >
              {severity?.toUpperCase() || "INFO"}
            </span>

            <span
              style={{
                fontSize: 8,
                fontFamily: "'JetBrains Mono', monospace",
                color: "#3A5070",
                background: "rgba(58,80,112,0.1)",
                border: "1px solid #142240",
                padding: "2px 6px",
                borderRadius: 3,
                letterSpacing: 1.5,
                fontWeight: 700,
              }}
            >
              {category?.toUpperCase()}
            </span>
          </div>
        </div>
      </div>

      {/* ==========================================================
          DESCRIPTION
      ========================================================== */}
      <div
        style={{
          fontSize: 11,
          color: "#7A8FA8",
          fontFamily: "'JetBrains Mono', monospace",
          lineHeight: 1.6,
        }}
      >
        {description}
      </div>

      {/* ==========================================================
          SUGGESTED RULE
      ========================================================== */}
      {suggested_rule && (
        <div
          style={{
            background: "rgba(0,0,0,0.4)",
            border: "1px solid #142240",
            borderRadius: 6,
            padding: "10px 12px",
            position: "relative",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              marginBottom: 6,
            }}
          >
            <span
              style={{
                fontSize: 8,
                color: "#00D4FF",
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: 2,
                fontWeight: 700,
              }}
            >
              ❯ SUGGESTED RULE
            </span>

            <button
              onClick={handleCopy}
              style={{
                background: "transparent",
                border: "none",
                color: copied ? "#00E676" : "#3A5070",
                fontSize: 9,
                fontFamily: "'JetBrains Mono', monospace",
                cursor: "pointer",
                letterSpacing: 1,
                fontWeight: 700,
                transition: "color 0.2s ease",
              }}
            >
              {copied ? "✓ COPIED" : "⧉ COPY"}
            </button>
          </div>

          <code
            style={{
              fontSize: 11,
              color: "#00D4FF",
              fontFamily: "'JetBrains Mono', monospace",
              wordBreak: "break-all",
              display: "block",
              lineHeight: 1.5,
            }}
          >
            {suggested_rule}
          </code>
        </div>
      )}

      {/* ==========================================================
          EXPANDED DETAILS
      ========================================================== */}
      {expanded && (reason || impact) && (
        <div
          style={{
            display: "flex",
            flexDirection: "column",
            gap: 10,
            paddingTop: 10,
            borderTop: "1px dashed #142240",
          }}
        >
          {reason && (
            <div>
              <div
                style={{
                  fontSize: 8,
                  color: "#FF8800",
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: 2,
                  fontWeight: 700,
                  marginBottom: 4,
                }}
              >
                ▸ REASON
              </div>
              <div
                style={{
                  fontSize: 10,
                  color: "#B8D0EE",
                  fontFamily: "'JetBrains Mono', monospace",
                  lineHeight: 1.6,
                }}
              >
                {reason}
              </div>
            </div>
          )}

          {impact && (
            <div>
              <div
                style={{
                  fontSize: 8,
                  color: "#00E676",
                  fontFamily: "'JetBrains Mono', monospace",
                  letterSpacing: 2,
                  fontWeight: 700,
                  marginBottom: 4,
                }}
              >
                ▸ IMPACT
              </div>
              <div
                style={{
                  fontSize: 10,
                  color: "#B8D0EE",
                  fontFamily: "'JetBrains Mono', monospace",
                  lineHeight: 1.6,
                }}
              >
                {impact}
              </div>
            </div>
          )}
        </div>
      )}

      {/* ==========================================================
          ACTIONS
      ========================================================== */}
      <div
        style={{
          display: "flex",
          gap: 8,
          alignItems: "center",
          justifyContent: "space-between",
          marginTop: 2,
        }}
      >
        {/* Expand toggle */}
        {(reason || impact) && (
          <button
            onClick={() => setExpanded(!expanded)}
            style={{
              background: "transparent",
              border: "none",
              color: "#7A8FA8",
              fontSize: 9,
              fontFamily: "'JetBrains Mono', monospace",
              cursor: "pointer",
              letterSpacing: 1,
              fontWeight: 700,
              padding: 0,
            }}
          >
            {expanded ? "▲ LESS" : "▼ MORE DETAILS"}
          </button>
        )}

        <div style={{ flex: 1 }} />

        {/* Apply button */}
        {!applied && (
          <button
            onClick={handleApply}
            style={{
              padding: "6px 14px",
              background: sev.bg,
              border: `1px solid ${sev.border}`,
              borderRadius: 5,
              color: sev.color,
              fontSize: 9,
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 900,
              letterSpacing: 1.5,
              cursor: "pointer",
              transition: "all 0.2s ease",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.boxShadow = `0 0 12px ${sev.glow}`;
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.boxShadow = "none";
            }}
          >
            ✓ APPLY FIX
          </button>
        )}
      </div>
    </div>
  );
}