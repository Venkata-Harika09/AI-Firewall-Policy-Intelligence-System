// ================================================================
// AI Firewall Policy Intelligence System
// src/components/PolicyInput.js
// ================================================================

import React, { useState, useEffect, useRef } from "react";

// ── Quick Suggestions ──────────────────────────────────────────
const SUGGESTIONS = [
  "Allow SSH from any IP",
  "Block MongoDB port 27017 from internet",
  "Deny RDP access from external networks",
  "Allow HTTPS traffic on port 443",
  "Restrict database access to internal subnet only",
  "Block all inbound telnet connections",
];

// ── Max characters ─────────────────────────────────────────────
const MAX_CHARS = 500;

// ================================================================
// POLICY INPUT
// ================================================================
export default function PolicyInput({
  onAnalyze,
  loading = false,
}) {
  const [policy, setPolicy] = useState("");
  const [focused, setFocused] = useState(false);
  const textareaRef = useRef(null);

  // ── Auto-focus on mount ───────────────────────────────────
  useEffect(() => {
    textareaRef.current?.focus();
  }, []);

  // ── Submit handler ────────────────────────────────────────
 const handleSubmit = () => {
  const trimmed = policy.trim();
  if (!trimmed || loading) {
    return;
  }
  onAnalyze(trimmed);
  // Keep policy visible after analysis
  // so user can modify and rerun quickly
};

  // ── Keyboard shortcut: Ctrl+Enter ─────────────────────────
  const handleKeyDown = (e) => {
    if ((e.ctrlKey || e.metaKey) && e.key === "Enter") {
      e.preventDefault();
      handleSubmit();
    }
  };

  // ── Clear ─────────────────────────────────────────────────
  const handleClear = () => {
    setPolicy("");
    textareaRef.current?.focus();
  };

  // ── Suggestion click ──────────────────────────────────────
  const handleSuggestionClick = (text) => {
    setPolicy(text);
    textareaRef.current?.focus();
  };

  const charsLeft = MAX_CHARS - policy.length;
  const charColor =
    charsLeft < 25
      ? "#FF2D55"
      : charsLeft < 100
      ? "#FF8800"
      : "#3A5070";

  return (
    <div
      className="glass"
      style={{
        background: "rgba(2,8,16,0.6)",
        border: "1px solid #142240",
        borderRadius: 10,
        padding: 20,
        display: "flex",
        flexDirection: "column",
        gap: 14,
      }}
    >
      {/* ==========================================================
          HEADER
      ========================================================== */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
        }}
      >
        <div
          style={{
            display: "flex",
            alignItems: "center",
            gap: 10,
          }}
        >
          <div
            style={{
              width: 6,
              height: 6,
              borderRadius: "50%",
              background: "#00D4FF",
              boxShadow: "0 0 8px #00D4FF",
            }}
          />
          <div
            style={{
              fontFamily: "'Orbitron', monospace",
              fontSize: 12,
              fontWeight: 900,
              color: "#00D4FF",
              letterSpacing: 2,
            }}
          >
            POLICY INPUT
          </div>
          <div
            style={{
              fontSize: 8,
              color: "#3A5070",
              fontFamily: "'JetBrains Mono', monospace",
              letterSpacing: 1.5,
            }}
          >
            · NATURAL LANGUAGE
          </div>
        </div>

        <div
          style={{
            fontSize: 9,
            color: charColor,
            fontFamily: "'JetBrains Mono', monospace",
            fontWeight: 700,
            letterSpacing: 1,
          }}
        >
          {policy.length} / {MAX_CHARS}
        </div>
      </div>

      {/* ==========================================================
          TEXTAREA
      ========================================================== */}
      <div
        style={{
          position: "relative",
          border: `1px solid ${
            focused ? "rgba(0,212,255,0.4)" : "#142240"
          }`,
          borderRadius: 8,
          background: "rgba(0,0,0,0.3)",
          transition: "all 0.2s ease",
          boxShadow: focused
            ? "0 0 16px rgba(0,212,255,0.15)"
            : "none",
        }}
      >
        <div
          style={{
            position: "absolute",
            top: 10,
            left: 12,
            fontSize: 10,
            fontFamily: "'JetBrains Mono', monospace",
            color: "#00D4FF",
            fontWeight: 700,
            letterSpacing: 1,
            zIndex: 1,
          }}
        >
          ❯
        </div>

        <textarea
          ref={textareaRef}
          value={policy}
          onChange={(e) => {
            if (e.target.value.length <= MAX_CHARS) {
              setPolicy(e.target.value);
            }
          }}
          onKeyDown={handleKeyDown}
          onFocus={() => setFocused(true)}
          onBlur={() => setFocused(false)}
          placeholder={`Describe your firewall policy in plain English...
            
          Examples:
          • Allow SSH from any IP
          • Block MongoDB port 27017 from internet
          • Allow HTTPS traffic on port 443`}
          disabled={loading}
          rows={5}
          style={{
            width: "100%",
            background: "transparent",
            border: "none",
            outline: "none",
            color: "#B8D0EE",
            fontFamily: "'JetBrains Mono', monospace",
            fontSize: 12,
            lineHeight: 1.6,
            padding: "10px 12px 10px 28px",
            resize: "vertical",
            minHeight: 100,
          }}
        />
      </div>

      {/* ==========================================================
          SUGGESTION CHIPS
      ========================================================== */}
      <div
        style={{
          display: "flex",
          flexDirection: "column",
          gap: 6,
        }}
      >
        <div
           style={{
                fontSize: 8,
                color: "#3A5070",
                fontFamily: "'JetBrains Mono', monospace",
                letterSpacing: 0.5,
                paddingLeft: 2,
        }}
       >
        NLP → Rule Generation → Risk Scoring → Threat Intel →
        Simulation → Self Healing → Explainability
       </div>

        <div
          style={{
            display: "flex",
            flexWrap: "wrap",
            gap: 6,
          }}
        >
          {SUGGESTIONS.map((suggestion, i) => (
            <button
              key={i}
              onClick={() => {
                if (!loading) {
                    handleSuggestionClick(suggestion);
              }
       }}
              disabled={loading}
              style={{
                background: "rgba(0,212,255,0.04)",
                border: "1px solid rgba(0,212,255,0.15)",
                color: "#7A8FA8",
                fontSize: 10,
                fontFamily: "'JetBrains Mono', monospace",
                padding: "5px 10px",
                borderRadius: 4,
                cursor: loading ? "not-allowed" : "pointer",
                transition: "all 0.15s ease",
                opacity: loading ? 0.5 : 1,
              }}
              onMouseEnter={(e) => {
                if (!loading) {
                  e.currentTarget.style.background =
                    "rgba(0,212,255,0.1)";
                  e.currentTarget.style.color = "#00D4FF";
                  e.currentTarget.style.borderColor =
                    "rgba(0,212,255,0.3)";
                }
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background =
                  "rgba(0,212,255,0.04)";
                e.currentTarget.style.color = "#7A8FA8";
                e.currentTarget.style.borderColor =
                  "rgba(0,212,255,0.15)";
              }}
            >
              {suggestion}
            </button>
          ))}
        </div>
      </div>

      {/* ==========================================================
          ACTION BUTTONS
      ========================================================== */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          justifyContent: "space-between",
          gap: 10,
          marginTop: 4,
        }}
      >
        {/* HINT */}
        <div
          style={{
            fontSize: 9,
            color: "#3A5070",
            fontFamily: "'JetBrains Mono', monospace",
            letterSpacing: 1,
          }}
        >
          <span style={{ color: "#00D4FF" }}>Ctrl + Enter</span> to analyze
        </div>

        {/* BUTTONS */}
        <div style={{ display: "flex", gap: 8 }}>
          <button
            onClick={handleClear}
            disabled={loading || !policy}
            style={{
              padding: "8px 16px",
              background: "transparent",
              border: "1px solid #142240",
              borderRadius: 6,
              color: "#7A8FA8",
              fontSize: 10,
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 700,
              letterSpacing: 1.5,
              cursor:
                loading || !policy ? "not-allowed" : "pointer",
              opacity: loading || !policy ? 0.4 : 1,
              transition: "all 0.2s ease",
            }}
          >
            CLEAR
          </button>

          <button
            onClick={handleSubmit}
            disabled={loading || !policy.trim()}
            style={{
              padding: "8px 22px",
              background: loading
                ? "rgba(0,212,255,0.1)"
                : "linear-gradient(135deg, #00D4FF 0%, #0088CC 100%)",
              border: "1px solid rgba(0,212,255,0.4)",
              borderRadius: 6,
              color: loading ? "#00D4FF" : "#020810",
              fontSize: 10,
              fontFamily: "'JetBrains Mono', monospace",
              fontWeight: 900,
              letterSpacing: 2,
              cursor:
                loading || !policy.trim()
                  ? "not-allowed"
                  : "pointer",
              opacity: !policy.trim() ? 0.4 : 1,
              transition: "all 0.2s ease",
              boxShadow:
                loading || !policy.trim()
                  ? "none"
                  : "0 0 16px rgba(0,212,255,0.4)",
              display: "flex",
              alignItems: "center",
              gap: 8,
            }}
          >
            {loading ? (
              <>
                <span
                  style={{
                    display: "inline-block",
                    width: 10,
                    height: 10,
                    border: "2px solid rgba(0,212,255,0.3)",
                    borderTopColor: "#00D4FF",
                    borderRadius: "50%",
                    animation: "spin 0.8s linear infinite",
                  }}
                />
                ANALYZING
              </>
            ) : (
              <>▶ ANALYZE</>
            )}
          </button>
        </div>
      </div>
    </div>
  );
}