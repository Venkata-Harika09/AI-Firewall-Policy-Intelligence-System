// ================================================================
// AI Firewall Policy Intelligence System
// src/components/Loader.js
// ================================================================

import React from "react";

// ================================================================
// SPINNER — small inline loader
// ================================================================
export function Spinner({ size = 16, color = "#00D4FF" }) {
  return (
    <svg
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      style={{ animation: "spin 1s linear infinite", flexShrink: 0 }}
    >
      <circle
        cx="12"
        cy="12"
        r="10"
        stroke={color}
        strokeWidth="2"
        strokeOpacity="0.2"
      />
      <path
        d="M12 2 A10 10 0 0 1 22 12"
        stroke={color}
        strokeWidth="2"
        strokeLinecap="round"
      />
    </svg>
  );
}

// ================================================================
// ANALYZING LOADER — shown while Flask processes
// ================================================================
export function AnalyzingLoader() {
  const stages = [
    { label: "NLP Preprocessing",       icon: "🔤", delay: 0    },
    { label: "Intent Classification",   icon: "🎯", delay: 200  },
    { label: "Rule Generation",         icon: "⚙️",  delay: 400  },
    { label: "Risk Scoring",            icon: "📊", delay: 600  },
    { label: "Threat Intelligence",     icon: "🛡️",  delay: 800  },
    { label: "Attack Simulation",       icon: "🎮", delay: 1000 },
    { label: "Self Healing",            icon: "🔧", delay: 1200 },
    { label: "Explainability",          icon: "📖", delay: 1400 },
  ];

  return (
    <div
      style={{
        display:        "flex",
        flexDirection:  "column",
        alignItems:     "center",
        justifyContent: "center",
        height:         "100%",
        gap:            24,
        padding:        40,
      }}
    >
      {/* Main spinner */}
      <div style={{ position: "relative", width: 80, height: 80 }}>
        {/* Outer ring */}
        <svg
          width="80"
          height="80"
          viewBox="0 0 80 80"
          style={{ position: "absolute", animation: "spin 2s linear infinite" }}
        >
          <circle
            cx="40" cy="40" r="36"
            fill="none"
            stroke="rgba(0,212,255,0.1)"
            strokeWidth="2"
          />
          <path
            d="M 40 4 A 36 36 0 0 1 76 40"
            fill="none"
            stroke="#00D4FF"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>

        {/* Inner ring */}
        <svg
          width="80"
          height="80"
          viewBox="0 0 80 80"
          style={{
            position:  "absolute",
            animation: "spin 1.5s linear infinite reverse",
          }}
        >
          <circle
            cx="40" cy="40" r="26"
            fill="none"
            stroke="rgba(255,45,85,0.1)"
            strokeWidth="2"
          />
          <path
            d="M 40 14 A 26 26 0 0 1 66 40"
            fill="none"
            stroke="#FF2D55"
            strokeWidth="2"
            strokeLinecap="round"
          />
        </svg>

        {/* Center icon */}
        <div
          style={{
            position:       "absolute",
            inset:          0,
            display:        "flex",
            alignItems:     "center",
            justifyContent: "center",
            fontSize:       24,
          }}
        >
          ⚡
        </div>
      </div>

      {/* Title */}
      <div
        style={{
          fontFamily:    "'Orbitron', monospace",
          fontSize:      14,
          fontWeight:    900,
          color:         "#00D4FF",
          letterSpacing: 3,
          textAlign:     "center",
        }}
      >
        ANALYZING POLICY
      </div>

      {/* Subtitle */}
      <div
        style={{
          fontSize:      11,
          color:         "#3A5070",
          letterSpacing: 2,
          textAlign:     "center",
          fontFamily:    "'JetBrains Mono', monospace",
        }}
      >
        RUNNING 14-STAGE AI PIPELINE
      </div>

      {/* Stage indicators */}
      <div
        style={{
          display:             "grid",
          gridTemplateColumns: "repeat(4, 1fr)",
          gap:                 8,
          maxWidth:            420,
          width:               "100%",
        }}
      >
        {stages.map((s, i) => (
          <div
            key={i}
            style={{
              background:    "rgba(11,22,40,0.8)",
              border:        "1px solid #142240",
              borderRadius:  8,
              padding:       "8px 6px",
              textAlign:     "center",
              animation:     `fadeUp 0.4s ease ${s.delay}ms both`,
            }}
          >
            <div style={{ fontSize: 16, marginBottom: 4 }}>{s.icon}</div>
            <div
              style={{
                fontSize:      8,
                color:         "#3A5070",
                fontFamily:    "'JetBrains Mono', monospace",
                letterSpacing: 0.5,
                lineHeight:    1.3,
              }}
            >
              {s.label}
            </div>
          </div>
        ))}
      </div>

      {/* Progress dots */}
      <div style={{ display: "flex", gap: 6 }}>
        {[0, 1, 2].map((i) => (
          <div
            key={i}
            style={{
              width:         6,
              height:        6,
              borderRadius:  "50%",
              background:    "#00D4FF",
              animation:     `pulse 1.2s ease-in-out ${i * 0.2}s infinite`,
            }}
          />
        ))}
      </div>
    </div>
  );
}

// ================================================================
// PAGE LOADER — full page loading screen
// ================================================================
export function PageLoader({ message = "Loading..." }) {
  return (
    <div
      style={{
        display:        "flex",
        flexDirection:  "column",
        alignItems:     "center",
        justifyContent: "center",
        height:         "100%",
        gap:            16,
      }}
    >
      <Spinner size={32} />
      <div
        style={{
          fontFamily:    "'JetBrains Mono', monospace",
          fontSize:      11,
          color:         "#3A5070",
          letterSpacing: 2,
        }}
      >
        {message}
      </div>
    </div>
  );
}

// ================================================================
// SKELETON — placeholder while data loads
// ================================================================
export function Skeleton({ width = "100%", height = 16, borderRadius = 4 }) {
  return (
    <div
      style={{
        width,
        height,
        borderRadius,
        background:     "linear-gradient(90deg, #0B1628, #0F1E35, #0B1628)",
        backgroundSize: "200% 100%",
        animation:      "shimmer 1.5s ease-in-out infinite",
      }}
    />
  );
}

// ================================================================
// DEFAULT EXPORT
// ================================================================
export default AnalyzingLoader; 