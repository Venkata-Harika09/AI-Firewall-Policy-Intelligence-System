// ================================================================
// AI Firewall Policy Intelligence System
// src/components/RiskGauge.js
// ================================================================

import React, { useEffect, useState } from "react";
import { riskColor } from "../services/api";

// ================================================================
// RISK GAUGE — SVG arc gauge
// ================================================================
export default function RiskGauge({
  score    = 0,
  level    = "Low",
  size     = 200,
  animated = true,
}) {
  const [current, setCurrent] = useState(0);

  // Animate score on mount / change
  useEffect(() => {
    if (!animated) {
      setCurrent(score);
      return;
    }
    const start    = performance.now();
    const duration = 1000;
    const from     = 0;
    const to       = parseFloat(score) || 0;

    const tick = (now) => {
      const p = Math.min((now - start) / duration, 1);
      const e = 1 - Math.pow(1 - p, 3);
      setCurrent(parseFloat((from + (to - from) * e).toFixed(1)));
      if (p < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  }, [score, animated]);

  const color      = riskColor(level);
  const cx         = size / 2;
  const cy         = size / 2;
  const r          = (size / 2) - 14;
  const circumf    = Math.PI * r;           // half circle
  const pct        = Math.min(current / 10, 1);
  const dash       = pct * circumf;

  // Tick marks
  const ticks = [0, 2, 4, 6, 8, 10];

  const tickAngle = (val) => {
    const angle = (val / 10) * 180 - 180; // -180 to 0 degrees
    return angle;
  };

  const polarToCart = (angleDeg, radius) => {
    const rad = (angleDeg * Math.PI) / 180;
    return {
      x: cx + radius * Math.cos(rad),
      y: cy + radius * Math.sin(rad),
    };
  };

  return (
    <div
      style={{
        display:        "flex",
        flexDirection:  "column",
        alignItems:     "center",
        gap:            8,
      }}
    >
      <svg
        width={size}
        height={size / 2 + 20}
        viewBox={`0 0 ${size} ${size / 2 + 20}`}
        style={{ overflow: "visible" }}
      >
        {/* Background track */}
        <path
          d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
          fill="none"
          stroke="rgba(255,255,255,0.04)"
          strokeWidth={12}
          strokeLinecap="round"
        />

        {/* Colored zones */}
        {[
          { from: 0,  to: 3,  color: "#00E676" },
          { from: 3,  to: 6,  color: "#FFD000" },
          { from: 6,  to: 8,  color: "#FF8800" },
          { from: 8,  to: 10, color: "#FF2D55" },
        ].map((zone, i) => {
          const zFrom = (zone.from / 10) * circumf;
          const zTo   = (zone.to   / 10) * circumf;
          const zLen  = zTo - zFrom;
          return (
            <path
              key={i}
              d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
              fill="none"
              stroke={zone.color}
              strokeWidth={4}
              strokeLinecap="butt"
              strokeOpacity={0.15}
              strokeDasharray={`${zLen} ${circumf - zLen}`}
              strokeDashoffset={-zFrom}
            />
          );
        })}

        {/* Active arc */}
        <path
          d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
          fill="none"
          stroke={color}
          strokeWidth={12}
          strokeLinecap="round"
          strokeDasharray={`${dash} ${circumf - dash}`}
          style={{
            filter:     `drop-shadow(0 0 8px ${color}99)`,
            transition: "stroke-dasharray 0.3s ease",
          }}
        />

        {/* Tick marks */}
        {ticks.map((val) => {
          const angle = tickAngle(val);
          const inner = polarToCart(angle, r - 16);
          const outer = polarToCart(angle, r - 8);
          const label = polarToCart(angle, r - 28);
          return (
            <g key={val}>
              <line
                x1={inner.x} y1={inner.y}
                x2={outer.x} y2={outer.y}
                stroke="rgba(184,208,238,0.2)"
                strokeWidth={1.5}
              />
              <text
                x={label.x}
                y={label.y}
                textAnchor="middle"
                dominantBaseline="middle"
                fill="rgba(58,80,112,0.8)"
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize:   9,
                }}
              >
                {val}
              </text>
            </g>
          );
        })}

        {/* Needle */}
        {(() => {
          const needleAngle = tickAngle(current);
          const tip  = polarToCart(needleAngle, r - 10);
          const base = polarToCart(needleAngle + 90,  8);
          const base2= polarToCart(needleAngle - 90,  8);
          return (
            <g>
              <polygon
                points={`${tip.x},${tip.y} ${base.x},${base.y} ${base2.x},${base2.y}`}
                fill={color}
                opacity={0.9}
                style={{ filter: `drop-shadow(0 0 4px ${color})` }}
              />
              <circle
                cx={cx} cy={cy} r={6}
                fill="#0B1628"
                stroke={color}
                strokeWidth={2}
              />
            </g>
          );
        })()}

        {/* Score display */}
        <text
          x={cx}
          y={cy - 22}
          textAnchor="middle"
          fill={color}
          style={{
            fontFamily: "'Orbitron', monospace",
            fontSize:   size * 0.16,
            fontWeight: 900,
            filter:     `drop-shadow(0 0 8px ${color}88)`,
          }}
        >
          {current.toFixed ? current.toFixed(1) : current}
        </text>

        {/* /10 label */}
        <text
          x={cx}
          y={cy - 6}
          textAnchor="middle"
          fill="rgba(58,80,112,0.8)"
          style={{
            fontFamily: "'JetBrains Mono', monospace",
            fontSize:   10,
            letterSpacing: 2,
          }}
        >
          OUT OF 10
        </text>
      </svg>

      {/* Risk level badge */}
      <div
        style={{
          fontFamily:    "'Orbitron', monospace",
          fontSize:      12,
          fontWeight:    900,
          color,
          letterSpacing: 3,
          textShadow:    `0 0 12px ${color}88`,
          textTransform: "uppercase",
          marginTop:     -8,
        }}
      >
        {level}
      </div>

      {/* Color zone legend */}
      <div
        style={{
          display: "flex",
          gap:     10,
          marginTop: 4,
        }}
      >
        {[
          { label: "Low",      color: "#00E676", range: "0-3"  },
          { label: "Medium",   color: "#FFD000", range: "3-6"  },
          { label: "High",     color: "#FF8800", range: "6-8"  },
          { label: "Critical", color: "#FF2D55", range: "8-10" },
        ].map((z) => (
          <div
            key={z.label}
            style={{
              display:    "flex",
              alignItems: "center",
              gap:        4,
            }}
          >
            <div
              style={{
                width:        6,
                height:       6,
                borderRadius: "50%",
                background:   z.color,
                boxShadow:    `0 0 4px ${z.color}`,
              }}
            />
            <span
              style={{
                fontSize:   8,
                color:      "#3A5070",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {z.range}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ================================================================
// MINI GAUGE — compact version
// ================================================================
export function MiniGauge({ score = 0, level = "Low", size = 100 }) {
  const color   = riskColor(level);
  const cx      = size / 2;
  const cy      = size / 2;
  const r       = (size / 2) - 8;
  const circumf = Math.PI * r;
  const pct     = Math.min(parseFloat(score) / 10, 1);
  const dash    = pct * circumf;

  return (
    <svg
      width={size}
      height={size / 2 + 10}
      viewBox={`0 0 ${size} ${size / 2 + 10}`}
    >
      {/* Track */}
      <path
        d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
        fill="none"
        stroke="rgba(255,255,255,0.04)"
        strokeWidth={6}
        strokeLinecap="round"
      />

      {/* Fill */}
      <path
        d={`M ${cx - r},${cy} A ${r},${r} 0 0,1 ${cx + r},${cy}`}
        fill="none"
        stroke={color}
        strokeWidth={6}
        strokeLinecap="round"
        strokeDasharray={`${dash} ${circumf - dash}`}
        style={{ filter: `drop-shadow(0 0 4px ${color}88)` }}
      />

      {/* Score */}
      <text
        x={cx} y={cy - 4}
        textAnchor="middle"
        fill={color}
        style={{
          fontFamily: "'Orbitron', monospace",
          fontSize:   size * 0.18,
          fontWeight: 900,
        }}
      >
        {parseFloat(score).toFixed(1)}
      </text>
    </svg>
  );
}