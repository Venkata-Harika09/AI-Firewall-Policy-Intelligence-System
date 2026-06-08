// ================================================================
// AI Firewall Policy Intelligence System
// src/components/StatCard.js
// ================================================================

import React, { useEffect, useRef, useState } from "react";

// ================================================================
// ANIMATED COUNTER
// ================================================================

function AnimatedCounter({
  value = 0,
  decimals = 1,
  duration = 900,
}) {
  const [display, setDisplay] = useState(0);
  const raf = useRef(null);

  useEffect(() => {
    const start = performance.now();

    const from = 0;
    const to = Number(value) || 0;

    const tick = (now) => {
      const progress = Math.min(
        (now - start) / duration,
        1
      );

      const eased =
        1 - Math.pow(1 - progress, 3);

      const current =
        from + (to - from) * eased;

      setDisplay(
        Number(current).toFixed(decimals)
      );

      if (progress < 1) {
        raf.current =
          requestAnimationFrame(tick);
      }
    };

    raf.current =
      requestAnimationFrame(tick);

    return () => {
      if (raf.current) {
        cancelAnimationFrame(raf.current);
      }
    };
  }, [value, decimals, duration]);

  return display;
}

// ================================================================
// MAIN STAT CARD
// ================================================================

export default function StatCard({
  icon,
  label,
  value = 0,
  sub,
  color = "#00D4FF",
  delay = 0,
  decimals = 1,
  suffix = "",
  onClick,
}) {
  const numericValue = Number(value) || 0;

  const isInteger =
    Number.isInteger(numericValue);

  return (
    <div
      onClick={onClick}
      className="glass card-hover"
      style={{
        borderRadius: 14,
        padding: "18px 20px",
        borderLeft: `3px solid ${color}`,
        cursor: onClick
          ? "pointer"
          : "default",
        animation: `fadeUp 0.5s ease ${delay}ms both`,
        position: "relative",
        overflow: "hidden",
      }}
    >
      {/* Scanline */}
      <div
        style={{
          position: "absolute",
          top: 0,
          left: 0,
          right: 0,
          height: 1,
          background: `linear-gradient(
            90deg,
            transparent,
            ${color}44,
            transparent
          )`,
          animation:
            "scanline 4s linear infinite",
        }}
      />

      {/* Header */}
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: 8,
          marginBottom: 10,
        }}
      >
        {icon && (
          <span style={{ fontSize: 16 }}>
            {icon}
          </span>
        )}

        <span
          className="section-label"
          style={{
            marginBottom: 0,
          }}
        >
          {label || "Metric"}
        </span>
      </div>

      {/* Value */}
      <div
        className="orb-number"
        style={{
          fontSize: 28,
          fontWeight: 900,
          color,
          lineHeight: 1,
          textShadow: `0 0 16px ${color}66`,
          marginBottom: 6,
        }}
      >
        <AnimatedCounter
          value={numericValue}
          decimals={
            isInteger
              ? 0
              : decimals
          }
        />

        {suffix && (
          <span
            style={{
              fontSize: 14,
              marginLeft: 4,
              opacity: 0.7,
            }}
          >
            {suffix}
          </span>
        )}
      </div>

      {/* Sub Text */}
      {sub && (
        <div
          style={{
            fontSize: 10,
            color: "#3A5070",
            fontFamily:
              "'JetBrains Mono', monospace",
            letterSpacing: 1,
          }}
        >
          {sub}
        </div>
      )}

      {/* Bottom Glow */}
      <div
        style={{
          position: "absolute",
          bottom: 0,
          left: 0,
          right: 0,
          height: 1,
          background: `linear-gradient(
            90deg,
            transparent,
            ${color}22,
            transparent
          )`,
        }}
      />
    </div>
  );
}

// ================================================================
// MINI STAT CARD
// ================================================================

export function MiniStat({
  label,
  value,
  color = "#00D4FF",
}) {
  return (
    <div
      style={{
        display: "flex",
        flexDirection: "column",
        gap: 4,
        padding: "10px 14px",
        background:
          "rgba(11,22,40,0.6)",
        border: `1px solid ${color}22`,
        borderRadius: 8,
      }}
    >
      <div
        style={{
          fontSize: 8,
          color: "#3A5070",
          fontFamily:
            "'JetBrains Mono', monospace",
          letterSpacing: 2,
          textTransform: "uppercase",
        }}
      >
        {label}
      </div>

      <div
        className="orb-number"
        style={{
          fontSize: 18,
          fontWeight: 900,
          color,
          textShadow: `0 0 10px ${color}55`,
        }}
      >
        {value ?? "—"}
      </div>
    </div>
  );
}