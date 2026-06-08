// ================================================================
// AI Firewall Policy Intelligence System
// src/components/NetworkGraph.js
// ================================================================

import React, { useEffect, useState, useRef, useCallback } from "react";

// ================================================================
// NETWORK TOPOLOGY
// ================================================================
const NODES = {
  internet: { x: 60,  y: 160, icon: "🌐", label: "INTERNET",  zone: "public"   },
  external: { x: 60,  y: 300, icon: "📡", label: "EXTERNAL",  zone: "external" },
  dmz:      { x: 240, y: 230, icon: "🔀", label: "DMZ",       zone: "dmz"      },
  internal: { x: 420, y: 140, icon: "🏢", label: "INTERNAL",  zone: "internal" },
  admin:    { x: 600, y: 70,  icon: "👑", label: "ADMIN",     zone: "admin"    },
  database: { x: 600, y: 310, icon: "🗄️", label: "DATABASE",  zone: "database" },
};

const EDGES = [
  { from: "internet", to: "dmz"      },
  { from: "internet", to: "external" },
  { from: "external", to: "dmz"      },
  { from: "dmz",      to: "internal" },
  { from: "dmz",      to: "database" },
  { from: "internal", to: "admin"    },
  { from: "internal", to: "database" },
  { from: "admin",    to: "database" },
];

const ZONE_BG = {
  public:   "rgba(0,100,160,0.18)",
  external: "rgba(0,80,130,0.18)",
  dmz:      "rgba(0,140,120,0.18)",
  internal: "rgba(0,80,200,0.18)",
  admin:    "rgba(200,40,40,0.22)",
  database: "rgba(140,40,200,0.22)",
};

const ZONE_BORDER = {
  public:   "rgba(0,150,220,0.3)",
  external: "rgba(0,120,180,0.3)",
  dmz:      "rgba(0,180,160,0.3)",
  internal: "rgba(0,120,255,0.3)",
  admin:    "rgba(255,45,85,0.4)",
  database: "rgba(180,50,255,0.4)",
};

// ================================================================
// HELPERS
// ================================================================
const midPoint = (x1, y1, x2, y2) => ({
  x: (x1 + x2) / 2,
  y: (y1 + y2) / 2,
});

// ================================================================
// NETWORK GRAPH COMPONENT
// ================================================================
export default function NetworkGraph({
  result     = {},
  showHealed = false,
  animated   = true,
  height     = 400,
}) {
  const [step,       setStep]       = useState(0);
  const [hoveredNode,setHoveredNode]= useState(null);
  const intervalRef                 = useRef();

  const attackPaths = result?.attack_paths    || [];
  const reachable   = result?.sim_reachable   || [];
  const simLevel    = result?.sim_level       || "LOW";
  const simPaths    = result?.sim_paths       || 0;

  // High value targets
  const targets = reachable.filter((n) =>
    ["admin", "database"].includes(n)
  );

  // ── Animation loop ──────────────────────────────────────────
  useEffect(() => {
    if (!animated || showHealed || attackPaths.length === 0) {
      clearInterval(intervalRef.current);
      return;
    }
    intervalRef.current = setInterval(
      () => setStep((s) => s + 1),
      650
    );
    return () => clearInterval(intervalRef.current);
  }, [animated, showHealed, attackPaths]);

  // Reset on result change
  useEffect(() => {
    setStep(0);
  }, [result]);

  // ── Compute active nodes/edges ──────────────────────────────
  const activeNodes = new Set();
  const activeEdges = new Set();

  if (!showHealed && attackPaths.length > 0) {
    const pathIdx  = step % attackPaths.length;
    const path     = attackPaths[pathIdx] || [];
    const stepIdx  = Math.floor(step / Math.max(attackPaths.length, 1)) % Math.max(path.length, 1);

    for (let i = 0; i <= stepIdx && i < path.length; i++) {
      activeNodes.add(path[i]);
      if (i > 0) activeEdges.add(`${path[i - 1]}-${path[i]}`);
    }
  }

  // ── Node style helpers ──────────────────────────────────────
  const isTarget  = (id) => !showHealed && targets.includes(id);
  const isActive  = (id) => !showHealed && activeNodes.has(id) && !targets.includes(id);
  const isSafe    = (id) => showHealed  && targets.includes(id);
  const isReached = (id) => !showHealed && reachable.includes(id);

  const nodeBorder = (id) => {
    if (isTarget(id))  return "#FF2D55";
    if (isActive(id))  return "#FF8800";
    if (isSafe(id))    return "#00E676";
    if (isReached(id)) return "rgba(255,136,0,0.4)";
    return ZONE_BORDER[NODES[id]?.zone] || "#142240";
  };

  const nodeGlow = (id) => {
    if (isTarget(id))  return `drop-shadow(0 0 12px #FF2D55)`;
    if (isActive(id))  return `drop-shadow(0 0 8px  #FF8800)`;
    if (isSafe(id))    return `drop-shadow(0 0 10px #00E676)`;
    return "none";
  };

  const edgeColor = (edgeId) => {
    if (showHealed)                   return "#00E676";
    if (activeEdges.has(edgeId))      return "#FF2D55";
    return "#142240";
  };

  const edgeWidth = (edgeId) =>
    activeEdges.has(edgeId) && !showHealed ? 2.5 : 1.2;

  const edgeOpacity = (edgeId) =>
    activeEdges.has(edgeId) && !showHealed ? 1 : 0.4;

  // ── SVG dimensions ──────────────────────────────────────────
  const W = 700;
  const H = height;

  return (
    <div style={{ position: "relative", width: "100%", height }}>
      {/* Status badge */}
      <div
        style={{
          position:      "absolute",
          top:           10,
          right:         10,
          zIndex:        5,
          fontSize:      9,
          fontFamily:    "'JetBrains Mono', monospace",
          fontWeight:    700,
          letterSpacing: 1.5,
          padding:       "3px 10px",
          borderRadius:  4,
          color:         showHealed
            ? "#00E676"
            : simLevel === "CRITICAL"
            ? "#FF2D55"
            : simLevel === "HIGH"
            ? "#FF8800"
            : simLevel === "MEDIUM"
            ? "#FFD000"
            : "#00E676",
          border: `1px solid currentColor`,
          background:    showHealed
            ? "rgba(0,230,118,0.08)"
            : "rgba(255,45,85,0.08)",
        }}
      >
        {showHealed ? "✓ HEALED" : `⚡ ${simLevel}`}
      </div>

      {/* Paths count */}
      {!showHealed && simPaths > 0 && (
        <div
          style={{
            position:   "absolute",
            top:        10,
            left:       10,
            zIndex:     5,
            fontSize:   9,
            fontFamily: "'JetBrains Mono', monospace",
            color:      "#FF2D55",
            background: "rgba(255,45,85,0.08)",
            border:     "1px solid rgba(255,45,85,0.2)",
            borderRadius: 4,
            padding:    "3px 10px",
          }}
        >
          {simPaths} PATHS
        </div>
      )}

      <svg
        width="100%"
        viewBox={`0 0 ${W} ${H}`}
        style={{ overflow: "visible" }}
      >
        <defs>
          {/* Arrow markers */}
          <marker
            id="arr-normal"
            markerWidth="6"
            markerHeight="6"
            refX="5"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L6,3 L0,6 Z" fill="rgba(20,34,64,0.8)" />
          </marker>
          <marker
            id="arr-hot"
            markerWidth="6"
            markerHeight="6"
            refX="5"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L6,3 L0,6 Z" fill="#FF2D55" />
          </marker>
          <marker
            id="arr-healed"
            markerWidth="6"
            markerHeight="6"
            refX="5"
            refY="3"
            orient="auto"
          >
            <path d="M0,0 L6,3 L0,6 Z" fill="#00E676" />
          </marker>

          {/* Glow filter */}
          <filter id="glow-red">
            <feGaussianBlur stdDeviation="3" result="blur" />
            <feMerge>
              <feMergeNode in="blur" />
              <feMergeNode in="SourceGraphic" />
            </feMerge>
          </filter>
        </defs>

        {/* ── Edges ──────────────────────────────────────────── */}
        {EDGES.map(({ from, to }) => {
          const na     = NODES[from];
          const nb     = NODES[to];
          const edgeId = `${from}-${to}`;
          const hot    = activeEdges.has(edgeId) && !showHealed;
          const color  = edgeColor(edgeId);
          const mid    = midPoint(
            na.x + 40, na.y + 27,
            nb.x + 40, nb.y + 27
          );

          return (
            <g key={edgeId}>
              <line
                x1={na.x + 40} y1={na.y + 27}
                x2={nb.x + 40} y2={nb.y + 27}
                stroke={color}
                strokeWidth={edgeWidth(edgeId)}
                strokeDasharray={hot ? "8 4" : "none"}
                strokeOpacity={edgeOpacity(edgeId)}
                markerEnd={
                  hot
                    ? "url(#arr-hot)"
                    : showHealed
                    ? "url(#arr-healed)"
                    : "url(#arr-normal)"
                }
                style={{
                  transition: "all 0.3s ease",
                  filter:     hot
                    ? "drop-shadow(0 0 3px #FF2D5566)"
                    : "none",
                }}
              />
              {/* Port label on active edges */}
              {hot && result?.port && (
                <text
                  x={mid.x}
                  y={mid.y - 6}
                  textAnchor="middle"
                  fill="#FF2D55"
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize:   8,
                    fontWeight: 700,
                  }}
                >
                  :{result.port}
                </text>
              )}
            </g>
          );
        })}

        {/* ── Nodes ──────────────────────────────────────────── */}
        {Object.entries(NODES).map(([id, n], idx) => {
          const hovered = hoveredNode === id;
          const border  = nodeBorder(id);
          const bg      = ZONE_BG[n.zone] || "rgba(11,22,40,0.9)";
          const target  = isTarget(id);
          const active  = isActive(id);
          const safe    = isSafe(id);

          return (
            <g
              key={id}
              transform={`translate(${n.x}, ${n.y})`}
              style={{
                filter:    nodeGlow(id),
                cursor:    "pointer",
                animation: `nodeIn 0.4s ease ${idx * 80}ms both`,
              }}
              onMouseEnter={() => setHoveredNode(id)}
              onMouseLeave={() => setHoveredNode(null)}
            >
              {/* Pulse ring for targets */}
              {(target || safe) && (
                <rect
                  x={-4} y={-4}
                  width={88} height={62}
                  rx={13}
                  fill="none"
                  stroke={target ? "#FF2D55" : "#00E676"}
                  strokeWidth={1}
                  strokeOpacity={0.4}
                  style={{ animation: "pulse 1.5s ease-in-out infinite" }}
                />
              )}

              {/* Node body */}
              <rect
                width={80}
                height={54}
                rx={10}
                fill={bg}
                stroke={hovered ? "#00D4FF" : border}
                strokeWidth={target || active || safe ? 2 : 1}
                style={{ transition: "all 0.2s ease" }}
              />

              {/* Icon */}
              <text
                x={40}
                y={20}
                textAnchor="middle"
                fontSize={16}
              >
                {n.icon}
              </text>

              {/* Label */}
              <text
                x={40}
                y={35}
                textAnchor="middle"
                fill={
                  target  ? "#FF2D55" :
                  active  ? "#FF8800" :
                  safe    ? "#00E676" :
                  hovered ? "#00D4FF" :
                  "#B8D0EE"
                }
                style={{
                  fontFamily: "'JetBrains Mono', monospace",
                  fontSize:   8.5,
                  fontWeight: target || active ? 700 : 400,
                  letterSpacing: 0.8,
                  transition: "fill 0.2s",
                }}
              >
                {n.label}
              </text>

              {/* Status label */}
              {target && (
                <text
                  x={40}
                  y={48}
                  textAnchor="middle"
                  fill="#FF2D55"
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize:   7,
                    fontWeight: 700,
                    animation:  "pulse 1s ease-in-out infinite",
                  }}
                >
                  ⚠ TARGET
                </text>
              )}
              {safe && (
                <text
                  x={40}
                  y={48}
                  textAnchor="middle"
                  fill="#00E676"
                  style={{
                    fontFamily: "'JetBrains Mono', monospace",
                    fontSize:   7,
                    fontWeight: 700,
                  }}
                >
                  ✓ PROTECTED
                </text>
              )}

              {/* Hover tooltip */}
              {hovered && (
                <g transform="translate(0, -36)">
                  <rect
                    x={-10}
                    y={0}
                    width={100}
                    height={28}
                    rx={5}
                    fill="#0B1628"
                    stroke="#142240"
                    strokeWidth={1}
                  />
                  <text
                    x={40}
                    y={11}
                    textAnchor="middle"
                    fill="#00D4FF"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize:   8,
                      fontWeight: 700,
                    }}
                  >
                    {n.zone.toUpperCase()} ZONE
                  </text>
                  <text
                    x={40}
                    y={22}
                    textAnchor="middle"
                    fill="#3A5070"
                    style={{
                      fontFamily: "'JetBrains Mono', monospace",
                      fontSize:   7,
                    }}
                  >
                    {reachable.includes(id) ? "⚡ REACHABLE" : "✓ ISOLATED"}
                  </text>
                </g>
              )}
            </g>
          );
        })}
      </svg>

      {/* ── Legend ─────────────────────────────────────────── */}
      <div
        style={{
          position:   "absolute",
          bottom:     10,
          left:       10,
          display:    "flex",
          gap:        12,
          flexWrap:   "wrap",
        }}
      >
        {[
          { color: "#FF2D55", label: "Target"    },
          { color: "#FF8800", label: "Active"    },
          { color: "#00E676", label: "Protected" },
          { color: "#142240", label: "Isolated"  },
        ].map(({ color, label }) => (
          <div
            key={label}
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
                background:   color,
                boxShadow:    `0 0 4px ${color}`,
              }}
            />
            <span
              style={{
                fontSize:   8,
                color:      "#3A5070",
                fontFamily: "'JetBrains Mono', monospace",
              }}
            >
              {label}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}