// ================================================================
// AI Firewall Policy Intelligence System
// src/components/Sidebar.js
// ================================================================

import React, { useState } from "react";
import { useNavigate, useLocation } from "react-router-dom";

// ── Version ─────────────────────────────────────────────────────
const VERSION = "v2.4.1";

// ── Navigation Items ────────────────────────────────────────────
const NAV_ITEMS = [
  {
    section: "OVERVIEW",
    items: [
      {
        id: "home",
        label: "Dashboard",
        path: "/home",
        icon: "▦",
      },
    ],
  },
  {
    section: "ANALYSIS",
    items: [
      {
        id: "analyzer",
        label: "Policy Analyzer",
        path: "/analyzer",
        icon: "◈",
      },
      {
        id: "simulation",
        label: "Simulation",
        path: "/simulation",
        icon: "◊",
      },
      {
        id: "attack-graph",
        label: "Attack Graph",
        path: "/attack-graph",
        icon: "⬢",
      },
    ],
  },
  {
    section: "INTELLIGENCE",
    items: [
      {
        id: "threats",
        label: "Threat Intel",
        path: "/threats",
        icon: "⚠",
      },
      {
        id: "reports",
        label: "Reports",
        path: "/reports",
        icon: "▤",
      },
    ],
  },
  {
    section: "SYSTEM",
    items: [
      {
        id: "terminal",
        label: "Terminal",
        path: "/terminal",
        icon: "❯_",
      },
    ],
  },
];

// ================================================================
// SIDEBAR
// ================================================================

export default function Sidebar({
  onLogout,
  user,
}) {
  const navigate = useNavigate();
  const location = useLocation();

  const [collapsed, setCollapsed] =
    useState(false);

  const [hoveredId, setHoveredId] =
    useState(null);

  const currentPath =
    location.pathname;

  return (
    <div
      className="glass"
      style={{
        width: collapsed ? 60 : 230,
        height: "100vh",
        background:
          "rgba(2,8,16,0.95)",
        borderRight:
          "1px solid #142240",
        display: "flex",
        flexDirection: "column",
        flexShrink: 0,
        transition:
          "width 0.25s ease",
        overflow: "hidden",
        zIndex: 20,
      }}
    >
      {/* ======================================================
          HEADER
      ====================================================== */}

      <div
        style={{
          padding: collapsed
            ? "16px 10px"
            : "16px 18px",
          borderBottom:
            "1px solid #142240",
          display: "flex",
          alignItems: "center",
          justifyContent:
            "space-between",
          gap: 10,
          height: 60,
        }}
      >
        {!collapsed && (
          <div
            style={{
              display: "flex",
              flexDirection: "column",
              gap: 2,
            }}
          >
            <div
              style={{
                fontFamily:
                  "'Orbitron', monospace",
                fontSize: 13,
                fontWeight: 900,
                color: "#00D4FF",
                letterSpacing: 2,
                textShadow:
                  "0 0 10px rgba(0,212,255,0.4)",
              }}
            >
              AI FIREWALL
            </div>

            <div
              style={{
                fontSize: 7,
                color: "#3A5070",
                fontFamily:
                  "'JetBrains Mono', monospace",
                letterSpacing: 2,
              }}
            >
              {VERSION} · ENTERPRISE
            </div>
          </div>
        )}

        <button
          onClick={() =>
            setCollapsed(
              !collapsed
            )
          }
          style={{
            width: 24,
            height: 24,
            borderRadius: 4,
            border:
              "1px solid rgba(0,212,255,0.2)",
            background:
              "rgba(0,212,255,0.06)",
            color: "#00D4FF",
            cursor: "pointer",
            fontSize: 12,
          }}
        >
          {collapsed ? "›" : "‹"}
        </button>
      </div>

      {/* ======================================================
          NAVIGATION
      ====================================================== */}

      <div
        style={{
          flex: 1,
          overflowY: "auto",
          padding: "12px 0",
        }}
      >
        {NAV_ITEMS.map(
          (section) => (
            <div
              key={
                section.section
              }
              style={{
                marginBottom: 18,
              }}
            >
              {!collapsed && (
                <div
                  style={{
                    fontSize: 8,
                    color:
                      "#3A5070",
                    letterSpacing: 2,
                    fontFamily:
                      "'JetBrains Mono', monospace",
                    fontWeight: 700,
                    padding:
                      "0 18px 6px",
                  }}
                >
                  {section.section}
                </div>
              )}

              {section.items.map(
                (item) => {
                  const active =
                    currentPath ===
                    item.path;

                  const hovered =
                    hoveredId ===
                    item.id;

                  return (
                    <div
                      key={item.id}
                      title={
                        collapsed
                          ? item.label
                          : ""
                      }
                      onClick={() =>
                        navigate(
                          item.path
                        )
                      }
                      onMouseEnter={() =>
                        setHoveredId(
                          item.id
                        )
                      }
                      onMouseLeave={() =>
                        setHoveredId(
                          null
                        )
                      }
                      style={{
                        display:
                          "flex",
                        alignItems:
                          "center",
                        gap: 12,
                        padding:
                          collapsed
                            ? "10px 0"
                            : "10px 18px",
                        justifyContent:
                          collapsed
                            ? "center"
                            : "flex-start",
                        cursor:
                          "pointer",
                        background:
                          active
                            ? "rgba(0,212,255,0.08)"
                            : hovered
                            ? "rgba(0,212,255,0.04)"
                            : "transparent",
                        borderLeft:
                          active
                            ? "2px solid #00D4FF"
                            : "2px solid transparent",
                        transition:
                          "all 0.15s ease",
                      }}
                    >
                      <div
                        style={{
                          width: 18,
                          textAlign:
                            "center",
                          color:
                            active
                              ? "#00D4FF"
                              : hovered
                              ? "#B8D0EE"
                              : "#3A5070",
                          fontSize: 14,
                        }}
                      >
                        {item.icon}
                      </div>

                      {!collapsed && (
                        <span
                          style={{
                            fontSize: 11,
                            color:
                              active
                                ? "#00D4FF"
                                : hovered
                                ? "#B8D0EE"
                                : "#7A8FA8",
                            fontFamily:
                              "'JetBrains Mono', monospace",
                            fontWeight:
                              active
                                ? 700
                                : 500,
                          }}
                        >
                          {item.label}
                        </span>
                      )}

                      {active &&
                        !collapsed && (
                          <div
                            style={{
                              marginLeft:
                                "auto",
                              width: 5,
                              height: 5,
                              borderRadius:
                                "50%",
                              background:
                                "#00D4FF",
                              boxShadow:
                                "0 0 8px #00D4FF",
                            }}
                          />
                        )}
                    </div>
                  );
                }
              )}
            </div>
          )
        )}
      </div>

      {/* ======================================================
          FOOTER
      ====================================================== */}

      <div
        style={{
          borderTop:
            "1px solid #142240",
          padding: collapsed
            ? "12px 8px"
            : "12px 14px",
          display: "flex",
          flexDirection: "column",
          gap: 10,
        }}
      >
        {!collapsed && (
          <div
            style={{
              display: "flex",
              alignItems: "center",
              gap: 10,
              padding: "8px 10px",
              background:
                "rgba(0,212,255,0.04)",
              border:
                "1px solid rgba(0,212,255,0.15)",
              borderRadius: 6,
            }}
          >
            <div
              style={{
                width: 28,
                height: 28,
                borderRadius: "50%",
                background:
                  "rgba(0,212,255,0.15)",
                display: "flex",
                alignItems: "center",
                justifyContent:
                  "center",
                color: "#00D4FF",
                fontWeight: 700,
              }}
            >
              {user?.[0]?.toUpperCase() ||
                "A"}
            </div>

            <div>
              <div
                style={{
                  fontSize: 11,
                  color:
                    "#B8D0EE",
                }}
              >
                {user ||
                  "Analyst"}
              </div>

              <div
                style={{
                  fontSize: 8,
                  color:
                    "#3A5070",
                }}
              >
                SECURITY ANALYST
              </div>
            </div>
          </div>
        )}

        <button
          onClick={() => {
            if (
              window.confirm(
                "Logout from AI Firewall?"
              )
            ) {
              onLogout();
            }
          }}
          style={{
            padding: collapsed
              ? "8px"
              : "8px 12px",
            background:
              "rgba(255,45,85,0.06)",
            border:
              "1px solid rgba(255,45,85,0.25)",
            borderRadius: 6,
            color: "#FF2D55",
            cursor: "pointer",
            fontSize: 10,
            fontWeight: 700,
          }}
        >
          {collapsed
            ? "⎋"
            : "⎋ LOGOUT"}
        </button>

        {!collapsed && (
          <div
            style={{
              display: "flex",
              justifyContent:
                "space-between",
              fontSize: 8,
              color: "#3A5070",
            }}
          >
            <span
              style={{
                color:
                  "#00E676",
              }}
            >
              ● SECURE
            </span>

            <span>
              TLS 1.3
            </span>
          </div>
        )}
      </div>
    </div>
  );
}