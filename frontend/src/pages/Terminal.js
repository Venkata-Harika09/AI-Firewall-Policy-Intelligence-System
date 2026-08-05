// ================================================================
// AI Firewall Policy Intelligence System
// src/pages/Terminal.js — Improved Version
// ================================================================

import React, { useState, useEffect, useRef, useCallback } from "react";
import { analyzePolicy, checkHealth, getReports, getThreats } from "../services/api";

// ================================================================
// HELPERS
// ================================================================
const typeColor = (type) => ({
  success: "#00E676",
  error:   "#FF2D55",
  warning: "#FFD000",
  info:    "#00D4FF",
  cmd:     "#B8D0EE",
  divider: "#142240",
  result:  "#00D4FF",
  user:    "#E8F4FF",
}[type] || "#B8D0EE");

const fmtUptime = (seconds) => {
  const h = Math.floor(seconds / 3600).toString().padStart(2,"0");
  const m = Math.floor((seconds % 3600) / 60).toString().padStart(2,"0");
  const s = Math.floor(seconds % 60).toString().padStart(2,"0");
  return `${h}:${m}:${s}`;
};

const downloadLog = (logs) => {
  const text = logs
    .map((l) => l.text)
    .join("\n");
  const blob = new Blob([text], { type:"text/plain" });
  const url  = URL.createObjectURL(blob);
  const a    = document.createElement("a");
  a.href     = url;
  a.download = `terminal_log_${Date.now()}.txt`;
  a.click();
  URL.revokeObjectURL(url);
};

const copyLogs = (logs) => {
  const text = logs.map((l) => l.text).join("\n");
  navigator.clipboard.writeText(text).then(() => {}).catch(() => {});
};

// ================================================================
// ALL COMMANDS
// ================================================================
const ALL_CMDS = [
  "help","status","health","scan","topology","risk","sim","heal",
  "threats","threat-feed","models","pipeline","version","whoami",
  "uptime","history","reports","clear","exit","analyze",
];

const buildCommands = (user, startTime, cmdHistory, reportsSummary, threatSummary) => ({

  help: () => [
    { type:"info",    text:"Available Commands:"                                   },
    { type:"divider", text:"─".repeat(50)                                         },
    { type:"cmd",     text:"  help          — show this help"                     },
    { type:"cmd",     text:"  version       — system version info"                },
    { type:"cmd",     text:"  whoami        — current user info"                  },
    { type:"cmd",     text:"  uptime        — session uptime"                     },
    { type:"cmd",     text:"  status        — system status"                      },
    { type:"cmd",     text:"  health        — check Flask API (live)"             },
    { type:"cmd",     text:"  scan          — network topology"                   },
    { type:"cmd",     text:"  topology      — same as scan"                       },
    { type:"cmd",     text:"  risk          — risk engine info"                   },
    { type:"cmd",     text:"  sim           — simulation stats"                   },
    { type:"cmd",     text:"  heal          — self-healing info"                  },
    { type:"cmd",     text:"  threats       — threat intel summary"               },
    { type:"cmd",     text:"  threat-feed   — live threat data from API"          },
    { type:"cmd",     text:"  models        — ML model info"                      },
    { type:"cmd",     text:"  pipeline      — all 14 pipeline stages"             },
    { type:"cmd",     text:"  reports       — reports summary"                    },
    { type:"cmd",     text:"  history       — command history"                    },
    { type:"cmd",     text:"  analyze <policy> — analyze a firewall policy"       },
    { type:"cmd",     text:"  clear         — clear terminal"                     },
    { type:"cmd",     text:"  exit          — end session"                        },
    { type:"divider", text:"─".repeat(50)                                         },
    { type:"info",    text:"Tip: Press Tab to autocomplete · ↑↓ for history"     },
  ],

  version: () => [
    { type:"info",    text:"AI Firewall Policy Intelligence System"               },
    { type:"divider", text:"─".repeat(50)                                         },
    { type:"success", text:"Version    : 4.0"                                     },
    { type:"info",    text:"Frontend   : React 18 + Tailwind CSS"                },
    { type:"info",    text:"Backend    : Flask + Flask-CORS"                      },
    { type:"info",    text:"ML Models  : SVM + GradientBoosting"                 },
    { type:"info",    text:"Simulation : BFS Graph Traversal"                    },
    { type:"info",    text:"Dataset    : 199 rules (153 allow · 46 deny)"        },
    { type:"info",    text:"Build      : July 2026"                              },
    { type:"divider", text:"─".repeat(50)                                         },
    { type:"cmd",     text:"Milestones : M1 NLP · M2 Rules · M3 Risk · M4 Sim"  },
  ],

  whoami: () => [
    { type:"info",    text:"Current Session:"                                     },
    { type:"divider", text:"─".repeat(50)                                         },
    { type:"success", text:`Current User : ${user || "analyst"}`                 },
    { type:"info",    text:"Role         : Security Analyst"                     },
    { type:"info",    text:"Access Level : Full Dashboard Access"                },
    { type:"info",    text:"Session      : Active"                               },
    { type:"info",    text:`Login Time   : ${new Date(startTime).toLocaleTimeString()}` },
    { type:"info",    text:`Uptime       : ${fmtUptime(Math.floor((Date.now()-startTime)/1000))}` },
  ],

  uptime: () => {
    const secs = Math.floor((Date.now() - startTime) / 1000);
    return [
      { type:"info",    text:"Session Uptime:"                                   },
      { type:"divider", text:"─".repeat(50)                                     },
      { type:"success", text:`  ${fmtUptime(secs)}`                             },
      { type:"info",    text:`Started : ${new Date(startTime).toLocaleTimeString()}` },
    ];
  },

  history: () => {
    if (!cmdHistory.length) {
      return [{ type:"warning", text:"No command history yet." }];
    }
    return [
      { type:"info",    text:"Command History:"                                  },
      { type:"divider", text:"─".repeat(50)                                     },
      ...cmdHistory.slice(0,20).map((cmd, i) => ({
        type: "cmd",
        text: `  ${String(i+1).padStart(2,"0")}  ${cmd}`,
      })),
    ];
  },

  status: () => [
    { type:"success", text:"AI Firewall Policy Intelligence System"              },
    { type:"success", text:"Status: OPERATIONAL"                                 },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"M1 NLP Pipeline        ✓ ACTIVE"                    },
    { type:"info",    text:"M2 Rule Intelligence    ✓ ACTIVE"                   },
    { type:"info",    text:"M3 Risk Scoring         ✓ ACTIVE"                   },
    { type:"info",    text:"M4 Attack Simulation    ✓ ACTIVE"                   },
    { type:"info",    text:"Flask Backend           ✓ ACTIVE (port 5000)"       },
    { type:"info",    text:"React Frontend          ✓ ACTIVE (port 3000)"       },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"SVM Classifier          100% accuracy · 87.7% CV"   },
    { type:"info",    text:"GradientBoosting        100% accuracy · 87.3% CV"   },
    { type:"info",    text:"Dataset                 199 rules (153A · 46D)"     },
  ],

  scan: () => [
    { type:"info",    text:"Network Topology Scan:"                              },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"INTERNET  → DMZ       [80,443,22,3389]"             },
    { type:"success", text:"INTERNET  → EXTERNAL  [80,443,25,22]"               },
    { type:"success", text:"EXTERNAL  → DMZ       [443,22,80]"                  },
    { type:"success", text:"DMZ       → INTERNAL  [22,8080,443]"                },
    { type:"success", text:"DMZ       → DATABASE  [3306,5432,22]"               },
    { type:"success", text:"INTERNAL  → ADMIN     [22,3389,6443]"               },
    { type:"success", text:"INTERNAL  → DATABASE  [3306,5432,27017]"            },
    { type:"success", text:"ADMIN     → DATABASE  [3306,5432,6379]"             },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"6 Zones · 8 Edges · 2 Entry Points"                 },
    { type:"warning", text:"High-value targets: ADMIN, DATABASE"                },
  ],

  risk: () => [
    { type:"info",    text:"Risk Scoring Engine:"                                },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"CVSS-inspired formula:"                              },
    { type:"cmd",     text:"  score = port(0.40) + range(0.35) + exposure(0.25)"},
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"Port Danger Scores:"                                 },
    { type:"cmd",     text:"  Port 22   (SSH)      → 0.80"                      },
    { type:"cmd",     text:"  Port 23   (Telnet)   → 0.95"                      },
    { type:"cmd",     text:"  Port 3389 (RDP)      → 0.85"                      },
    { type:"cmd",     text:"  Port 3306 (MySQL)    → 0.80"                      },
    { type:"cmd",     text:"  Port 27017(MongoDB)  → 0.75"                      },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"Risk Levels:"                                        },
    { type:"cmd",     text:"  0-4  Low  | 4-6  Medium | 6-8  High | 8-10 Critical" },
  ],

  sim: () => [
    { type:"info",    text:"BFS Attack Simulation Engine:"                       },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"Algorithm      : Breadth-First Search (BFS)"        },
    { type:"info",    text:"Max Depth      : 6 hops"                            },
    { type:"info",    text:"Network Zones  : 6 (internet → database)"           },
    { type:"info",    text:"Bidirectional  : Yes"                               },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"warning", text:"SSH from any   → 776 paths · 194 targets"          },
    { type:"warning", text:"All traffic    → 1128 paths · 350 targets"         },
    { type:"success", text:"Deny all       → 0 paths · 0 targets"              },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"Sim Levels: LOW / MEDIUM / HIGH / CRITICAL"         },
  ],

  heal: () => [
    { type:"info",    text:"Self-Healing Engine:"                                },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"6 Recommendation Types:"                             },
    { type:"cmd",     text:"  1. RESTRICT_IP_RANGE    — limit source IPs"       },
    { type:"cmd",     text:"  2. NARROW_IP_RANGE      — reduce CIDR range"      },
    { type:"cmd",     text:"  3. ADD_TIME_CONSTRAINT  — business hours only"    },
    { type:"cmd",     text:"  4. CHANGE_PRIORITY      — reorder rules"          },
    { type:"cmd",     text:"  5. PORT_HARDENING       — harden service"         },
    { type:"cmd",     text:"  6. BLOCK_MALICIOUS_IP   — drop known threats"     },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"info",    text:"Priority Levels: CRITICAL → HIGH → MEDIUM"          },
    { type:"success", text:"Generates real iptables commands"                    },
  ],

  threats: () => [
    { type:"info",    text:"Threat Intelligence Database:"                       },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"warning", text:"Malicious IPs  : 15 known bad actors"               },
    { type:"warning", text:"CIDR Ranges    : 3 blocked subnets"                 },
    { type:"warning", text:"High-Risk Ports: 15 dangerous services"             },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"error",   text:"45.155.205.233  Botnet C2      abuse:95"            },
    { type:"error",   text:"198.51.100.25   Port Scanner   abuse:78"            },
    { type:"error",   text:"203.0.113.45    Malware Host   abuse:88"            },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"Source: threat_intel.json"                          },
    { type:"info",    text:"Tip: run 'threat-feed' for live API data"           },
  ],

  models: () => [
    { type:"info",    text:"Machine Learning Models:"                            },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"Intent Classifier (M1):"                            },
    { type:"cmd",     text:"  Algorithm : SVM (Support Vector Machine)"         },
    { type:"cmd",     text:"  Accuracy  : 100% test · 87.7% CV"                },
    { type:"cmd",     text:"  Dataset   : 199 rules (153 allow, 46 deny)"      },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"Risk Scorer (M3):"                                  },
    { type:"cmd",     text:"  Algorithm : GradientBoosting"                     },
    { type:"cmd",     text:"  Accuracy  : 100% test · 87.3% CV"                },
    { type:"cmd",     text:"  Features  : 8 (port, protocol, exposure...)"     },
    { type:"cmd",     text:"  Classes   : Low / Medium / High / Critical"       },
  ],

  pipeline: () => [
    { type:"info",    text:"AI Firewall 14-Stage Pipeline:"                      },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"cmd",     text:"Stage  1 → TextPreprocessor"                        },
    { type:"cmd",     text:"Stage  2 → IntentClassifier (SVM)"                 },
    { type:"cmd",     text:"Stage  3 → RuleGenerator (iptables)"               },
    { type:"cmd",     text:"Stage  4 → ConflictDetector"                       },
    { type:"cmd",     text:"Stage  5 → RuleOrderingEngine"                      },
    { type:"cmd",     text:"Stage  6 → RuleOptimizer"                           },
    { type:"cmd",     text:"Stage  7 → ZeroTrustValidator"                      },
    { type:"cmd",     text:"Stage  8 → ThreatIntelligence"                      },
    { type:"cmd",     text:"Stage  9 → RiskScorer (CVSS)"                      },
    { type:"cmd",     text:"Stage 10 → RiskMLScorer (GradientBoosting)"        },
    { type:"cmd",     text:"Stage 11 → PolicySimulator (BFS)"                  },
    { type:"cmd",     text:"Stage 12 → AttackSurfaceCalculator"                },
    { type:"cmd",     text:"Stage 13 → SelfHealingEngine"                      },
    { type:"cmd",     text:"Stage 14 → ExplainabilityEngine"                   },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"success", text:"Input: plain English → Output: full AI analysis"    },
  ],

  reports: () => reportsSummary,

});

// ================================================================
// TERMINAL PAGE
// ================================================================
export default function Terminal({ user }) {
  const startTime = useRef(Date.now());
  const [logs,      setLogs]      = useState([
    { type:"success", text:"AI Firewall Policy Intelligence System v4.0"        },
    { type:"info",    text:`Welcome, ${user || "analyst"}! Type 'help' for commands.` },
    { type:"info",    text:"All 4 Milestones Active — M1 M2 M3 M4"             },
    { type:"divider", text:"─".repeat(50)                                        },
    { type:"cmd",     text:"Quick tip: Press Tab to autocomplete · ↑↓ for history" },
    { type:"divider", text:"─".repeat(50)                                        },
  ]);
  const [input,     setInput]     = useState("");
  const [history,   setHistory]   = useState([]);
  const [histIdx,   setHistIdx]   = useState(-1);
  const [loading,   setLoading]   = useState(false);
  const [exited,    setExited]    = useState(false);
  const [uptime,    setUptime]    = useState(0);
  const [reportsSummary, setReportsSummary] = useState([
    { type:"info", text:"Run 'reports' to load summary from backend." }
  ]);
  const bottomRef = useRef();
  const inputRef  = useRef();

  // ── Uptime counter ──────────────────────────────────────────
  useEffect(() => {
    const id = setInterval(() => setUptime(Math.floor((Date.now()-startTime.current)/1000)), 1000);
    return () => clearInterval(id);
  }, []);

  // ── Auto scroll ─────────────────────────────────────────────
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior:"smooth" });
  }, [logs]);

  // ── Add lines ────────────────────────────────────────────────
  const addLines = useCallback((lines) => {
    setLogs((prev) => [...prev, ...lines].slice(-300));
  }, []);

  // ── Execute ──────────────────────────────────────────────────
  const execute = useCallback(async (raw) => {
    const full = raw.trim();
    const cmd  = full.toLowerCase();
    if (!full) return;
    if (exited) return;

    setHistory((h) => [full, ...h].slice(0, 50));
    setHistIdx(-1);
    addLines([{ type:"user", text:`firewall> ${full}` }]);

    // ── clear ────────────────────────────────────────────────
    if (cmd === "clear") {
      setLogs([{ type:"info", text:"Terminal cleared. Type 'help' for commands." }]);
      return;
    }

    // ── exit ─────────────────────────────────────────────────
    if (cmd === "exit") {
      addLines([
        { type:"warning", text:"Terminating session..."                         },
        { type:"warning", text:`Session duration: ${fmtUptime(uptime)}`         },
        { type:"error",   text:"Session terminated. Refresh page to restart."   },
      ]);
      setExited(true);
      return;
    }

    // ── topology alias ────────────────────────────────────────
    if (cmd === "topology") {
      const CMDS = buildCommands(user, startTime.current, history, reportsSummary);
      addLines(CMDS.scan());
      return;
    }

    // ── health (async) ────────────────────────────────────────
    if (cmd === "health") {
      addLines([{ type:"info", text:"Checking Flask API..." }]);
      try {
        const res = await checkHealth();
        addLines([
          { type:"success", text:"Flask API Status: ONLINE"                     },
          { type:"info",    text:`Message   : ${res.message}`                   },
          { type:"info",    text:`Endpoints : ${res.endpoints?.length || 0} registered` },
        ]);
      } catch {
        addLines([
          { type:"error",   text:"Flask API Status: OFFLINE"                    },
          { type:"warning", text:"Start backend: python api/app.py"             },
        ]);
      }
      return;
    }

    // ── threat-feed (async, live) ─────────────────────────────
    if (cmd === "threat-feed") {
      addLines([{ type:"info", text:"Fetching live threat data from API..." }]);
      try {
        const res = await getThreats();
        const ips = res.threats || [];
        addLines([
          { type:"success", text:"Live Threat Feed:"                            },
          { type:"divider", text:"─".repeat(50)                                 },
          { type:"info",    text:`Total Entries   : ${ips.length}`              },
          { type:"warning", text:`Malicious IPs   : ${ips.filter(t=>!t.ip?.includes("/")).length}` },
          { type:"warning", text:`CIDR Ranges      : ${ips.filter(t=>t.ip?.includes("/")).length}` },
          { type:"error",   text:`High Abuse (≥80): ${ips.filter(t=>(t.abuse_score||0)>=80).length}` },
          { type:"divider", text:"─".repeat(50)                                 },
          ...ips.slice(0,5).map((t) => ({
            type: "error",
            text: `  ${t.ip.padEnd(20)} ${(t.category||"").padEnd(14)} abuse:${t.abuse_score}`,
          })),
          { type:"success", text:"Source: Flask /api/threats (live)"            },
        ]);
      } catch {
        addLines([
          { type:"error",   text:"Failed to fetch threat feed"                  },
          { type:"warning", text:"Flask API offline — use 'threats' for static data" },
        ]);
      }
      return;
    }

    // ── reports (async) ───────────────────────────────────────
    if (cmd === "reports") {
      addLines([{ type:"info", text:"Fetching reports from backend..." }]);
      try {
        const res   = await getReports();
        const reps  = res.reports || [];
        const crits = reps.filter((r) => r.risk_level === "Critical").length;
        const avg   = reps.length
          ? (reps.reduce((a,r) => a+(r.risk_score||0), 0)/reps.length).toFixed(1)
          : "0.0";
        const lines = [
          { type:"success", text:"Reports Summary:"                             },
          { type:"divider", text:"─".repeat(50)                                 },
          { type:"info",    text:`Total Reports : ${reps.length}`               },
          { type:"error",   text:`Critical      : ${crits}`                     },
          { type:"warning", text:`Average Risk  : ${avg}/10`                    },
          { type:"info",    text:`Healed Rules  : ${reps.filter(r=>r.healing_count>0).length}` },
          { type:"divider", text:"─".repeat(50)                                 },
          { type:"success", text:"Source: Flask /api/reports (live)"            },
        ];
        setReportsSummary(lines);
        addLines(lines);
      } catch {
        addLines([
          { type:"error",   text:"Failed to fetch reports"                      },
          { type:"warning", text:"Flask API offline"                            },
        ]);
      }
      return;
    }

    // ── analyze (async) ───────────────────────────────────────
    if (cmd.startsWith("analyze ")) {
      const policy = full.slice(8).trim();
      if (!policy) {
        addLines([{ type:"error", text:"Usage: analyze <policy text>" }]);
        return;
      }
      setLoading(true);
      addLines([
        { type:"info", text:`Analyzing: "${policy}"` },
        { type:"info", text:"Running 14-stage AI pipeline..." },
      ]);
      try {
        const r = await analyzePolicy(policy);
        addLines([
          { type:"divider", text:"─".repeat(50)                                 },
          { type:"success", text:`Rule      : ${r.iptables}`                    },
          { type:"result",  text:`Risk      : ${r.risk_score}/10 — ${r.risk_level}` },
          { type:"result",  text:`ML Score  : ${r.ml_score||0}/10 — ${r.ml_level}` },
          { type:"result",  text:`Surface   : ${r.surface_score}/10 — ${r.surface_level}` },
          { type:"result",  text:`Sim       : ${r.sim_paths} paths — ${r.sim_level}` },
          { type:"result",  text:`Healing   : ${r.healing_count} recs — ${r.healing_priority}` },
          { type:"result",  text:`Confidence: ${((r.confidence_score||0)*100).toFixed(0)}%` },
          { type:"divider", text:"─".repeat(50)                                 },
          { type:"info",    text: r.explanation || "Analysis complete."         },
          { type:"divider", text:"─".repeat(50)                                 },
        ]);
      } catch {
        addLines([
          { type:"error",   text:"Analysis failed — Flask API not reachable"   },
          { type:"warning", text:"Start backend: python api/app.py"            },
        ]);
      } finally {
        setLoading(false);
      }
      return;
    }

    // ── Static commands ───────────────────────────────────────
    const CMDS = buildCommands(user, startTime.current, history, reportsSummary);
    const handler = CMDS[cmd];
    if (handler) {
      addLines(handler());
    } else {
      addLines([
        { type:"error", text:`Command not found: '${cmd}'`                      },
        { type:"cmd",   text:"Type 'help' to see all commands"                  },
      ]);
    }
  }, [addLines, exited, history, reportsSummary, uptime, user]);

  // ── Tab autocomplete ──────────────────────────────────────────
  const handleKeyDown = (e) => {
    if (e.key === "Tab") {
      e.preventDefault();
      const partial = input.toLowerCase();
      if (!partial) return;
      const matches = ALL_CMDS.filter((c) => c.startsWith(partial));
      if (matches.length === 1) {
        setInput(matches[0] + " ");
      } else if (matches.length > 1) {
        addLines([
          { type:"info", text:`Matches: ${matches.join("  ")}` },
        ]);
      }
    } else if (e.key === "Enter") {
      execute(input);
      setInput("");
    } else if (e.key === "ArrowUp") {
      e.preventDefault();
      const idx = Math.min(histIdx + 1, history.length - 1);
      setHistIdx(idx);
      setInput(history[idx] || "");
    } else if (e.key === "ArrowDown") {
      e.preventDefault();
      const idx = Math.max(histIdx - 1, -1);
      setHistIdx(idx);
      setInput(idx === -1 ? "" : history[idx] || "");
    }
  };

  const QUICK_CMDS = [
    "help","version","whoami","uptime","status",
    "pipeline","models","scan","threat-feed","reports",
    "analyze Allow SSH from any",
  ];

  return (
    <div
      style={{
        display:       "flex",
        flexDirection: "column",
        height:        "100%",
        background:    "rgba(0,0,0,0.5)",
        fontFamily:    "'JetBrains Mono', monospace",
      }}
    >
      {/* ── Header ──────────────────────────────────────── */}
      <div
        style={{
          display:        "flex",
          alignItems:     "center",
          justifyContent: "space-between",
          padding:        "8px 16px",
          background:     "rgba(0,0,0,0.4)",
          borderBottom:   "1px solid rgba(0,230,118,0.15)",
          flexShrink:     0,
        }}
      >
        <div style={{ display:"flex", alignItems:"center", gap:10 }}>
          {["#FF2D55","#FFD000","#00E676"].map((c) => (
            <div key={c} style={{ width:10, height:10, borderRadius:"50%", background:c, boxShadow:`0 0 6px ${c}88` }}/>
          ))}
          <span style={{ fontSize:14, color:"#00E676", fontWeight:700, letterSpacing:1.5, marginLeft:6 }}>
            ⬛ SECURITY TERMINAL
          </span>
          {exited && (
            <span style={{ fontSize:9, color:"#FF2D55", letterSpacing:1.5, marginLeft:8 }}>
              [SESSION TERMINATED]
            </span>
          )}
        </div>

        <div style={{ display:"flex", alignItems:"center", gap:16 }}>
          {/* Uptime */}
          <span style={{ fontSize:9, color:"#3A5070", fontFamily:"'JetBrains Mono',monospace" }}>
            ⏱ {fmtUptime(uptime)}
          </span>

          {loading && (
            <span style={{ fontSize:9, color:"#FFD000", letterSpacing:1.5, animation:"pulse 1s ease-in-out infinite" }}>
              ◌ PROCESSING...
            </span>
          )}

          {/* Copy button */}
          <button
            onClick={() => { copyLogs(logs); addLines([{ type:"success", text:"✓ Terminal output copied to clipboard" }]); }}
            style={{
              padding:"3px 10px", borderRadius:4,
              background:"rgba(0,212,255,0.06)", border:"1px solid rgba(0,212,255,0.2)",
              color:"#00D4FF", fontSize:9, fontFamily:"'JetBrains Mono',monospace",
              fontWeight:700, cursor:"pointer", transition:"all 0.2s",
            }}
          >
            📋 Copy
          </button>

          {/* Download log */}
          <button
            onClick={() => downloadLog(logs)}
            style={{
              padding:"3px 10px", borderRadius:4,
              background:"rgba(0,230,118,0.06)", border:"1px solid rgba(0,230,118,0.2)",
              color:"#00E676", fontSize:9, fontFamily:"'JetBrains Mono',monospace",
              fontWeight:700, cursor:"pointer", transition:"all 0.2s",
            }}
          >
            ⬇ Log
          </button>

          <span style={{ fontSize:9, color:"#3A5070", letterSpacing:1.5 }}>
            AI FIREWALL v4.0
          </span>
        </div>
      </div>

      {/* ── Log area ────────────────────────────────────── */}
      <div
        style={{flex: 1,overflowY: "auto",overflowX: "auto",padding: "20px",display: "flex",flexDirection: "column",gap: 4,
                minWidth: 0,boxSizing: "border-box",
               }}
        onClick={() => !exited && inputRef.current?.focus()}
      >
        {logs.map((log, i) => (
          <div
            key={i}
            style={{
              fontSize:    11,
              color:       typeColor(log.type),
              lineHeight:  1.8,
              opacity:     log.type === "divider" ? 0.15 : 1,
              fontWeight:  log.type === "user" ? 700 : 400,
              paddingLeft: ["cmd","result"].includes(log.type) ? 16 : 0,
            }}
          >
            {log.text}
          </div>
        ))}
        <div ref={bottomRef}/>
      </div>

      {/* ── Input area ──────────────────────────────────── */}
      <div
        style={{
          padding:    "10px 16px",
          background: "rgba(0,0,0,0.6)",
          borderTop:  "1px solid rgba(0,230,118,0.12)",
          flexShrink: 0,
          opacity:    exited ? 0.4 : 1,
        }}
      >
        <div style={{ display:"flex", alignItems:"center", gap:8 }}>
          <span style={{ color:"#00E676", opacity:0.7, fontSize:12, flexShrink:0 }}>
            firewall&gt;
          </span>
          <input
            ref={inputRef}
            value={input}
            onChange={(e) => setInput(e.target.value)}
            onKeyDown={handleKeyDown}
            disabled={loading || exited}
            autoFocus
            style={{
              flex:1, background:"transparent", border:"none", outline:"none",
              fontSize:12, color:"#00E676",
              fontFamily:"'JetBrains Mono',monospace", caretColor:"#00E676",
            }}
            placeholder={
              exited  ? "Session terminated — refresh to restart" :
              loading ? "Processing..." :
              "type a command... (Tab to autocomplete)"
            }
          />
        </div>

        {/* Quick commands */}
        {!exited && (
          <div style={{ display:"flex", gap:5, marginTop:8, flexWrap:"wrap" }}>
            {QUICK_CMDS.map((cmd) => (
              <button
                key={cmd}
                onClick={() => { execute(cmd); setInput(""); inputRef.current?.focus(); }}
                style={{
                  padding:"3px 8px", borderRadius:4,
                  background:"rgba(0,230,118,0.05)", border:"1px solid rgba(0,230,118,0.12)",
                  color:"#3A5070", fontSize:8, fontFamily:"'JetBrains Mono',monospace",
                  cursor:"pointer", transition:"all 0.2s",
                }}
                onMouseEnter={(e) => { e.target.style.color="#00E676"; e.target.style.borderColor="rgba(0,230,118,0.35)"; }}
                onMouseLeave={(e) => { e.target.style.color="#3A5070"; e.target.style.borderColor="rgba(0,230,118,0.12)"; }}
              >
                {cmd}
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}