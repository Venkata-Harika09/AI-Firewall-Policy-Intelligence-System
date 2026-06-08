// ================================================================
// AI Firewall Policy Intelligence System
// src/App.js
// ================================================================

import React, { useState, useEffect } from "react";
import {
  Routes,
  Route,
  Navigate,
} from "react-router-dom";

// ── Layout Components ──────────────────────────────────────────
import Sidebar from "./components/Sidebar";
import Navbar from "./components/Navbar";

// ── Pages ──────────────────────────────────────────────────────
import Login from "./pages/Login";
import Home from "./pages/Home";
import Analyzer from "./pages/Analyzer";
import Simulation from "./pages/Simulation";
import AttackGraph from "./pages/AttackGraph";
import Reports from "./pages/Reports";
import Threats from "./pages/Threats";
import Terminal from "./pages/Terminal";

// ================================================================
// DASHBOARD LAYOUT
// ================================================================

function DashboardLayout({
  user,
  onLogout,
  reports,
  onAddReport,
}) {
  return (
    <div
      style={{
        display: "flex",
        height: "100vh",
        background: "#020810",
        position: "relative",
      }}
    >
      {/* Background Grid */}
      <div
        className="grid-bg"
        style={{
          position: "absolute",
          inset: 0,
          opacity: 0.04,
          pointerEvents: "none",
          zIndex: 0,
        }}
      />

      {/* Sidebar */}
      <Sidebar
        user={user}
        reports={reports}
        onLogout={onLogout}
      />

      {/* Main Content */}
      <div
        style={{
          flex: 1,
          display: "flex",
          flexDirection: "column",
          position: "relative",
          zIndex: 1,
        }}
      >
        {/* Navbar */}
        <Navbar
          user={user}
          reports={reports}
        />

        {/* Page Content */}
        <div
          style={{
            flex: 1,
            overflowY: "auto",
            overflowX: "hidden",
          }}
        >
          <Routes>
            <Route
              path="/home"
              element={<Home reports={reports} />}
            />

            <Route
              path="/analyzer"
              element={
                <Analyzer
                  onAddReport={onAddReport}
                />
              }
            />

            <Route
              path="/simulation"
              element={<Simulation />}
            />

            <Route
              path="/attack-graph"
              element={<AttackGraph />}
            />

            <Route
              path="/reports"
              element={
                <Reports reports={reports} />
              }
            />

            <Route
              path="/threats"
              element={<Threats />}
            />

            <Route
              path="/terminal"
              element={<Terminal />}
            />

            <Route
              path="*"
              element={
                <Navigate
                  to="/home"
                  replace
                />
              }
            />
          </Routes>
        </div>
      </div>
    </div>
  );
}

// ================================================================
// ROOT APP
// ================================================================

export default function App() {
  // ─────────────────────────────────────────────────
  // Restore User Session
  // ─────────────────────────────────────────────────

  const [user, setUser] = useState(
    localStorage.getItem("fw-user")
  );

  // ─────────────────────────────────────────────────
  // Restore Reports
  // ─────────────────────────────────────────────────

  const [reports, setReports] = useState(() => {
    const saved =
      localStorage.getItem("fw-reports");

    return saved ? JSON.parse(saved) : [];
  });

  // ─────────────────────────────────────────────────
  // Persist Reports
  // ─────────────────────────────────────────────────

  useEffect(() => {
    localStorage.setItem(
      "fw-reports",
      JSON.stringify(reports)
    );
  }, [reports]);

  // ─────────────────────────────────────────────────
  // Login
  // ─────────────────────────────────────────────────

  const handleLogin = (username) => {
    localStorage.setItem(
      "fw-user",
      username
    );

    setUser(username);
  };

  // ─────────────────────────────────────────────────
  // Logout
  // ─────────────────────────────────────────────────

  const handleLogout = () => {
    localStorage.removeItem("fw-user");

    setUser(null);
    setReports([]);
  };

  // ─────────────────────────────────────────────────
  // Add Report
  // ─────────────────────────────────────────────────

  const addReport = (report) => {
    setReports((prev) => [
      {
        ...report,
        id: Date.now(),
        createdAt:
          new Date().toLocaleString(),
      },
      ...prev,
    ]);
  };

  // ─────────────────────────────────────────────────
  // LOGIN ROUTES
  // ─────────────────────────────────────────────────

  if (!user) {
    return (
      <Routes>
        <Route
          path="/login"
          element={
            <Login
              onLogin={handleLogin}
            />
          }
        />

        <Route
          path="*"
          element={
            <Navigate
              to="/login"
              replace
            />
          }
        />
      </Routes>
    );
  }

  // ─────────────────────────────────────────────────
  // DASHBOARD
  // ─────────────────────────────────────────────────

  return (
    <DashboardLayout
      user={user}
      reports={reports}
      onLogout={handleLogout}
      onAddReport={addReport}
    />
  );
}