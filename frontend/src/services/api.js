// ================================================================
// AI Firewall Policy Intelligence System
// src/services/api.js
// ================================================================

import axios from "axios";

// ================================================================
// CONFIGURATION
// ================================================================

const BASE_URL =
  process.env.REACT_APP_API_URL ||
  "http://localhost:5000";

// ================================================================
// AXIOS INSTANCE
// ================================================================

const api = axios.create({
  baseURL: BASE_URL,
  headers: {
    "Content-Type": "application/json",
  },
  timeout: 60000,
});

// ================================================================
// REQUEST INTERCEPTOR
// ================================================================

api.interceptors.request.use(
  (config) => {
    console.log(
      `[API] ${config.method?.toUpperCase()} ${config.url}`
    );

    return config;
  },
  (error) => Promise.reject(error)
);

// ================================================================
// RESPONSE INTERCEPTOR
// ================================================================

api.interceptors.response.use(
  (response) => response,

  (error) => {
    if (
      error.code === "ERR_NETWORK" ||
      !error.response
    ) {
      console.error(
        "[API] Unable to reach Flask backend"
      );
    }

    console.error(
      "[API ERROR]",
      error.response?.data || error.message
    );

    return Promise.reject(error);
  }
);

// ================================================================
// ANALYZER
// ================================================================

export const analyzePolicy = async (policy) => {
  const response = await api.post(
    "/api/analyze",
    { policy }
  );

  return response.data;
};

// ================================================================
// SIMULATION
// ================================================================

export const runSimulation = async (policy) => {
  const response = await api.post(
    "/api/simulate",
    { policy }
  );

  return response.data;
};

// ================================================================
// REPORTS
// ================================================================

export const getReports = async () => {
  const response = await api.get(
    "/api/reports"
  );

  return response.data;
};

export const getReport = async (id) => {
  const response = await api.get(
    `/api/reports/${id}`
  );

  return response.data;
};

export const saveReport = async (report) => {
  const response = await api.post(
    "/api/reports",
    report
  );

  return response.data;
};

export const deleteReport = async (id) => {
  const response = await api.delete(
    `/api/reports/${id}`
  );

  return response.data;
};

// ================================================================
// THREATS
// ================================================================

export const getThreats = async () => {
  const response = await api.get(
    "/api/threats"
  );

  return response.data;
};

// ================================================================
// TOPOLOGY
// ================================================================

export const getTopology = async () => {
  const response = await api.get(
    "/api/topology"
  );

  return response.data;
};

// ================================================================
// HEALTH CHECK
// ================================================================

export const checkHealth = async () => {
  const response = await api.get(
    "/api/health"
  );

  return response.data;
};

export const backendOnline = async () => {
  try {
    await checkHealth();
    return true;
  } catch {
    return false;
  }
};

// ================================================================
// HELPERS
// ================================================================

export const riskColor = (level) =>
  ({
    Critical: "#FF2D55",
    High: "#FF8800",
    Medium: "#FFD000",
    Low: "#00E676",
  }[level] || "#3A5070");

export const riskBadgeClass = (level) =>
  ({
    Critical: "badge-critical",
    High: "badge-high",
    Medium: "badge-medium",
    Low: "badge-low",
  }[level] || "");

export const riskIcon = (level) =>
  ({
    Critical: "🔴",
    High: "🟠",
    Medium: "🟡",
    Low: "🟢",
  }[level] || "⚪");

export const simColor = (level) =>
  ({
    CRITICAL: "#FF2D55",
    HIGH: "#FF8800",
    MEDIUM: "#FFD000",
    LOW: "#00E676",
  }[level] || "#3A5070");

export const fmt = (
  value,
  decimals = 1
) => {
  const n = parseFloat(value);

  return isNaN(n)
    ? "—"
    : n.toFixed(decimals);
};

export const percent = (value) => {
  const n = parseFloat(value);

  return isNaN(n)
    ? "0%"
    : `${n.toFixed(1)}%`;
};

export const truncate = (
  text,
  max = 40
) => {
  if (!text) return "—";

  return text.length > max
    ? text.slice(0, max) + "..."
    : text;
};

// ================================================================
// EXPORT
// ================================================================

export default api;