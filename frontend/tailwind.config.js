/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    "./src/**/*.{js,jsx,ts,tsx}",
  ],

  theme: {
    extend: {
      // ─────────────────────────────────────────────
      // Colors
      // ─────────────────────────────────────────────
      colors: {
        // Backgrounds
        bg0: "#020810",
        bg1: "#070F1E",
        bg2: "#0B1628",
        bg3: "#0F1E35",

        // Borders
        border: "#142240",

        // Accent Colors
        cyan: "#00D4FF",
        cyan2: "#00A8CC",

        // Risk Levels
        critical: "#FF2D55",
        high: "#FF8800",
        medium: "#FFD000",
        low: "#00E676",

        // Text
        primary: "#E8F4FF",
        secondary: "#B8D0EE",
        muted: "#3A5070",
      },

      // ─────────────────────────────────────────────
      // Fonts
      // ─────────────────────────────────────────────
      fontFamily: {
        orbitron: ["Orbitron", "monospace"],
        mono: ["JetBrains Mono", "monospace"],
        syne: ["Syne", "sans-serif"],
      },

      // ─────────────────────────────────────────────
      // Border Radius
      // ─────────────────────────────────────────────
      borderRadius: {
        xl2: "1rem",
        xl3: "1.25rem",
      },

      // ─────────────────────────────────────────────
      // Shadows
      // ─────────────────────────────────────────────
      boxShadow: {
        cyan: "0 0 20px rgba(0,212,255,0.15)",
        "cyan-lg": "0 0 40px rgba(0,212,255,0.25)",
        red: "0 0 20px rgba(255,45,85,0.20)",
        green: "0 0 20px rgba(0,230,118,0.15)",
        orange: "0 0 20px rgba(255,136,0,0.15)",

        glass:
          "0 20px 40px rgba(0,0,0,0.50), inset 0 1px 0 rgba(0,212,255,0.05)",
      },

      // ─────────────────────────────────────────────
      // Backdrop Blur
      // ─────────────────────────────────────────────
      backdropBlur: {
        xs: "2px",
      },

      // ─────────────────────────────────────────────
      // Animations
      // ─────────────────────────────────────────────
      animation: {
        "fade-up": "fadeUp 0.5s ease both",
        scanline: "scanline 3s linear infinite",
        ticker: "ticker 35s linear infinite",
        "pulse-slow": "pulse 3s ease-in-out infinite",
        "spin-slow": "spin 2s linear infinite",
        glow: "glow 2s ease-in-out infinite",
        float: "float 6s ease-in-out infinite",
      },

      // ─────────────────────────────────────────────
      // Keyframes
      // ─────────────────────────────────────────────
      keyframes: {
        fadeUp: {
          "0%": {
            opacity: "0",
            transform: "translateY(16px)",
          },
          "100%": {
            opacity: "1",
            transform: "translateY(0)",
          },
        },

        scanline: {
          "0%": {
            transform: "translateX(-100%)",
          },
          "100%": {
            transform: "translateX(500%)",
          },
        },

        ticker: {
          from: {
            transform: "translateX(100%)",
          },
          to: {
            transform: "translateX(-100%)",
          },
        },

        glow: {
          "0%,100%": {
            boxShadow: "0 0 8px rgba(0,212,255,0.3)",
          },
          "50%": {
            boxShadow: "0 0 24px rgba(0,212,255,0.7)",
          },
        },

        float: {
          "0%,100%": {
            transform: "translateY(0px)",
          },
          "50%": {
            transform: "translateY(-8px)",
          },
        },
      },

      // ─────────────────────────────────────────────
      // Background Images
      // ─────────────────────────────────────────────
      backgroundImage: {
        "grid-pattern":
          "linear-gradient(rgba(20,34,64,0.4) 1px, transparent 1px), linear-gradient(90deg, rgba(20,34,64,0.4) 1px, transparent 1px)",

        "cyan-gradient":
          "linear-gradient(135deg, rgba(0,212,255,0.15), rgba(0,168,204,0.05))",

        "card-gradient":
          "linear-gradient(135deg, rgba(7,15,30,0.95), rgba(11,22,40,0.85))",
      },

      backgroundSize: {
        grid: "40px 40px",
      },

      // ─────────────────────────────────────────────
      // Transition Helpers
      // ─────────────────────────────────────────────
      transitionProperty: {
        height: "height",
        spacing: "margin, padding",
      },
    },
  },

  plugins: [],
};