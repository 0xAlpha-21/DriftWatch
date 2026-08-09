/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{js,ts,jsx,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        primary: "#4cd7f6",
        "primary-container": "#06b6d4",
        error: "#ffb4ab",
        "surface-container-lowest": "#0e0e10",
        "surface-container-low": "#1c1b1d",
        "surface-container-high": "#2a2a2c",
        outline: "#869397",
        "outline-variant": "#3d494c",
        "on-surface": "#e5e1e4",
        "on-surface-variant": "#bcc9cd",
        tertiary: "#4edea3",
      },
      fontFamily: {
        "body-lg": ["Inter", "sans-serif"],
        "label-mono": ["JetBrains Mono", "monospace"],
        "label-caps": ["Inter", "sans-serif"],
        display: ["Inter", "sans-serif"],
        "data-mono": ["JetBrains Mono", "monospace"],
        headline: ["Inter", "sans-serif"],
        "body-sm": ["Inter", "sans-serif"],
      },
      fontSize: {
        "body-lg": ["16px", { lineHeight: "24px", fontWeight: "400" }],
        "label-mono": ["11px", { lineHeight: "14px", fontWeight: "400" }],
        "label-caps": [
          "11px",
          { lineHeight: "16px", letterSpacing: "0.05em", fontWeight: "700" },
        ],
        display: [
          "32px",
          { lineHeight: "40px", letterSpacing: "-0.02em", fontWeight: "700" },
        ],
        "data-mono": ["13px", { lineHeight: "18px", fontWeight: "450" }],
        headline: [
          "20px",
          { lineHeight: "28px", letterSpacing: "-0.01em", fontWeight: "600" },
        ],
        "body-sm": ["14px", { lineHeight: "20px", fontWeight: "400" }],
      },
      spacing: {
        "cell-padding-h": "12px",
        "container-padding": "24px",
        unit: "4px",
        "cell-padding-v": "8px",
        gutter: "16px",
      },
      borderRadius: {
        DEFAULT: "0.25rem",
        lg: "0.5rem",
        xl: "0.75rem",
        full: "9999px",
      },
    },
  },
  plugins: [],
};
