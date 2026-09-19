/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Adwaita-ish dark palette
        bg: "#1e1e24",
        bg2: "#26262e",
        card: "#2d2d36",
        cardHover: "#36363f",
        border: "#3d3d47",
        fg: "#eeeeee",
        muted: "#9a9aa5",
        accent: "#3584e4",     // GNOME blue
        accentHover: "#4a9cf5",
        ok: "#33d17a",
        warn: "#f6d32d",
        err: "#e01b24",
      },
      borderRadius: {
        xl: "12px",
      },
    },
  },
  plugins: [],
};
