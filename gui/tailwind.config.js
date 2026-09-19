/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  darkMode: "class",
  theme: {
    extend: {
      colors: {
        // Deep Adwaita-dark palette — near-black chrome, tinted panels
        bg: "#111114",
        bg2: "#17171c",
        card: "#1c1c23",
        cardHover: "#23232b",
        border: "#2a2a32",
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
