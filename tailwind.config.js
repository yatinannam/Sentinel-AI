module.exports = {
  content: [
    "./renderer/index.html",
    "./renderer/src/**/*.{js,ts,jsx,tsx}"
  ],
  theme: {
    extend: {
      colors: {
        cyber: {
          bg: "#0B1220",
          card: "rgba(16, 22, 38, 0.7)",
          accent: "#00E5FF",
          border: "rgba(0, 229, 255, 0.15)",
          text: "#E2E8F0"
        }
      }
    }
  },
  plugins: []
}
