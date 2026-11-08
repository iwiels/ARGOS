;(function () {
  // Preload anti-FOUC: aplica el color scheme persistido antes del primer paint.
  // Única fuente de verdad: localStorage["argos-color-scheme"] (light | dark | system).
  // El runtime (ThemeProvider) es el dueño de los cambios posteriores.
  // OJO: los colores del meta theme-color (#121212 / #fafafa) deben coincidir con
  // THEME_COLOR en packages/ui/src/theme/context.tsx y con --bg-base de theme.css.
  var scheme = localStorage.getItem("argos-color-scheme") || "system"
  var isDark =
    scheme === "dark" ||
    (scheme !== "light" && matchMedia("(prefers-color-scheme: dark)").matches)
  var mode = isDark ? "dark" : "light"

  document.documentElement.dataset.colorScheme = mode

  var metas = document.querySelectorAll("meta[name='theme-color']")
  if (metas.length > 0) metas[0].setAttribute("content", isDark ? "#121212" : "#fafafa")
})()
