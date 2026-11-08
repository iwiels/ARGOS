module.exports = {
  multipass: true,
  plugins: [
    { name: "removeDimensions" },
    { name: "removeViewBox", active: false },
    { name: "convertColors", params: { currentColor: true } },
    { name: "removeAttrs", params: { attrs: "(class|id|data-*)" } },
    { name: "mergePaths" },
  ],
}
