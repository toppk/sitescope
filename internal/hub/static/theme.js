// Applies the saved light/dark choice before the page paints.
try {
  var t = localStorage.getItem("sitescope-theme");
  if (t === "light" || t === "dark") document.documentElement.dataset.theme = t;
} catch (e) {}
