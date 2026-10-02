// Light/dark toggle, and expanded sections that survive the page's auto-refresh.
(function () {
  var root = document.documentElement;
  var toggle = document.querySelector(".theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var dark = root.dataset.theme
        ? root.dataset.theme === "dark"
        : window.matchMedia("(prefers-color-scheme: dark)").matches;
      root.dataset.theme = dark ? "light" : "dark";
      try {
        localStorage.setItem("sitescope-theme", root.dataset.theme);
      } catch (e) {}
    });
  }

  var key = "sitescope-open:" + location.pathname + location.search;
  var saved = {};
  try {
    saved = JSON.parse(sessionStorage.getItem(key) || "{}");
  } catch (e) {}
  document.querySelectorAll("details[id]").forEach(function (d) {
    if (d.id in saved) d.open = saved[d.id];
    d.addEventListener("toggle", function () {
      saved[d.id] = d.open;
      try {
        sessionStorage.setItem(key, JSON.stringify(saved));
      } catch (e) {}
    });
  });
})();
