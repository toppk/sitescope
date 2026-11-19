// Horizon: small conveniences, none required. Light/dark toggle, code
// language labels and copy buttons, heading anchors, the "on this page"
// marker, and a closed contents menu on narrow screens.
(function () {
  var root = document.documentElement;

  function dark() {
    var set = root.dataset.theme;
    if (set) return set === "dark";
    return window.matchMedia("(prefers-color-scheme: dark)").matches;
  }

  var toggle = document.querySelector(".theme-toggle");
  if (toggle) {
    toggle.addEventListener("click", function () {
      var next = dark() ? "light" : "dark";
      root.dataset.theme = next;
      try {
        localStorage.setItem("horizon-theme", next);
      } catch (e) {}
    });
  }

  // Contents start closed where they would push the page down.
  var nav = document.querySelector(".sidebar details");
  if (nav && window.matchMedia("(max-width: 55.99rem)").matches) nav.open = false;

  document.querySelectorAll("pre").forEach(function (pre) {
    var cls = (pre.className || "").split(/\s+/).filter(function (c) {
      return c && c !== "sourceCode" && c !== "numberSource";
    });
    if (cls.length) pre.dataset.lang = cls[0];
    if (!navigator.clipboard) return;
    var button = document.createElement("button");
    button.type = "button";
    button.className = "copy";
    button.textContent = "Copy";
    button.addEventListener("click", function () {
      navigator.clipboard.writeText(pre.innerText.replace(/\nCopy$/, "")).then(function () {
        button.textContent = "Copied";
        setTimeout(function () {
          button.textContent = "Copy";
        }, 1400);
      });
    });
    pre.appendChild(button);
  });

  // Config examples come as TOML, JSON and Nix: one choice, remembered, switches every example.
  var groups = document.querySelectorAll(".config-tabs");
  if (groups.length) {
    var buttons = [];
    var show = function (format) {
      groups.forEach(function (g) {
        var tabs = g.querySelectorAll(":scope > .config-tab");
        var pick = tabs[0].dataset.format;
        tabs.forEach(function (t) {
          if (t.dataset.format === format) pick = format;
        });
        tabs.forEach(function (t) {
          t.hidden = t.dataset.format !== pick;
        });
        g.querySelectorAll(".config-tablist button").forEach(function (b) {
          b.setAttribute("aria-selected", b.dataset.format === pick ? "true" : "false");
        });
      });
    };
    groups.forEach(function (g) {
      var list = document.createElement("div");
      list.className = "config-tablist";
      list.setAttribute("role", "tablist");
      g.querySelectorAll(":scope > .config-tab").forEach(function (t) {
        var b = document.createElement("button");
        b.type = "button";
        b.setAttribute("role", "tab");
        b.dataset.format = t.dataset.format;
        b.textContent = t.dataset.label;
        b.addEventListener("click", function () {
          try {
            localStorage.setItem("sitescope-config-format", b.dataset.format);
          } catch (e) {}
          show(b.dataset.format);
        });
        list.appendChild(b);
        buttons.push(b);
      });
      g.insertBefore(list, g.firstChild);
      g.classList.add("tabbed");
    });
    var saved = null;
    try {
      saved = localStorage.getItem("sitescope-config-format");
    } catch (e) {}
    show(saved || "toml");
  }

  document.querySelectorAll(".page h2[id], .page h3[id]").forEach(function (h) {
    var a = document.createElement("a");
    a.className = "anchor";
    a.href = "#" + h.id;
    a.setAttribute("aria-label", "Link to this section");
    a.textContent = "#";
    h.appendChild(a);
  });

  var links = Array.prototype.slice.call(document.querySelectorAll(".toc a[href^='#']"));
  if (links.length && "IntersectionObserver" in window) {
    var byId = {};
    links.forEach(function (a) {
      byId[decodeURIComponent(a.getAttribute("href").slice(1))] = a;
    });
    var observer = new IntersectionObserver(
      function (entries) {
        entries.forEach(function (e) {
          if (!e.isIntersecting) return;
          links.forEach(function (a) {
            a.classList.remove("active");
          });
          var a = byId[e.target.id];
          if (a) a.classList.add("active");
        });
      },
      { rootMargin: "0px 0px -70% 0px" }
    );
    Object.keys(byId).forEach(function (id) {
      var el = document.getElementById(id);
      if (el) observer.observe(el);
    });
  }
})();
