/* Shared site behaviour: theme, mobile nav, copy buttons, footer year.
   No framework, no build step — the same rule the product follows. */

"use strict";

/* ------------------------------------------------------------------ theme */

const THEME_KEY = "guardiantus-site-theme";

function resolveTheme(choice) {
  if (choice === "light" || choice === "dark") return choice;
  return matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(choice) {
  const resolved = resolveTheme(choice);
  document.documentElement.dataset.theme = resolved;
  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.setAttribute("aria-label", resolved === "dark" ? "Switch to light theme" : "Switch to dark theme");
    const use = button.querySelector("use");
    if (use) use.setAttribute("href", resolved === "dark" ? "#i-sun" : "#i-moon");
  });
  try { localStorage.setItem(THEME_KEY, choice); } catch { /* private mode */ }
}

function initTheme() {
  let stored = "system";
  try { stored = localStorage.getItem(THEME_KEY) || "system"; } catch { /* private mode */ }
  applyTheme(stored);

  document.querySelectorAll("[data-theme-toggle]").forEach((button) => {
    button.addEventListener("click", () => {
      applyTheme(document.documentElement.dataset.theme === "dark" ? "light" : "dark");
    });
  });
}

/* -------------------------------------------------------------- mobile nav */

function initNav() {
  const toggle = document.querySelector("[data-nav-toggle]");
  const nav = document.getElementById("site-nav");
  if (!toggle || !nav) return;

  const isMobile = () => matchMedia("(max-width: 900px)").matches;
  const setOpen = (open) => {
    nav.hidden = !open;
    toggle.setAttribute("aria-expanded", String(open));
  };

  const sync = () => setOpen(!isMobile());
  sync();
  addEventListener("resize", sync);

  toggle.addEventListener("click", () => setOpen(nav.hidden));
  nav.addEventListener("click", (event) => {
    if (event.target.tagName === "A" && isMobile()) setOpen(false);
  });
  addEventListener("keydown", (event) => {
    if (event.key === "Escape" && isMobile()) setOpen(false);
  });
}

/* ------------------------------------------------------------ copy buttons */

function initCopy() {
  document.querySelectorAll(".code").forEach((block) => {
    const pre = block.querySelector("pre");
    if (!pre) return;

    const button = document.createElement("button");
    button.className = "btn btn--sm code__copy";
    button.type = "button";
    button.textContent = "Copy";
    button.addEventListener("click", async () => {
      try {
        await navigator.clipboard.writeText(pre.innerText.trim());
        button.textContent = "Copied";
      } catch {
        button.textContent = "Press ⌘C";
      }
      setTimeout(() => { button.textContent = "Copy"; }, 1600);
    });
    block.append(button);
  });
}

/* ------------------------------------------------------------------- misc */

function initYear() {
  document.querySelectorAll("[data-year]").forEach((node) => {
    node.textContent = String(new Date().getFullYear());
  });
}

function initCurrentPage() {
  const here = location.pathname.replace(/\/index\.html$/, "/").replace(/\.html$/, "");
  document.querySelectorAll(".site-nav a").forEach((link) => {
    const target = link.getAttribute("href").split("#")[0].replace(/\.html$/, "");
    if (target && (here === target || here.endsWith(target))) link.setAttribute("aria-current", "page");
  });
}

initTheme();
addEventListener("DOMContentLoaded", () => {
  initNav();
  initCopy();
  initYear();
  initCurrentPage();
});
