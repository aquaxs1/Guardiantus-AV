/* Download page: detect the visitor's platform and highlight the matching
   build. Every button already points at a real, working URL without this
   script -- it only reorders and relabels the primary choice. */

"use strict";

(() => {
  const RELEASES = "https://github.com/aquaxs1/Guardiantus-AV/releases/latest/download";

  const BUILDS = {
    "windows-x64": { label: "Windows", sub: "64-bit, Windows 10 or newer", file: "guardiantus-av-windows-x64.zip" },
    "macos-arm64": { label: "macOS", sub: "Apple Silicon (M1 and newer)", file: "guardiantus-av-macos-arm64.zip" },
    "macos-x64": { label: "macOS", sub: "Intel", file: "guardiantus-av-macos-x64.zip" },
    "linux-x64": { label: "Linux", sub: "64-bit, most distributions", file: "guardiantus-av-linux-x64.tar.gz" },
  };

  function detect() {
    const ua = navigator.userAgent || "";
    const platform = navigator.platform || "";
    if (/Win/.test(platform) || /Windows/.test(ua)) return "windows-x64";
    if (/Mac/.test(platform) || /Macintosh/.test(ua)) {
      // Browsers do not expose a reliable Apple-Silicon-vs-Intel signal, even
      // on an Apple Silicon Mac running under Rosetta the UA still reports
      // "Intel". Default to Apple Silicon, the current shipping hardware;
      // the page lists both explicitly for anyone on an older Intel Mac.
      return "macos-arm64";
    }
    if (/Linux/.test(platform) || /Linux/.test(ua)) return "linux-x64";
    return null;
  }

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else node.setAttribute(key, value);
    }
    for (const child of children.flat()) {
      if (child) node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name) {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function render() {
    const slot = document.getElementById("primary-download");
    if (!slot) return;
    const key = detect();
    const build = key ? BUILDS[key] : null;

    if (!build) {
      slot.replaceChildren(
        el("a", { class: "btn btn--primary btn--lg", href: `${RELEASES.replace("/latest/download", "/latest")}` },
          icon("download"), "See all downloads"),
      );
      return;
    }

    slot.replaceChildren(
      el("a", { class: "btn btn--primary btn--lg", href: `${RELEASES}/${build.file}` },
        icon("download"), `Download for ${build.label}`),
      el("span", { class: "field__hint", text: build.sub }),
    );

    const card = document.querySelector(`[data-build="${key}"]`);
    if (card) card.classList.add("build-card--match");
  }

  document.addEventListener("DOMContentLoaded", render);
})();
