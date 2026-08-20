/* Threat Lab — the minigame.
 *
 * You triage incoming files; the engine then shows what it actually found and
 * which layer found it. Verdicts come from assets/js/engine.js, a port of the
 * real detection layers — nothing here is scripted.
 */

"use strict";

(() => {
  const Engine = window.GuardiantusEngine;
  const SAMPLES = window.GUARDIANTUS_SAMPLES || [];
  const stage = document.getElementById("lab-body");
  if (!Engine || !stage) return;

  const $ = (id) => document.getElementById(id);

  /* -------------------------------------------------------------- helpers */

  function el(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    for (const [key, value] of Object.entries(attrs)) {
      if (value === null || value === undefined || value === false) continue;
      if (key === "class") node.className = value;
      else if (key === "text") node.textContent = value;
      else if (key.startsWith("on")) node.addEventListener(key.slice(2), value);
      else if (value === true) node.setAttribute(key, "");
      else node.setAttribute(key, value);
    }
    for (const child of children.flat()) {
      if (child === null || child === undefined || child === false) continue;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    }
    return node;
  }

  function icon(name, cls = "") {
    const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    if (cls) svg.setAttribute("class", cls);
    const use = document.createElementNS("http://www.w3.org/2000/svg", "use");
    use.setAttribute("href", `#i-${name}`);
    svg.append(use);
    return svg;
  }

  const SEVERITY_TONE = { critical: "risk", high: "risk", medium: "warn", low: "", info: "" };

  function severityBadge(severity) {
    const tone = SEVERITY_TONE[severity] ?? "";
    return el("span", { class: `badge ${tone ? `badge--${tone}` : ""}`, text: severity });
  }

  function bytes(count) {
    const n = Number(count) || 0;
    return n < 1024 ? `${n} B` : `${(n / 1024).toFixed(1)} KB`;
  }

  function shuffle(list) {
    const copy = [...list];
    for (let i = copy.length - 1; i > 0; i -= 1) {
      const j = Math.floor(Math.random() * (i + 1));
      [copy[i], copy[j]] = [copy[j], copy[i]];
    }
    return copy;
  }

  /* ---------------------------------------------------------------- state */

  const MAX_LIVES = 3;
  const COMBO_CAP = 5;

  const state = {
    queue: [],
    index: 0,
    score: 0,
    combo: 1,
    lives: MAX_LIVES,
    caught: 0,
    falsePositives: 0,
    missed: 0,
    decisions: 0,
    correct: 0,
    phase: "idle", // idle | prompt | verdict | over
    current: null,
    timerId: null,
    deadline: 0,
  };

  /* --------------------------------------------------------------- header */

  function renderBar() {
    $("m-score").textContent = state.score.toLocaleString();
    $("m-combo").textContent = `×${state.combo}`;
    $("m-caught").textContent = String(state.caught);
    $("m-round").textContent = state.queue.length
      ? `${Math.min(state.index + 1, state.queue.length)}/${state.queue.length}`
      : "—";

    const lives = $("m-lives");
    lives.replaceChildren(
      ...Array.from({ length: MAX_LIVES }, (_, i) =>
        el("i", { class: i < state.lives ? "" : "spent" })),
    );
  }

  /* ---------------------------------------------------------------- timer */

  function roundSeconds() {
    return Math.max(6, 14 - state.index * 0.5);
  }

  function startTimer(seconds) {
    stopTimer();
    const bar = $("lab-timer");
    const fill = bar.firstElementChild;
    bar.hidden = false;
    bar.classList.remove("low");
    state.deadline = performance.now() + seconds * 1000;

    const tick = () => {
      const left = state.deadline - performance.now();
      const ratio = Math.max(0, left / (seconds * 1000));
      fill.style.transform = `scaleX(${ratio})`;
      bar.classList.toggle("low", ratio < 0.3);
      if (left <= 0) { stopTimer(); decide(null); return; }
      state.timerId = requestAnimationFrame(tick);
    };
    state.timerId = requestAnimationFrame(tick);
  }

  function stopTimer() {
    if (state.timerId) cancelAnimationFrame(state.timerId);
    state.timerId = null;
    $("lab-timer").hidden = true;
  }

  /* ---------------------------------------------------------------- rounds */

  function start() {
    Object.assign(state, {
      queue: shuffle(SAMPLES),
      index: 0, score: 0, combo: 1, lives: MAX_LIVES,
      caught: 0, falsePositives: 0, missed: 0, decisions: 0, correct: 0,
      phase: "prompt", current: null,
    });
    renderBar();
    nextRound();
  }

  async function nextRound() {
    if (state.index >= state.queue.length || state.lives <= 0) { gameOver(); return; }

    const sample = state.queue[state.index];
    const result = await Engine.scanText(sample.body, sample.name);
    state.current = { sample, result };
    state.phase = "prompt";
    renderBar();
    renderPrompt(sample, result);
    startTimer(roundSeconds());
  }

  function renderPrompt(sample, result) {
    stage.replaceChildren(
      el("div", { class: "row lab__tags" },
        el("span", { class: "badge badge--solid" }, el("span", { class: "dot dot--pulse" }), "Incoming"),
        el("span", { class: "badge", text: sample.from }),
      ),
      el("div", { class: "file-card" },
        el("div", { class: "file-card__head" },
          icon("file"),
          el("span", { class: "file-card__name", text: sample.name }),
          el("span", { class: "file-card__meta", text: bytes(result.size) }),
        ),
        el("pre", { text: sample.body }),
      ),
      el("div", { class: "lab__choices" },
        el("button", { class: "btn choice btn--ok", onclick: () => decide("allow") },
          el("strong", {}, "Allow"),
          el("small", {}, "Looks harmless ", el("kbd", { text: "A" })),
        ),
        el("button", { class: "btn choice btn--risk", onclick: () => decide("quarantine") },
          el("strong", {}, "Quarantine"),
          el("small", {}, "This is a threat ", el("kbd", { text: "Q" })),
        ),
      ),
    );
  }

  /* -------------------------------------------------------------- scoring */

  function decide(choice) {
    if (state.phase !== "prompt" || !state.current) return;
    stopTimer();
    state.phase = "verdict";

    const { sample, result } = state.current;
    const isThreat = result.verdict !== "clean";
    const timedOut = choice === null;
    const right = !timedOut && ((choice === "quarantine") === isThreat);

    state.decisions += 1;
    if (right) {
      state.correct += 1;
      state.score += 100 * state.combo;
      state.combo = Math.min(COMBO_CAP, state.combo + 1);
      if (isThreat) state.caught += 1;
    } else {
      state.combo = 1;
      if (isThreat) {
        // Letting malware through is the expensive mistake.
        state.lives -= 1;
        state.missed += 1;
      } else {
        // A false positive costs points and trust, not a life.
        state.falsePositives += 1;
        state.score = Math.max(0, state.score - 50);
      }
    }

    renderBar();
    renderVerdict({ sample, result, choice, right, timedOut, isThreat });
  }

  function renderVerdict({ sample, result, choice, right, timedOut, isThreat }) {
    const headline = timedOut
      ? "Too slow"
      : right ? "Correct" : (isThreat ? "Threat let through" : "False positive");

    const detail = timedOut
      ? `The file was ${isThreat ? "a threat" : "clean"} — undecided counts as a miss.`
      : right
        ? (isThreat ? `+${100 * Math.max(1, state.combo - 1)} points` : "Correctly cleared — no action needed.")
        : (isThreat ? "A life lost. This one was real." : "−50 points. Blocking safe files erodes trust fast.");

    const last = state.index + 1 >= state.queue.length || state.lives <= 0;

    stage.replaceChildren(
      el("div", { class: "verdict" },
        el("div", { class: `verdict__banner verdict--${right ? "right" : "wrong"}` },
          icon(right ? "check" : "alert"),
          el("div", {}, el("strong", { text: headline }), el("small", { text: detail })),
        ),

        el("div", { class: "row" },
          el("span", { class: "badge", text: sample.name }),
          el("span", { class: `badge badge--${isThreat ? "risk" : "ok"}`, text: result.verdict }),
          result.threatName ? el("span", { class: "badge", text: result.threatName }) : null,
          severityBadge(result.severity),
        ),

        el("p", { class: "lab__hint", text: sample.hint }),

        ...(result.detections.length
          ? result.detections.map((detection) => el("div", { class: "layer" },
              el("span", { class: "layer__tag badge", text: detection.layer }),
              el("div", { class: "layer__text" },
                el("b", { text: detection.name }),
                el("p", { text: detection.description }),
                el("p", { class: "mono", text: detection.evidence }),
              ),
            ))
          : [el("div", { class: "layer" },
              el("span", { class: "layer__tag badge badge--ok", text: "All layers" }),
              el("div", { class: "layer__text" },
                el("b", {}, "Nothing fired"),
                el("p", {}, `Hashes, patterns, ${Engine.ruleCount} YARA rules and the heuristics all stayed quiet.`),
              ),
            )]),

        el("div", { class: "row lab__next" },
          el("button", { class: "btn btn--primary", onclick: advance },
            last ? "See results" : "Next file", el("kbd", { text: "↵" })),
        ),
      ),
    );
  }

  function advance() {
    state.index += 1;
    nextRound();
  }

  /* ------------------------------------------------------------- game over */

  function gameOver() {
    state.phase = "over";
    stopTimer();

    const accuracy = state.decisions ? Math.round((state.correct / state.decisions) * 100) : 0;
    const survived = state.lives > 0;
    const rank = accuracy >= 95 ? "Security engineer"
      : accuracy >= 80 ? "Solid instincts"
      : accuracy >= 60 ? "Getting there"
      : "Install the real thing";

    stage.replaceChildren(
      el("div", { class: "verdict" },
        el("div", { class: `verdict__banner verdict--${survived ? "right" : "wrong"}` },
          icon(survived ? "shield-check" : "shield-alert"),
          el("div", {},
            el("strong", { text: survived ? "Shift complete" : "Breached" }),
            el("small", { text: survived
              ? `You triaged every file. Rank: ${rank}.`
              : "Three threats got through. That is how one bad afternoon starts." }),
          ),
        ),

        el("div", { class: "stats" },
          el("div", {}, el("b", { text: state.score.toLocaleString() }), el("span", {}, "Score")),
          el("div", {}, el("b", { text: `${accuracy}%` }), el("span", {}, "Accuracy")),
          el("div", {}, el("b", { text: String(state.caught) }), el("span", {}, "Caught")),
          el("div", {}, el("b", { text: String(state.missed) }), el("span", {}, "Missed")),
        ),

        el("p", { class: "lab__hint" },
          state.falsePositives
            ? `You quarantined ${state.falsePositives} safe file(s). Guardiantus stores every quarantined file intact, so a mistake like that is one click to undo.`
            : "No false positives — you never quarantined a safe file. That is the hard half.",
        ),

        el("div", { class: "row lab__next" },
          el("button", { class: "btn btn--primary", onclick: start }, icon("refresh"), "Play again"),
          el("a", { class: "btn", href: "download.html" }, icon("download"), "Get Guardiantus"),
        ),
      ),
    );
    renderBar();
  }

  /* ------------------------------------------------------------- idle card */

  function renderIdle() {
    stage.replaceChildren(
      el("div", { class: "empty" },
        icon("shield"),
        el("h3", {}, "Can you spot the threats?"),
        el("p", { class: "lab__hint" },
          `${SAMPLES.length} files, 3 lives. Allow the safe ones, quarantine the dangerous ones — `
          + "then see exactly which layer the engine used and why."),
        el("div", { class: "row lab__next" },
          el("button", { class: "btn btn--primary btn--lg", onclick: start }, icon("play"), "Start shift"),
        ),
      ),
    );
    renderBar();
  }

  /* -------------------------------------------------------------- keyboard */

  addEventListener("keydown", (event) => {
    if (event.target.matches("input, textarea")) return;
    const key = event.key.toLowerCase();
    if (state.phase === "prompt" && (key === "a" || key === "q")) {
      event.preventDefault();
      decide(key === "a" ? "allow" : "quarantine");
    } else if (state.phase === "verdict" && (key === "enter" || key === " ")) {
      event.preventDefault();
      advance();
    } else if ((state.phase === "idle" || state.phase === "over") && key === "enter") {
      event.preventDefault();
      start();
    }
  });

  /* ====================================================== your own files */

  const drop = $("lab-drop");
  const input = $("lab-file");
  const output = $("lab-results");

  async function scanFiles(files) {
    const list = [...files].slice(0, 12);
    if (!list.length) return;

    if (output.querySelector(".empty")) output.replaceChildren();

    for (const file of list) {
      const row = el("div", { class: "result-row" },
        icon("file"),
        el("span", { class: "mono", text: file.name }),
        el("span", { class: "badge", text: "scanning…" }),
      );
      output.prepend(row);

      let result;
      try {
        result = await Engine.scanFile(file);
      } catch {
        row.lastElementChild.replaceWith(el("span", { class: "badge badge--warn", text: "unreadable" }));
        continue;
      }

      const tone = result.verdict === "clean" ? "ok" : result.verdict === "suspicious" ? "warn" : "risk";
      row.lastElementChild.replaceWith(
        el("span", { class: `badge badge--${tone}`, text: result.threatName || result.verdict }),
      );
      row.title = result.detections.length
        ? result.detections.map((d) => `${d.layer}: ${d.name} — ${d.description}`).join("\n")
        : `Clean · ${result.fileType} · entropy ${result.entropy.toFixed(2)} · ${bytes(result.size)}`;
    }
  }

  if (drop && input) {
    drop.addEventListener("click", () => input.click());
    drop.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") { event.preventDefault(); input.click(); }
    });
    input.addEventListener("change", () => { scanFiles(input.files); input.value = ""; });

    ["dragenter", "dragover"].forEach((type) => drop.addEventListener(type, (event) => {
      event.preventDefault(); drop.classList.add("over");
    }));
    ["dragleave", "drop"].forEach((type) => drop.addEventListener(type, (event) => {
      event.preventDefault(); drop.classList.remove("over");
    }));
    drop.addEventListener("drop", (event) => scanFiles(event.dataTransfer.files));
  }

  /* ------------------------------------------------------------------ boot */

  const engineInfo = $("lab-engine-info");
  if (engineInfo) {
    engineInfo.textContent = `${Engine.signatureCount} signatures · ${Engine.ruleCount} YARA rules · heuristics`;
  }

  renderIdle();
})();
