/* Guardiantus AV — browser engine.
 *
 * A faithful port of the four detection layers from `guardiantus/core`, small
 * enough to run in a page. It is what powers the Threat Lab: the verdicts you
 * see here are produced by the same logic the real scanner uses, not scripted.
 *
 * What is NOT ported: the full signature feed, native YARA, PE section
 * parsing and archive unpacking. The desktop product does all of that.
 *
 * Everything runs locally. No file, hash or byte ever leaves the browser.
 */

"use strict";

const GuardiantusEngine = (() => {
  const SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"];
  const SEVERITY_SCORE = { info: 10, low: 40, medium: 65, high: 85, critical: 100 };

  /* ------------------------------------------------------------ signatures */

  // Assembled at runtime so this source file does not itself contain the
  // literal test string that on-access scanners look for.
  const EICAR_ID = ["EICAR", "STANDARD", "ANTIVIRUS", "TEST", "FILE"].join("-");

  const HASH_SIGNATURES = {
    // sha256 of "GUARDIANTUS-AV-SIGNATURE-SELFTEST-FILE-DO-NOT-REMOVE\n"
    fdd7d929408aa6fde9eda1a38bdf9c8950c527b6d4ea86b1ef79dee644b37b3d: {
      name: "Guardiantus.SelfTest.HashProbe",
      severity: "info",
      description: "Harmless self-test file that proves hash detection is live.",
    },
  };

  const PATTERN_SIGNATURES = [
    { name: "EICAR-Test-File", needle: EICAR_ID, severity: "low",
      description: "Industry-standard test file. Harmless by design." },
    { name: "Backdoor.PHP.WebShell.Eval", needle: "<?php @eval($_POST", severity: "critical",
      description: "PHP web shell running attacker-supplied POST data." },
    { name: "Backdoor.PHP.WebShell.Assert", needle: "assert($_REQUEST[", severity: "critical",
      description: "PHP web shell running attacker-supplied request data." },
    { name: "Trojan.PowerShell.HiddenEncoded", needle: "powershell -nop -w hidden -enc", severity: "high",
      description: "PowerShell with no profile, hidden window and a base64 payload." },
    { name: "Backdoor.Meterpreter.Marker", needle: "meterpreter", severity: "high",
      description: "Metasploit Meterpreter payload marker." },
    { name: "HackTool.Mimikatz.Command", needle: "sekurlsa::logonpasswords", severity: "critical",
      description: "Mimikatz credential-dumping command." },
    { name: "Trojan.Win32.ReflectiveLoader", needle: "ReflectiveLoader", severity: "high",
      description: "Reflective DLL loader export used by post-exploitation implants." },
  ];

  /* ----------------------------------------------------------------- YARA */

  // Ported from rules/guardiantus_base.yar. `all` = every string must appear;
  // `any` = at least one; `count` = at least N of the listed strings.
  const YARA_RULES = [
    { rule: "Guardiantus_SelfTest_Yara", name: "Guardiantus.SelfTest.YaraProbe", severity: "info", score: 10,
      description: "Self-test rule proving the YARA layer is live.",
      all: ["GUARDIANTUS-AV-YARA-SELFTEST-MARKER"] },

    { rule: "Reverse_Shell_Bash", name: "Backdoor.Shell.ReverseTCP", severity: "critical", score: 90,
      description: "Bash reverse shell using /dev/tcp redirection.",
      all: ["/dev/tcp/", ">&", "bash -i"] },

    { rule: "Reverse_Shell_Python", name: "Backdoor.Python.ReverseShell", severity: "critical", score: 90,
      description: "Python socket reverse shell wiring stdio onto a socket.",
      all: ["socket.socket", ".connect(", "os.dup2"], any: ["pty.spawn", "subprocess.call"] },

    { rule: "PowerShell_Download_Cradle", name: "Trojan.PowerShell.DownloadCradle", severity: "high", score: 85,
      description: "PowerShell one-liner that downloads and immediately executes a payload.",
      all: ["system.net.webclient"], any: ["downloadstring", "downloadfile"], any2: ["invoke-expression", "iex("],
      nocase: true },

    { rule: "Ransomware_Shadow_Copy_Wipe", name: "Ransom.Generic.ShadowWipe", severity: "critical", score: 95,
      description: "Deletes shadow copies and disables recovery — the ransomware fingerprint.",
      anyGroup: [["vssadmin", "delete shadows"], ["bcdedit", "recoveryenabled no"], ["delete catalog"]],
      nocase: true },

    { rule: "Ransom_Note_Text", name: "Ransom.Note.Generic", severity: "high", score: 80,
      description: "Text file carrying a ransom note.",
      count: 3, nocase: true,
      strings: ["your files have been encrypted", "all your files are encrypted", "to decrypt your files",
                "bitcoin", ".onion", "decryption key"] },

    { rule: "Credential_Stealer_Browser", name: "Spyware.Stealer.BrowserCredentials", severity: "critical", score: 90,
      description: "Reads browser credential stores — infostealer behaviour.",
      anyGroup: [["Login Data", "\\Google\\Chrome\\User Data"], ["logins.json", "key4.db"],
                 ["CryptUnprotectData", "Cookies"]] },

    { rule: "Keylogger_Windows_Hooks", name: "Spyware.Keylogger.WinHook", severity: "high", score: 85,
      description: "Installs a low-level keyboard hook and records keystrokes.",
      anyGroup: [["SetWindowsHookEx", "WH_KEYBOARD_LL"], ["GetAsyncKeyState", "GetKeyboardState"]] },

    { rule: "Process_Injection_Classic", name: "Trojan.Win32.ProcessInjection", severity: "high", score: 85,
      description: "Classic CreateRemoteThread process-injection API chain.",
      all: ["VirtualAllocEx", "WriteProcessMemory"],
      any: ["CreateRemoteThread", "QueueUserAPC", "OpenProcess"] },

    { rule: "Crypto_Miner_Config", name: "Trojan.CoinMiner.Config", severity: "high", score: 80,
      description: "Cryptocurrency miner configuration or command line.",
      nocase: true,
      anyGroup: [["stratum+tcp://"], ["xmrig", "--donate-level"], ["randomx", "cryptonight"]] },

    { rule: "Linux_Persistence_Cron", name: "Backdoor.Linux.CronPersistence", severity: "medium", score: 70,
      description: "Cron entry that repeatedly fetches and runs remote code.",
      anyOf: [["/etc/cron", "crontab -"], ["curl -", "wget -"], ["| sh", "| bash"]] },

    { rule: "Suspicious_UPX_Dropper", name: "Trojan.Packed.UPXDropper", severity: "medium", score: 65,
      description: "UPX-packed executable that also reaches for remote-download APIs.",
      all: ["UPX!"], any: ["URLDownloadToFile", "WinHttpOpenRequest", "InternetOpenUrlA"] },

    { rule: "Office_Macro_Dropper", name: "Trojan.Doc.MacroDropper", severity: "high", score: 85,
      description: "Office macro that auto-runs and spawns a shell or downloader.",
      nocase: true,
      anyOf: [["auto_open", "autoopen", "document_open"], ["shell(", "wscript.shell", "msxml2.xmlhttp"]] },
  ];

  /* ----------------------------------------------------------- heuristics */

  const SCRIPT_PATTERNS = [
    [/frombase64string\s*\(/i, "PowerShell base64 payload decode", 25],
    [/-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}/i, "PowerShell encoded command", 40],
    [/invoke-expression|(?<![\w-])iex(?![\w-])/i, "Dynamic code execution (IEX)", 25],
    [/downloadstring\s*\(|downloadfile\s*\(/i, "Remote payload download", 30],
    [/new-object\s+system\.net\.webclient/i, "WebClient dropper pattern", 25],
    [/-(?:exec(?:utionpolicy)?)\s+bypass/i, "ExecutionPolicy bypass", 30],
    [/\beval\s*\(\s*(?:atob|base64_decode|gzinflate)/i, "Obfuscated eval chain", 40],
    [/\bshell_exec\s*\(|\bpassthru\s*\(|\bsystem\s*\(\s*\$_/i, "PHP command execution", 35],
    [/wscript\.shell/i, "WScript.Shell automation", 20],
    [/reg(?:\.exe)?\s+add\s+.{0,80}\\currentversion\\run/i, "Run-key persistence", 35],
    [/schtasks\s+\/create/i, "Scheduled-task persistence", 25],
    [/vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog/i, "Shadow-copy deletion (ransomware)", 60],
    [/bcdedit\s+.{0,40}recoveryenabled\s+no/i, "Recovery disabled (ransomware)", 55],
    [/rm\s+-rf\s+(?:\/|\/\*|\$HOME)/i, "Destructive recursive delete", 45],
    [/(?:curl|wget)\s+[^|\n]{0,120}\|\s*(?:ba)?sh/i, "Pipe-to-shell installer", 40],
    [/nc(?:\.exe)?\s+-(?:l|e)\s/i, "Netcat listener/reverse shell", 35],
    [/\/dev\/tcp\/\d{1,3}(?:\.\d{1,3}){3}\/\d+/i, "Raw TCP reverse shell", 45],
    [/crontab\s+-\s*$|>>\s*\/etc\/cron/im, "Cron persistence", 25],
    [/mimikatz|sekurlsa::|lsadump::/i, "Credential-dumping tooling", 70],
    [/\bkeylog|GetAsyncKeyState|SetWindowsHookEx/i, "Keylogging API usage", 40],
  ];

  const RANSOM_HINTS = [
    "your files have been encrypted", "all your files are encrypted", "to decrypt your files",
    "bitcoin wallet", "tor browser", "recover your data", "decryption key",
  ];

  const EXECUTABLE_EXT = [".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".bat", ".cmd", ".js", ".vbs", ".msi"];
  const DECOY_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"];
  const DOCUMENT_EXT = [".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf"];
  const RTL_MARKS = ["‮", "‫", "⁧"];

  const ONION_RE = /\b[a-z2-7]{16,56}\.onion\b/i;
  const LONG_B64_RE = /[A-Za-z0-9+/]{200,}={0,2}/;
  const URL_RE = /\bhttps?:\/\/[a-z0-9.\-]{4,}/gi;
  const IPV4_RE = /\b(?:\d{1,3}\.){3}\d{1,3}\b/g;

  /* -------------------------------------------------------------- helpers */

  function entropy(bytes) {
    if (!bytes.length) return 0;
    const counts = new Uint32Array(256);
    for (let i = 0; i < bytes.length; i += 1) counts[bytes[i]] += 1;
    let total = 0;
    for (let i = 0; i < 256; i += 1) {
      if (!counts[i]) continue;
      const p = counts[i] / bytes.length;
      total -= p * Math.log2(p);
    }
    return total;
  }

  function detectType(bytes, name = "") {
    const head = String.fromCharCode(...bytes.slice(0, 4));
    if (head.startsWith("MZ")) return "pe";
    if (bytes[0] === 0x7f && head.slice(1) === "ELF") return "elf";
    if (head.startsWith("PK")) return "zip";
    if (head.startsWith("%PDF")) return "pdf";
    if (bytes[0] === 0xd0 && bytes[1] === 0xcf) return "ole";
    if (head.startsWith("#!")) return "script";
    const lower = name.toLowerCase();
    if (/\.(ps1|bat|cmd|vbs|js|sh|py|pl|php|rb|hta|wsf)$/.test(lower)) return "script";
    let printable = 0;
    const sample = bytes.slice(0, 8192);
    for (const b of sample) if ((b >= 32 && b <= 126) || b === 9 || b === 10 || b === 13) printable += 1;
    if (sample.length && printable / sample.length < 0.75) return "binary";
    return "text";
  }

  function extension(name) {
    const index = name.lastIndexOf(".");
    return index < 0 ? "" : name.slice(index).toLowerCase();
  }

  function worstSeverity(list) {
    return list.reduce((worst, s) => (SEVERITY_ORDER.indexOf(s) > SEVERITY_ORDER.indexOf(worst) ? s : worst), "info");
  }

  async function sha256(bytes) {
    if (!globalThis.crypto?.subtle) return "";
    const digest = await crypto.subtle.digest("SHA-256", bytes);
    return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, "0")).join("");
  }

  /* --------------------------------------------------------- layer: hash */

  function matchHash(digest) {
    const hit = HASH_SIGNATURES[digest];
    if (!hit) return [];
    return [{
      source: "signature", layer: "Hash signature", name: hit.name,
      severity: hit.severity, score: SEVERITY_SCORE[hit.severity],
      description: hit.description,
      evidence: `sha256 ${digest.slice(0, 16)}…`,
    }];
  }

  /* ------------------------------------------------------ layer: patterns */

  function matchPatterns(text) {
    const found = [];
    for (const signature of PATTERN_SIGNATURES) {
      const offset = text.indexOf(signature.needle);
      if (offset < 0) continue;
      found.push({
        source: "signature", layer: "Pattern signature", name: signature.name,
        severity: signature.severity, score: SEVERITY_SCORE[signature.severity],
        description: signature.description,
        evidence: `matched at byte ${offset}`,
      });
    }
    return found;
  }

  /* ---------------------------------------------------------- layer: YARA */

  function matchYara(text) {
    const lower = text.toLowerCase();
    const found = [];

    for (const rule of YARA_RULES) {
      const haystack = rule.nocase ? lower : text;
      const has = (needle) => haystack.includes(rule.nocase ? needle.toLowerCase() : needle);

      let fired;
      if (rule.count) {
        fired = rule.strings.filter(has).length >= rule.count;
      } else if (rule.anyGroup) {
        fired = rule.anyGroup.some((group) => group.every(has));
      } else if (rule.anyOf) {
        fired = rule.anyOf.every((group) => group.some(has));
      } else {
        fired = (rule.all || []).every(has)
          && (!rule.any || rule.any.some(has))
          && (!rule.any2 || rule.any2.some(has));
      }
      if (!fired) continue;

      found.push({
        source: "yara", layer: "YARA rule", name: rule.name,
        severity: rule.severity, score: rule.score, description: rule.description,
        evidence: `rule ${rule.rule}`,
      });
    }
    return found;
  }

  /* ---------------------------------------------------- layer: heuristics */

  function analyseHeuristics(bytes, text, name, threshold = 60) {
    const rules = [];
    const type = detectType(bytes, name);
    const ext = extension(name);
    const lowerName = name.toLowerCase();

    // Naming tricks.
    const parts = lowerName.split(".");
    if (parts.length >= 3) {
      const inner = `.${parts[parts.length - 2]}`;
      if (DECOY_EXT.includes(inner) && EXECUTABLE_EXT.includes(ext)) {
        rules.push(["Double extension disguise", 45, "high"]);
      }
    }
    if (RTL_MARKS.some((mark) => name.includes(mark))) {
      rules.push(["Right-to-left override in filename", 60, "high"]);
    }
    if (DOCUMENT_EXT.includes(ext) && ["pe", "elf"].includes(type)) {
      rules.push(["Executable masquerading as a document", 65, "critical"]);
    }
    if ([".jpg", ".png", ".gif", ".mp3", ".mp4"].includes(ext) && ["pe", "elf"].includes(type)) {
      rules.push(["Executable masquerading as media", 60, "high"]);
    }

    // Entropy.
    const bits = entropy(bytes.slice(0, 262144));
    if (["pe", "elf"].includes(type) && bits > 7.2) {
      rules.push([`High-entropy executable (packed, ${bits.toFixed(2)} bits/byte)`, 30, "medium"]);
    } else if (["script", "text"].includes(type) && bits > 5.6 && bytes.length > 2048) {
      rules.push([`Obfuscated script content (${bits.toFixed(2)} bits/byte)`, 30, "medium"]);
    }

    // Script constructs.
    if (["script", "text", "ole"].includes(type)) {
      for (const [regex, label, score] of SCRIPT_PATTERNS) {
        if (regex.test(text)) rules.push([label, score, score >= 40 ? "high" : "medium"]);
      }
      if (LONG_B64_RE.test(text)) rules.push(["Large embedded base64 blob", 25, "medium"]);
      if (ONION_RE.test(text)) rules.push(["Tor hidden-service address", 35, "high"]);

      const urls = new Set(text.match(URL_RE) || []);
      if (urls.size > 12) rules.push([`Many hardcoded URLs (${urls.size})`, 15, "low"]);

      const ips = new Set((text.match(IPV4_RE) || []).filter((ip) => !/^(0\.|127\.|255\.)/.test(ip)));
      if (ips.size >= 3) rules.push([`Multiple hardcoded IP addresses (${ips.size})`, 20, "medium"]);
    }

    // Structural.
    if (type === "pe") {
      for (const marker of ["UPX!", "UPX0", "ASPack", "MPRESS1", "Themida", "VMProtect"]) {
        if (text.includes(marker)) { rules.push([`Packed executable (${marker})`, 30, "medium"]); break; }
      }
      const apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
                    "SetThreadContext", "NtUnmapViewOfSection"].filter((api) => text.includes(api));
      if (apis.length >= 2) rules.push([`Process-injection API combination (${apis.length})`, 20 + 15 * Math.min(apis.length, 4), "high"]);
    }
    if (type === "pdf" && (text.includes("/JavaScript") || text.includes("/JS")) && text.includes("/OpenAction")) {
      rules.push(["PDF with auto-run JavaScript", 40, "high"]);
    }
    if (text.includes("Auto_Open") || text.includes("AutoOpen") || text.includes("Document_Open")) {
      rules.push(["Auto-executing office macro", 45, "high"]);
    }
    const noteHits = RANSOM_HINTS.filter((hint) => text.toLowerCase().includes(hint));
    if (noteHits.length >= 2) rules.push(["Ransom-note text", 70, "critical"]);
    if (["pe", "elf"].includes(type) && bytes.length < 8192) {
      rules.push(["Unusually small executable", 15, "low"]);
    }

    if (!rules.length) return { detections: [], type, entropy: bits, rules: [] };

    const total = rules.reduce((sum, r) => sum + r[1], 0);
    if (total < threshold) return { detections: [], type, entropy: bits, rules };

    const sorted = [...rules].sort((a, b) => b[1] - a[1]);
    const severity = worstSeverity(rules.map((r) => r[2]));
    const slug = sorted[0][0].replace(/[^A-Za-z0-9]+/g, "").slice(0, 34) || "Generic";

    return {
      type,
      entropy: bits,
      rules: sorted,
      detections: [{
        source: "heuristic", layer: "Heuristics", name: `Heuristic.${slug}`,
        severity, score: Math.min(100, total),
        description: sorted.slice(0, 3).map((r) => r[0]).join("; "),
        evidence: `score ${total} of ${threshold} needed`,
      }],
    };
  }

  /* --------------------------------------------------------------- verdict */

  function dedupe(detections) {
    const best = new Map();
    for (const detection of detections) {
      const key = `${detection.name}|${detection.source}`;
      const current = best.get(key);
      if (!current || detection.score > current.score) best.set(key, detection);
    }
    return [...best.values()].sort((a, b) => b.score - a.score);
  }

  function verdictFor(detections) {
    if (!detections.length) return "clean";
    if (detections.some((d) => d.source === "signature" || d.source === "yara")) return "malicious";
    if (detections.some((d) => d.severity === "critical")) return "malicious";
    return "suspicious";
  }

  /* The name shown to the user: a signature or YARA hit identifies a concrete
     family, so it outranks a heuristic hit even when the heuristic scored
     higher. Same rule as ScanResult.primary_name in the product. */
  function primaryName(detections) {
    if (!detections.length) return "";
    const rank = { signature: 3, yara: 2, heuristic: 0 };
    return [...detections].sort((a, b) =>
      (rank[b.source] - rank[a.source]) || (b.score - a.score))[0].name;
  }

  /* ------------------------------------------------------------------ api */

  async function scanBytes(bytes, name = "buffer", { threshold = 60 } = {}) {
    const started = performance.now();
    const view = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
    const slice = view.slice(0, 1024 * 1024);

    let text = "";
    try {
      text = new TextDecoder("latin1").decode(slice);
    } catch {
      text = Array.from(slice, (b) => String.fromCharCode(b)).join("");
    }

    const digest = await sha256(view);
    const heur = analyseHeuristics(view, text, name, threshold);

    const detections = dedupe([
      ...matchHash(digest),
      ...matchPatterns(text),
      ...matchYara(text),
      ...heur.detections,
    ]);

    return {
      name,
      size: view.length,
      sha256: digest,
      fileType: heur.type,
      entropy: heur.entropy,
      heuristicRules: heur.rules,
      detections,
      verdict: verdictFor(detections),
      threatName: primaryName(detections),
      severity: worstSeverity(detections.map((d) => d.severity)),
      durationMs: performance.now() - started,
    };
  }

  async function scanText(content, name = "buffer", options) {
    return scanBytes(new TextEncoder().encode(content), name, options);
  }

  async function scanFile(file, options) {
    const buffer = await file.slice(0, 1024 * 1024).arrayBuffer();
    return scanBytes(new Uint8Array(buffer), file.name, options);
  }

  return {
    scanBytes, scanText, scanFile,
    entropy, detectType,
    SEVERITY_ORDER,
    ruleCount: YARA_RULES.length,
    signatureCount: PATTERN_SIGNATURES.length + Object.keys(HASH_SIGNATURES).length,
  };
})();

if (typeof window !== "undefined") window.GuardiantusEngine = GuardiantusEngine;
