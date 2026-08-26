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

  /* Ported from rules/guardiantus_base.yar. `when` mirrors the rule's own
     condition: `has(s)` is one string, `count([...])` is how many of a set
     matched. `confidence: "low"` marks a rule that describes plausible
     behaviour rather than identifying a threat -- see verdictFor. */
  const YARA_RULES = [
    { rule: "Guardiantus_SelfTest_Yara", name: "Guardiantus.SelfTest.YaraProbe", severity: "info", score: 10,
      description: "Self-test rule proving the YARA layer is live.",
      when: (has) => has("GUARDIANTUS-AV-YARA-SELFTEST-MARKER") },

    { rule: "Reverse_Shell_Bash", name: "Backdoor.Shell.ReverseTCP", severity: "critical", score: 90,
      description: "Bash reverse shell using /dev/tcp redirection.",
      when: (has) => has("/dev/tcp/") && has(">&") && has("bash -i") },

    { rule: "Reverse_Shell_Python", name: "Backdoor.Python.ReverseShell", severity: "critical", score: 90,
      description: "Python socket reverse shell wiring stdio onto a socket.",
      when: (has) => has("socket.socket") && has(".connect(") && has("os.dup2")
        && (has("pty.spawn") || has("subprocess.call")) },

    { rule: "PowerShell_Download_Cradle", name: "Trojan.PowerShell.DownloadCradle", severity: "high", score: 85,
      description: "PowerShell one-liner that downloads and immediately executes a payload.",
      nocase: true,
      when: (has) => has("system.net.webclient")
        && (has("downloadstring") || has("downloadfile"))
        && (has("invoke-expression") || has("iex(")) },

    { rule: "Ransomware_Shadow_Copy_Wipe", name: "Ransom.Generic.ShadowWipe", severity: "critical", score: 95,
      description: "Deletes shadow copies and disables recovery — the ransomware fingerprint.",
      nocase: true,
      when: (has) => (has("vssadmin") && has("delete shadows"))
        || (has("bcdedit") && has("recoveryenabled no")) || has("delete catalog") },

    /* A note has to claim the encryption *and* name a way to pay. Three of six
       generic words also describes any article about ransomware -- and nothing
       in the text can tell those apart, so this reports rather than convicts. */
    { rule: "Ransom_Note_Text", name: "Ransom.Note.Generic", severity: "high", score: 75,
      confidence: "low", description: "Text that reads like a ransom note.",
      nocase: true,
      when: (has, count) =>
        count(["your files have been encrypted", "all your files are encrypted", "to decrypt your files"]) >= 1
        && count(["bitcoin", ".onion", "decryption key"]) >= 2 },

    /* Chrome contains every string a Chrome-stealer references: its own
       user-data path, "Login Data" and its own master-key name. Reaching into
       several vendors' stores at once is the part that is hard to explain --
       and a profile importer does that too, so this reports rather than
       convicts. */
    { rule: "Credential_Stealer_Browser", name: "Spyware.Stealer.BrowserCredentials", severity: "high", score: 75,
      confidence: "low", description: "Reads several browsers' credential stores — infostealer behaviour.",
      nocase: true,
      when: (has, count) =>
        count(["\\google\\chrome\\user data", "\\microsoft\\edge\\user data",
               "\\bravesoftware\\brave-browser", "\\opera software\\opera stable",
               "logins.json", "key4.db", "login data"]) >= 3
        && (has("cryptunprotectdata") || has("encrypted_key")) },

    /* Reading key state is what every game and input library does; installing
       the low-level hook is what makes it a keylogger. */
    { rule: "Keylogger_Windows_Hooks", name: "Spyware.Keylogger.WinHook", severity: "high", score: 85,
      description: "Installs a low-level keyboard hook and records keystrokes.",
      when: (has) => has("SetWindowsHookEx")
        && (has("WH_KEYBOARD_LL") || (has("GetAsyncKeyState") && has("GetKeyboardState"))) },

    /* All three stages, not two plus OpenProcess: naming a couple of these is
       ordinary for debuggers, installers and every Windows library that
       re-exports the process API. */
    { rule: "Process_Injection_Classic", name: "Trojan.Win32.ProcessInjection", severity: "high", score: 85,
      description: "Classic CreateRemoteThread process-injection API chain.",
      when: (has) => has("VirtualAllocEx") && has("WriteProcessMemory")
        && (has("CreateRemoteThread") || has("QueueUserAPC")) },

    /* A stratum URL on its own is just the word: it appears in documentation
       and in the config of someone who mines on purpose. */
    { rule: "Crypto_Miner_Config", name: "Trojan.CoinMiner.Config", severity: "high", score: 70,
      confidence: "low", description: "Cryptocurrency miner configuration or command line.",
      nocase: true,
      when: (has, count) =>
        (has("stratum+tcp://") && count(["xmrig", "donate-level", "randomx", "cryptonight"]) >= 1)
        || (has("xmrig") && has("donate-level")) },

    { rule: "Linux_Persistence_Cron", name: "Backdoor.Linux.CronPersistence", severity: "medium", score: 70,
      description: "Cron entry that repeatedly fetches and runs remote code.",
      when: (has) => (has("/etc/cron") || has("crontab -"))
        && (has("curl -") || has("wget -")) && (has("| sh") || has("| bash")) },

    { rule: "Suspicious_UPX_Dropper", name: "Trojan.Packed.UPXDropper", severity: "medium", score: 65,
      description: "UPX-packed executable that also reaches for remote-download APIs.",
      when: (has) => has("UPX!")
        && (has("URLDownloadToFile") || has("WinHttpOpenRequest") || has("InternetOpenUrlA")) },

    { rule: "Office_Macro_Dropper", name: "Trojan.Doc.MacroDropper", severity: "high", score: 85,
      description: "Office macro that auto-runs and spawns a shell or downloader.",
      nocase: true,
      when: (has) => (has("auto_open") || has("autoopen") || has("document_open"))
        && (has("shell(") || has("wscript.shell") || has("msxml2.xmlhttp")) },
  ];

  /* ----------------------------------------------------------- heuristics */

  /* [regex, label, score, primary]. A *primary* finding is a construct
     specific to malicious software; the rest are *supporting* -- properties
     malware often has and ordinary files have too. Only a primary finding can
     raise an alarm. See analyseHeuristics. */
  const SCRIPT_PATTERNS = [
    [/frombase64string\s*\(/i, "PowerShell base64 payload decode", 25, false],
    [/-enc(?:odedcommand)?\s+[A-Za-z0-9+/=]{40,}/i, "PowerShell encoded command", 40, true],
    [/invoke-expression|(?<![\w-])iex(?![\w-])/i, "Dynamic code execution (IEX)", 25, false],
    [/downloadstring\s*\(|downloadfile\s*\(/i, "Remote payload download", 30, false],
    [/new-object\s+system\.net\.webclient/i, "WebClient dropper pattern", 25, false],
    [/-(?:exec(?:utionpolicy)?)\s+bypass/i, "ExecutionPolicy bypass", 30, true],
    [/\beval\s*\(\s*(?:atob|base64_decode|gzinflate)/i, "Obfuscated eval chain", 40, true],
    [/\bshell_exec\s*\(|\bpassthru\s*\(|\bsystem\s*\(\s*\$_/i, "PHP command execution", 35, true],
    [/wscript\.shell/i, "WScript.Shell automation", 20, false],
    [/reg(?:\.exe)?\s+add\s+.{0,80}\\currentversion\\run/i, "Run-key persistence", 35, true],
    [/schtasks\s+\/create/i, "Scheduled-task persistence", 25, false],
    [/vssadmin\s+delete\s+shadows|wbadmin\s+delete\s+catalog/i, "Shadow-copy deletion (ransomware)", 60, true],
    [/bcdedit\s+.{0,40}recoveryenabled\s+no/i, "Recovery disabled (ransomware)", 55, true],
    [/rm\s+-rf\s+(?:\/|\/\*|\$HOME)/i, "Destructive recursive delete", 45, true],
    [/(?:curl|wget)\s+[^|\n]{0,120}\|\s*(?:ba)?sh/i, "Pipe-to-shell installer", 40, true],
    [/nc(?:\.exe)?\s+-(?:l|e)\s/i, "Netcat listener/reverse shell", 35, true],
    [/\/dev\/tcp\/\d{1,3}(?:\.\d{1,3}){3}\/\d+/i, "Raw TCP reverse shell", 45, true],
    [/crontab\s+-\s*$|>>\s*\/etc\/cron/im, "Cron persistence", 25, false],
    [/mimikatz|sekurlsa::|lsadump::/i, "Credential-dumping tooling", 70, true],
    [/\bkeylog|GetAsyncKeyState|SetWindowsHookEx/i, "Keylogging API usage", 40, true],
  ];

  const DOWNLOAD_LABELS = ["Remote payload download", "WebClient dropper pattern"];
  const EXECUTE_LABELS = ["Dynamic code execution (IEX)", "Obfuscated eval chain",
                          "WScript.Shell automation"];

  // A note claims the encryption happened, and names a way to pay. Either half
  // alone is ordinary: a backup note mentions a wallet and a decryption key.
  const RANSOM_CLAIMS = [
    "your files have been encrypted", "all your files are encrypted",
    "to decrypt your files", "your data has been encrypted",
  ];
  const RANSOM_DEMANDS = [
    "bitcoin wallet", "tor browser", "recover your data",
    "decryption key", "contact us", "payment",
  ];

  // Windows forwarder DLLs contain nothing but the names of the Win32
  // functions they re-export, so every behavioural rule matches them.
  const SYSTEM_LIBRARY_PREFIXES = [
    "api-ms-win-", "ext-ms-win-", "ucrtbase", "vcruntime", "msvcp", "msvcr",
    "kernel32", "kernelbase", "ntdll", "advapi32", "combase", "python3",
  ];

  const SCRIPT_EXT = [".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse", ".wsf",
                      ".hta", ".sh", ".bash", ".py", ".pl", ".php", ".rb", ".lua"];
  const EXECUTABLE_EXT = [".exe", ".dll", ".scr", ".com", ".pif", ".cpl", ".bat", ".cmd", ".js", ".vbs", ".msi"];
  const DECOY_EXT = [".pdf", ".doc", ".docx", ".xls", ".xlsx", ".jpg", ".jpeg", ".png", ".txt", ".mp4", ".zip"];
  const DOCUMENT_EXT = [".doc", ".docm", ".xls", ".xlsm", ".ppt", ".pptm", ".rtf", ".pdf"];
  const RTL_MARKS = ["‮", "‫", "⁧"];

  const ONION_RE = /\b[a-z2-7]{16,56}\.onion\b/i;
  // Only very long unbroken runs are interesting: config files, skin caches
  // and web assets routinely carry a few hundred characters of base64.
  const LONG_B64_RE = /[A-Za-z0-9+/]{1500,}={0,2}/;
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
      const count = (needles) => needles.filter(has).length;

      if (!rule.when(has, count)) continue;

      found.push({
        source: "yara", layer: "YARA rule", name: rule.name,
        severity: rule.severity, score: rule.score, description: rule.description,
        confidence: rule.confidence || "high",
        evidence: `rule ${rule.rule}`,
      });
    }
    return found;
  }

  /* ---------------------------------------------------- layer: heuristics */

  function isOsRuntimeLibrary(name, text) {
    const lower = name.toLowerCase();
    if (!SYSTEM_LIBRARY_PREFIXES.some((prefix) => lower.startsWith(prefix))) return false;
    if (!text.startsWith("MZ")) return false;
    // The export directory of a forwarder carries the module's own name; an
    // impostor that only borrows the name does not get the free pass.
    const stem = lower.replace(/\.[^.]*$/, "");
    return stem.length > 0 && text.toLowerCase().includes(stem);
  }

  /* Findings are [label, score, severity, primary]. A file is only reported
     when at least one *primary* finding is present: entropy, base64 blobs,
     hardcoded URLs and injection API imports are things ordinary files have
     too, and adding them up used to be enough to raise an alarm on a game
     asset bundle or a launcher log. */
  function analyseHeuristics(bytes, text, name, threshold = 60) {
    const rules = [];
    const type = detectType(bytes, name);
    const ext = extension(name);
    const lowerName = name.toLowerCase();
    const isScript = type === "script" || SCRIPT_EXT.includes(ext);
    const bits = entropy(bytes.slice(0, 262144));

    // Naming tricks.
    const parts = lowerName.split(".");
    if (parts.length >= 3) {
      const inner = `.${parts[parts.length - 2]}`;
      if (DECOY_EXT.includes(inner) && EXECUTABLE_EXT.includes(ext)) {
        rules.push(["Double extension disguise", 45, "high", true]);
      }
    }
    if (RTL_MARKS.some((mark) => name.includes(mark))) {
      rules.push(["Right-to-left override in filename", 60, "high", true]);
    }
    if (DOCUMENT_EXT.includes(ext) && ["pe", "elf"].includes(type)) {
      rules.push(["Executable masquerading as a document", 65, "critical", true]);
    }
    if ([".jpg", ".png", ".gif", ".mp3", ".mp4"].includes(ext) && ["pe", "elf"].includes(type)) {
      rules.push(["Executable masquerading as media", 60, "high", true]);
    }

    // Entropy. Compressed archives, media and minified assets are all
    // high-entropy, so this only ever counts as corroboration.
    if (["pe", "elf"].includes(type) && bits > 7.2) {
      rules.push([`High-entropy executable (packed, ${bits.toFixed(2)} bits/byte)`, 30, "medium", false]);
    } else if (isScript && bits > 6.2 && bytes.length > 2048) {
      rules.push([`Obfuscated script content (${bits.toFixed(2)} bits/byte)`, 20, "medium", false]);
    }

    // Attacker constructs. These run on plain text too -- a ransom note or a
    // wiper batch file is not a script by extension.
    if (["script", "text", "ole"].includes(type) || isScript) {
      const labels = new Set();
      for (const [regex, label, score, primary] of SCRIPT_PATTERNS) {
        if (regex.test(text)) {
          rules.push([label, score, score >= 40 ? "high" : "medium", primary]);
          labels.add(label);
        }
      }
      // Fetching a payload is ordinary and running a string is ordinary; a
      // script that does both in one breath is a download cradle.
      if (DOWNLOAD_LABELS.some((l) => labels.has(l)) && EXECUTE_LABELS.some((l) => labels.has(l))) {
        rules.push(["Download-and-execute chain", 45, "high", true]);
      }
      if (ONION_RE.test(text)) rules.push(["Tor hidden-service address", 35, "high", true]);
    }

    // Shape-of-the-file signals. Scripts only: data files trip all of them.
    if (isScript) {
      if (LONG_B64_RE.test(text)) rules.push(["Large embedded base64 blob", 20, "low", false]);

      const urls = new Set(text.match(URL_RE) || []);
      if (urls.size > 12) rules.push([`Many hardcoded URLs (${urls.size})`, 10, "low", false]);

      const ips = new Set((text.match(IPV4_RE) || []).filter((ip) => !/^(0\.|127\.|255\.)/.test(ip)));
      if (ips.size >= 3) rules.push([`Multiple hardcoded IP addresses (${ips.size})`, 10, "low", false]);
    }

    // Structural.
    if (type === "pe") {
      for (const marker of ["UPX!", "UPX0", "ASPack", "MPRESS1", "Themida", "VMProtect"]) {
        if (text.includes(marker)) { rules.push([`Packed executable (${marker})`, 30, "medium", false]); break; }
      }
      // Two matching strings prove nothing -- debuggers, installers and
      // anti-cheat shims import them too.
      const apis = ["VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread", "QueueUserAPC",
                    "SetThreadContext", "NtUnmapViewOfSection"].filter((api) => text.includes(api));
      if (apis.length >= 3) {
        rules.push([`Process-injection API combination (${apis.length})`,
                    Math.min(30, 10 * apis.length), "medium", false]);
      }
    }
    if (type === "pdf" && (text.includes("/JavaScript") || text.includes("/JS")) && text.includes("/OpenAction")) {
      rules.push(["PDF with auto-run JavaScript", 40, "high", true]);
    }
    if (text.includes("Auto_Open") || text.includes("AutoOpen") || text.includes("Document_Open")) {
      rules.push(["Auto-executing office macro", 45, "high", true]);
    }

    const lowerText = text.toLowerCase();
    const claims = RANSOM_CLAIMS.filter((hint) => lowerText.includes(hint));
    const demands = RANSOM_DEMANDS.filter((hint) => lowerText.includes(hint));
    // High, not critical: nothing in the words separates a real note from an
    // article about ransomware, and critical would have the file taken away.
    if (claims.length && demands.length) rules.push(["Ransom-note text", 70, "high", true]);

    if (["pe", "elf"].includes(type) && bytes.length < 8192) {
      rules.push(["Unusually small executable", 15, "low", false]);
    }

    const primary = rules.filter((r) => r[3]);
    if (!rules.length || !primary.length) return { detections: [], type, entropy: bits, rules };

    const total = rules.reduce((sum, r) => sum + r[1], 0);
    if (total < threshold) return { detections: [], type, entropy: bits, rules };

    const sorted = [...rules].sort((a, b) => b[1] - a[1]);
    // Both the name and the severity come from the primary findings, so the
    // user never sees an alarm titled after a supporting observation.
    const label = [...primary].sort((a, b) => b[1] - a[1])[0][0];
    const severity = worstSeverity(primary.map((r) => r[2]));
    const slug = label.replace(/[^A-Za-z0-9]+/g, "").slice(0, 34) || "Generic";

    return {
      type,
      entropy: bits,
      rules: sorted,
      detections: [{
        source: "heuristic", layer: "Heuristics", name: `Heuristic.${slug}`,
        severity, score: Math.min(100, total), confidence: "high",
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

  /* A signature or YARA hit normally names a specific threat, which makes the
     file malicious and therefore something to move. Rules that describe
     behaviour they cannot pin down say so with confidence "low" and only ever
     reach suspicious, so an imprecise rule reports rather than takes a file
     away. Same rule as FileScanner._verdict_for in the product. */
  function verdictFor(detections) {
    if (!detections.length) return "clean";
    const identified = (d) => (d.source === "signature" || d.source === "yara")
      && d.confidence !== "low";
    if (detections.some(identified)) return "malicious";
    if (detections.some((d) => d.severity === "critical" && d.confidence !== "low")) return "malicious";
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

    /* Windows API-set forwarder DLLs contain nothing but the names of the
       Win32 functions they re-export, so every behavioural rule matches them
       by construction. They are judged on signatures alone; a real threat
       wearing one of those names still has to survive the hash and pattern
       database. Same gate as FileScanner._inspect_buffer in the product. */
    const behavioural = !isOsRuntimeLibrary(name, text);
    const heur = behavioural
      ? analyseHeuristics(view, text, name, threshold)
      : { detections: [], type: detectType(view, name), entropy: entropy(view.slice(0, 262144)), rules: [] };

    const detections = dedupe([
      ...matchHash(digest),
      ...matchPatterns(text),
      ...(behavioural ? matchYara(text) : []),
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
