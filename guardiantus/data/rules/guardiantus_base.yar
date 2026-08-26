/*
    Guardiantus AV — baseline YARA rules.

    These run under yara-python when it is installed, and under the built-in
    fallback interpreter otherwise. Keep conditions to the supported subset:
    "N of them", "any of them", "all of them", "N of ($a*)" and boolean
    combinations of string identifiers.

    meta fields Guardiantus understands:
        threat_name  name reported in the UI (defaults to the rule name)
        severity     info | low | medium | high | critical
        score        0-100 confidence contribution
        confidence   high (default) | low -- "low" marks a rule that describes
                     plausible behaviour rather than identifying a threat, so
                     it reports the file instead of convicting it
        description  shown in the detection detail panel
*/

rule Guardiantus_SelfTest_Yara
{
    meta:
        threat_name = "Guardiantus.SelfTest.YaraProbe"
        severity = "info"
        score = 10
        description = "Self-test rule; matches the Guardiantus YARA probe marker"
        author = "Guardiantus AV"
    strings:
        $probe = "GUARDIANTUS-AV-YARA-SELFTEST-MARKER"
    condition:
        any of them
}

rule Reverse_Shell_Bash
{
    meta:
        threat_name = "Backdoor.Shell.ReverseTCP"
        severity = "critical"
        score = 90
        description = "Bash reverse shell using /dev/tcp redirection"
    strings:
        $tcp = "/dev/tcp/"
        $redirect = ">&"
        $shell = "bash -i"
    condition:
        $tcp and $redirect and $shell
}

rule Reverse_Shell_Python
{
    meta:
        threat_name = "Backdoor.Python.ReverseShell"
        severity = "critical"
        score = 90
        description = "Python socket reverse shell duplicating stdio onto a socket"
    strings:
        $sock = "socket.socket"
        $connect = ".connect("
        $dup = "os.dup2"
        $spawn = "pty.spawn"
        $sub = "subprocess.call"
    condition:
        $sock and $connect and $dup and ($spawn or $sub)
}

rule PowerShell_Download_Cradle
{
    meta:
        threat_name = "Trojan.PowerShell.DownloadCradle"
        severity = "high"
        score = 85
        description = "PowerShell one-liner that downloads and immediately executes a payload"
    strings:
        $web = "System.Net.WebClient" nocase
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $iex = "Invoke-Expression" nocase
        $iex2 = "IEX(" nocase
    condition:
        $web and ($dl1 or $dl2) and ($iex or $iex2)
}

rule Ransomware_Shadow_Copy_Wipe
{
    meta:
        threat_name = "Ransom.Generic.ShadowWipe"
        severity = "critical"
        score = 95
        description = "Deletes volume shadow copies and disables recovery — hallmark of ransomware"
    strings:
        $vss = "vssadmin" nocase
        $delete = "delete shadows" nocase
        $bcd = "bcdedit" nocase
        $recovery = "recoveryenabled no" nocase
        $wbadmin = "delete catalog" nocase
    condition:
        ($vss and $delete) or ($bcd and $recovery) or $wbadmin
}

/*
    A note has to claim the encryption *and* name a way to pay; three of the
    six words alone also describes any article about ransomware.  Nothing in
    the text can tell those apart, so this reports: a note is evidence of an
    attack rather than the thing that carried it out, and taking the victim's
    copy away helps nobody.
*/
rule Ransom_Note_Text
{
    meta:
        threat_name = "Ransom.Note.Generic"
        severity = "high"
        score = 75
        confidence = "low"
        description = "Text that reads like a ransom note"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "to decrypt your files" nocase
        $d = "bitcoin" nocase
        $e = ".onion" nocase
        $f = "decryption key" nocase
    condition:
        1 of ($a, $b, $c) and 2 of ($d, $e, $f)
}

/*
    A browser contains every string a browser-stealer references: Chrome ships
    "Login Data", its own user-data path and its own master-key name, and Edge
    imports from Chrome on purpose.  Reaching into *several* vendors' stores at
    once is the part that is hard to explain innocently, so that is what this
    counts -- and because a profile importer does the same thing, it reports
    rather than convicts.
*/
rule Credential_Stealer_Browser
{
    meta:
        threat_name = "Spyware.Stealer.BrowserCredentials"
        severity = "high"
        score = 75
        confidence = "low"
        description = "Reads several browsers' credential stores — infostealer behaviour"
    strings:
        $chrome = "\\Google\\Chrome\\User Data" nocase
        $edge = "\\Microsoft\\Edge\\User Data" nocase
        $brave = "\\BraveSoftware\\Brave-Browser" nocase
        $opera = "\\Opera Software\\Opera Stable" nocase
        $firefox = "logins.json" nocase
        $key = "key4.db" nocase
        $login = "Login Data"
        $master = "encrypted_key" nocase
        $dpapi = "CryptUnprotectData" nocase
    condition:
        3 of ($chrome, $edge, $brave, $opera, $firefox, $key, $login)
        and ($dpapi or $master)
}

/*
    Reading key state is what every game and input library does; installing the
    low-level hook is what makes it a keylogger.  Requiring the hook keeps this
    off ordinary input code.
*/
rule Keylogger_Windows_Hooks
{
    meta:
        threat_name = "Spyware.Keylogger.WinHook"
        severity = "high"
        score = 85
        description = "Installs a low-level keyboard hook and records keystrokes"
    strings:
        $hook = "SetWindowsHookEx"
        $ll = "WH_KEYBOARD_LL"
        $async = "GetAsyncKeyState"
        $state = "GetKeyboardState"
    condition:
        $hook and ($ll or ($async and $state))
}

/*
    All three stages of the injection chain, not two of them plus OpenProcess.
    Naming a couple of these APIs is ordinary for debuggers, installers, and
    every Windows library that re-exports the process API -- the api-ms-win-*
    forwarder DLLs list the lot of them and nothing else.
*/
rule Process_Injection_Classic
{
    meta:
        threat_name = "Trojan.Win32.ProcessInjection"
        severity = "high"
        score = 85
        description = "Classic CreateRemoteThread process-injection API chain"
    strings:
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $thread = "CreateRemoteThread"
        $apc = "QueueUserAPC"
    condition:
        $alloc and $write and ($thread or $apc)
}

/*
    A stratum URL on its own is just the word: it appears in documentation, in
    articles and in the config of someone who mines on purpose.  Pairing it
    with a miner-specific option is what makes it a miner.  Mining is also a
    choice a user is allowed to make, so this reports rather than convicts.
*/
rule Crypto_Miner_Config
{
    meta:
        threat_name = "Trojan.CoinMiner.Config"
        severity = "high"
        score = 70
        confidence = "low"
        description = "Cryptocurrency miner configuration or command line"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $pool = "--donate-level" nocase
        $algo = "randomx" nocase
        $coin = "cryptonight" nocase
    condition:
        ($stratum and 1 of ($xmrig, $pool, $algo, $coin)) or ($xmrig and $pool)
}

rule Linux_Persistence_Cron
{
    meta:
        threat_name = "Backdoor.Linux.CronPersistence"
        severity = "medium"
        score = 70
        description = "Installs a cron entry that repeatedly fetches and runs remote code"
    strings:
        $cron = "/etc/cron"
        $crontab = "crontab -"
        $curl = "curl -"
        $wget = "wget -"
        $pipe = "| sh"
        $pipe2 = "| bash"
    condition:
        ($cron or $crontab) and ($curl or $wget) and ($pipe or $pipe2)
}

rule Office_Macro_Dropper
{
    meta:
        threat_name = "Trojan.Doc.MacroDropper"
        severity = "high"
        score = 85
        description = "Office macro that auto-runs and spawns a shell or downloader"
    strings:
        $auto1 = "Auto_Open"
        $auto2 = "AutoOpen"
        $auto3 = "Document_Open"
        $shell = "Shell(" nocase
        $wscript = "WScript.Shell" nocase
        $xmlhttp = "MSXML2.XMLHTTP" nocase
    condition:
        (1 of ($auto*)) and ($shell or $wscript or $xmlhttp)
}

rule Suspicious_UPX_Dropper
{
    meta:
        threat_name = "Trojan.Packed.UPXDropper"
        severity = "medium"
        score = 65
        description = "UPX-packed executable that also references remote-download APIs"
    strings:
        $upx = "UPX!"
        $url = "URLDownloadToFile"
        $winhttp = "WinHttpOpenRequest"
        $internet = "InternetOpenUrlA"
    condition:
        $upx and ($url or $winhttp or $internet)
}
