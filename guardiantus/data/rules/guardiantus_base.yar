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

rule Ransom_Note_Text
{
    meta:
        threat_name = "Ransom.Note.Generic"
        severity = "high"
        score = 80
        description = "Text file carrying a ransom note"
    strings:
        $a = "your files have been encrypted" nocase
        $b = "all your files are encrypted" nocase
        $c = "to decrypt your files" nocase
        $d = "bitcoin" nocase
        $e = ".onion" nocase
        $f = "decryption key" nocase
    condition:
        3 of them
}

rule Credential_Stealer_Browser
{
    meta:
        threat_name = "Spyware.Stealer.BrowserCredentials"
        severity = "critical"
        score = 90
        description = "Reads browser credential stores — infostealer behaviour"
    strings:
        $login = "Login Data"
        $cookies = "Cookies"
        $chrome = "\\Google\\Chrome\\User Data" nocase
        $firefox = "logins.json" nocase
        $key = "key4.db" nocase
        $dpapi = "CryptUnprotectData" nocase
    condition:
        ($login and $chrome) or ($firefox and $key) or ($dpapi and $cookies)
}

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
        ($hook and $ll) or ($async and $state)
}

rule Process_Injection_Classic
{
    meta:
        threat_name = "Trojan.Win32.ProcessInjection"
        severity = "high"
        score = 85
        description = "Classic CreateRemoteThread process-injection API chain"
    strings:
        $open = "OpenProcess"
        $alloc = "VirtualAllocEx"
        $write = "WriteProcessMemory"
        $thread = "CreateRemoteThread"
        $apc = "QueueUserAPC"
    condition:
        $alloc and $write and ($thread or $apc or $open)
}

rule Crypto_Miner_Config
{
    meta:
        threat_name = "Trojan.CoinMiner.Config"
        severity = "high"
        score = 80
        description = "Cryptocurrency miner configuration or command line"
    strings:
        $stratum = "stratum+tcp://" nocase
        $xmrig = "xmrig" nocase
        $pool = "--donate-level" nocase
        $algo = "randomx" nocase
        $coin = "cryptonight" nocase
    condition:
        $stratum or ($xmrig and $pool) or ($algo and $coin)
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
