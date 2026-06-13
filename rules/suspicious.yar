/*
 * FileDessect bundled YARA rules.
 *
 * These are intentionally generic, behaviour-oriented heuristics meant to
 * raise visibility — not high-confidence family signatures. Drop additional
 * .yar / .yara files in this directory (mounted into the container) to extend
 * coverage; each rule's `severity` meta value feeds the verdict engine.
 */

rule Embedded_PE_In_NonPE
{
    meta:
        description = "A second Windows PE executable is embedded inside the file"
        severity = "high"
        author = "FileDessect"
    strings:
        $mz = { 4D 5A 90 00 03 00 00 00 04 00 00 00 FF FF }
    condition:
        // First match is the host file's own header at offset 0; a second
        // occurrence means an embedded/dropped executable.
        #mz > 1
}

rule Suspicious_PowerShell_Encoded
{
    meta:
        description = "Encoded/obfuscated PowerShell execution"
        severity = "high"
        author = "FileDessect"
    strings:
        $a = "powershell" nocase
        $b = "-enc" nocase
        $c = "-EncodedCommand" nocase
        $d = "FromBase64String" nocase
        $e = "-w hidden" nocase
        $f = "-nop" nocase
    condition:
        $a and (2 of ($b, $c, $d, $e, $f))
}

rule Process_Injection_APIs
{
    meta:
        description = "Combination of APIs used for process injection"
        severity = "high"
        author = "FileDessect"
    strings:
        $a = "VirtualAllocEx"
        $b = "WriteProcessMemory"
        $c = "CreateRemoteThread"
        $d = "NtUnmapViewOfSection"
        $e = "SetThreadContext"
    condition:
        3 of them
}

rule Ransomware_Shadow_Copy_Deletion
{
    meta:
        description = "Deletes Volume Shadow Copies to prevent recovery (ransomware)"
        severity = "critical"
        author = "FileDessect"
    strings:
        $a = "vssadmin" nocase
        $b = "delete shadows" nocase
        $c = "Win32_ShadowCopy" nocase
        $d = "bcdedit" nocase
        $e = "recoveryenabled no" nocase
    condition:
        ($a and $b) or $c or ($d and $e)
}

rule Keylogger_Behaviour
{
    meta:
        description = "APIs associated with keystroke logging"
        severity = "high"
        author = "FileDessect"
    strings:
        $a = "SetWindowsHookEx"
        $b = "GetAsyncKeyState"
        $c = "GetForegroundWindow"
        $d = "GetKeyboardState"
    condition:
        2 of them
}

rule Mimikatz_Indicators
{
    meta:
        description = "Strings associated with the Mimikatz credential dumper"
        severity = "critical"
        author = "FileDessect"
    strings:
        $a = "mimikatz" nocase
        $b = "sekurlsa" nocase
        $c = "logonpasswords" nocase
        $d = "gentilkiwi" nocase
    condition:
        any of them
}

rule UPX_Packed
{
    meta:
        description = "Binary packed with UPX"
        severity = "low"
        author = "FileDessect"
    strings:
        $a = "UPX0"
        $b = "UPX1"
        $c = "UPX!"
    condition:
        2 of them
}

rule Suspicious_Script_Eval_Download
{
    meta:
        description = "Script that downloads and dynamically executes code"
        severity = "medium"
        author = "FileDessect"
    strings:
        $dl1 = "DownloadString" nocase
        $dl2 = "DownloadFile" nocase
        $dl3 = "urllib" nocase
        $dl4 = "wget " nocase
        $dl5 = "curl " nocase
        $ev1 = "Invoke-Expression" nocase
        $ev2 = "eval(" nocase
        $ev3 = "exec(" nocase
    condition:
        any of ($dl*) and any of ($ev*)
}
