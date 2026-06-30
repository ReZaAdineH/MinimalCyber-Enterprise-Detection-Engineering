rule Office_Macro_Dropper_Suspicious
{
    meta:
        author = "Reza Adineh"
        description = "Detects suspicious Office macro patterns associated with downloader and dropper behavior"
        severity = "high"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1566.001,T1204.002,T1059"
        platform = "Office"
        category = "Initial Access / Execution"
        false_positives = "Legacy business macros, admin automation documents"

    strings:
        $o1 = "AutoOpen" nocase
        $o2 = "Document_Open" nocase
        $o3 = "CreateObject" nocase
        $o4 = "WScript.Shell" nocase
        $o5 = "Shell.Application" nocase
        $o6 = "URLDownloadToFile" nocase
        $o7 = "powershell" nocase
        $o8 = "cmd.exe" nocase

    condition:
        4 of them
}
