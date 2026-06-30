rule Windows_Execution_PowerShell_Dropper
{
    meta:
        author = "Reza Adineh"
        description = "Detects suspicious PowerShell downloader and dropper patterns commonly seen in enterprise intrusions"
        severity = "high"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1059.001"
        platform = "Windows"
        category = "Execution"
        false_positives = "Administrative scripts, software deployment tooling, EDR scripts"

    strings:
        $ps1 = "powershell" nocase
        $ps2 = "Invoke-WebRequest" nocase
        $ps3 = "DownloadString" nocase
        $ps4 = "FromBase64String" nocase
        $ps5 = "-nop" nocase
        $ps6 = "-w hidden" nocase
        $ps7 = "IEX" nocase
        $ps8 = "System.Net.WebClient" nocase

    condition:
        4 of them
}
