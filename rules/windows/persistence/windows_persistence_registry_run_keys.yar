rule Windows_Persistence_Registry_Run_Keys
{
    meta:
        author = "Reza Adineh"
        description = "Detects registry Run key persistence references commonly seen in malware and intrusion tooling"
        severity = "medium"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1060,T1547.001"
        platform = "Windows"
        category = "Persistence"
        false_positives = "Legitimate software installers and endpoint agents"

    strings:
        $reg1 = "Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg2 = "Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce" nocase
        $reg3 = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $reg4 = "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" nocase
        $cmd1 = "reg add" nocase
        $cmd2 = "schtasks /create" nocase

    condition:
        any of ($reg*) and any of ($cmd*)
}
