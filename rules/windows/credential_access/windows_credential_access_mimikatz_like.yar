rule Windows_Credential_Access_Mimikatz_Like
{
    meta:
        author = "Reza Adineh"
        description = "Detects common Mimikatz-like credential dumping strings"
        severity = "critical"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1003"
        platform = "Windows"
        category = "Credential Access"
        false_positives = "Security training labs, red-team tools, malware analysis repositories"

    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "lsadump::sam" nocase
        $m3 = "privilege::debug" nocase
        $m4 = "mimikatz" nocase
        $m5 = "kuhl_m_sekurlsa" nocase
        $m6 = "sekurlsa::tickets" nocase

    condition:
        any of them
}
