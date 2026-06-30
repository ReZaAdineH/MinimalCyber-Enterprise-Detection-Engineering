rule Linux_Privilege_Escalation_Sudoers_Suspicious
{
    meta:
        author = "Reza Adineh"
        description = "Detects suspicious sudoers modification and privilege escalation script artifacts"
        severity = "high"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1548.003"
        platform = "Linux"
        category = "Privilege Escalation"
        false_positives = "Configuration management, system hardening scripts, admin automation"

    strings:
        $s1 = "/etc/sudoers" nocase
        $s2 = "NOPASSWD" nocase
        $s3 = "chmod u+s" nocase
        $s4 = "setuid" nocase
        $s5 = "usermod -aG sudo" nocase
        $s6 = "visudo" nocase

    condition:
        2 of them
}
