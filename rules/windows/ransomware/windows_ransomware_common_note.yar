rule Windows_Ransomware_Common_Note
{
    meta:
        author = "Reza Adineh"
        description = "Detects common ransomware note language and recovery-pressure wording"
        severity = "critical"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1486"
        platform = "Windows"
        category = "Impact"
        false_positives = "Threat reports, incident documentation, training material"

    strings:
        $r1 = "Your files have been encrypted" nocase
        $r2 = "decrypt your files" nocase
        $r3 = "bitcoin" nocase
        $r4 = ".onion" nocase
        $r5 = "restore your data" nocase
        $r6 = "shadow copies" nocase
        $r7 = "private key" nocase

    condition:
        3 of them
}
