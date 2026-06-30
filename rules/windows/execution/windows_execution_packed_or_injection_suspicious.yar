rule Windows_Execution_Packed_Or_Injection_Suspicious
{
    meta:
        author = "Reza Adineh"
        description = "Detects suspicious PE files with packing markers or process injection API combinations"
        severity = "medium"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1027,T1055"
        platform = "Windows"
        category = "Defense Evasion / Process Injection"
        false_positives = "Installers, protectors, legitimate packed software, endpoint agents"

    strings:
        $mz = { 4D 5A }
        $upx1 = "UPX0"
        $upx2 = "UPX1"
        $api1 = "VirtualAlloc" nocase
        $api2 = "WriteProcessMemory" nocase
        $api3 = "CreateRemoteThread" nocase
        $api4 = "LoadLibraryA" nocase
        $api5 = "GetProcAddress" nocase

    condition:
        $mz at 0 and (any of ($upx*) or 3 of ($api*))
}
