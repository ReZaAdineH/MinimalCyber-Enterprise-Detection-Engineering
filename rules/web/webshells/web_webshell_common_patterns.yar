rule Web_Webshell_Common_Patterns
{
    meta:
        author = "Reza Adineh"
        description = "Detects common PHP, ASP.NET, and JSP webshell execution patterns"
        severity = "critical"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1505.003"
        platform = "Web"
        category = "Persistence"
        false_positives = "Admin panels, test scripts, vulnerable training applications"

    strings:
        $php1 = "eval($_POST" nocase
        $php2 = "system($_GET" nocase
        $php3 = "base64_decode" nocase
        $asp1 = "cmd.exe /c" nocase
        $asp2 = "ProcessStartInfo" nocase
        $jsp1 = "Runtime.getRuntime().exec" nocase
        $jsp2 = "request.getParameter" nocase

    condition:
        2 of them
}
