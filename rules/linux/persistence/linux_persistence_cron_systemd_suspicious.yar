rule Linux_Persistence_Cron_Systemd_Suspicious
{
    meta:
        author = "Reza Adineh"
        description = "Detects suspicious Linux persistence artifacts using cron and systemd"
        severity = "medium"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1053.003,T1543.002"
        platform = "Linux"
        category = "Persistence"
        false_positives = "Legitimate service installation and scheduled administration tasks"

    strings:
        $cron1 = "/etc/cron.d" nocase
        $cron2 = "crontab -e" nocase
        $cron3 = "@reboot" nocase
        $sys1 = "/etc/systemd/system" nocase
        $sys2 = "systemctl enable" nocase
        $sys3 = "WantedBy=multi-user.target" nocase
        $net1 = "curl" nocase
        $net2 = "wget" nocase

    condition:
        (2 of ($cron*) or 2 of ($sys*)) and any of ($net*)
}
