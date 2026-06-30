rule Cloud_AWS_Metadata_Credential_Access
{
    meta:
        author = "Reza Adineh"
        description = "Detects AWS metadata service credential access indicators in scripts or captured artifacts"
        severity = "high"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1552.005,T1528"
        platform = "AWS"
        category = "Credential Access"
        false_positives = "Cloud automation, approved metadata service usage, bootstrap scripts"

    strings:
        $a1 = "169.254.169.254" nocase
        $a2 = "/latest/meta-data" nocase
        $a3 = "/iam/security-credentials" nocase
        $a4 = "X-aws-ec2-metadata-token" nocase
        $a5 = "metadata/identity/oauth2/token" nocase

    condition:
        2 of them
}
