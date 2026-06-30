rule Linux_Cloud_Recon_AWS_Metadata
{
    meta:
        author = "Reza Adineh"
        description = "Detects AWS instance metadata service access and cloud credential discovery artifacts"
        severity = "high"
        status = "experimental"
        date = "2026-06-30"
        modified = "2026-06-30"
        mitre_attack = "T1552.005,T1528"
        platform = "Linux / AWS"
        category = "Credential Access / Discovery"
        false_positives = "Cloud bootstrap scripts, monitoring agents, legitimate inventory tooling"

    strings:
        $imds1 = "curl http://169.254.169.254" nocase
        $imds2 = "wget http://169.254.169.254" nocase
        $imds3 = "/latest/meta-data/iam/security-credentials" nocase
        $aws1 = "aws_access_key_id" nocase
        $aws2 = "aws_secret_access_key" nocase
        $aws3 = ".aws/credentials" nocase
        $aws4 = "AWS_SESSION_TOKEN" nocase

    condition:
        any of ($imds*) or 2 of ($aws*)
}
