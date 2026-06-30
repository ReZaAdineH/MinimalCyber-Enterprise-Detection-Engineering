# Threat-Informed YARA

Threat-informed YARA rules for hybrid enterprise detection engineering across Windows, Linux, cloud, web, and office attack surfaces.

## Purpose

This repository provides practical, high-level YARA rules for SOC teams, detection engineers, malware analysts, incident responders, and security operations architects.

The goal is not to provide perfect signatures. The goal is to provide reusable detection logic that can be tested, tuned, mapped to adversary behavior, and adapted to real enterprise environments.

## Detection Scope

- PowerShell abuse and droppers
- Credential dumping artifacts
- Ransomware note patterns
- Suspicious packed Windows executables
- Office macro droppers
- Webshell patterns
- Linux and cloud reconnaissance
- AWS metadata credential access
- Common C2 and post-exploitation artifacts

## Repository Structure

```text
rules/      YARA rules grouped by platform and adversary behavior
docs/       Rule writing, tuning, and false-positive guidance
scripts/    Rule validation and testing helpers
mappings/   MITRE ATT&CK, platform, and data-source mappings
tests/      Test placeholders for benign and malicious patterns
```

## Rule Maturity

Each rule should use one of the following maturity states:

- experimental
- testing
- stable
- deprecated

## Disclaimer

These rules are intended for defensive security operations, research, malware analysis, and detection engineering. They require validation and tuning before production deployment.
