# Rule Writing Guide

## Standard Metadata

Each rule should include:

```yara
meta:
    author = "Reza Adineh"
    description = "Short behavior-focused description"
    severity = "low | medium | high | critical"
    status = "experimental | testing | stable | deprecated"
    date = "YYYY-MM-DD"
    modified = "YYYY-MM-DD"
    mitre_attack = "Txxxx"
    platform = "Windows | Linux | AWS | Azure | GCP | Web | Office"
    category = "ATT&CK tactic or detection category"
    false_positives = "Expected benign matches"
```

## Naming Convention

```text
platform_category_behavior.yar
```

## Detection Philosophy

Prefer behavior-focused rules over malware-family-only naming. The best enterprise rules explain what adversary behavior is being detected and where the rule should be used.
