#!/usr/bin/env python3
"""Simple helper to list YARA rule files and expected repository structure."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
rules = sorted(root.glob("rules/**/*.yar"))

print(f"Found {len(rules)} YARA rule files:")
for rule in rules:
    print(f"- {rule.relative_to(root)}")
