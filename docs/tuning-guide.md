# Tuning Guide

YARA rules should be tested against both malicious and benign corpora before production use.

## Recommended Tuning Steps

1. Test against known-good enterprise software.
2. Test against threat samples or safe synthetic patterns.
3. Review false positives by business unit and asset type.
4. Add file type, filesize, PE section, import, or path constraints where needed.
5. Move rules from experimental to testing only after controlled validation.
6. Move rules to stable only after repeated low-noise detection.
