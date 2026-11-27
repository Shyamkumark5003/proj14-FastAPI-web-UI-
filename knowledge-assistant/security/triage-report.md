# Security Scan Triage Report

Project: Knowledge Assistant (FastAPI)
Branch: task-17-security-hardening
Scan date: 2026-11-27

## Scope and tools

| Tool | Version | Scope | Command |
|------|---------|-------|---------|
| pip-audit | (fill in) | requirements.txt (hashed lockfile) | see security/README.md |
| Bandit | (fill in) | application code; tests/ excluded (assert noise) | see security/README.md |
| Semgrep CE | (fill in) | p/python, p/owasp-top-ten | see security/README.md |
| gitleaks | 8.30.1 | full git history, secrets redacted | see security/README.md |

Raw output: `security/scans/`

## Decision key

- **Fixed**: real issue, code or dependency changed
- **False positive**: tool is wrong, reason given
- **Accepted risk**: real but accepted, reason and owner given
- **Follow-up**: real, fix planned later

## Summary

| Tool | Findings | Fixed | False positive | Accepted | Follow-up |
|------|----------|-------|----------------|----------|-----------|
| pip-audit | | | | | |
| Bandit | | | | | |
| Semgrep CE | | | | | |
| gitleaks | | | | | |

## Findings

| # | Tool | Rule / ID | Location | Decision | Reason and evidence |
|---|------|-----------|----------|----------|---------------------|
| 1 | | | | | |
