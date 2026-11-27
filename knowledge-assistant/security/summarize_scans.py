"""Print a short summary of all scanner outputs in security/scans/."""

import json
from pathlib import Path

SCANS = Path(__file__).parent / "scans"


def load(name):
    path = SCANS / name
    if not path.exists() or path.stat().st_size == 0:
        return None
    return json.loads(path.read_text())


def pip_audit():
    data = load("pip-audit.json")
    print("\n== pip-audit ==")
    if data is None:
        print("no output file")
        return
    found = 0
    for dep in data.get("dependencies", []):
        for vuln in dep.get("vulns", []):
            found += 1
            fixes = ", ".join(vuln.get("fix_versions", [])) or "no fix yet"
            print(f"- {dep['name']}=={dep['version']}: {vuln['id']} (fix: {fixes})")
    print(f"total: {found}")


def bandit():
    data = load("bandit.json")
    print("\n== Bandit ==")
    if data is None:
        print("no output file")
        return
    results = data.get("results", [])
    for r in results:
        print(
            f"- {r['test_id']} {r['issue_severity']}/{r['issue_confidence']} "
            f"{r['filename']}:{r['line_number']} {r['issue_text']}"
        )
    print(f"total: {len(results)}")


def semgrep():
    data = load("semgrep.json")
    print("\n== Semgrep CE ==")
    if data is None:
        print("no output file")
        return
    results = data.get("results", [])
    for r in results:
        print(
            f"- {r['extra'].get('severity', '?')} {r['check_id']} "
            f"{r['path']}:{r['start']['line']}"
        )
    print(f"total: {len(results)}")


def gitleaks():
    data = load("gitleaks.json")
    print("\n== gitleaks ==")
    if data is None:
        print("no findings file (empty or missing means no leaks, or the scan did not run)")
        return
    for f in data:
        print(f"- {f.get('RuleID')} {f.get('File')}:{f.get('StartLine')} commit {str(f.get('Commit'))[:8]}")
    print(f"total: {len(data)}")


if __name__ == "__main__":
    pip_audit()
    bandit()
    semgrep()
    gitleaks()
