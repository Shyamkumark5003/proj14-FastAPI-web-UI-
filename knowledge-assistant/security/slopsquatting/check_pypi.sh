#!/usr/bin/env bash
# Read-only PyPI lookup. It never installs or downloads packages.
# Usage: bash check_pypi.sh name1 name2 ...
set -u

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

for name in "$@"; do
  echo "=== $name ==="
  code=$(curl -sL -o "$TMP" -w "%{http_code}" "https://pypi.org/pypi/${name}/json")
  if [ "$code" != "200" ]; then
    echo "NOT FOUND on PyPI (HTTP $code)  -> do not install"
    echo
    continue
  fi
  python3 - "$TMP" << 'PY'
import json
import sys

data = json.load(open(sys.argv[1]))
info = data["info"]

uploads = []
for version, files in (data.get("releases") or {}).items():
    for f in files:
        uploads.append((f["upload_time_iso_8601"], version))
uploads.sort()

first = uploads[0] if uploads else ("unknown", "unknown")
last = uploads[-1] if uploads else ("unknown", "unknown")

print("summary       :", info.get("summary"))
print("author        :", info.get("author") or info.get("author_email"))
print("maintainer    :", info.get("maintainer") or info.get("maintainer_email"))
print("first release :", first[0][:10], "(version", first[1] + ")")
print("latest upload :", last[0][:10], "(version", last[1] + ")")
print("release count :", len(data.get("releases") or {}))
print("project urls  :", info.get("project_urls") or info.get("home_page"))
print("pypi page     :", info.get("package_url"))
PY
  echo
done
