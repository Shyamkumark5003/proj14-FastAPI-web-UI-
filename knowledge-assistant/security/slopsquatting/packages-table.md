# Slopsquatting Drill: AI-suggested packages

Project: Knowledge Assistant (FastAPI)
Date checked: 2026-11-27
Method: read-only lookup (`check_pypi.sh` and the pypi.org project page). Nothing was installed.

Decision key: **use**, **skip**, **replace** (use something else we already have).

| # | Package | AI said it is for | Exists on PyPI? | Owner / maintainer | First release | Repo checked? | Decision | Reason |
|---|---------|-------------------|-----------------|--------------------|---------------|---------------|----------|--------|
| 1 | slowapi | Rate limiting | | | | | | |
| 2 | fastapi-limiter | Rate limiting (Redis) | | | | | | |
| 3 | secure | Security headers | | | | | | |
| 4 | python-magic | File type detection | | | | | | |
| 5 | filetype | File type detection | | | | | | |
| 6 | nh3 | HTML sanitizer | | | | | | |
| 7 | bleach | HTML sanitizer | | | | | | |
| 8 | itsdangerous | Signed tokens | | | | | | |
| 9 | pydantic-settings | Typed config | | | | | | |
| 10 | python-multipart | Form and upload parsing | | | | | | |

## Findings

(Write 3 to 5 lines: did any suggested name not exist, look suspicious, or duplicate something we already built?)

## Rule going forward

No package is installed until it has a row in this table. Approved packages go into `requirements.in`, then the lockfile is regenerated and pip-audit is re-run.
