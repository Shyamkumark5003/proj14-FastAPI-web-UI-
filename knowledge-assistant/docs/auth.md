# Authentication and access control (Task 16)

The Knowledge Assistant supports registration, login, logout, roles and per-user records.
Everything lives in the `knowledge-assistant/` folder.

## Requirement to implementation

| Requirement | Where | How it is proven |
|---|---|---|
| Hash with argon2id | `security.py` | `test_hash_is_argon2id_and_not_plaintext` |
| NIST rules: 15 characters (password alone), accept 64 or more, blocklist, no composition rules | `security.py`, `common_passwords.txt` | `tests/test_auth_passwords.py` |
| No forced rotation, change forced only on evidence of compromise | `login_service.py`, `password_service.py`, `rbac.py` | `test_no_forced_rotation_for_old_strong_password`, `tests/test_change_password.py` |
| Session cookie flags | `auth_routes.py`, `auth_deps.py` | `tests/test_login_routes.py` |
| Login throttling | `login_service.py` | `test_lockout_*`, `test_ip_throttle_across_usernames` |
| Logout invalidates the session on the server | `sessions.py`, `login_service.py` | `test_logout_revokes_session_on_server` |
| Audit events | `audit.py` | `tests/test_audit_privacy.py` and the audit assertions in other tests |
| Roles enforced in one place (RBAC) | `rbac.py` | `test_role_comparisons_live_only_in_rbac_py`, `tests/test_rbac_coverage.py` |
| Object-level ownership checks | `rbac.get_record_or_404` | `tests/test_access_matrix.py` |
| Test matrix: role by endpoint by own or other record | `docs/test_matrix.md` | `tests/test_access_matrix.py` |
| Reading another user's record fails | `demo_ownership.py` | `docs/demo_ownership_output.txt` |

## Passwords

* argon2id with the library defaults, rehash on login when parameters change.
* Minimum 15 characters, accepted up to 128, Unicode and spaces allowed, pasting allowed.
* Blocklist check (case-insensitive) and "must not contain the username". No composition rules.
* No expiry. `must_change_password` is set only when a login shows the password is on the blocklist.
  While it is set, protected routes return 403 and `/` redirects to `/change-password`.
* Changing a password needs the current password, revokes every session and issues a new one.

## Sessions

* A random 256-bit token goes into the cookie. The database stores only its SHA-256 hash.
* Cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` 8 hours, no `Domain`.
  With `COOKIE_SECURE=1` the name is `__Host-session` and the `Secure` flag is on.
* A new token for every login (no session fixation). Logout sets `revoked_at` on the server.
* Login, logout and change-password are POST requests with a CSRF token.

## Throttling

* 5 failed logins per username and 20 per IP in 15 minutes give HTTP 429 with `Retry-After`.
* While blocked, even the correct password is refused.
* A successful login resets the username counter, not the IP counter.
* Wrong password and unknown user give the same message and always run one argon2 check.
* Typed text of an unknown username is never stored. A keyed hash (`AUTH_LOG_KEY`) is used instead.

## Access control

1. Authentication: no valid session gives 401.
2. RBAC: the role must hold the permission, otherwise 403. `ROLE_PERMISSIONS` in `rbac.py` is the only place that decides.
3. Ownership: another user's record gives 404, the same answer as a missing record.

The owner of a new record always comes from the session. Admins are created only with `make_admin.py`.

## Audit events

`register_success`, `register_rejected`, `login_success`, `login_failed`, `login_throttled`, `logout`,
`password_flagged`, `password_changed`, `password_change_failed`, `password_change_rejected`,
`password_change_throttled`, `access_denied`, `ownership_denied`, `record_access_other`,
`record_created`, `record_deleted`, `role_changed`. Passwords and tokens are never logged.

## Known limitations

* SQLite and in-process state: one server instance. Use a shared database for several instances.
* The blocklist is a small starter list. Use a large breach list in production.
* No email, so there is no "forgot password" flow.
* No multi-factor authentication, which is why the 15 character minimum applies.
* The client IP is the direct peer address. Behind a proxy it needs trusted `X-Forwarded-For` handling.
* Serve over HTTPS and set `COOKIE_SECURE=1` outside local development.
* `/api/ask` stays on an API key for n8n and Langflow. It does not use sessions.

## Run and test
cd "/mnt/c/Users/Shyamkumar.K/Desktop/project-14(FastAPI web UI with Jinja2 and HTMX)/knowledge-assistant"
source .venv/bin/activate

cat > docs/auth.md << 'EOF'
# Authentication and access control (Task 16)

The Knowledge Assistant supports registration, login, logout, roles and per-user records.
Everything lives in the `knowledge-assistant/` folder.

## Requirement to implementation

| Requirement | Where | How it is proven |
|---|---|---|
| Hash with argon2id | `security.py` | `test_hash_is_argon2id_and_not_plaintext` |
| NIST rules: 15 characters (password alone), accept 64 or more, blocklist, no composition rules | `security.py`, `common_passwords.txt` | `tests/test_auth_passwords.py` |
| No forced rotation, change forced only on evidence of compromise | `login_service.py`, `password_service.py`, `rbac.py` | `test_no_forced_rotation_for_old_strong_password`, `tests/test_change_password.py` |
| Session cookie flags | `auth_routes.py`, `auth_deps.py` | `tests/test_login_routes.py` |
| Login throttling | `login_service.py` | `test_lockout_*`, `test_ip_throttle_across_usernames` |
| Logout invalidates the session on the server | `sessions.py`, `login_service.py` | `test_logout_revokes_session_on_server` |
| Audit events | `audit.py` | `tests/test_audit_privacy.py` and the audit assertions in other tests |
| Roles enforced in one place (RBAC) | `rbac.py` | `test_role_comparisons_live_only_in_rbac_py`, `tests/test_rbac_coverage.py` |
| Object-level ownership checks | `rbac.get_record_or_404` | `tests/test_access_matrix.py` |
| Test matrix: role by endpoint by own or other record | `docs/test_matrix.md` | `tests/test_access_matrix.py` |
| Reading another user's record fails | `demo_ownership.py` | `docs/demo_ownership_output.txt` |

## Passwords

* argon2id with the library defaults, rehash on login when parameters change.
* Minimum 15 characters, accepted up to 128, Unicode and spaces allowed, pasting allowed.
* Blocklist check (case-insensitive) and "must not contain the username". No composition rules.
* No expiry. `must_change_password` is set only when a login shows the password is on the blocklist.
  While it is set, protected routes return 403 and `/` redirects to `/change-password`.
* Changing a password needs the current password, revokes every session and issues a new one.

## Sessions

* A random 256-bit token goes into the cookie. The database stores only its SHA-256 hash.
* Cookie: `HttpOnly`, `SameSite=Lax`, `Path=/`, `Max-Age` 8 hours, no `Domain`.
  With `COOKIE_SECURE=1` the name is `__Host-session` and the `Secure` flag is on.
* A new token for every login (no session fixation). Logout sets `revoked_at` on the server.
* Login, logout and change-password are POST requests with a CSRF token.

## Throttling

* 5 failed logins per username and 20 per IP in 15 minutes give HTTP 429 with `Retry-After`.
* While blocked, even the correct password is refused.
* A successful login resets the username counter, not the IP counter.
* Wrong password and unknown user give the same message and always run one argon2 check.
* Typed text of an unknown username is never stored. A keyed hash (`AUTH_LOG_KEY`) is used instead.

## Access control

1. Authentication: no valid session gives 401.
2. RBAC: the role must hold the permission, otherwise 403. `ROLE_PERMISSIONS` in `rbac.py` is the only place that decides.
3. Ownership: another user's record gives 404, the same answer as a missing record.

The owner of a new record always comes from the session. Admins are created only with `make_admin.py`.

## Audit events

`register_success`, `register_rejected`, `login_success`, `login_failed`, `login_throttled`, `logout`,
`password_flagged`, `password_changed`, `password_change_failed`, `password_change_rejected`,
`password_change_throttled`, `access_denied`, `ownership_denied`, `record_access_other`,
`record_created`, `record_deleted`, `role_changed`. Passwords and tokens are never logged.

## Known limitations

* SQLite and in-process state: one server instance. Use a shared database for several instances.
* The blocklist is a small starter list. Use a large breach list in production.
* No email, so there is no "forgot password" flow.
* No multi-factor authentication, which is why the 15 character minimum applies.
* The client IP is the direct peer address. Behind a proxy it needs trusted `X-Forwarded-For` handling.
* Serve over HTTPS and set `COOKIE_SECURE=1` outside local development.
* `/api/ask` stays on an API key for n8n and Langflow. It does not use sessions.

## Run and test

    pip install -r requirements.txt -r requirements-dev.txt
    python -m pytest -q
    COOKIE_SECURE=1 uvicorn app:app --port 8000
    python demo_ownership.py
    python make_admin.py <username>

The repository root also holds an older copy of the Project 14 page. Task 16 lives in `knowledge-assistant/`.
