# Code Review: 6 AI-written snippets

Reviewer: Shyam Kumar K
Source: spot_the_flaw/SNIPPETS.md
Format per comment: **Problem**, **Why it matters**, **Fix**.

---

## Snippet 1: `/tickets/search`

```python
sql = f"SELECT id, title FROM tickets WHERE title LIKE '%{q}%'"
return db.execute(sql).fetchall()
```

**Severity: Critical**

**Problem.** `q` is put straight into the SQL string with an f-string. This is SQL injection.

**Why it matters.** A request like `q=' UNION SELECT id, password_hash FROM users --` lets an attacker read other tables, or change and delete data. The endpoint also has no authentication, no input length limit and no `LIMIT`, so anyone can dump the whole table.

**Fix.** Pass the value as a bound parameter, never inside the SQL text. Add auth, a length limit and a result limit.

```python
@router.get("/tickets/search")
def search(
    q: str = Query(min_length=1, max_length=100),
    user=Depends(current_user),
    db=Depends(get_db),
):
    rows = db.execute(
        "SELECT id, title FROM tickets WHERE title LIKE ? LIMIT 50",
        (f"%{q}%",),
    ).fetchall()
    return rows
```

(Use `%s` instead of `?` for psycopg. If `%` and `_` in the search term must be treated literally, escape them and add `ESCAPE`.) Add a test that sends `' OR 1=1 --` and checks it is treated as plain text.

---

## Snippet 2: `/invoices/{invoice_id}`

```python
row = db.execute("SELECT * FROM invoices WHERE id = %s", (invoice_id,)).fetchone()
if not row:
    raise HTTPException(status_code=404)
return row
```

**Severity: High**

**Good.** The query is parameterized, so there is no SQL injection here.

**Problem.** The route receives `user=Depends(current_user)` but never uses it. Any logged-in user can read any invoice by changing `invoice_id` (IDOR, broken object-level authorization). `SELECT *` also returns every column, including fields the client should not see.

**Why it matters.** Invoice ids are sequential integers, so an attacker can loop over `1..N` and download every customer's invoice. This is one of the most common real-world data leaks.

**Fix.** Check ownership in the same query, return 404 (not 403) for other people's records so existence is not revealed, and return only the needed columns.

```python
row = db.execute(
    "SELECT id, amount, status, created_at FROM invoices WHERE id = ? AND owner_id = ?",
    (invoice_id, user["id"]),
).fetchone()
if not row:
    raise HTTPException(status_code=404)
return row
```

Add a test matrix: user A reads own invoice (200), user A reads user B's invoice (404), anonymous (401).

---

## Snippet 3: passwords and tokens

```python
SECRET_KEY = "super-secret-key-123"

def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()

def create_token(user_id: int) -> str:
    return jwt.encode({"sub": user_id}, SECRET_KEY, algorithm="HS256")
```

**Severity: Critical**

**Problem 1: hardcoded secret.** The signing key is in source code, so it is in git history and visible to everyone with repo access. It is also short and guessable.

**Problem 2: MD5 for passwords.** MD5 is fast and unsalted. Identical passwords give identical hashes, and a GPU can try billions of guesses per second. If the database leaks, most passwords are cracked quickly.

**Problem 3: token without expiry.** The token has no `exp`, so a stolen token works forever. It also has no `iat`, `iss` or `aud`. `sub` is an int, but the JWT spec says `sub` is a string and newer PyJWT versions reject an int.

**Why it matters.** Anyone who knows the key can forge a token for any user, including an admin.

**Fix.**

```python
SECRET_KEY = os.environ["JWT_SECRET"]  # at least 32 random bytes, from env or a secret manager

ph = PasswordHasher()  # argon2-cffi, argon2id

def hash_password(password: str) -> str:
    return ph.hash(password)

def create_token(user_id: int) -> str:
    now = datetime.now(timezone.utc)
    claims = {"sub": str(user_id), "iat": now, "exp": now + timedelta(minutes=15)}
    return jwt.encode(claims, SECRET_KEY, algorithm="HS256")
```

On decode, always pass `algorithms=["HS256"]` and require `exp`. The key that was committed must be treated as leaked: **rotate it first**, then remove it from history if needed. Add a gitleaks rule or pre-commit hook.

---

## Snippet 4: sessions and preferences

```python
import fastapi_jwt_guardrail_kit   # pip install fastapi-jwt-guardrail-kit
import pickle

def load_prefs(blob: bytes):
    return pickle.loads(blob)
```

**Severity: Critical**

**Problem 1: unverified package (slopsquatting risk).** `fastapi_jwt_guardrail_kit` is not a package I recognize, and the comment tells the reader to install it. AI tools sometimes invent package names, and attackers register those names with malware. The import is also unused.

**Problem 2: `pickle.loads` on a blob.** Unpickling untrusted data runs arbitrary code. If `blob` comes from a cookie, upload or request, the attacker gets remote code execution on the server.

**Why it matters.** Either one alone can fully compromise the server.

**Fix.**
- Do not install the package. Look it up on pypi.org first (does it exist, who owns it, when was the first release, does the repo match). Prefer well-known libraries such as PyJWT. Any new dependency goes through `requirements.in`, then the hashed lockfile, then pip-audit.
- Replace pickle with JSON and validate the shape.

```python
class Prefs(BaseModel):
    theme: Literal["light", "dark"] = "light"
    page_size: int = Field(default=20, ge=1, le=100)

def load_prefs(blob: bytes) -> Prefs:
    return Prefs.model_validate_json(blob)
```

If the blob must be tamper-proof, sign it (HMAC or `itsdangerous`) and still use JSON, never pickle.

---

## Snippet 5: error handler

```python
@app.exception_handler(Exception)
async def handle(request, exc):
    logger.error("login failed for %s password %s", body["user"], body["password"])
    return JSONResponse({"error": str(exc), "trace": traceback.format_exc()}, status_code=200)
```

**Severity: High**

**Problem 1: password in logs.** The plaintext password is written to the log. Logs are copied to many systems and read by many people.

**Problem 2: `body` is not defined.** The handler would raise `NameError` itself, so the error handler crashes while handling an error. A global handler should not parse login data at all.

**Problem 3: stack trace sent to the client.** `str(exc)` and `traceback.format_exc()` reveal file paths, library versions, SQL text and internal logic, which helps an attacker plan the next step.

**Problem 4: status 200 for an error.** Clients, monitoring, alerts and caches all think the request succeeded. Failures become invisible.

**Why it matters.** Credentials leak through logs, internals leak to attackers, and real outages are hidden.

**Fix.**

```python
@app.exception_handler(Exception)
async def handle(request: Request, exc: Exception):
    error_id = uuid.uuid4().hex
    logger.exception("unhandled error id=%s path=%s", error_id, request.url.path)
    return JSONResponse(
        {"error": "Internal server error", "error_id": error_id},
        status_code=500,
    )
```

Log events and ids, never passwords, tokens or full request bodies. Keep the trace in server logs only, and let the user quote `error_id` to support. Add a test that a forced error returns 500 with no `trace` key.

---

## Snippet 6: `/preview` and `/download`

```python
@router.get("/preview")
def preview(url: str):
    return requests.get(url).text

@router.get("/download")
def download(name: str):
    return FileResponse(f"/data/uploads/{name}")
```

**Severity: Critical (preview), High (download)**

**Problem 1: SSRF in `/preview`.** The server fetches any URL the caller gives. An attacker can point it at internal services, `http://localhost:...`, or the cloud metadata address `http://169.254.169.254/` to steal cloud credentials, and read the response. Redirects are followed, so a simple host check can be bypassed. There is no timeout (a slow server hangs the worker) and no size limit (a huge response fills memory). There is also no authentication.

**Problem 2: path traversal in `/download`.** `name=../../etc/passwd` escapes `/data/uploads/` and reads any file the app can read, such as `.env` or the database. There is no auth and no ownership check either.

**Why it matters.** SSRF can turn one endpoint into access to the whole internal network. Path traversal can leak secrets and source code.

**Fix for `/preview`.**
- Require login and rate limit it.
- Allow only `https`, and only hosts on an allowlist.
- Resolve the host and block private, loopback, link-local and reserved IPs. Check again after every redirect, or disable redirects.
- Set a timeout and read with a size cap.

```python
ALLOWED_HOSTS = {"docs.example.com"}

def fetch_preview(url: str) -> str:
    parsed = urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_HOSTS:
        raise HTTPException(status_code=400, detail="URL not allowed")
    # also resolve parsed.hostname and reject private/loopback/link-local IPs here
    resp = requests.get(url, timeout=5, allow_redirects=False, stream=True)
    return resp.raw.read(100_000, decode_content=True).decode("utf-8", "replace")
```

**Fix for `/download`.**
- Do not accept a file name. Accept the stored random id, validate its format, and look it up in the database with an ownership check.
- Resolve the path and confirm it stays inside the upload folder.
- Send `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`.

```python
NAME_RE = re.compile(r"^[0-9a-f]{32}\.(pdf|png|jpg|txt)$")
BASE = Path("/data/uploads").resolve()

@router.get("/download")
def download(name: str, user=Depends(current_user)):
    if not NAME_RE.fullmatch(name):
        raise HTTPException(status_code=404)
    path = (BASE / name).resolve()
    if not path.is_relative_to(BASE) or not path.is_file():
        raise HTTPException(status_code=404)
    # check in the database that this file belongs to user
    return FileResponse(path, headers={"Content-Disposition": "attachment"})
```

This matches the upload design: files are stored with random server-side names, so a user-supplied name never reaches the file system. Add tests for `../../etc/passwd`, an absolute path, and another user's file.

---

## Summary

| # | Snippet | Main issue | Severity |
|---|---------|-----------|----------|
| 1 | search | SQL injection | Critical |
| 2 | invoice | IDOR, no ownership check | High |
| 3 | passwords and tokens | Hardcoded secret, MD5, no token expiry | Critical |
| 4 | sessions and preferences | Unverified package, pickle RCE | Critical |
| 5 | error handler | Password in logs, trace leak, status 200 | High |
| 6 | preview and download | SSRF, path traversal | Critical / High |
