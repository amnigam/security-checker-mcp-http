<!-- Security Compliance Report -->
<!-- Generated: 2026-05-26 08:08:24 UTC -->
<!-- Tool: security-checker-mcp -->

# Security Compliance Report

## Executive Summary
Reviewed 4 files under `tests/fixtures`: 2 config files, 1 source file, and 1 dependency manifest. The review found 24 guideline-backed CRITICAL violations, and the deterministic secret scan produced 10 CR-05.1 hits that corroborate the secret-storage findings. The target fails compliance across Authentication, Authorization, Cryptography & Secrets, Error Handling & Logging, Input Validation, Security Headers, Session Management, and Cross-Site Scripting.

These files are explicitly labeled as test fixtures and appear intentionally vulnerable. That lowers the likelihood of accidental production use, but it does not change the security impact if the same patterns are copied into deployable code or bundled into a release artifact.

## Findings by Domain

### Authentication (AU)

- **[AU-01.1]** `tests/fixtures/vulnerable_app.py:19-24` — Passwords are hashed with MD5 and SHA-1, both of which are explicitly prohibited for password storage.
  - Evidence: `return hashlib.md5(password.encode()).hexdigest()` and `return hashlib.sha1(password.encode()).hexdigest()`
  - Fix: Replace both helpers with Argon2id, bcrypt, or scrypt through a vetted password hashing library, and migrate existing password hashes safely.

- **[AU-07.1]** `tests/fixtures/vulnerable_app.py:100-103` — Authentication failures disclose whether the username exists by returning different messages for missing users and wrong passwords.
  - Evidence: `return "User not found", 401` and `return "Wrong password", 401`
  - Fix: Return the same generic error message and status for all authentication failures, and keep user-existence checks internal only.

### Authorization (AZ)

- **[AZ-03.1]** `tests/fixtures/vulnerable_app.py:45-51` — The user profile endpoint fetches arbitrary records by `user_id` without verifying the requester is authorized to access that object.
  - Evidence: `@app.route("/api/user/<int:user_id>")` followed by `cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")`
  - Fix: Enforce object-level authorization before every record lookup and scope queries to the authenticated principal instead of trusting a path parameter.

### Cryptography & Secrets (CR)

- **[CR-05.1]** `tests/fixtures/.env.test:4-5,7-8,10,13,15,17,19,22,24-25` — Plaintext database credentials, cloud keys, tokens, JWT material, framework secrets, and passwords are stored directly in an environment file.
  - Evidence: `DATABASE_URL=postgresql://admin:SuperSecretPass123@prod-db.example.com:5432/production`, `REDIS_URL=redis://:redis_password_789@cache.internal:6379/0`, `AWS_ACCESS_KEY_ID=...`, `AWS_SECRET_ACCESS_KEY=...`, `STRIPE_SECRET_KEY=...`, `GITHUB_TOKEN=...`, `JWT_SECRET=...`, `SLACK_WEBHOOK=...`, `SENDGRID_API_KEY=...`, `SECRET_KEY=...`, `PASSWORD=admin123`, `API_KEY="sk-proj-reallyLongAPIKeyThatShouldBeInAVault12345"`
  - Fix: Move all secrets to an approved secret manager such as HashiCorp Vault, AWS Secrets Manager, or Azure Key Vault. For connection strings, separate credentials from the URL and inject them at runtime via secure configuration.

- **[CR-05.1]** `tests/fixtures/vulnerable_app.py:15,107-108` — Application and infrastructure secrets are hardcoded in Python source.
  - Evidence: `app.secret_key = "super_secret_key_12345"`, `DB_URL = "postgresql://admin:p@ssw0rd123@prod-db.internal:5432/maindb"`, `AWS_KEY = "AKIAIOSFODNN7EXAMPLE"`
  - Fix: Remove secrets from source control, rotate any exposed credentials, and load them from a managed secret store at runtime.

- **[CR-07.1]** `tests/fixtures/vulnerable_app.py:84-85` — TLS certificate verification is explicitly disabled for outbound HTTPS requests.
  - Evidence: `response = http_requests.get(url, verify=False)`
  - Fix: Enable certificate validation, trust the system CA bundle or an approved internal CA, and fail closed on certificate errors.

- **[CR-04.1]** `tests/fixtures/nginx.conf:11-12` — The nginx TLS configuration allows TLS 1.0 and 1.1.
  - Evidence: `ssl_protocols TLSv1 TLSv1.1 TLSv1.2 TLSv1.3;`
  - Fix: Restrict `ssl_protocols` to `TLSv1.2 TLSv1.3` only and redeploy with modern cipher and protocol settings.

### Error Handling & Logging (EL)

- **[EL-01.1]** `tests/fixtures/vulnerable_app.py:16,111` — Flask debug mode is enabled and the app is bound to `0.0.0.0`, exposing interactive error details to network clients.
  - Evidence: `app.config["DEBUG"] = True` and `app.run(debug=True, host="0.0.0.0")`
  - Fix: Disable debug mode outside isolated local development and ensure production error responses use generic handlers without tracebacks.

- **[EL-04.1]** `tests/fixtures/vulnerable_app.py:77-79` — Registration logging writes plaintext passwords to application logs.
  - Evidence: `logger.info(f"User registered: {username} with password: {password}")`
  - Fix: Never log passwords or other sensitive fields. Log only non-sensitive identifiers and redact or hash any security-relevant metadata that must be recorded.

### Input Validation & Output Encoding (IV)

- **[IV-05.1]** `tests/fixtures/vulnerable_app.py:27-31` — The user lookup query interpolates attacker-controlled input directly into SQL.
  - Evidence: `cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")`
  - Fix: Use parameterized queries, for example `cursor.execute("SELECT * FROM users WHERE username = ?", (username,))`.

- **[IV-06.1]** `tests/fixtures/vulnerable_app.py:35-36` — User input is passed into an OS command executed with `shell=True`.
  - Evidence: `subprocess.call(f"ping -c 1 {hostname}", shell=True)`
  - Fix: Avoid shell execution entirely and use a fixed command with argument lists, or remove the feature if unneeded.

- **[IV-09.1]** `tests/fixtures/vulnerable_app.py:54-57` — The import endpoint deserializes untrusted request data with `pickle.loads`.
  - Evidence: `obj = pickle.loads(data)`
  - Fix: Use a safe serialization format such as JSON and validate the resulting structure against a strict schema.

### Security Headers (SH)

- **[SH-01.1]** `tests/fixtures/nginx.conf:14-15` — HSTS is missing despite TLS termination being configured.
  - Evidence: `# SH-01.1: Missing HSTS header` and no `Strict-Transport-Security` header is set anywhere in the file.
  - Fix: Add `Strict-Transport-Security` with `max-age=31536000` and, where appropriate, `includeSubDomains`.

- **[SH-03.1]** `tests/fixtures/nginx.conf:20-21` — Clickjacking protection is absent because `X-Frame-Options` is not configured.
  - Evidence: `# SH-03.1: Missing X-Frame-Options`
  - Fix: Add `X-Frame-Options: DENY` or `SAMEORIGIN` on all responses.

- **[SH-04.1]** `tests/fixtures/nginx.conf:23-24` — MIME-sniffing protection is absent because `X-Content-Type-Options: nosniff` is not set.
  - Evidence: `# SH-04.1: Missing X-Content-Type-Options`
  - Fix: Add `X-Content-Type-Options nosniff` for all responses.

- **[SH-02.1]** `tests/fixtures/nginx.conf:40-41` — No Content Security Policy is configured for proxied application responses.
  - Evidence: `# Missing: CSP, Referrer-Policy, Permissions-Policy`
  - Fix: Deploy a `Content-Security-Policy` header with at least `default-src 'self'` and tighten directives per application needs.

- **[SH-05.1]** `tests/fixtures/nginx.conf:40-41` — `Referrer-Policy` is missing.
  - Evidence: `# Missing: CSP, Referrer-Policy, Permissions-Policy`
  - Fix: Set `Referrer-Policy: strict-origin-when-cross-origin` or a more restrictive value.

- **[SH-06.1]** `tests/fixtures/nginx.conf:40-41` — `Permissions-Policy` is missing, leaving sensitive browser capabilities unrestricted by policy.
  - Evidence: `# Missing: CSP, Referrer-Policy, Permissions-Policy`
  - Fix: Add a restrictive `Permissions-Policy` that disables unneeded features and limits any allowed features to same-origin.

- **[SH-07.1]** `tests/fixtures/nginx.conf:17-18` — A wildcard CORS origin is configured at the HTTP level.
  - Evidence: `add_header Access-Control-Allow-Origin *;`
  - Fix: Replace `*` with a strict allowlist of trusted origins for any authenticated or sensitive routes.

- **[SH-07.2]** `tests/fixtures/nginx.conf:47-49` — CORS credentials are combined with a wildcard origin, which is explicitly prohibited.
  - Evidence: `add_header Access-Control-Allow-Credentials true;` with `add_header Access-Control-Allow-Origin *;`
  - Fix: Do not send `Access-Control-Allow-Credentials: true` unless the response also sends one specific allowed origin.

### Session Management (SM)

- **[SM-01.1]** `tests/fixtures/vulnerable_app.py:39-42` — Session IDs are generated with Python’s non-cryptographic `random` module.
  - Evidence: `return str(random.randint(100000, 999999))`
  - Fix: Generate at least 128 bits of entropy with `secrets.token_urlsafe()` or an equivalent CSPRNG-backed API.

- **[SM-04.1]** `tests/fixtures/vulnerable_app.py:67-68` — The session cookie is issued without the `Secure` attribute.
  - Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  - Fix: Mark session cookies `Secure` and serve them only over HTTPS.

- **[SM-05.1]** `tests/fixtures/vulnerable_app.py:67-68` — The session cookie is issued without the `HttpOnly` attribute.
  - Evidence: `resp.set_cookie("session_id", generate_session_id(), secure=False, httponly=False)`
  - Fix: Mark session cookies `HttpOnly` so client-side JavaScript cannot read them.

### Cross-Site Scripting (XS)

- **[XS-03.1]** `tests/fixtures/vulnerable_app.py:89-92` — Request data is reflected directly into HTML without context-appropriate encoding.
  - Evidence: `query = request.args.get("q", "")` followed by `return f"<html><body>Results for: {query}</body></html>"`
  - Fix: HTML-encode reflected values or render them through a templating engine with autoescaping enabled.

## Secret Scan Results

All secret-scan findings map to **CR-05.1**.

| File | Line | Secret Type | Evidence |
|------|------|-------------|----------|
| `tests/fixtures/.env.test` | 4 | Database Connection String | `postgresql://a***REDACTED***432/production` |
| `tests/fixtures/.env.test` | 7 | AWS Access Key ID | `AKIA***REDACTED***MPLE` |
| `tests/fixtures/.env.test` | 8 | AWS Secret Access Key | `AWS_SECRET_A***REDACTED***CYEXAMPLEKEY` |
| `tests/fixtures/.env.test` | 10 | Stripe API Key | `sk_liv***REDACTED***zdp7dc` |
| `tests/fixtures/.env.test` | 13 | GitHub Token | `ghp_ABCD***REDACTED***ghijklmn` |
| `tests/fixtures/.env.test` | 17 | Slack Webhook | `https://hooks.s***REDACTED***XXXXXXXXXXXXXXX` |
| `tests/fixtures/.env.test` | 19 | SendGrid API Key | `SG.abcdefghij***REDACTED***456789ABCDEFG` |
| `tests/fixtures/.env.test` | 25 | Secret/Token Assignment | `API_KEY="sk***REDACTED***Vault12345"` |
| `tests/fixtures/vulnerable_app.py` | 107 | Database Connection String | `postgresql:***REDACTED***5432/maindb` |
| `tests/fixtures/vulnerable_app.py` | 108 | AWS Access Key ID | `AKIA***REDACTED***MPLE` |

## Observations

- `tests/fixtures/package.json` uses non-exact dependency versions such as `^`, `~`, `>=`, `*`, and `latest`. That is a supply-chain risk pattern, but this review did not count it as a guideline-backed finding because no lockfile or vulnerability scan data was provided for this fixture set.

## Summary Statistics

- Files scanned: 4
- File types: 2 config, 1 source_code, 1 dependency_manifest
- Violations found: 24 guideline-backed findings
- Secret-scan hits: 10
- Domains represented in scope: AU, AZ, CR, DS, EL, IV, SH, SM, XS
- Domains with violations: AU, AZ, CR, EL, IV, SH, SM, XS
- Compliance verdict: **FAIL**

## Top 5 Priority Remediations

1. **CR-05.1** — Remove all hardcoded secrets from `.env.test` and `vulnerable_app.py`, rotate exposed credentials, and move secret material into an approved secret manager.
2. **IV-05.1 / IV-06.1 / IV-09.1** — Eliminate direct SQL interpolation, shell-based command execution, and unsafe deserialization from `vulnerable_app.py` because they enable direct attacker-controlled code or data execution paths.
3. **AZ-03.1 / AU-07.1** — Enforce object-level authorization on `/api/user/<user_id>` and replace account-revealing authentication messages with generic responses.
4. **SM-01.1 / SM-04.1 / SM-05.1** — Replace the custom session ID generator with a CSPRNG-backed token and issue cookies with `Secure` and `HttpOnly` enabled.
5. **CR-04.1 / SH-01.1 / SH-02.1 / SH-07.1 / SH-07.2** — Harden the nginx edge configuration by disabling legacy TLS, adding mandatory security headers, and replacing wildcard CORS with an origin allowlist.
