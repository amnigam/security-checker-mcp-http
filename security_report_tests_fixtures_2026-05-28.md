<!-- Security Compliance Report -->
<!-- Generated: 2026-05-28 12:58:12 UTC -->
<!-- Tool: security-checker-mcp -->

# Secret Scan Report: tests/fixtures

## Executive Summary

Result: FAIL

Scope reviewed:
- `tests/fixtures/.env.test`
- `tests/fixtures/nginx.conf`
- `tests/fixtures/package.json`
- `tests/fixtures/vulnerable_app.py`

Files reviewed: 4
Files with secrets: 2
Total secret findings: 10
Files skipped: 0

Applicable requirement:
- **CR-05.1** — Secrets MUST be stored in approved vaults (HashiCorp Vault, AWS Secrets Manager, Azure Key Vault). Plaintext secrets in code, config files, VCS, environment variable files, and properties files PROHIBITED.

## Findings

### tests/fixtures/.env.test

1. Line 4: Hardcoded database connection string with embedded credentials. Guideline: `CR-05.1`.
2. Line 7: Hardcoded AWS access key ID. Guideline: `CR-05.1`.
3. Line 8: Hardcoded AWS secret access key. Guideline: `CR-05.1`.
4. Line 10: Hardcoded Stripe secret API key. Guideline: `CR-05.1`.
5. Line 13: Hardcoded GitHub token. Guideline: `CR-05.1`.
6. Line 17: Hardcoded Slack webhook URL. Guideline: `CR-05.1`.
7. Line 19: Hardcoded SendGrid API key. Guideline: `CR-05.1`.
8. Line 25: Hardcoded API key assignment. Guideline: `CR-05.1`.

### tests/fixtures/vulnerable_app.py

1. Line 107: Hardcoded database connection string with embedded credentials. Guideline: `CR-05.1`.
2. Line 108: Hardcoded AWS access key ID. Guideline: `CR-05.1`.

## Secret Scan Table

| File | Line | Secret Type | Evidence | Guideline |
| --- | ---: | --- | --- | --- |
| tests/fixtures/.env.test | 4 | Database Connection String | `postgresql://a***REDACTED***432/production` | `CR-05.1` |
| tests/fixtures/.env.test | 7 | AWS Access Key ID | `AKIA***REDACTED***MPLE` | `CR-05.1` |
| tests/fixtures/.env.test | 8 | AWS Secret Access Key | `AWS_SECRET_A***REDACTED***CYEXAMPLEKEY` | `CR-05.1` |
| tests/fixtures/.env.test | 10 | Stripe API Key | `sk_liv***REDACTED***zdp7dc` | `CR-05.1` |
| tests/fixtures/.env.test | 13 | GitHub Token | `ghp_ABCD***REDACTED***ghijklmn` | `CR-05.1` |
| tests/fixtures/.env.test | 17 | Slack Webhook | `https://hooks.s***REDACTED***XXXXXXXXXXXXXXX` | `CR-05.1` |
| tests/fixtures/.env.test | 19 | SendGrid API Key | `SG.abcdefghij***REDACTED***456789ABCDEFG` | `CR-05.1` |
| tests/fixtures/.env.test | 25 | Secret/Token Assignment | `API_KEY="sk***REDACTED***Vault12345"` | `CR-05.1` |
| tests/fixtures/vulnerable_app.py | 107 | Database Connection String | `postgresql:***REDACTED***5432/maindb` | `CR-05.1` |
| tests/fixtures/vulnerable_app.py | 108 | AWS Access Key ID | `AKIA***REDACTED***MPLE` | `CR-05.1` |

## Notes

- This scan was intentionally limited to `tests/fixtures`.
- The findings are in test fixtures, but they still violate `CR-05.1` because plaintext secrets in repository-tracked files are prohibited regardless of environment intent.
- `tests/fixtures/nginx.conf` and `tests/fixtures/package.json` contained no secret findings in this scan.

## Top Remediations

1. Replace literal secrets in fixtures with clearly fake placeholders that do not match live secret formats.
2. If realistic formats are required for tests, generate them at runtime and inject them through test setup rather than storing them in files.
3. Add fixture-path allowlisting or test-data conventions so secret scanners can distinguish synthetic values without weakening production checks.
4. Rotate any credential if there is any chance it was ever real before assuming it is safe.
5. Add a CI secret scan for fixtures with approved synthetic-token patterns only.
