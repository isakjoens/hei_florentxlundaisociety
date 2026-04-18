# Scan Checks

All checks implemented in the MVP, in priority order. Each check maps to a scanner module and produces one or more `Finding` objects.

---

## Severity Scale

| Severity | Meaning |
|---|---|
| **CRITICAL** | Immediate risk of data breach, unauthorized access, or remote code execution |
| **HIGH** | Significant exposure that should be fixed within days |
| **MEDIUM** | Risk exists but requires additional conditions to exploit |
| **PASS** | Check ran and found no issue — shown so users know what was verified |

---

## Check Definitions

### Category: `secrets` — Exposed Files
**Module:** `scanner/secrets_scanner.py`
**Method:** `httpx.AsyncClient` GET, follow_redirects=False, timeout 5s

| ID | Path probed | Trigger | Severity | Title |
|---|---|---|---|---|
| `secrets_env` | `/.env` | HTTP 200 | CRITICAL | .env file publicly accessible |
| `secrets_env_local` | `/.env.local` | HTTP 200 | CRITICAL | .env.local file publicly accessible |
| `secrets_env_production` | `/.env.production` | HTTP 200 | CRITICAL | .env.production file publicly accessible |
| `secrets_git_config` | `/.git/config` | HTTP 200 | CRITICAL | Git repository exposed |
| `secrets_wp_config` | `/wp-config.php` | HTTP 200 | CRITICAL | WordPress config file exposed |
| `secrets_htpasswd` | `/.htpasswd` | HTTP 200 | CRITICAL | .htpasswd credentials file exposed |
| `secrets_backup_sql` | `/backup.sql` | HTTP 200 | CRITICAL | SQL backup file publicly accessible |
| `secrets_db_yml` | `/config/database.yml` | HTTP 200 | CRITICAL | Database config file exposed |
| `secrets_ds_store` | `/.DS_Store` | HTTP 200 | MEDIUM | .DS_Store file exposed (leaks directory structure) |

**Fix text:** "Block access to this path in your web server config (nginx: `location ~ /\.env { deny all; }`, Apache: `<Files .env> Require all denied </Files>`). Rotate any credentials the file contains immediately."

**PASS condition:** All probed paths returned 403, 404, or non-200. Emit a single `secrets_clean` PASS finding.

**Notes:**
- A 301/302 response should be flagged MEDIUM: "Path redirects — may be behind auth, verify manually."
- Response body is NOT read or logged — only the status code matters.

---

### Category: `ports` — Open Dangerous Ports
**Module:** `scanner/port_scanner.py`
**Method:** `asyncio.open_connection()`, timeout 1.5s, all ports concurrent via `asyncio.gather()`

| ID | Port | Service | Severity | Title |
|---|---|---|---|---|
| `port_6379_open` | 6379 | Redis | CRITICAL | Redis database publicly accessible |
| `port_2375_open` | 2375 | Docker API | CRITICAL | Docker API exposed (unauthenticated) |
| `port_3306_open` | 3306 | MySQL | CRITICAL | MySQL database port open |
| `port_5432_open` | 5432 | PostgreSQL | CRITICAL | PostgreSQL database port open |
| `port_27017_open` | 27017 | MongoDB | CRITICAL | MongoDB port open |
| `port_22_open` | 22 | SSH | HIGH | SSH port open to the internet |
| `port_21_open` | 21 | FTP | HIGH | FTP port open (unencrypted) |
| `port_3389_open` | 3389 | RDP | HIGH | Remote Desktop port open |

**Special checks:**

**Redis auth probe** (only if port 6379 is open):
- Open raw TCP socket, send `*1\r\n$4\r\nPING\r\n`
- If response starts with `+PONG`: severity upgrades to CRITICAL with note "No authentication required — anyone can read and write your Redis data."
- If response starts with `-NOAUTH` or `-ERR`: severity stays CRITICAL (port open) but note "Password required — verify it's strong."

**Docker API probe** (only if port 2375 is open):
- `httpx.get(f"http://{host}:2375/info", timeout=3)`
- If HTTP 200: CRITICAL, "Unauthenticated Docker API — this is effectively remote code execution."

**Firewall inference** (derived, produced by orchestrator, not this module):

| ID | Trigger | Severity | Title |
|---|---|---|---|
| `firewall_disabled` | 3 or more ports in the dangerous list are open | CRITICAL | Firewall likely disabled |

**PASS condition:** No ports in the list are open. Emit `ports_clean` PASS finding.

---

### Category: `ssl` — SSL/TLS & HTTPS
**Module:** `scanner/ssl_checker.py`
**Method:** Python `ssl` stdlib + `httpx`

| ID | Check | Trigger | Severity | Title |
|---|---|---|---|---|
| `ssl_no_https` | GET `https://` variant of URL | Connection refused / SSL error | HIGH | Site not available over HTTPS |
| `ssl_cert_expired` | Check `ssl.get_server_certificate()` notAfter | Cert expired | HIGH | SSL certificate expired |
| `ssl_cert_expiring_soon` | notAfter within 30 days | Within 30 days | MEDIUM | SSL certificate expiring soon |
| `ssl_no_redirect` | GET `http://` URL, check if redirects to `https://` | No redirect | MEDIUM | HTTP does not redirect to HTTPS |
| `ssl_valid` | All above pass | — | PASS | SSL certificate valid and HTTPS enforced |

**Implementation notes:**
- Use `ssl.get_server_certificate((host, 443))` then parse with `ssl.DER_cert_to_PEM_cert` and `x509` via `ssl` stdlib or `cryptography` lib.
- Simpler alternative: check `httpx` response headers for `Strict-Transport-Security`.
- For MVP, use `ssl.create_default_context()` and `socket.create_connection()` to get cert info — no extra library needed.

**Fix text:**
- No HTTPS: "Install an SSL certificate (Let's Encrypt is free) and configure your web server to serve HTTPS."
- Expired: "Renew your SSL certificate immediately. If using Let's Encrypt, run `certbot renew`."
- No redirect: "Add an HTTP → HTTPS redirect in your web server config."

---

### Category: `admin` — Exposed Admin Panels
**Module:** `scanner/admin_panel.py`
**Method:** `httpx.AsyncClient` GET, follow_redirects=False, timeout 5s

| ID | Path | Trigger | Severity | Title |
|---|---|---|---|---|
| `admin_panel_admin` | `/admin` | HTTP 200 | HIGH | Admin panel publicly accessible |
| `admin_panel_wp` | `/wp-admin` | HTTP 200 or 302 to /wp-login | HIGH | WordPress admin panel exposed |
| `admin_panel_phpmyadmin` | `/phpmyadmin` | HTTP 200 | HIGH | phpMyAdmin exposed |
| `admin_panel_adminer` | `/adminer.php` | HTTP 200 | CRITICAL | Adminer database UI exposed |
| `admin_panel_administrator` | `/administrator` | HTTP 200 | HIGH | Administrator panel exposed |

**Notes:**
- A 200 on `/wp-admin` OR a 302 to `/wp-login.php` both indicate WordPress is installed — flag HIGH.
- Description should say: "This panel is accessible from the internet. Ensure only authorized users have credentials, and consider restricting access by IP."
- PASS: All paths returned 403/404.

---

### Category: `github` — GitHub Repository Scan
**Module:** `scanner/github_scanner.py`
**Method:** GitHub Trees API (unauthenticated) + raw content fetch

**Input parsing:** Extract `owner` and `repo` from `https://github.com/{owner}/{repo}`.

#### Step 1 — List workflow files
```
GET https://api.github.com/repos/{owner}/{repo}/git/trees/HEAD?recursive=1
```
Filter results for paths matching `.github/workflows/*.yml` or `.github/workflows/*.yaml`.

#### Step 2 — Fetch and scan each workflow file
```
GET https://raw.githubusercontent.com/{owner}/{repo}/HEAD/{path}
```

**Check: Dangerous workflow commands**

| ID | Pattern | Severity | Title |
|---|---|---|---|
| `github_curl_pipe_bash` | `curl.*\|.*bash` or `wget.*\|.*sh` in workflow | HIGH | Workflow downloads and executes remote code |
| `github_external_script` | `run:.*curl` or `run:.*wget` with external URL | MEDIUM | Workflow fetches from external URL |

**Check: Hardcoded secrets in workflow env/vars**

| ID | Regex pattern | Severity | Title |
|---|---|---|---|
| `github_secret_aws_key` | `AKIA[0-9A-Z]{16}` | CRITICAL | AWS access key hardcoded in workflow |
| `github_secret_gh_token` | `ghp_[a-zA-Z0-9]{36}` | CRITICAL | GitHub personal access token hardcoded |
| `github_secret_password` | `password\s*[:=]\s*["'][^"']{8,}["']` (case-insensitive) | CRITICAL | Hardcoded password found in workflow |
| `github_secret_generic` | `(secret|token|api_key|apikey)\s*[:=]\s*["'][^"']{8,}["']` | HIGH | Possible hardcoded secret in workflow |

**Note:** Only scan `.github/workflows/` files for the MVP. Scanning the full repo codebase is a V2 feature.

**PASS condition:** Workflow files found, none matched any pattern. Emit `github_workflows_clean` PASS.
**Skip condition:** No workflow files found. Emit `github_no_workflows` MEDIUM ("No CI/CD workflows found — consider adding automated security scanning").

---

## Severity Mapping Quick Reference

| Condition | Severity |
|---|---|
| .env / .git / wp-config / backup.sql HTTP 200 | CRITICAL |
| .DS_Store HTTP 200 | MEDIUM |
| Redis PING → PONG (no auth) | CRITICAL |
| Docker API HTTP 200 on :2375 | CRITICAL |
| MySQL / PostgreSQL / MongoDB port open | CRITICAL |
| SSH / FTP / RDP port open | HIGH |
| 3+ dangerous ports open | CRITICAL (firewall inference) |
| Admin panel / phpMyAdmin HTTP 200 | HIGH |
| Adminer HTTP 200 | CRITICAL |
| No HTTPS | HIGH |
| SSL cert expired | HIGH |
| SSL cert expiring ≤30 days | MEDIUM |
| No HTTP→HTTPS redirect | MEDIUM |
| Path returns 301/302 (ambiguous) | MEDIUM |
| `curl | bash` in GitHub workflow | HIGH |
| AWS/GH token regex match in workflow | CRITICAL |
| Hardcoded password in workflow | CRITICAL |
| Generic secret regex in workflow | HIGH |
| All checks clean | PASS |

---

## Future Checks (Post-MVP)

These are high-value checks to add after the MVP ships:

| Check | Category | Why deferred |
|---|---|---|
| Full repo secret scan (all files, not just workflows) | github | Requires more API calls, rate limit risk |
| Subdomain takeover detection | dns | Requires DNS tooling |
| Security headers (CSP, X-Frame-Options, HSTS) | headers | Medium priority, low drama |
| Dependency vulnerability scan (package.json / requirements.txt) | deps | Requires CVE database |
| Email security (SPF, DKIM, DMARC) | dns | DNS queries only, easy to add |
| Default credentials check (admin/admin, etc.) | admin | Requires careful ethics handling |
| Directory listing enabled | web | Easy to add to secrets scanner |
