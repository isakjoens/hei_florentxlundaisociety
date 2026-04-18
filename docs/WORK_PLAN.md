# Work Plan — 7-Hour Sprint

**Goal:** Ship a working security scanner web app by end of session.
**Stack:** FastAPI (Python) backend + Next.js (TypeScript) frontend.
**Source of truth:** `docs/ARCHITECTURE.md` (structure, API, models), `docs/CHECKS.md` (scan logic).

---

## Hour-by-Hour Breakdown

---

### Hour 1 — Backend scaffolding + docs
**Goal:** Backend skeleton running, stub endpoint returning hardcoded data.

#### Tasks
1. Create `docs/` with `ARCHITECTURE.md`, `CHECKS.md`, `WORK_PLAN.md` *(if not already done)*
2. Create `backend/` directory
3. Create `backend/requirements.txt`:
   ```
   fastapi==0.111.0
   uvicorn[standard]==0.29.0
   httpx==0.27.0
   pydantic==2.7.0
   python-dotenv==1.0.1
   PyYAML==6.0.1
   ```
4. Create `backend/models.py` — all Pydantic models: `ScanRequest`, `ScanResponse`, `Finding`, `Severity` enum, `Category` enum
5. Create `backend/scanner/__init__.py` (empty)
6. Create `backend/scanner/orchestrator.py` — skeleton that returns 2-3 hardcoded findings
7. Create `backend/main.py`:
   - FastAPI app instance
   - CORS middleware (`allowed_origins` from env, default `http://localhost:3000`)
   - `POST /api/scan` endpoint calling `orchestrator.run_scan(request)`
   - `GET /health` returning `{"status": "ok"}`

#### Acceptance criteria
- `uvicorn main:app --reload` starts without error
- `GET http://localhost:8000/docs` shows the Swagger UI
- `POST http://localhost:8000/api/scan` with `{"url": "https://example.com"}` returns hardcoded findings JSON

---

### Hour 2 — Secrets scanner + SSL checker
**Goal:** Two real scanners wired into the orchestrator, returning live findings.

#### Tasks
1. Create `backend/scanner/secrets_scanner.py`:
   - List of 9 paths to probe (see `CHECKS.md`)
   - `async def scan(host_url: str) -> list[Finding]`
   - Use `httpx.AsyncClient(follow_redirects=False, timeout=5)`
   - HTTP 200 → CRITICAL finding; 301/302 → MEDIUM; 403/404 → PASS aggregate
   - Return a single `secrets_clean` PASS if nothing found
2. Create `backend/scanner/ssl_checker.py`:
   - `async def scan(host_url: str) -> list[Finding]`
   - Check HTTPS reachability with `httpx`
   - Check cert expiry using `ssl` stdlib (`ssl.create_default_context`, `socket.create_connection`, `conn.getpeercert()`)
   - Check HTTP → HTTPS redirect
   - Emit findings per `CHECKS.md` severity table
3. Update `orchestrator.py` to call both scanners with `asyncio.gather()`

#### Acceptance criteria
- POST to `/api/scan` with `{"url": "http://testphp.vulnweb.com"}` returns real findings (this is a legal test target)
- At minimum: 1+ secrets finding or PASS, 1+ SSL finding

---

### Hour 3 — Port scanner + Admin panel checker
**Goal:** Open port detection and admin panel exposure working.

#### Tasks
1. Create `backend/scanner/port_scanner.py`:
   - List of 8 ports with metadata (see `CHECKS.md`)
   - `async def scan(host: str) -> list[Finding]`
   - For each port: `asyncio.open_connection(host, port, ssl=False)` with `asyncio.wait_for(..., timeout=1.5)`
   - `ConnectionRefusedError` / `TimeoutError` → port closed (skip)
   - Success → port open → emit finding
   - Special: if 6379 open, send Redis PING and check for PONG
   - Special: if 2375 open, try `httpx.get(f"http://{host}:2375/info")`
   - Firewall inference: if 3+ ports open, also emit `firewall_disabled` CRITICAL
   - Return `ports_clean` PASS if nothing open
2. Create `backend/scanner/admin_panel.py`:
   - 5 admin paths to probe (see `CHECKS.md`)
   - `async def scan(host_url: str) -> list[Finding]`
   - Same `httpx.AsyncClient` pattern as secrets scanner
   - WordPress special case: 302 to `/wp-login.php` counts as HIGH
3. Update `orchestrator.py` to include both new scanners in `asyncio.gather()`

#### Acceptance criteria
- Port scanner returns findings (or PASS) within 5 seconds wall-clock time for all 8 ports
- Admin panel scanner correctly identifies exposed panels

---

### Hour 4 — Full orchestrator + GitHub scanner
**Goal:** All backend scanners running concurrently, end-to-end test passing.

#### Tasks
1. Complete `backend/scanner/orchestrator.py`:
   ```python
   async def run_scan(request: ScanRequest) -> ScanResponse:
       start = time.time()
       tasks = [
           secrets_scanner.scan(request.url),
           ssl_checker.scan(request.url),
           port_scanner.scan(host),        # extract host from URL
           admin_panel.scan(request.url),
       ]
       if request.github_url:
           tasks.append(github_scanner.scan(request.github_url))
       
       results = await asyncio.wait_for(asyncio.gather(*tasks), timeout=25)
       findings = [f for sublist in results for f in sublist]
       # sort: CRITICAL first, then HIGH, MEDIUM, PASS
       # build summary dict
       return ScanResponse(...)
   ```
2. Create `backend/scanner/github_scanner.py`:
   - Parse owner/repo from GitHub URL
   - Fetch file tree from GitHub Trees API
   - Filter for workflow files
   - Fetch each workflow file raw content
   - Run regex patterns (see `CHECKS.md`)
   - Emit findings or PASS
3. Add proper error handling to `main.py`:
   - `asyncio.TimeoutError` → 504
   - `httpx.ConnectError` → 400 "Host unreachable"
   - Pydantic validation → 422 (automatic)

#### Acceptance criteria
- Full scan of a real URL completes in under 25 seconds
- All scanner categories represented in response
- GitHub scan works with a public repo URL

---

### Hour 5 — Next.js scaffold + ScanForm
**Goal:** Frontend running, form submits to backend, raw JSON response visible.

#### Tasks
1. Scaffold frontend:
   ```bash
   npx create-next-app@latest frontend \
     --typescript --tailwind --app --no-src-dir \
     --import-alias "@/*"
   ```
2. Create `frontend/types/scan.ts` — TypeScript interfaces (copy from `ARCHITECTURE.md`)
3. Create `frontend/lib/api.ts`:
   ```typescript
   export async function runScan(url: string, githubUrl?: string): Promise<ScanResponse> {
     const res = await fetch(`${process.env.NEXT_PUBLIC_API_URL}/api/scan`, {
       method: "POST",
       headers: { "Content-Type": "application/json" },
       body: JSON.stringify({ url, github_url: githubUrl || undefined }),
     });
     if (!res.ok) throw new Error(await res.text());
     return res.json();
   }
   ```
4. Create `frontend/components/ScanForm.tsx`:
   - URL input (required, placeholder "https://example.com")
   - GitHub URL input (optional, placeholder "https://github.com/owner/repo")
   - Scan button (disabled while scanning)
   - Client-side URL validation: must start with `http://` or `https://`
   - `onSubmit` calls `runScan()` and passes result up via prop callback
5. Update `frontend/app/page.tsx`:
   - State: `"idle" | "scanning" | "results" | "error"`
   - Renders `<ScanForm>` in idle state
   - Transitions to `scanning` on submit, `results` on success, `error` on failure

#### Acceptance criteria
- Form renders correctly
- Submitting valid URL calls the backend (check Network tab)
- `console.log(response)` shows real findings in browser console

---

### Hour 6 — Results UI
**Goal:** Full end-to-end working — scan runs, results displayed as severity cards.

#### Tasks
1. Create `frontend/components/FindingCard.tsx`:
   - Severity badge: CRITICAL=red, HIGH=orange, MEDIUM=yellow, PASS=green (Tailwind)
   - Title (bold, plain English)
   - Description (normal text, smaller)
   - Affected (monospace, link if URL)
   - Fix (italic or muted text, prefixed with "Fix:")
   - Category chip (small badge)
2. Create `frontend/components/ScanResults.tsx`:
   - Summary bar: "2 critical · 1 high · 1 medium · 4 passed"
   - Sort findings: CRITICAL → HIGH → MEDIUM → PASS
   - Map sorted findings to `<FindingCard>`
   - Scan duration shown at top ("Scanned in 8.3s")
3. Create `frontend/components/LoadingState.tsx`:
   - Centered spinner (Tailwind `animate-spin`)
   - Cycling messages, rotating every 3s:
     ```
     "Probing for exposed secret files..."
     "Scanning for open ports..."
     "Checking SSL certificate..."
     "Inspecting admin panels..."
     "Scanning GitHub workflows..."
     ```
4. Update `frontend/app/page.tsx` to render correct component per state:
   - `idle` → `<ScanForm>`
   - `scanning` → `<LoadingState>`
   - `results` → `<ScanResults findings={...} />`
   - `error` → error banner + `<ScanForm>` (pre-filled)

#### Acceptance criteria
- End-to-end: enter URL → loading state → results cards appear
- CRITICAL findings visually distinct from PASS findings
- At least one complete scan works with real findings displayed

---

### Hour 7 — Polish, error handling, README
**Goal:** Handles errors gracefully, looks presentable, can be demo'd.

#### Tasks
1. **Error handling:**
   - Frontend: catch fetch errors, show error banner with message
   - Frontend: validate URL format before submitting (regex or `new URL(url)`)
   - Backend: verify 504 and 400 error responses work correctly
2. **UI polish:**
   - Page title and header ("Security Scanner" / brief tagline)
   - Mobile layout check (scan form should be usable on phone)
   - Loading state minimum display time (500ms) to avoid flash
   - "Scan another" button on results page
3. **README.md** — update with:
   - What it does (2 sentences)
   - Prerequisites (Python 3.11+, Node 18+)
   - Setup and run instructions (backend + frontend)
   - Example scan target for demo (`http://testphp.vulnweb.com`)
4. **Final smoke test** (see Verification below)

#### Acceptance criteria
- Entering an invalid URL shows an inline error before submission
- Entering an unreachable host shows a clear error banner
- Demo runs cleanly start-to-finish for a non-technical observer

---

## File Creation Order

```
Hour 1:  backend/requirements.txt
         backend/models.py
         backend/scanner/__init__.py
         backend/scanner/orchestrator.py   (stub)
         backend/main.py

Hour 2:  backend/scanner/secrets_scanner.py
         backend/scanner/ssl_checker.py
         backend/scanner/orchestrator.py   (update: add secrets + ssl)

Hour 3:  backend/scanner/port_scanner.py
         backend/scanner/admin_panel.py
         backend/scanner/orchestrator.py   (update: add ports + admin)

Hour 4:  backend/scanner/github_scanner.py
         backend/scanner/orchestrator.py   (update: final, add github + error handling)
         backend/main.py                   (update: add error responses)

Hour 5:  frontend/  (npx create-next-app)
         frontend/types/scan.ts
         frontend/lib/api.ts
         frontend/components/ScanForm.tsx
         frontend/app/page.tsx             (state machine)

Hour 6:  frontend/components/FindingCard.tsx
         frontend/components/ScanResults.tsx
         frontend/components/LoadingState.tsx
         frontend/app/page.tsx             (update: wire all components)

Hour 7:  README.md
         frontend/app/page.tsx             (update: polish)
         frontend/app/layout.tsx           (update: title, meta)
```

---

## Verification (End-to-End Test)

Run this sequence before declaring done:

1. Start backend:
   ```bash
   cd backend && uvicorn main:app --reload --port 8000
   ```

2. Start frontend:
   ```bash
   cd frontend && npm run dev
   ```

3. Open `http://localhost:3000`

4. **Test 1 — Happy path:**
   - Enter `http://testphp.vulnweb.com` (known-vulnerable legal test site)
   - Click Scan
   - Verify: loading state shows, then results appear
   - Verify: at least 1 CRITICAL or HIGH card visible
   - Verify: at least 1 PASS card visible
   - Verify: scan completes in under 25 seconds

5. **Test 2 — GitHub scan:**
   - Enter a public GitHub repo URL in the optional field
   - Verify: GitHub findings appear (or a PASS / "no workflows" card)

6. **Test 3 — Invalid input:**
   - Enter `not-a-url`
   - Verify: error shown before scan starts (client-side validation)

7. **Test 4 — Unreachable host:**
   - Enter `http://192.0.2.1` (non-routable, will timeout)
   - Verify: error banner with clear message (not a crash)

---

## Cut Scope if Running Short on Time

If time runs out, cut in this order (least to most impactful):

1. **Cut first:** GitHub scanner — skip `github_scanner.py`, backend still works
2. **Cut second:** Admin panel checker — merge into secrets scanner as extra paths
3. **Cut third:** Redis/Docker special probes — return generic "port open" CRITICAL without the handshake
4. **Never cut:** .env probe, SSL check, port scan, the results UI cards