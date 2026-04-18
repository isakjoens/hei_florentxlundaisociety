# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

Security scanning web app. Users paste a URL (and optionally a GitHub repo URL) and receive a list of security vulnerabilities displayed as severity-coded cards (CRITICAL / HIGH / MEDIUM / PASS).

- **Backend:** FastAPI (Python) — `backend/` — runs on port 8000
- **Frontend:** Next.js 14 with TypeScript + Tailwind — `frontend/` — runs on port 3000
- **Docs:** `docs/` — three source-of-truth files defining architecture, scan checks, and the sprint work plan

## Commands

### Backend
```bash
cd backend
pip install -r requirements.txt
uvicorn main:app --reload --port 8000
```

### Frontend
```bash
cd frontend
npm install
npm run dev        # development server on port 3000
npm run build      # production build
npm run lint       # ESLint
```

## Architecture

The full architecture is defined in `docs/ARCHITECTURE.md`. Key points:

**API:** Single endpoint — `POST /api/scan` — accepts `{ url, github_url? }`, returns all findings in one response (no streaming). Stateless: no database, no auth.

**Backend concurrency:** All scanner modules run concurrently inside a single `asyncio.gather()` in `scanner/orchestrator.py`, wrapped in a 25-second global timeout. Wall-clock scan time ≈ slowest individual check.

**Port scanning:** Uses `asyncio.open_connection()` with 1.5s timeout — no `nmap`, no root required. Redis (6379) and Docker API (2375) get additional handshake probes if the port is open.

**HTTP probing:** Uses `httpx.AsyncClient` with `follow_redirects=False`. A 301/302 on a secret file path is flagged MEDIUM rather than treated as "not found."

**Firewall inference:** If 3+ dangerous ports are open, the orchestrator emits an additional CRITICAL `firewall_disabled` finding. This is derived — no separate network call.

**Finding schema:** Every scanner returns `list[Finding]`. The `Finding` model (defined in `models.py`) is uniform across all scanner categories: `id`, `severity`, `title`, `description`, `affected`, `fix`, `category`. See `docs/CHECKS.md` for the full severity mapping table.

**Frontend state machine:** `page.tsx` cycles through `"idle" | "scanning" | "results" | "error"`. The loading state is purely client-side with cycling messages — the backend returns all results at once.

## Scan Checks Reference

All checks with severity rules, trigger conditions, regex patterns, and fix text are defined in `docs/CHECKS.md`. Do not hardcode severity levels or fix text without consulting it.

## Test Target

`http://testphp.vulnweb.com` is a legally sanctioned intentionally vulnerable site — use it for manual end-to-end testing.
