# GuardTab

Website Security & Privacy Inspector — Chrome Extension + Node.js Backend + PostgreSQL.

Full specification: [`GuardTab-Technical-Requirements-v3.docx`](./GuardTab-Technical-Requirements-v3.docx).
This repo currently implements **Phase 1 — Backend foundation** and
**Phase 2 — Authentication & RBAC** of the revised build roadmap (§32).
See [Project status](#project-status) below for exactly what that means.

## Monorepo layout

```
guardtab/
├── shared/    # Types shared between backend and (future) extension
├── backend/   # Fastify + TypeScript + Prisma + PostgreSQL API
└── extension/ # Chrome Extension (Phase 3 — not created yet)
```

## Prerequisites

- Node.js ≥ 20 (developed against Node 24)
- Docker Desktop (for local PostgreSQL)

## Setup

```bash
npm install                        # installs all workspaces
cp .env.example backend/.env       # then fill in real values
docker compose up -d               # starts PostgreSQL on localhost:5433
npm run prisma:migrate             # applies migrations (backend/prisma)
npm run build                      # builds shared/ then backend/
npm run dev:backend                # starts the API with hot reload
```

The backend reads its environment from **`backend/.env`** (not a root
`.env`) — the root `.env.example` is the template listing every variable
the full project will eventually need, grouped by the phase that introduces
it. The "Phase 1" and "Phase 2" groups are required today.

### Google OAuth credentials

`GOOGLE_CLIENT_ID`/`GOOGLE_CLIENT_SECRET` must come from a real OAuth client
(Google Cloud Console → APIs & Services → Credentials → OAuth client ID,
type "Web application") before `/auth/google` will work against Google's
real consent screen — an authorized redirect URI matching
`GOOGLE_CALLBACK_URL` must be added there too. Everything else in Phase 2
(JWT verification, refresh rotation + reuse detection, RBAC, audit
logging, `/auth/me`, `/admin/*`) is fully tested without a real Google app,
since none of it depends on completing the actual OAuth handshake — see
`tests/auth.service.test.ts`, `tests/auth.routes.test.ts` and
`tests/admin.routes.test.ts`.

### Why PostgreSQL is on port 5433, not 5432

`docker-compose.yml` maps the container's PostgreSQL to **host port 5433**.
If this machine already has a native/other PostgreSQL service listening on
5432, mapping to the same host port would silently connect to that instead
of this project's database. If your machine has no conflicting service, it
is safe to change the mapping back to `5432:5432` (and update
`DATABASE_URL` accordingly) — just confirm nothing else owns port 5432 first
(`netstat -ano | grep 5432` on Windows, `lsof -i :5432` on macOS/Linux).

### Verify it's running

```bash
curl http://localhost:3000/health         # {"status":"ok"}
curl http://localhost:3000/health/ready   # {"status":"ok","dependencies":{"postgres":true,"migrations":true}}
```

## Testing

```bash
npm test         # runs the backend's vitest suite
npm run typecheck  # tsc over both src/ and tests/
```

Covers `url-normalizer.service.ts` and `url-safety.service.ts` against the
exact examples in §20.2/§20.4/§20.5 of the spec, the IP/CIDR math in
`ip-utils.ts`, JWT signing/verification and forgery attempts, refresh-token
rotation with reuse detection, RBAC enforcement (including the literal
Phase 2 milestone — a USER token rejected by an admin route), and an
end-to-end health-check test against the real app + database. The DNS- and
public-IP-dependent tests need network access; the rest run offline.

## Project status

Built so far (roadmap §32):

**Phase 1 — Backend foundation**
- Fastify + TypeScript API skeleton (`backend/src/app.ts`, `server.ts`)
- Docker Compose PostgreSQL for local dev
- Prisma schema for `users`, `scan_results`, `user_settings` — using the
  corrected column set from §25.1 (e.g. the full URL is never persisted;
  `registrable_domain`/`host`/`path`/`scan_status`/scores/`risk_band` exist
  from day one even though nothing populates the score columns until the
  risk engine, Phase 6, and reputation checks, Phase 5, exist)
- Structured logging with request IDs and redaction (§28.1)
- `GET /health` and `GET /health/ready` (§28.3) — `/health/dependencies` is
  deferred until Phase 5/7 introduce the third-party services it checks
- `url-normalizer.service.ts` (§20.1/§20.2) and `url-safety.service.ts`
  (§20.4/§20.5) — the SSRF guard is built now, before anything fetches a
  user-supplied URL, per the spec's explicit instruction not to defer it

**Phase 2 — Authentication & RBAC**
- Google OAuth via Passport (`GET /auth/google`, `GET /auth/google/callback`),
  stateless JWT access tokens (1h, HS256-pinned) and SHA-256-hashed refresh
  tokens (30d) in an HttpOnly, SameSite=Strict cookie
- Refresh-token rotation with reuse detection (§18.3/§26.5): replaying an
  already-rotated token revokes the entire token family, not just that token
- `role` column (`USER`/`ANALYST`/`ADMIN`) on `users`; `authenticate`/
  `authorize` middleware that re-reads the role from the database on every
  request rather than trusting the JWT claim (§21.3)
- `audit_logs` table and `writeAuditLog()`, wired into login, logout, token
  refresh, reuse detection, forbidden-access attempts, and admin actions
- `GET /auth/me`, `POST /auth/refresh`, `POST /auth/logout`
- Admin routes that depend only on Phase 1/2 tables: `GET /admin/users`,
  `GET /admin/users/:id`, `POST /admin/users/:id/role`,
  `POST /admin/users/:id/suspend` — RBAC enforced at the plugin level
  (§21.3) so a new route can't be added without inheriting the guard.
  The rest of §21.4's admin surface (threats, domain overrides, feedback,
  statistics) needs the Phase 10 threat-intelligence tables and is deferred

Deliberately **not** built yet, because later phases own it:

- Chrome Extension (`extension/` package) — Phase 3
- Any scan routes, checkers, or the deterministic risk engine — Phases 4–6
- AI explanation layer, dashboard, threat intelligence — Phases 7, 8, 10
- Deletion/export columns on `users`, account retention — Phase 11

See §32 "Revised Build Roadmap" in the spec for the full phase list and
§33 for three open assumptions (SSL/TLS certificate access, HIBP quota
wording, third-party quotas) that must be verified before the phases that
depend on them.

## Useful commands

| Command | What it does |
|---|---|
| `npm run dev:backend` | Backend with hot reload (`tsx watch`) |
| `npm run build` | Builds `shared/` then `backend/` to `dist/` |
| `npm run prisma:migrate` | Runs `prisma migrate dev` in `backend/` |
| `npm run prisma:generate` | Regenerates the Prisma client |
| `npx prisma studio` (from `backend/`) | Browse the local database |
| `npm run docker:up` / `docker:down` | Start/stop the local Postgres container |
| `npm run typecheck` | `tsc --noEmit` over both `src/` and `tests/` |
| `npm run lint` | ESLint over `backend/src` and `backend/tests` |

## Known gaps to close before Phase 3

- **CORS allow-list** (§18.3 "CSRF on cookie endpoints" names this as part of
  the mitigation, alongside SameSite=Strict/HttpOnly which are already in
  place): not yet configured, because the two origins it should allow — the
  Chrome extension's id and the dashboard's origin — don't exist until
  Phase 3 and Phase 8. `CORS_ORIGIN` is declared in the env schema but unused.
- `/health/dependencies` (§28.3, ADMIN-only reachability/quota check):
  deferred until Phase 5/7 introduce the third-party services it checks.
