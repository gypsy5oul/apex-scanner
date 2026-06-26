# Per-User Scan Ownership (Tenancy) — Phase 1 Design

**Date:** 2026-06-26
**Status:** Approved design → ready for implementation plan
**Scope:** Phase 1 only (ownership filtering of in-app lists). Phase 2 (Batch
results pages) is a separate follow-up spec that builds on this.

## Problem

Today the app has **no tenancy model**: every authenticated user sees *all*
scans in the system (the dashboard, scan history, recent scans, search, and the
~2,500 accumulated scan records are a global firehose). A regular user should
see only the scans **they** performed; an **admin** should see everyone's.

This is the "no tenancy model" gap flagged in the security review, scoped here
to the in-app experience (not artifact access control — see Non-Goals).

## Goals

- A regular (non-admin) user's in-app lists show **only scans they created**.
- An **admin** continues to see **all** scans (every user + system).
- Zero data migration; existing behavior for admins is unchanged.
- Efficient on a Redis-only store (no full-keyspace scans per request).

## Non-Goals (explicitly out of scope)

- **Report/SBOM files stay public and shareable.** `/reports/*.html` and
  `/sboms/*` remain unauthenticated static mounts, unchanged — users share
  report URLs with people who may not be logged in. (Per product decision.)
- **Direct access by scan-id stays open.** `GET /scan/{scan_id}` and the other
  by-id detail endpoints are NOT ownership-gated, so a shared link works for
  anyone. Filtering applies only to *list/aggregate* views that populate a
  user's own screens. (Tightening these to 404-on-not-owner is a possible
  future hardening, deliberately deferred.)
- **Teams/groups.** Ownership is per-individual-user only. No team sharing.
- **Phase 2 batch pages** (`/batches`, `/batches/:id`) — separate spec.

## Ownership Model

**Owner identity = the authenticated principal's `username`** (`TokenData.username`,
already available from `get_current_user`):
- Local login → that account's username (e.g. `admin`).
- OIDC/SSO login → the mapped username (the same value stored in the session
  token today).
- API key → the key's `created_by` username (already on the key record).

**System-generated scans** (scheduled base-image scans in `tasks.py`,
`scan_base_images`) → `created_by = "system"`. These are visible to admins only.

**Rule (applied on every list/aggregate read):**
```
admin           → see ALL scans (no filter)
non-admin user  → see ONLY scans where created_by == user.username
```

**Legacy scans** (created before this change, no `created_by`) require **no
migration**: they are absent from every per-user index, so non-admins never list
them, and admins read the global index and still see them. They are effectively
admin-only by construction.

## Data Model Changes (Redis)

1. **`created_by` field** added to each scan hash (`<scan_id>`) and batch hash
   (`batch:<batch_id>`) at creation time.
2. **Per-user index** `user_scans:<username>` — a Redis **sorted set** of
   `scan_id` scored by creation timestamp (epoch seconds), mirroring the
   existing `recent_scans` pattern. Given the same `SCAN_RESULT_TTL` lifecycle,
   the index is trimmed/expired in step with scan records (see Index hygiene).
3. **Per-user batch index** `user_batches:<username>` — same shape, for Phase 2.
   (Created in Phase 1 so batch submit is tagged now; consumed in Phase 2.)

### Index hygiene
- On each scan create: `ZADD user_scans:<username> <ts> <scan_id>`, then
  `ZREMRANGEBYRANK` to cap to a sane bound (e.g. last 2,000 per user) and
  `EXPIRE user_scans:<username> <SCAN_RESULT_TTL>` refreshed on write.
- Stale member tolerance: a `scan_id` in the index whose hash has TTL-expired is
  simply skipped on read (the reader already `hgetall`s and ignores empties).

## Write-Path Changes

| Location | Change |
|---|---|
| `routes.py` `POST /scan` (single, ~line 493) | add `created_by: user.username` to the hash mapping; `ZADD user_scans:<username>` |
| `routes.py` `POST /scan/batch` (~line 577) | add `created_by` to each scan hash + the `batch:<id>` hash; `ZADD user_scans` per scan and `ZADD user_batches:<username>` |
| `tasks.py` `scan_base_images` (~line 1150) | set `created_by: "system"`; do **not** add to any per-user index. System scans surface to admins via the existing global read path only. |

The owner is read from the `TokenData` of the request that initiates the scan.
Re-scans and cache-hit copies inherit the requesting user's username.

## Read-Path Changes (the filter)

A small helper centralizes the rule:

```python
def visible_scan_ids(redis_client, user, limit) -> list[str]:
    if user.role == "admin":
        return get_recent_scan_ids(redis_client, limit)      # existing global path
    return redis_client.zrevrange(f"user_scans:{user.username}", 0, limit - 1)
```

Endpoints updated (all already receive `TokenData` via `Depends`):

| Endpoint | File:area | Filter behavior |
|---|---|---|
| `GET /scans/recent` | routes.py ~1072 | admin: global; user: `user_scans:<me>` |
| `GET /stats` (`total_images_scanned`, `total_scans`) | routes.py ~1139 | admin: global counts; user: counts over their own index |
| `GET /history/{image_name}` | routes.py ~920 | user: return only the scan_ids in that image's history that they own (intersect `history:<image>` with ownership); admin: all |
| `GET /vulnerabilities/search` | routes.py ~813 | user: restrict the searched scan set to their own; admin: all |
| `GET /api/v2/batches` (Phase 2 endpoint) | new | user: `user_batches:<me>`; admin: global — built in Phase 2 but indexes ready now |

**Dashboard** (`Dashboard.js`) and **History/Search** pages need **no frontend
changes** — they call these endpoints, so once the backend filters, each user
automatically sees only their data. Admins see the full set as before.

## Error / Edge Cases

- **No username on token** (shouldn't happen): treat as non-admin with an empty
  result set (fail-safe to "see nothing" rather than "see everything").
- **Username case / stability:** compare usernames exactly as stored on the
  token; OIDC usernames are already stable in the current session model.
- **Admin demoted to user** (or vice-versa): filtering is per-request from the
  live token role, so it takes effect on next request — no stale state.
- **`system` owner:** surfaced to admins via the global path; never shown to a
  non-admin (no non-admin has username `system`).

## Testing

- **Unit:** `visible_scan_ids` returns global for admin, per-user zset for user;
  empty username → empty list.
- **Integration (two users + admin):**
  - User A scans image X; User B (non-admin) `GET /scans/recent` → does **not**
    include A's scan; `GET /stats` for B counts 0 (or only B's).
  - Admin `GET /scans/recent` → includes both A's and B's and legacy/system.
  - User B `GET /reports/<A's scan>.html` → **200** (public, shareable —
    confirms Non-Goal honored).
  - `GET /history/<image>` as B → only B's scans of that image.
- **Migration check:** a pre-existing (ownerless) scan appears for admin, not for
  a non-admin.

## Rollout

1. Deploy backend (write-path tagging + indexes + read-path filter). No data
   migration. Existing admin experience unchanged; non-admins immediately scoped.
2. No frontend deploy strictly required for Phase 1 (server-side filtering), but
   ship together for consistency.

## Follow-ups (not this spec)

- **Phase 2:** Batch results pages (`/batches`, `/batches/:id`) with policy-gate
  column, bulk re-scan, CSV — consumes `user_batches` built here.
- **Optional hardening (deferred):** 404 on direct by-id access to non-owned
  scans (would conflict with shareable links unless paired with a share token).
