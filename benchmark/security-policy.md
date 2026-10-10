# Shoply Security Policy

This document is the authoritative access-control and secure-coding policy
for the Shoply API. Pull requests that violate any rule in this document
MUST be rejected.

## 1. Authentication

- Every endpoint except `GET /health` and `POST /login` requires
  authentication: either a user bearer token (`Authorization: Bearer <token>`)
  or a scoped API key (`X-Api-Key` header).
- Endpoints MUST use the decorators provided in `app/auth.py`
  (`@require_auth`, `@require_role`, `@require_api_key_scope`). Hand-rolled
  header checks, query-string flags, or debug bypasses are forbidden.

## 2. User data access rules

- A user may read or update ONLY their own profile (`/users/<id>`).
  Administrators may read or update any profile. Use
  `is_owner_or_admin(current_user, user_id)` for this check.
- Listing all users (`GET /users`) requires the **manager** role or above.
- Deleting a user account requires the **admin** role.
- Changing a user's role requires the **admin** role. A user must NEVER be
  able to change their own role or grant themselves additional privileges.

## 3. Order data access rules

- A user may view ONLY their own orders. Every endpoint that fetches an
  order by its identifier MUST verify ownership with
  `is_owner_or_admin(current_user, order.user_id)` before returning data.
- Listing another user's orders is restricted to that user themselves and
  administrators.
- Managers and admins may list all orders (`GET /orders/all`).
- Only admins may delete or refund orders.

## 4. Admin panel

- Every endpoint under `/admin` requires the **admin** role, enforced with
  `@require_role("admin")`.
- There are NO alternative access paths to admin functionality: no debug
  headers, no secret query parameters, no IP allowlists.

## 5. Database access (SQL)

- All SQL statements MUST use bound parameters (SQLAlchemy `text()` with
  `:name` parameters, or DB-API placeholders with a separate params
  argument).
- String interpolation, f-strings, `%` formatting, `.format()`, or string
  concatenation of request-derived values into SQL is forbidden (CWE-89).
- Dynamic identifiers (table or column names, sort keys) MUST be validated
  against a hard-coded allowlist before being placed in a query.

## 6. API keys

- API keys carry exactly one scope: `reports:read`, `orders:read`, or
  `orders:write`.
- An endpoint accepting API keys MUST verify the key's scope matches the
  operation with `@require_api_key_scope(...)`. Possession of a valid key
  alone is NOT sufficient authorization.
- Report exports are readable only with the `reports:read` scope.

## 7. Review requirements

- Security-relevant changes (auth code, SQL, new endpoints) require review
  by a security champion before merge.
