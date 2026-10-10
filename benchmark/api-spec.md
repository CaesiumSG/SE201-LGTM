# Shoply API Specification

Base URL: `https://api.shoply.example`

Roles: `user` < `manager` < `admin` (see `security-policy.md` for the
authoritative access rules).

## Authentication

| Endpoint | Method | Access |
|---|---|---|
| `/health` | GET | public |
| `/login` | POST | public |

`POST /login` returns a bearer token used in the `Authorization` header.
Machine integrations use scoped API keys in the `X-Api-Key` header.

## Users

| Endpoint | Method | Access |
|---|---|---|
| `/users` | GET | manager, admin |
| `/users/<id>` | GET | owner or admin |
| `/users/<id>` | PUT | owner or admin |
| `/users/<id>` | DELETE | admin only |
| `/users/<id>/role` | PUT | admin only; self-promotion forbidden |
| `/users/<id>/orders` | GET | owner or admin |
| `/users/search` | GET | manager, admin |

## Orders

| Endpoint | Method | Access |
|---|---|---|
| `/orders` | POST | any authenticated user (creates own order) |
| `/orders/mine` | GET | any authenticated user (own orders only) |
| `/orders/all` | GET | manager, admin |
| `/orders/<id>` | GET | owner or admin |
| `/orders/<id>` | DELETE | admin only |
| `/orders/search` | GET | authenticated; results scoped to own orders unless admin |

## Admin

| Endpoint | Method | Access |
|---|---|---|
| `/admin/stats` | GET | admin only |
| `/admin/audit` | GET | admin only |
| `/admin/export` | GET | admin only |
| `/admin/maintenance` | POST | admin only |

## Reports (API-key access)

| Endpoint | Method | Access |
|---|---|---|
| `/orders/report` | GET | API key with `reports:read` scope |

All list endpoints support `limit` and `offset` query parameters. All
timestamps are UTC ISO-8601.
