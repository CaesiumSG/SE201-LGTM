# Aegra access-control policy

Written from the project's public documentation as published on 2026-10-15.
Source: the Aegra authentication guide,
https://docs.aegra.dev/guides/authentication (linked from the README at
https://github.com/aegra/aegra). Where the guide is silent, this policy says
so instead of guessing.

## 1. Authentication
- Aegra uses one configurable `@auth.authenticate` handler, set with
  `auth.path` in `aegra.json`. It must return a dict containing `identity`.
- If the handler raises, the request is rejected with `401`. If it returns
  any user, the request is let in: "Your `authenticate` handler is the only
  gate."
- With no auth configured, "All requests are allowed": every caller is the
  shared `anonymous` user and authorization handlers are not called. A server
  without auth must not be exposed to the internet.
- The verified user is injected server-side, so clients cannot tamper with it.

## 2. Authorization handlers
- Authorization is a set of handlers: `@auth.on`, `@auth.on.threads`,
  `@auth.on.threads.create`, and so on. They are matched from most specific
  to least specific.
- A handler returns `None` or `True` to allow, `False` to deny with `403`,
  a dict to allow with filters applied to queries, or a modified `value`.
- "Handlers only restrict access when they explicitly deny."

## 3. Ownership and isolation
- There is no built-in owner field or role system. Isolation is built from
  handlers: write an owner or team marker into `value["metadata"]` on create,
  and filter on it for searches.
- A `threads` filter also applies to by-id reads and deletes, not only search.
- All guests share one identity, so they can see each other's threads and
  store items unless each guest is given a distinct identity.
- `role`, `team_id` and `permissions` are custom fields that handlers return
  and read; `permissions` is exposed to handlers as `ctx.permissions`.

## 4. Which handler protects which endpoint
- There is no `runs` resource: run operations are authorized under their
  owning thread.
- `threads.read`: `GET /threads/{id}`, state, history, a run's GET, join,
  stream.
- `threads.update`: `PATCH /threads/{id}`, `POST /threads/{id}/state`, run
  PATCH and cancel.
- `threads.delete`: `DELETE /threads/{id}`, run DELETE.
- `threads.create_run`: `POST /threads/{id}/runs`, `/runs/stream`,
  `/runs/wait`, commands, and stateless `POST /runs*`. Omitting `thread_id`
  does not bypass thread rules.
- `threads.search`: `GET /threads`, `POST /threads/search`,
  `GET /threads/{id}/runs`.
- Creating a run or a cron also checks `assistants.read`.
- Custom routes can require auth with the `require_auth` dependency, and
  `http.enable_custom_route_auth` requires auth on all custom routes.

## 5. Not specified in the documentation
- The status code returned when a caller reaches another user's resource.
- A route-by-route listing for `/assistants`.
