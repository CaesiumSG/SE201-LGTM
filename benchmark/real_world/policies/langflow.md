# Langflow access-control policy

Written from the project's public documentation as published on 2026-10-15.
Sources:
- https://docs.langflow.org/api-keys-and-authentication
- https://docs.langflow.org/api-users
- https://docs.langflow.org/api-files

## 1. Authentication
- "By default, most Langflow API endpoints, such as `/v1/run/$FLOW_ID`,
  require authentication with a Langflow API key." The key goes in the
  `x-api-key` header or query parameter.
- Webhook endpoints require a key by default (`LANGFLOW_WEBHOOK_AUTH_ENABLE`
  is `True`).
- Running a public flow is the exception: "An anonymous link grants only
  resource read and flow execution." Anonymous callers cannot create, edit,
  delete, deploy or administer anything, and cannot reach the owner's
  credentials, variables, files or knowledge bases.
- `LANGFLOW_AUTO_LOGIN` signs every user in as superuser (default `True` in
  the app, `false` in the official Docker images).
  `LANGFLOW_SKIP_AUTH_AUTO_LOGIN` additionally skips API key checks.

## 2. API keys
- "A Langflow API key adopts the privileges of the user who created it." A
  key cannot reach resources outside its own Langflow server.
- In single-user mode "your Langflow API keys always have superuser
  privileges". In multi-user mode, non-superusers cannot use their keys to
  reach other users' resources.
- `LANGFLOW_API_KEY_SOURCE=db` (default) validates keys per user in the
  database. `env` uses one shared key that grants superuser rights, so it
  suits single-tenant or automated setups only.
- Revoking a key invalidates it immediately. Component API keys (model
  provider credentials) are not Langflow access keys.

## 3. Users
- "Only superusers can manage user accounts for a Langflow server through the
  Users API."
- Add user, list all users, update user (activation, superuser status) and
  delete user require a superuser when authentication is enabled. On the
  update route, "Non-superusers cannot change passwords."
- Any authenticated user may call `whoami`, and may change their own password
  with reset password; a superuser changing someone else's password must use
  update user.
- New accounts stay inactive until a superuser activates them
  (`LANGFLOW_NEW_USER_IS_ACTIVE` is `False`). Public self-registration is
  `LANGFLOW_ENABLE_SIGNUP`.

## 4. Resource ownership
- Flows: "Superusers can only run their own flows, and cannot run flows owned
  by other users."
- Files, in both `/v1/files` and `/v2/files`: "You can only access files that
  belong to your own user account, even as a superuser." v2 files "are owned
  by users" and are not attached to flows.

## 5. Not specified in the documentation
- Per-endpoint ownership rules beyond those listed above; for example, the
  Flows endpoints page states none.
- The hardening flags are described as not providing "full user isolation".
