# LiteLLM proxy access-control policy

Written from the project's public documentation as published on 2026-10-15.
Sources:
- https://docs.litellm.ai/docs/proxy/access_control
- https://docs.litellm.ai/docs/proxy/virtual_keys
- https://docs.litellm.ai/docs/proxy/self_serve
- https://docs.litellm.ai/docs/proxy/users
- https://docs.litellm.ai/docs/proxy/multi_tenant_architecture

## 1. Roles
Global (platform-wide):
- `proxy_admin`: "Admin over the entire platform": full control over
  organizations, teams, users, keys and budgets.
- `proxy_admin_viewer`: read-only. Can view all keys and all spend; cannot
  create or delete keys or add users.
- `internal_user`: can log in, view/create/delete their own keys and view
  their own spend. Cannot add new users.
- `internal_user_viewer`: deprecated ("Use team/org specific roles instead").
  Can view their own keys and spend only; cannot create or delete keys.

Scoped (Enterprise):
- `org_admin`: creates teams and users within their own organization and
  creates keys for org users. Cannot manage other organizations or change org
  budgets, rate limits or allowed models.
- `team_admin`: manages their own team's members, member permissions and
  keys. Cannot create new teams, raise `max_budget` unless a proxy admin
  enabled it, or add or remove global proxy models.
- Team member (`user`): by default only `/key/info` and `/key/health`. Other
  key and spend endpoints are granted through team member permissions. "Team
  admins and org admins always have full permissions regardless of these
  settings."

## 2. Hierarchy and delegation
- "Organizations contain Teams, Teams contain Users, and Users and Teams own
  Keys." Organizations cannot see each other's data or keys.
- A proxy admin creates organizations and assigns org admins; an org admin
  creates teams in their organization and assigns team admins; a team admin
  manages their own team's members and keys "without touching anything else".
- Only a proxy admin enables which team settings team admins may change.
- A proxy admin, or an admin of the team or its organization, can reset a
  member's spend; a team admin cannot reset their own spend.

## 3. Users
- Users are created by an administrator through `/user/new` or an invitation
  (`/invitation/new`). Internal users and `proxy_admin_viewer` users cannot
  add new users.
- New SSO users are created with the role in `default_internal_user_params`
  (default `internal_user`).
- A user's personal `max_budget` is the ceiling for the personal keys they
  create.

## 4. Virtual keys
- A key's owner is whoever its `user_id` points to, which is not always its
  creator. Non-admin callers get their own `user_id` stamped on new keys; a
  proxy admin must pass `user_id` explicitly.
- Keys can be scoped to a user, a team, or both. Removing a user deletes the
  keys they personally own.
- Key generation can be restricted by role (`personal_key_generation` with
  `allowed_user_roles`, `team_key_generation` with
  `allowed_team_member_roles`) and by a `custom_key_generate` hook.
  `custom_key_update` can reject an update with `403`.
- "management-route access is decided by the role of the owning user". A key
  owned by a `proxy_admin` skips every non-admin route restriction.
  `allowed_routes` on a key "is enforced for every role, including
  admin-owned keys".
- Model and MCP access are evaluated against the key itself; the owner's
  entitlement acts as a ceiling.

## 5. Not specified in the documentation
- A per-endpoint role matrix for the `/user/*` and `/key/*` management routes;
  the role descriptions above are the documented rules.
