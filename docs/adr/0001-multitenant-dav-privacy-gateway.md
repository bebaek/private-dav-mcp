# ADR 0001: Evolve Private DAV MCP into a multi-tenant DAV privacy gateway

- **Status:** Accepted
- **Date:** 2026-07-30
- **Amended:** 2026-08-10 to separate personal ownership from tenant-owned account grants
- **Decision owners:** Private DAV MCP and Minigent maintainers

## Context

Private DAV MCP currently runs as two loopback sidecars. Each process receives one DAV account
through environment variables, keeps opaque references in memory, and exposes only MCP. This is a
good boundary for one shared CardDAV account and one shared CalDAV account, but it does not support
users adding and managing their own accounts at runtime.

Running one sidecar per account would preserve isolation, but dynamic onboarding would require
creating containers, Secrets, MCP registrations, and capability policies for every account. That
model does not scale with users or account churn. Putting multiple static credentials in one MCP
configuration would remove container isolation without adding a durable identity or authorization
model.

The service therefore needs to become an identity-aware application similar in shape to Netwise:
one application core, an authenticated management API, an authenticated MCP interface, and
persistent tenant-scoped state. DAV credentials and private DAV fields must remain outside model
context.

## Decision

We will evolve this repository into a **multi-tenant DAV privacy gateway**. The gateway will expose:

1. an authenticated REST API for account onboarding and lifecycle management; and
2. an authenticated MCP endpoint for privacy-preserving calendar operations.

Both interfaces will use the same authorization, encrypted account vault, DAV adapters, reference
store, private-value envelope, and audit subsystem.

The first account-backed MCP scope is CalDAV. CardDAV account lifecycle now uses the same identity
and encrypted vault foundation, while CardDAV MCP data access continues through the compatibility
endpoint until account-backed contact routing is migrated separately.

### Identity boundary

Minigent will issue a short-lived, asymmetrically signed bearer token for each user-scoped gateway
request. The gateway will verify the token locally against configured issuer keys and require:

- `iss`: configured trusted issuer;
- `aud`: `private-dav`;
- `sub`: stable user identifier;
- `tenant_id`: stable tenant identifier;
- `scope`: permitted REST or MCP capabilities;
- `iat`, `exp`, and `jti`: bounded lifetime and replay/audit identifiers.

Tenant and user identifiers are derived only from the verified token. They are never accepted as
REST fields or MCP tool arguments. Minigent must therefore support per-execution MCP authorization
headers rather than one static service credential shared by all users.

An installation may use a trusted ingress to validate tokens, but the gateway will still verify
the application identity token itself. Network location is not an identity control.

### Authorization model

Every durable account belongs to exactly one tenant and has one of two ownership modes:

- a **user-owned account** belongs to `(tenant_id, owner_user_id)` and is accessible only to that
  user; or
- a **tenant-owned account** belongs to `tenant_id` and is accessible only through an explicit
  account grant to one user or to the reserved `*` tenant-wide subject.

Ownership and access are separate. Tenant ownership MUST NOT be represented by a wildcard owner ID,
and account grants MUST NOT cross tenants. Every transient calendar, event, or contact reference is
bound to the requesting `(tenant_id, user_id)`, account, account revision, and reference type. A
reference issued to one caller is invalid for every other caller, including another user authorized
to use the same tenant-owned account.

Scopes are additive and initially include:

- `dav:accounts:read`
- `dav:accounts:write`
- `dav:tenant-accounts:read`
- `dav:tenant-accounts:write`
- `dav:account-grants:read`
- `dav:account-grants:write`
- `dav:calendar:read`
- `dav:calendar:write`

The existing account scopes govern only the caller's user-owned accounts. Tenant-account scopes
govern tenant-owned credential lifecycle, and account-grant scopes govern which tenant users may
use those accounts. Grant permissions are initially `read` and `read_write`; credential and grant
management are administrative token capabilities rather than grant permissions.

REST account mutation requires the corresponding personal or tenant administrative scope. MCP
event reads and free/busy require `dav:calendar:read` plus read access to the selected account;
event mutation requires `dav:calendar:write` plus `read_write` account access. Administrative
scopes do not imply calendar access. Minigent remains responsible for user confirmation and
exact-call approval before invoking model-requested event mutations. Administrative scopes MUST
NOT be included in normal model-facing tool identities.

### Account vault

Account records are persisted in a relational database and always belong to exactly one tenant.
User-owned and tenant-owned records use explicit ownership metadata; tenant ownership is never
encoded as `user_id = "*"`. Secret fields are envelope-encrypted:

- each account receives a random data-encryption key (DEK);
- account credentials and private labels are encrypted with authenticated encryption;
- the DEK is wrapped by a versioned deployment key-encryption key (KEK);
- ciphertext is bound to account and owner identifiers as authenticated associated data;
- KEK rotation re-wraps DEKs without requiring DAV credential changes.

Plaintext credentials may exist only in request memory while validating or calling DAV. They must
not appear in logs, traces, exception text, metrics, API responses, MCP results, or audit payloads.
The gateway will not store raw bearer tokens.

The initial credential type is username/password with `auto`, `basic`, or `digest` authentication.
The schema and API are extensible to OAuth refresh credentials, but OAuth provider flows are not
part of the first implementation.

### References

`account_ref` is a stable, random public identifier for account management. `calendar_ref` and
`event_ref` are high-entropy opaque tokens stored by hash in a reference table with requesting
tenant and user, account, resource locator, ETag, type, issuance time, and expiry. Reference lookup
requires the verified requesting identity, expected account revision, and expected type.

References are never credentials and are never authorization on their own. They must not expose
upstream URLs or database keys. Unknown, expired, cross-caller, cross-account, and wrong-type
references fail with the same non-enumerating error. Users sharing a tenant-owned account receive
independent caller-bound references. Event mutations retain ETag preconditions.

### Interface split

The REST API owns actions that should not be selected by a model:

- add, test, update, disable, and remove a caller's user-owned accounts;
- administer tenant-owned accounts under separate tenant-account scopes;
- grant or revoke tenant users' access to tenant-owned accounts;
- submit or rotate credentials;
- inspect non-sensitive connection state;
- enable or disable discovered calendars.

The MCP API owns agent-facing calendar work:

- list authorized accounts and calendars using protected labels;
- list and selectively retrieve events;
- calculate single- or multi-account free/busy;
- create, update, and delete events after Minigent approval.

The existing `io.minigent/private-values` envelope remains the confidential-result convention.
Account labels, calendar names, event summaries, descriptions, locations, attendee addresses, and
upstream identifiers are private. Busy intervals and non-sensitive operation status may remain in
model-visible structured content.

### Multi-account behavior

A caller may access multiple personal accounts and multiple explicitly granted tenant-owned
accounts. `free_busy` may target explicit authorized calendar references or, when omitted, all
enabled calendars accessible to the caller. The gateway queries accounts concurrently with
per-account and overall deadlines, merges intervals, and returns only UTC intervals. A partial
upstream failure is reported as a non-sensitive count/status; it must not identify an account to the
model by its private label.

Account access composes with MCP scopes: `read` permits calendar reads, while `read_write` also
permits mutations when the caller has `dav:calendar:write`. Administrative tenant-account or grant
scopes never imply DAV data access. Users sharing one tenant-owned account receive separate
caller-bound reference namespaces.

Event mutations always target exactly one account through an account-bound calendar or event
reference. There is no cross-account write fan-out.

### Outbound network policy

Dynamic DAV URLs create an SSRF boundary. The gateway will:

- require HTTPS by default;
- validate every redirect and discovered URL against the original allowed origin policy;
- reject embedded credentials and non-HTTP schemes;
- apply deployment-configured hostname and CIDR allow/deny policy after DNS resolution;
- deny loopback, link-local, metadata, and private destinations unless explicitly allowlisted by an
  administrator;
- enforce response-size, timeout, redirect, and concurrency limits.

Private/self-hosted DAV remains possible through explicit deployment policy, not a user-controlled
bypass flag.

### Runtime and availability

The first version remains a live proxy and does not synchronize event bodies into the gateway
database. Account connection state may be cached, but upstream DAV is the source of truth.

`/health/live` reports process liveness. `/health/ready` reports whether the gateway can serve
requests and access required local dependencies such as its database and keyring; one user's
unavailable DAV account does not make the whole service unready. Account-specific diagnostics are
available only through authenticated REST responses.

## Compatibility and migration

The current CardDAV and CalDAV v1 binaries and `docs/contract-v1.md` remain supported during the
migration. The gateway uses a new API contract and does not silently change the v1 tool schemas.

Migration proceeds in stages:

1. add token verification, database migrations, the encrypted vault, and personal-account REST
   endpoints;
2. add a gateway MCP endpoint using account-backed CalDAV adapters;
3. add Minigent per-user token issuance and migrate calendar traffic;
4. add explicit account ownership metadata without changing existing personal-account behavior;
5. add tenant-owned account grants and tenant administrative REST endpoints;
6. include granted tenant accounts in MCP with caller-bound references and composed scope/grant
   authorization;
7. converge existing static CalDAV resources through an explicit administrative migration path;
8. remove the static calendar sidecar only after contract and production parity;
9. migrate CardDAV separately.

## Consequences

### Benefits

- Users can add personal accounts without deployment changes.
- Tenant administrators can add shared accounts and explicitly grant access without exposing
  credentials to users or models.
- One authorization model covers REST and MCP.
- Credentials are tenant-bound, and references are strongly tenant-, caller-, and account-scoped.
- Multi-account free/busy becomes a first-class privacy-preserving operation.
- CardDAV can later reuse the vault and identity foundation.

### Costs and risks

- The service now owns a database, encryption-key lifecycle, migrations, and token verification.
- Minigent needs per-request user identity propagation for MCP.
- Dynamic outbound URLs require strict SSRF controls.
- Availability must handle partial failure across multiple providers.
- Multi-tenant isolation requires negative authorization and concurrency tests, not only happy-path
  DAV contract tests.

## Rejected alternatives

### One sidecar per account

This preserves process isolation but requires runtime orchestration and Secret management for every
user account. It is unsuitable for self-service onboarding.

### One process with credentials supplied in MCP arguments

This would expose credentials to model-selected tool calls and logs and would make identity
spoofable. Credentials are never MCP arguments.

### Shared service token plus model-supplied user ID

A shared token authenticates Minigent but not the end user. Model- or client-supplied owner IDs
create a confused-deputy risk and are rejected.

### Wildcard user ID as tenant account ownership

Representing a shared account as owned by `user_id = "*"` conflates ownership with authorization,
complicates encryption context and audit attribution, and encourages accidental tenant-wide access.
Tenant-owned accounts use explicit ownership metadata and separate grants instead.

### Account `manage` grants

A `manage` grant would mix DAV data permissions with credential and authorization administration.
Tenant-account lifecycle and account-grant administration therefore require separate trusted token
scopes; account grants are limited to `read` and `read_write`.

### Synchronize all calendar content locally in the first release

Synchronization may improve latency later, but it greatly expands private-data retention and
conflict handling. The initial gateway remains a live DAV proxy.
