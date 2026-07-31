# Private DAV MCP

Privacy-preserving CardDAV and CalDAV MCP servers extracted from Minigent. Both servers return
model-safe `{{pii:kind:reference}}` placeholders and place corresponding private values in the
protocol-neutral MCP metadata envelope:

```text
_meta["io.minigent/private-values"]
```

The envelope is a Minigent extension, not a standard MCP confidential channel. Deploy these
servers only across a trusted transport; the production setup uses loopback sidecars in the same
pod as Minigent.

## Development

```bash
uv sync --dev
uv run ruff check .
uv run ruff format --check .
uv run basedpyright
uv run pytest
```

## Compatibility contract

The versioned Minigent integration contract is documented in
[`docs/contract-v1.md`](docs/contract-v1.md). CI builds the production image, starts both server
processes, and runs the black-box suite in `tests/test_container_contract.py` against their HTTP
endpoints.

The accepted next architecture evolves these sidecars into an identity-aware, multi-tenant DAV
privacy gateway with a management API and MCP interface. See
[ADR 0001](docs/adr/0001-multitenant-dav-privacy-gateway.md) and the draft
[gateway contract v1](docs/gateway-contract-v1.md). The first implementation milestone now includes
identity-token verification, an encrypted SQLite account vault, outbound URL policy, and
owner-scoped account lifecycle endpoints. Gateway MCP and calendar configuration routes remain
planned; the gateway does not replace the current executable sidecar contract yet.

To run that suite locally:

```bash
docker build -t private-dav-mcp:contract .
docker run --rm -d --name private-dav-carddav-contract -p 18767:8767 \
  private-dav-mcp:contract private-dav-carddav-mcp --host 0.0.0.0 --port 8767
docker run --rm -d --name private-dav-caldav-contract -p 18768:8768 \
  private-dav-mcp:contract private-dav-caldav-mcp --host 0.0.0.0 --port 8768
PRIVATE_DAV_CARDDAV_CONTRACT_URL=http://127.0.0.1:18767/mcp \
PRIVATE_DAV_CALDAV_CONTRACT_URL=http://127.0.0.1:18768/mcp \
  uv run pytest tests/test_container_contract.py
```

The default in-memory sources are intentionally used for these contract checks; no DAV credentials
or network service are required. Stop both containers when finished.

## Releases and image security

The production image is vulnerability-scanned before publication, receives attached SBOM and
provenance attestations, and is signed by the GitHub Actions OIDC identity. Semantic-version tags
publish matching container tags and generated GitHub release notes. See
[`docs/releasing.md`](docs/releasing.md) for the release procedure and verification commands.

## Experimental multi-tenant gateway

The gateway process listens on port `8769` by default:

```bash
uv run private-dav-gateway --host 127.0.0.1 --port 8769
```

It requires a SQLite path, JWT issuer/public-key ring, and versioned 32-byte encryption-key ring:

```text
PRIVATE_DAV_GATEWAY_DB_PATH
PRIVATE_DAV_GATEWAY_JWT_ISSUER
PRIVATE_DAV_GATEWAY_JWT_AUDIENCE
PRIVATE_DAV_GATEWAY_JWT_PUBLIC_KEYS
PRIVATE_DAV_GATEWAY_ENCRYPTION_KEYS
PRIVATE_DAV_GATEWAY_ACTIVE_ENCRYPTION_KEY_VERSION
```

Keyrings are JSON objects keyed by version or JWT `kid`. Encryption values are URL-safe base64;
JWT values are PEM public keys. Optional `PRIVATE_DAV_GATEWAY_ALLOWED_NETWORKS` and
`PRIVATE_DAV_GATEWAY_ALLOWED_HOST_SUFFIXES` provide administrator-controlled outbound DAV policy.
Do not put private keys, bearer tokens, or plaintext DAV credentials in these settings.

Implemented management routes:

- `GET/POST /v1/accounts`
- `GET/PATCH/DELETE /v1/accounts/{account_ref}`
- `POST /v1/accounts/{account_ref}/test`
- `GET /health/live`
- `GET /health/ready`

Credential fields are write-only and account labels, URLs, usernames, and passwords are encrypted
at rest with a per-account DEK wrapped by the active deployment KEK. Every account query is scoped
to the tenant and user from the verified bearer token.

## CardDAV

```bash
export MINIGENT_CARDDAV_URL='https://dav.example/dav.php'
export MINIGENT_CARDDAV_USERNAME='user'
read -r -s MINIGENT_CARDDAV_PASSWORD
export MINIGENT_CARDDAV_PASSWORD
uv run private-dav-carddav-mcp --host 127.0.0.1 --port 8767
```

`MINIGENT_CARDDAV_AUTH_MODE` accepts `auto`, `basic`, or `digest`. Without a URL, the server uses
fake contacts for local contract testing. Tools:

- `contacts_list`
- `contacts_get`
- `contacts_create`
- `contacts_update`
- `contacts_delete`
- `contacts_protect_text`

Create uses `If-None-Match: *`; update and delete use `If-Match` with the listed ETag.

## CalDAV

```bash
export MINIGENT_CALDAV_URL='https://dav.example/dav.php'
export MINIGENT_CALDAV_USERNAME='user'
read -r -s MINIGENT_CALDAV_PASSWORD
export MINIGENT_CALDAV_PASSWORD
uv run private-dav-caldav-mcp --host 127.0.0.1 --port 8768
```

`MINIGENT_CALDAV_AUTH_MODE` accepts `auto`, `basic`, or `digest`. Without a URL, the server uses a
fake calendar. Tools:

- `calendars_list`
- `events_list`
- `events_get`
- `free_busy`
- `events_create`
- `events_update`
- `events_delete`

The server discovers the current principal and calendar home, requires bounded event queries,
and rejects ranges over 366 days. `free_busy` expands recurring instances through CalDAV and
returns only merged UTC intervals, never titles or other event fields. Create uses
`If-None-Match: *`; update and delete use `If-Match`. V1 supports explicitly scoped whole-series
updates to summary, description, location, and attendees, plus whole-series deletion; recurring
time shifts remain rejected. When changing the time of an event carrying `TZID`, pass both start
and end as local date-times without offsets; the original timezone and `VTIMEZONE` content are
preserved.

## Health checks

Both server processes expose:

- `GET /health/live` — process liveness only; it does not contact the DAV server.
- `GET /health/ready` — validates the configured CardDAV or CalDAV source. Upstream results,
  including failures, are cached for 30 seconds so frequent orchestrator probes do not repeatedly
  authenticate against DAV. The endpoint returns `200 {"status":"ready"}` or a non-sensitive
  `503 {"status":"not_ready"}` response.

When no DAV URL is configured, the in-memory development source is immediately ready. Use the
liveness route for a Kubernetes liveness probe and the readiness route for readiness and startup
probes.

## Security and runtime policy

The MCP servers enforce protocol validation and stale-write checks, but the Minigent runtime owns
private-value storage, argument resolution, exact-call approval, audit records, and hiding trusted
input preprocessors. A Minigent CardDAV server configuration should explicitly set:

```json
{
  "trusted_input_preprocessor_tools": ["contacts_protect_text"]
}
```

Credentials belong only on the corresponding sidecar process. TLS verification is enabled by
default; `--insecure-skip-tls-verify` is for trusted local development only.
