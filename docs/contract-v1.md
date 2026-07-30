# Private DAV MCP compatibility contract v1

This document defines the compatibility boundary between Private DAV MCP `0.x` servers and a
Minigent-compatible caller. It describes the observable HTTP/JSON-RPC behavior; implementation
details and DAV wire behavior are outside this contract.

## Transport and lifecycle

- Each server exposes stateless JSON-RPC requests at `POST /mcp`.
- `GET /health/live` reports process liveness without contacting DAV.
- `GET /health/ready` checks the configured DAV source, caches success and failure for 30 seconds,
  and returns a non-sensitive `503` response when the source is unavailable.
- `initialize` returns the negotiated MCP protocol version, server identity, and tool capability.
- `notifications/initialized` returns HTTP `202` with no JSON body.
- `tools/list` returns the supported tool descriptors, including JSON input schemas.
- Invalid JSON and non-object payloads return HTTP `400` with a JSON-RPC error.
- Tool validation and execution failures are JSON-RPC errors. Opaque or expired object references
  use error code `-32001`; invalid arguments use `-32602`.

The v1 contract uses MCP protocol version `2025-11-25`. A server may negotiate another protocol
version in a future contract revision.

## Private-value envelope

A successful tool result containing private data has this shape:

```json
{
  "content": [{"type": "text", "text": "Human-readable non-private summary."}],
  "structuredContent": {"field": "{{pii:kind:reference}}"},
  "_meta": {
    "io.minigent/private-values": {
      "reference": "private value"
    }
  }
}
```

The metadata key is exactly `io.minigent/private-values`. Every placeholder exposed in
`structuredContent` must have the form `{{pii:KIND:REFERENCE}}`, and `REFERENCE` must identify an
entry in the envelope. Private values must not appear in `structuredContent` or in the text
summary. An empty private-value map is valid for mutation acknowledgements.

The envelope is a Minigent extension, not a standard MCP confidential channel. The caller must
remove it before exposing tool results to a model and must use a trusted transport.

## Opaque references

`contact_ref`, `calendar_ref`, and `event_ref` are short-lived implementation-defined identifiers.
Callers must not show them to users, persist them as durable DAV identifiers, inspect their
contents, or use a reference with another server instance. Unknown and expired references fail
closed.

## CardDAV tools

The CardDAV server exposes exactly these v1 tools:

- `contacts_list`
- `contacts_get`
- `contacts_create`
- `contacts_update`
- `contacts_delete`
- `contacts_protect_text`

`contacts_list` protects names and returns opaque contact references. `contacts_get` returns only
the requested email and phone fields. `contacts_protect_text` is a trusted runtime preprocessor,
not a model-visible tool.

## CalDAV tools

The CalDAV server exposes exactly these v1 tools:

- `calendars_list`
- `events_list`
- `events_get`
- `events_create`
- `events_update`
- `events_delete`

`events_list` requires a bounded date-time range no longer than 366 days and protects summaries.
`events_get` returns only selected description, location, and attendee fields. Updating the time of
a `TZID` event requires both local start and end values and preserves its timezone definition.
Recurring non-temporal updates and deletion require `scope: "series"`; recurring time changes are
rejected so recurrence exceptions cannot be shifted incorrectly.

## Mutation policy

The DAV MCP servers execute a valid mutation request. They do **not** implement user approval or
resolve private placeholders themselves. The caller must resolve only policy-approved argument
paths and obtain approval before invoking create, update, or delete tools. The tool descriptions
mark this requirement, while enforcement belongs to the Minigent runtime.

DAV-backed create requests use `If-None-Match: *`; update and delete requests use the ETag obtained
when the opaque reference was created. A stale or removed resource fails rather than overwriting a
newer version.

## Compatibility policy

Within contract v1:

- Tool removals, tool renames, metadata-key changes, placeholder grammar changes, newly required
  arguments, and incompatible result-shape changes are breaking.
- Optional tool arguments and additive result fields may be introduced compatibly. Callers should
  ignore unknown result fields.
- The container conformance suite in `tests/test_container_contract.py` is the executable baseline
  for this document and runs against both server processes built from the production image.
