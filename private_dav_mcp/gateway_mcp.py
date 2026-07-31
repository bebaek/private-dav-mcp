from __future__ import annotations

import base64
import hashlib
import json
import secrets
import threading
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from private_dav_mcp import __version__
from private_dav_mcp.caldav import (
    CALENDARS_LIST_TOOL,
    EVENTS_CREATE_TOOL,
    EVENTS_DELETE_TOOL,
    EVENTS_GET_TOOL,
    EVENTS_LIST_TOOL,
    EVENTS_UPDATE_TOOL,
    FREE_BUSY_TOOL,
    CalDAVCalendarSource,
    PrivateCalendarMCPServer,
)
from private_dav_mcp.gateway_identity import GatewayIdentity
from private_dav_mcp.gateway_store import AccountStore, GatewayAccount, PasswordCredential
from private_dav_mcp.protocol import DEFAULT_MCP_PROTOCOL_VERSION, PRIVATE_VALUES_META_KEY

CALENDAR_ACCOUNTS_LIST_TOOL = {
    "name": "calendar_accounts_list",
    "description": (
        "List the authenticated user's enabled calendar accounts with opaque account_ref values "
        "and protected labels. Never display account_ref values."
    ),
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}

GATEWAY_CALENDARS_LIST_TOOL = {
    **CALENDARS_LIST_TOOL,
    "inputSchema": {
        "type": "object",
        "properties": {"account_ref": {"type": "string", "minLength": 1}},
        "additionalProperties": False,
    },
}

GATEWAY_FREE_BUSY_TOOL = {
    **FREE_BUSY_TOOL,
    "description": (
        "Return merged UTC busy intervals across authorized calendars without titles or other "
        "private event fields. Omit calendar references to query all enabled calendars."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "calendar_ref": {"type": "string", "minLength": 1},
            "calendar_refs": {
                "type": "array",
                "items": {"type": "string", "minLength": 1},
                "minItems": 1,
                "maxItems": 100,
                "uniqueItems": True,
            },
            "start": {"type": "string", "minLength": 1},
            "end": {"type": "string", "minLength": 1},
            "limit": {"type": "integer", "minimum": 1, "maximum": 100},
        },
        "required": ["start", "end"],
        "additionalProperties": False,
    },
}

GATEWAY_CALENDAR_TOOLS = [
    CALENDAR_ACCOUNTS_LIST_TOOL,
    GATEWAY_CALENDARS_LIST_TOOL,
    EVENTS_LIST_TOOL,
    EVENTS_GET_TOOL,
    GATEWAY_FREE_BUSY_TOOL,
    EVENTS_CREATE_TOOL,
    EVENTS_UPDATE_TOOL,
    EVENTS_DELETE_TOOL,
]


@dataclass(frozen=True, repr=False)
class StaticCalendarAccount:
    account_id: str
    label: str
    base_url: str
    username: str
    password: str
    auth_mode: str = "basic"
    tenant_id: str = "*"
    user_id: str = "*"

    def for_identity(self, identity: GatewayIdentity) -> GatewayAccount | None:
        if self.tenant_id not in {"*", identity.tenant_id} or self.user_id not in {
            "*",
            identity.user_id,
        }:
            return None
        owner = f"{identity.tenant_id}\0{identity.user_id}\0{self.account_id}".encode()
        account_ref = "acct_" + base64.urlsafe_b64encode(
            hashlib.sha256(owner).digest()[:18]
        ).decode().rstrip("=")
        revision_payload = json.dumps(
            {
                "account_id": self.account_id,
                "label": self.label,
                "base_url": self.base_url,
                "username": self.username,
                "password": self.password,
                "auth_mode": self.auth_mode,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        revision = "env:" + hashlib.sha256(revision_payload).hexdigest()
        return GatewayAccount(
            account_ref=account_ref,
            tenant_id=identity.tenant_id,
            user_id=identity.user_id,
            kind="caldav",
            label=self.label,
            base_url=self.base_url,
            credential=PasswordCredential(
                username=self.username,
                password=self.password,
                mode=self.auth_mode,
            ),
            status="configured",
            enabled=True,
            last_checked_at=None,
            last_error=None,
            created_at="env",
            updated_at=revision,
        )


@dataclass
class _AccountServer:
    account_ref: str
    account_updated_at: str
    server: PrivateCalendarMCPServer


@dataclass(frozen=True)
class _ReferenceRoute:
    account_ref: str
    account_updated_at: str
    reference_type: str


class GatewayCalendarMCP:
    def __init__(
        self,
        store: AccountStore,
        *,
        server_factory: Callable[[GatewayAccount], PrivateCalendarMCPServer] | None = None,
        static_accounts: tuple[StaticCalendarAccount, ...] = (),
    ) -> None:
        self._store = store
        self._static_accounts = static_accounts
        self._server_factory = server_factory or _default_server_factory
        self._lock = threading.RLock()
        self._servers: dict[tuple[str, str, str], _AccountServer] = {}
        self._routes: dict[tuple[str, str, str], _ReferenceRoute] = {}

    def check_ready(self) -> None:
        for template in self._static_accounts:
            identity = GatewayIdentity(
                tenant_id=(template.tenant_id if template.tenant_id != "*" else "__health__"),
                user_id=(template.user_id if template.user_id != "*" else "__health__"),
                scopes=frozenset(),
                token_id="__health__",
            )
            account = template.for_identity(identity)
            if account is None:  # pragma: no cover - identity is derived from the template
                raise RuntimeError("Static account owner configuration is invalid")
            self._server_for(account).server.check_ready()

    def handle(self, identity: GatewayIdentity, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        method = payload.get("method")
        if method == "notifications/initialized" or request_id is None:
            return None
        if method == "initialize":
            return _result(
                request_id,
                {
                    "protocolVersion": DEFAULT_MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": "private-dav-gateway", "version": __version__},
                    "capabilities": {"tools": {}},
                },
            )
        if method == "tools/list":
            return _result(request_id, {"tools": GATEWAY_CALENDAR_TOOLS})
        if method != "tools/call":
            return _error(request_id, -32601, f"Unsupported MCP method '{method}'")
        try:
            return self._handle_tool_call(identity, request_id, payload.get("params"))
        except PermissionError as exc:
            return _error(request_id, -32001, str(exc))
        except (TypeError, ValueError) as exc:
            return _error(request_id, -32602, str(exc))
        except Exception:
            return _error(request_id, -32000, "Calendar operation failed")

    def _handle_tool_call(
        self, identity: GatewayIdentity, request_id: Any, params: Any
    ) -> dict[str, Any]:
        if not isinstance(params, dict):
            raise TypeError("tools/call params must be an object")
        name = params.get("name")
        arguments = params.get("arguments") or {}
        if not isinstance(name, str) or not isinstance(arguments, dict):
            raise TypeError("tools/call requires name and object arguments")
        if name in {"events_create", "events_update", "events_delete"}:
            identity.require("dav:calendar:write")
        else:
            identity.require("dav:calendar:read")
        if name == "calendar_accounts_list":
            return self._accounts_list(identity, request_id, arguments)
        if name == "calendars_list":
            return self._calendars_list(identity, request_id, arguments)
        if name == "free_busy":
            return self._free_busy(identity, request_id, arguments)
        if name in {"events_list", "events_create"}:
            reference_type = "calendar"
            reference_name = "calendar_ref"
        elif name in {"events_get", "events_update", "events_delete"}:
            reference_type = "event"
            reference_name = "event_ref"
        else:
            raise ValueError(f"Unknown tool: {name}")
        reference = arguments.get(reference_name)
        if not isinstance(reference, str) or not reference:
            raise ValueError(f"{name} requires {reference_name}")
        account, account_server = self._resolve_route(identity, reference, reference_type)
        response = self._delegate(account_server.server, name, arguments)
        result = _extract_result(response)
        if name in {"events_list", "events_create"}:
            self._record_event_references(identity, account, result)
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    def _accounts_list(
        self, identity: GatewayIdentity, request_id: Any, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if arguments:
            raise ValueError("calendar_accounts_list accepts no arguments")
        private_values: dict[str, str] = {}
        accounts = []
        for account in self._enabled_accounts(identity):
            private_ref = secrets.token_urlsafe(16)
            private_values[private_ref] = account.label
            accounts.append(
                {
                    "account_ref": account.account_ref,
                    "label": f"{{{{pii:account:{private_ref}}}}}",
                    "status": account.status,
                }
            )
        return _private_result(
            request_id,
            {"accounts": accounts},
            private_values,
            f"Found {len(accounts)} enabled calendar accounts.",
        )

    def _calendars_list(
        self, identity: GatewayIdentity, request_id: Any, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not set(arguments) <= {"account_ref"}:
            raise ValueError("calendars_list accepts only account_ref")
        requested = arguments.get("account_ref")
        if requested is not None and (not isinstance(requested, str) or not requested):
            raise TypeError("account_ref must be a non-empty string")
        accounts = (
            [self._owned_enabled_account(identity, requested)]
            if requested is not None
            else self._enabled_accounts(identity)
        )
        calendars: list[dict[str, Any]] = []
        private_values: dict[str, str] = {}
        failed = 0
        for account in accounts:
            try:
                account_server = self._server_for(account)
                result = _extract_result(
                    self._delegate(account_server.server, "calendars_list", {})
                )
                self._merge_private_values(private_values, result)
                for calendar in result["structuredContent"]["calendars"]:
                    calendar_copy = dict(calendar)
                    calendar_copy["account_ref"] = account.account_ref
                    calendars.append(calendar_copy)
                    self._record_route(
                        identity,
                        calendar_copy["calendar_ref"],
                        account,
                        "calendar",
                    )
            except Exception:
                failed += 1
        return _private_result(
            request_id,
            {
                "calendars": calendars,
                "partial": failed > 0,
                "failed_account_count": failed,
            },
            private_values,
            f"Found {len(calendars)} calendars.",
        )

    def _free_busy(
        self, identity: GatewayIdentity, request_id: Any, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        allowed = {"calendar_ref", "calendar_refs", "start", "end", "limit"}
        if not set(arguments) <= allowed or "start" not in arguments or "end" not in arguments:
            raise ValueError("free_busy requires start and end with optional calendar references")
        _validate_window(arguments["start"], arguments["end"])
        limit = arguments.get("limit", 100)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 100:
            raise ValueError("limit must be between 1 and 100")
        single = arguments.get("calendar_ref")
        multiple = arguments.get("calendar_refs")
        if single is not None and multiple is not None:
            raise ValueError("free_busy accepts calendar_ref or calendar_refs, not both")
        if single is not None:
            references = [single]
        elif multiple is not None:
            if (
                not isinstance(multiple, list)
                or not multiple
                or not all(isinstance(value, str) and value for value in multiple)
            ):
                raise TypeError("calendar_refs must be a non-empty string array")
            if len(set(multiple)) != len(multiple) or len(multiple) > 100:
                raise ValueError("calendar_refs must contain 1 to 100 unique references")
            references = multiple
        else:
            listed = self._calendars_list(identity, request_id, {})
            references = [
                item["calendar_ref"] for item in listed["result"]["structuredContent"]["calendars"]
            ]
        intervals: list[tuple[datetime, datetime]] = []
        failed = 0
        truncated = False
        for reference in references:
            try:
                _account, account_server = self._resolve_route(identity, reference, "calendar")
                delegated_arguments = {
                    "calendar_ref": reference,
                    "start": arguments["start"],
                    "end": arguments["end"],
                }
                if "limit" in arguments:
                    delegated_arguments["limit"] = arguments["limit"]
                result = _extract_result(
                    self._delegate(account_server.server, "free_busy", delegated_arguments)
                )["structuredContent"]
                truncated = truncated or bool(result.get("truncated"))
                for interval in result["busy"]:
                    intervals.append((_parse_utc(interval["start"]), _parse_utc(interval["end"])))
            except Exception:
                failed += 1
        if references and failed == len(references):
            return _error(request_id, -32002, "All selected calendars are unavailable")
        merged = _merge_intervals(intervals)
        output = [
            {"start": _format_utc(start), "end": _format_utc(end)} for start, end in merged[:limit]
        ]
        return _private_result(
            request_id,
            {
                "busy": output,
                "truncated": truncated or len(merged) > limit,
                "partial": failed > 0,
                "queried_calendar_count": len(references) - failed,
                "failed_calendar_count": failed,
            },
            {},
            f"Found {len(output)} busy intervals.",
        )

    def _enabled_accounts(self, identity: GatewayIdentity) -> list[GatewayAccount]:
        static_accounts = [
            account
            for template in self._static_accounts
            if (account := template.for_identity(identity)) is not None
        ]
        dynamic_accounts = [
            account
            for account in self._store.list_accounts(
                identity.tenant_id, identity.user_id, limit=100
            )
            if account.enabled
        ]
        static_refs = {account.account_ref for account in static_accounts}
        return static_accounts + [
            account for account in dynamic_accounts if account.account_ref not in static_refs
        ]

    def _owned_enabled_account(self, identity: GatewayIdentity, account_ref: str) -> GatewayAccount:
        for template in self._static_accounts:
            static_account = template.for_identity(identity)
            if static_account is not None and static_account.account_ref == account_ref:
                return static_account
        account = self._store.get_account(identity.tenant_id, identity.user_id, account_ref)
        if account is None or not account.enabled:
            raise PermissionError("Unknown or unavailable account reference")
        return account

    def _server_for(self, account: GatewayAccount) -> _AccountServer:
        key = (account.tenant_id, account.user_id, account.account_ref)
        with self._lock:
            cached = self._servers.get(key)
            if cached is not None and cached.account_updated_at == account.updated_at:
                return cached
            current = _AccountServer(
                account_ref=account.account_ref,
                account_updated_at=account.updated_at,
                server=self._server_factory(account),
            )
            self._servers[key] = current
            return current

    def _record_route(
        self,
        identity: GatewayIdentity,
        reference: str,
        account: GatewayAccount,
        reference_type: str,
    ) -> None:
        with self._lock:
            if len(self._routes) >= 10_000:
                self._routes.pop(next(iter(self._routes)))
            self._routes[(identity.tenant_id, identity.user_id, reference)] = _ReferenceRoute(
                account_ref=account.account_ref,
                account_updated_at=account.updated_at,
                reference_type=reference_type,
            )

    def _resolve_route(
        self, identity: GatewayIdentity, reference: str, reference_type: str
    ) -> tuple[GatewayAccount, _AccountServer]:
        with self._lock:
            route = self._routes.get((identity.tenant_id, identity.user_id, reference))
        if route is None or route.reference_type != reference_type:
            raise PermissionError("Unknown or expired reference")
        account = self._owned_enabled_account(identity, route.account_ref)
        if account.updated_at != route.account_updated_at:
            raise PermissionError("Unknown or expired reference")
        return account, self._server_for(account)

    def _record_event_references(
        self, identity: GatewayIdentity, account: GatewayAccount, result: dict[str, Any]
    ) -> None:
        structured = result.get("structuredContent") or {}
        candidates = list(structured.get("events") or [])
        if "event_ref" in structured:
            candidates.append(structured)
        for item in candidates:
            reference = item.get("event_ref") if isinstance(item, dict) else None
            if isinstance(reference, str) and reference:
                self._record_route(identity, reference, account, "event")

    @staticmethod
    def _delegate(
        server: PrivateCalendarMCPServer, name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        response = server.handle(
            {
                "jsonrpc": "2.0",
                "id": 1,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
        )
        if response is None:
            raise RuntimeError("Calendar server returned no response")
        if "error" in response:
            error = response["error"]
            code = error.get("code")
            message = error.get("message", "Calendar operation failed")
            if code == -32001:
                raise PermissionError(message)
            if code == -32602:
                raise ValueError(message)
            raise RuntimeError(message)
        return response

    @staticmethod
    def _merge_private_values(target: dict[str, str], result: dict[str, Any]) -> None:
        values = (result.get("_meta") or {}).get(PRIVATE_VALUES_META_KEY, {})
        for reference, value in values.items():
            if reference in target and target[reference] != value:
                raise RuntimeError("Private reference collision")
            target[reference] = value


def _default_server_factory(account: GatewayAccount) -> PrivateCalendarMCPServer:
    source = CalDAVCalendarSource(
        calendar_url=account.base_url,
        username=account.credential.username,
        password=account.credential.password,
        auth_mode=account.credential.mode,
    )
    return PrivateCalendarMCPServer(calendar_source=source)


def _extract_result(response: dict[str, Any]) -> dict[str, Any]:
    result = response.get("result")
    if not isinstance(result, dict):
        raise RuntimeError("Calendar server returned an invalid result")
    return result


def _private_result(
    request_id: Any,
    structured_content: dict[str, Any],
    private_values: dict[str, str],
    message: str,
) -> dict[str, Any]:
    return _result(
        request_id,
        {
            "content": [{"type": "text", "text": message}],
            "structuredContent": structured_content,
            "_meta": {PRIVATE_VALUES_META_KEY: private_values},
        },
    )


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _validate_window(start_value: Any, end_value: Any) -> tuple[datetime, datetime]:
    if not isinstance(start_value, str) or not isinstance(end_value, str):
        raise TypeError("start and end must be date-time strings")
    start = _parse_utc(start_value)
    end = _parse_utc(end_value)
    if end <= start:
        raise ValueError("end must be after start")
    if end - start > timedelta(days=366):
        raise ValueError("time range must not exceed 366 days")
    return start, end


def _parse_utc(value: str) -> datetime:
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    if parsed.tzinfo is None:
        raise ValueError("Busy interval must include a UTC offset")
    return parsed.astimezone(timezone.utc)


def _format_utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _merge_intervals(intervals: list[tuple[datetime, datetime]]) -> list[tuple[datetime, datetime]]:
    merged: list[tuple[datetime, datetime]] = []
    for start, end in sorted(intervals):
        if end <= start:
            continue
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return merged
