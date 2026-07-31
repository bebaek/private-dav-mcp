from __future__ import annotations

import hashlib
import json
import threading
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from private_dav_mcp import __version__
from private_dav_mcp.carddav import (
    CONTACTS_CREATE_TOOL,
    CONTACTS_DELETE_TOOL,
    CONTACTS_GET_TOOL,
    CONTACTS_LIST_TOOL,
    CONTACTS_PROTECT_TEXT_TOOL,
    CONTACTS_UPDATE_TOOL,
    CardDAVContactSource,
    PrivateContactsMCPServer,
)
from private_dav_mcp.gateway_identity import GatewayIdentity
from private_dav_mcp.protocol import DEFAULT_MCP_PROTOCOL_VERSION

_CONTACT_WRITE_TOOLS = {"contacts_create", "contacts_update", "contacts_delete"}
_MAX_OWNER_SERVERS = 1_000


@dataclass(frozen=True, repr=False)
class StaticContactAccount:
    account_id: str
    addressbook_url: str
    username: str
    password: str
    auth_mode: str = "auto"
    tenant_id: str = "*"
    user_id: str = "*"

    def owns(self, identity: GatewayIdentity) -> bool:
        return self.tenant_id in {"*", identity.tenant_id} and self.user_id in {
            "*",
            identity.user_id,
        }

    @property
    def revision(self) -> str:
        payload = json.dumps(
            {
                "account_id": self.account_id,
                "addressbook_url": self.addressbook_url,
                "username": self.username,
                "password": self.password,
                "auth_mode": self.auth_mode,
                "tenant_id": self.tenant_id,
                "user_id": self.user_id,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        return "env:" + hashlib.sha256(payload).hexdigest()


@dataclass
class _OwnerServer:
    revision: str
    server: PrivateContactsMCPServer


class GatewayContactsMCP:
    def __init__(
        self,
        account: StaticContactAccount | None,
        *,
        server_factory: Callable[[StaticContactAccount], PrivateContactsMCPServer] | None = None,
    ) -> None:
        self._account = account
        self._server_factory = server_factory or _default_server_factory
        self._lock = threading.RLock()
        self._servers: dict[tuple[str, str], _OwnerServer] = {}

    def check_ready(self) -> None:
        if self._account is None:
            return
        identity = GatewayIdentity(
            tenant_id=(self._account.tenant_id if self._account.tenant_id != "*" else "__health__"),
            user_id=self._account.user_id if self._account.user_id != "*" else "__health__",
            scopes=frozenset(),
            token_id="__health__",
        )
        self._server_for(identity).check_ready()

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
                    "serverInfo": {
                        "name": "private-dav-gateway-contacts",
                        "version": __version__,
                    },
                    "capabilities": {"tools": {}},
                },
            )
        if method == "tools/list":
            return _result(
                request_id,
                {
                    "tools": [
                        CONTACTS_LIST_TOOL,
                        CONTACTS_GET_TOOL,
                        CONTACTS_CREATE_TOOL,
                        CONTACTS_UPDATE_TOOL,
                        CONTACTS_DELETE_TOOL,
                        CONTACTS_PROTECT_TEXT_TOOL,
                    ]
                },
            )
        try:
            if method == "tools/call":
                params = payload.get("params")
                tool_name = params.get("name") if isinstance(params, dict) else None
                if isinstance(tool_name, str):
                    identity.require(
                        "dav:contacts:write"
                        if tool_name in _CONTACT_WRITE_TOOLS
                        else "dav:contacts:read"
                    )
            server = self._server_for(identity)
        except PermissionError as exc:
            return _error(request_id, -32001, str(exc))
        return server.handle(payload)

    def _server_for(self, identity: GatewayIdentity) -> PrivateContactsMCPServer:
        account = self._account
        if account is None or not account.owns(identity):
            raise PermissionError("Contacts are unavailable for this identity")
        key = (identity.tenant_id, identity.user_id)
        with self._lock:
            cached = self._servers.get(key)
            if cached is not None and cached.revision == account.revision:
                return cached.server
            if len(self._servers) >= _MAX_OWNER_SERVERS:
                self._servers.pop(next(iter(self._servers)))
            server = self._server_factory(account)
            self._servers[key] = _OwnerServer(revision=account.revision, server=server)
            return server


def _default_server_factory(account: StaticContactAccount) -> PrivateContactsMCPServer:
    return PrivateContactsMCPServer(
        contact_source=CardDAVContactSource(
            addressbook_url=account.addressbook_url,
            username=account.username,
            password=account.password,
            auth_mode=account.auth_mode,
        )
    )


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
