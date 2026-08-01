from __future__ import annotations

import hashlib
import json
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, cast

from mcp.server.lowlevel import Server

from private_dav_mcp import __version__
from private_dav_mcp.carddav import (
    CONTACTS_CREATE_TOOL,
    CONTACTS_DELETE_TOOL,
    CONTACTS_GET_TOOL,
    CONTACTS_LIST_TOOL,
    CONTACTS_PROTECT_TEXT_TOOL,
    CONTACTS_UPDATE_TOOL,
    CachedContact,
    CardDAVContactSource,
    Contact,
    ContactResource,
    PrivateContactsMCPServer,
)
from private_dav_mcp.gateway_identity import GatewayIdentity
from private_dav_mcp.gateway_references import DurableReferenceCache
from private_dav_mcp.gateway_store import AccountStore
from private_dav_mcp.mcp_sdk import build_mcp_sdk_server
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
        store: AccountStore | None = None,
    ) -> None:
        self._account = account
        self._server_factory = server_factory
        self._store = store
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

    def build_sdk_server(self, identity: GatewayIdentity) -> Server[Any]:
        return build_mcp_sdk_server(
            name="private-dav-gateway-contacts",
            version=__version__,
            tools=[
                CONTACTS_LIST_TOOL,
                CONTACTS_GET_TOOL,
                CONTACTS_CREATE_TOOL,
                CONTACTS_UPDATE_TOOL,
                CONTACTS_DELETE_TOOL,
                CONTACTS_PROTECT_TEXT_TOOL,
            ],
            handler=lambda payload: self.handle(identity, payload),
        )

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
            server = (
                self._server_factory(account)
                if self._server_factory is not None
                else self._default_server(account, identity)
            )
            self._servers[key] = _OwnerServer(revision=account.revision, server=server)
            return server

    def _default_server(
        self, account: StaticContactAccount, identity: GatewayIdentity
    ) -> PrivateContactsMCPServer:
        references = None
        if self._store is not None:
            references = DurableReferenceCache[CachedContact](
                self._store,
                tenant_id=identity.tenant_id,
                user_id=identity.user_id,
                account_ref=account.account_id,
                account_updated_at=account.revision,
                encode=_encode_contact_reference,
                decode=_decode_contact_reference,
                reference_types=frozenset({"contact"}),
            )
        return PrivateContactsMCPServer(
            contact_source=CardDAVContactSource(
                addressbook_url=account.addressbook_url,
                username=account.username,
                password=account.password,
                auth_mode=account.auth_mode,
            ),
            clock=time.time if references is not None else time.monotonic,
            contact_references=references,
        )


def _encode_contact_reference(value: CachedContact) -> tuple[str, dict[str, object], float]:
    resource = value.resource
    return (
        "contact",
        {
            "contact": {
                "name": resource.contact.name,
                "emails": list(resource.contact.emails),
                "phones": list(resource.contact.phones),
            },
            "href": resource.href,
            "etag": resource.etag,
            "uid": resource.uid,
            "raw_vcard": resource.raw_vcard,
        },
        value.expires_at,
    )


def _decode_contact_reference(
    reference_type: str, payload: dict[str, object], expires_at: float
) -> CachedContact:
    if reference_type != "contact" or not isinstance(payload.get("contact"), dict):
        raise RuntimeError("Stored contact reference is invalid")
    contact_payload = payload["contact"]
    assert isinstance(contact_payload, dict)
    name = contact_payload.get("name")
    emails = contact_payload.get("emails")
    phones = contact_payload.get("phones")
    if (
        not isinstance(name, str)
        or not isinstance(emails, list)
        or not all(isinstance(item, str) for item in emails)
        or not isinstance(phones, list)
        or not all(isinstance(item, str) for item in phones)
    ):
        raise RuntimeError("Stored contact reference is invalid")
    optional = {key: payload.get(key) for key in ("href", "etag", "uid", "raw_vcard")}
    if any(value is not None and not isinstance(value, str) for value in optional.values()):
        raise RuntimeError("Stored contact reference is invalid")
    return CachedContact(
        resource=ContactResource(
            contact=Contact(name=name, emails=tuple(emails), phones=tuple(phones)),
            href=cast(str | None, optional["href"]),
            etag=cast(str | None, optional["etag"]),
            uid=cast(str | None, optional["uid"]),
            raw_vcard=cast(str | None, optional["raw_vcard"]),
        ),
        expires_at=expires_at,
    )


def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
    return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}
