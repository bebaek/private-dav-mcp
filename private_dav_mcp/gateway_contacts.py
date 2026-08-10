from __future__ import annotations

import base64
import hashlib
import json
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Literal, cast

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
    _partial_contact_alias_has_context,
)
from private_dav_mcp.gateway_access import AccountAccessPolicy
from private_dav_mcp.gateway_identity import GatewayIdentity
from private_dav_mcp.gateway_references import DurableReferenceCache
from private_dav_mcp.gateway_store import AccountStore, GatewayAccount, PasswordCredential
from private_dav_mcp.mcp_sdk import MCPToolCallFailure, build_mcp_sdk_server
from private_dav_mcp.protocol import PRIVATE_VALUES_META_KEY

_CONTACT_WRITE_TOOLS = {"contacts_create", "contacts_update", "contacts_delete"}
_MAX_OWNER_SERVERS = 1_000

CONTACT_ACCOUNTS_LIST_TOOL = {
    "name": "contact_accounts_list",
    "description": (
        "List the authenticated caller's accessible enabled contact accounts with opaque "
        "account_ref values and protected labels. Never display account_ref values."
    ),
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}

GATEWAY_CONTACTS_LIST_TOOL = {
    **CONTACTS_LIST_TOOL,
    "inputSchema": {
        "type": "object",
        "properties": {
            **CONTACTS_LIST_TOOL["inputSchema"]["properties"],
            "account_ref": {"type": "string", "minLength": 1},
        },
        "additionalProperties": False,
    },
}

GATEWAY_CONTACTS_CREATE_TOOL = {
    **CONTACTS_CREATE_TOOL,
    "description": (
        f"{CONTACTS_CREATE_TOOL['description']} Supply account_ref when more than one contact "
        "account is accessible."
    ),
    "inputSchema": {
        **CONTACTS_CREATE_TOOL["inputSchema"],
        "properties": {
            **CONTACTS_CREATE_TOOL["inputSchema"]["properties"],
            "account_ref": {"type": "string", "minLength": 1},
        },
    },
}

GATEWAY_CONTACT_TOOLS = [
    CONTACT_ACCOUNTS_LIST_TOOL,
    GATEWAY_CONTACTS_LIST_TOOL,
    CONTACTS_GET_TOOL,
    GATEWAY_CONTACTS_CREATE_TOOL,
    CONTACTS_UPDATE_TOOL,
    CONTACTS_DELETE_TOOL,
    CONTACTS_PROTECT_TEXT_TOOL,
]


@dataclass(frozen=True, repr=False)
class StaticContactAccount:
    account_id: str
    addressbook_url: str
    username: str
    password: str
    auth_mode: str = "auto"
    tenant_id: str = "*"
    user_id: str = "*"

    @property
    def resource_id(self) -> str:
        return f"carddav:{self.account_id}"

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

    def materialize(self, identity: GatewayIdentity) -> GatewayAccount:
        owner = f"{identity.tenant_id}\0{identity.user_id}\0{self.account_id}".encode()
        account_ref = "acct_" + base64.urlsafe_b64encode(
            hashlib.sha256(owner).digest()[:18]
        ).decode().rstrip("=")
        return GatewayAccount(
            account_ref=account_ref,
            tenant_id=identity.tenant_id,
            owner_type="user",
            owner_user_id=identity.user_id,
            kind="carddav",
            label="Contacts",
            base_url=self.addressbook_url,
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
            updated_at=self.revision,
        )


@dataclass
class _AccountServer:
    revision: str
    server: PrivateContactsMCPServer


@dataclass(frozen=True)
class _ReferenceRoute:
    account_ref: str
    account_updated_at: str


class GatewayContactsMCP:
    def __init__(
        self,
        account: StaticContactAccount | None,
        *,
        server_factory: Callable[[StaticContactAccount], PrivateContactsMCPServer] | None = None,
        account_server_factory: Callable[[GatewayAccount], PrivateContactsMCPServer] | None = None,
        store: AccountStore | None = None,
        require_resource_grants: bool = False,
        access_policy: AccountAccessPolicy | None = None,
    ) -> None:
        self._account = account
        self._server_factory = server_factory
        self._account_server_factory = account_server_factory
        self._store = store
        self._access_policy = access_policy or (
            AccountAccessPolicy(store) if store is not None else None
        )
        self._require_resource_grants = require_resource_grants
        self._lock = threading.RLock()
        self._servers: dict[tuple[str, str, str], _AccountServer] = {}
        self._routes: dict[tuple[str, str, str], _ReferenceRoute] = {}

    def check_ready(self) -> None:
        if self._account is None:
            return
        identity = GatewayIdentity(
            tenant_id=(self._account.tenant_id if self._account.tenant_id != "*" else "__health__"),
            user_id=self._account.user_id if self._account.user_id != "*" else "__health__",
            scopes=frozenset(),
            token_id="__health__",
        )
        account = self._account.materialize(identity)
        self._server_for(identity, account, static=True).server.check_ready()

    def build_sdk_server(self, identity: GatewayIdentity) -> Server[Any]:
        return build_mcp_sdk_server(
            name="private-dav-gateway-contacts",
            version=__version__,
            tools=GATEWAY_CONTACT_TOOLS,
            tool_handler=lambda name, arguments: self.call_tool(identity, name, arguments),
        )

    def call_tool(
        self,
        identity: GatewayIdentity,
        name: str,
        arguments: dict[str, Any],
    ) -> dict[str, Any]:
        try:
            permission: Literal["read", "write"] = (
                "write" if name in _CONTACT_WRITE_TOOLS else "read"
            )
            identity.require("dav:contacts:write" if permission == "write" else "dav:contacts:read")
            if name == "contact_accounts_list":
                return self._accounts_list(identity, arguments)
            if name == "contacts_list":
                return self._contacts_list(identity, arguments)
            if name == "contacts_protect_text":
                return self._protect_text(identity, arguments)
            if name == "contacts_create":
                account = self._select_create_account(identity, arguments)
                delegated = dict(arguments)
                delegated.pop("account_ref", None)
                account_server = self._server_for_identity(identity, account)
                result = account_server.server.call_tool(name, delegated)
                self._record_contact_references(identity, account, result)
                return result
            if name in {"contacts_get", "contacts_update", "contacts_delete"}:
                reference = arguments.get("contact_ref")
                if not isinstance(reference, str) or not reference:
                    raise ValueError(f"{name} requires contact_ref")
                account, account_server = self._resolve_route(
                    identity, reference, permission=permission
                )
                result = account_server.server.call_tool(name, arguments)
                if name == "contacts_update":
                    self._record_contact_references(identity, account, result)
                return result
            raise ValueError(f"Unknown tool: {name}")
        except MCPToolCallFailure:
            raise
        except PermissionError as exc:
            raise MCPToolCallFailure(-32001, str(exc)) from exc
        except (TypeError, ValueError) as exc:
            raise MCPToolCallFailure(-32602, str(exc)) from exc
        except Exception as exc:
            raise MCPToolCallFailure(-32000, "Contact operation failed") from exc

    def _accounts_list(
        self, identity: GatewayIdentity, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if arguments:
            raise ValueError("contact_accounts_list accepts no arguments")
        private_values: dict[str, str] = {}
        accounts: list[dict[str, Any]] = []
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
            {"accounts": accounts}, private_values, f"Found {len(accounts)} contact accounts."
        )

    def _contacts_list(
        self, identity: GatewayIdentity, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if not set(arguments) <= {"account_ref", "limit"}:
            raise ValueError("contacts_list accepts only account_ref and limit")
        limit = arguments.get("limit", 10)
        if not isinstance(limit, int) or isinstance(limit, bool) or not 1 <= limit <= 50:
            raise ValueError("limit must be between 1 and 50")
        requested = arguments.get("account_ref")
        if requested is not None and (not isinstance(requested, str) or not requested):
            raise TypeError("account_ref must be a non-empty string")
        accounts = (
            [self._accessible_account(identity, requested, permission="read")]
            if requested is not None
            else self._enabled_accounts(identity)
        )
        contacts: list[dict[str, Any]] = []
        private_values: dict[str, str] = {}
        truncated = False
        failed = 0
        for index, account in enumerate(accounts):
            if len(contacts) >= limit:
                truncated = True
                break
            try:
                account_server = self._server_for_identity(identity, account)
                result = account_server.server.call_tool(
                    "contacts_list", {"limit": limit - len(contacts)}
                )
                self._merge_private_values(private_values, result)
                items = result["structuredContent"]["contacts"]
                contacts.extend(dict(item) for item in items)
                self._record_contact_references(identity, account, result)
                truncated = truncated or bool(result["structuredContent"].get("truncated"))
                if index < len(accounts) - 1 and len(contacts) >= limit:
                    truncated = True
            except Exception:
                failed += 1
        if accounts and failed == len(accounts):
            raise MCPToolCallFailure(-32002, "All contact accounts are unavailable")
        truncated = truncated or failed > 0
        return _private_result(
            {"contacts": contacts, "truncated": truncated},
            private_values,
            f"Found {len(contacts)} contacts.",
        )

    def _protect_text(self, identity: GatewayIdentity, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"text"} or not isinstance(arguments.get("text"), str):
            raise ValueError("contacts_protect_text requires a text string")
        text = cast(str, arguments["text"])
        accounts = self._enabled_accounts(identity)
        resources: list[tuple[GatewayAccount, _AccountServer, ContactResource]] = []
        failed = 0
        for account in accounts:
            try:
                account_server = self._server_for_identity(identity, account)
                resources.extend(
                    (account, account_server, resource)
                    for resource in account_server.server.trusted_contact_resources()
                )
            except Exception:
                failed += 1
        if failed:
            raise MCPToolCallFailure(-32002, "Contact protection is unavailable")

        aliases: dict[
            str,
            list[
                tuple[
                    str,
                    GatewayAccount,
                    _AccountServer,
                    ContactResource,
                    bool,
                ]
            ],
        ] = {}
        for account, account_server, resource in resources:
            full_name = resource.contact.name.strip()
            if not full_name:
                continue
            contact_aliases = {full_name: True}
            name_parts = full_name.split()
            if len(name_parts) > 1:
                contact_aliases.update(
                    {part: False for part in (name_parts[0], name_parts[-1]) if len(part) >= 2}
                )
            for alias, is_full_name in contact_aliases.items():
                aliases.setdefault(alias.casefold(), []).append(
                    (alias, account, account_server, resource, is_full_name)
                )

        matches: list[tuple[int, int, GatewayAccount, _AccountServer, ContactResource]] = []
        for entries in aliases.values():
            if len(entries) != 1:
                continue
            alias, account, account_server, resource, is_full_name = entries[0]
            pattern = re.compile(rf"(?<!\w){re.escape(alias)}(?!\w)", re.IGNORECASE)
            matches.extend(
                (match.start(), match.end(), account, account_server, resource)
                for match in pattern.finditer(text)
                if is_full_name
                or _partial_contact_alias_has_context(text, match.start(), match.end())
            )

        selected: list[tuple[int, int, GatewayAccount, _AccountServer, ContactResource]] = []
        occupied: list[tuple[int, int]] = []
        for match in sorted(matches, key=lambda item: (-(item[1] - item[0]), item[0])):
            start, end = match[0], match[1]
            if any(start < used_end and end > used_start for used_start, used_end in occupied):
                continue
            occupied.append((start, end))
            selected.append(match)

        private_values: dict[str, str] = {}
        references: dict[tuple[str, ContactResource], str] = {}
        protected_text = text
        for start, end, account, account_server, resource in sorted(
            selected, key=lambda item: item[0], reverse=True
        ):
            key = (account.account_ref, resource)
            reference = references.get(key)
            if reference is None:
                reference = account_server.server.cache_trusted_contact(resource)
                references[key] = reference
                private_values[reference] = resource.contact.name
                self._record_route(identity, reference, account)
            protected_text = (
                protected_text[:start] + f"{{{{pii:contact:{reference}}}}}" + protected_text[end:]
            )
        protected_count = len(selected)
        return _private_result(
            {"text": protected_text, "protected_contact_count": protected_count},
            private_values,
            f"Protected {protected_count} contact name occurrence(s).",
        )

    def _select_create_account(
        self, identity: GatewayIdentity, arguments: dict[str, Any]
    ) -> GatewayAccount:
        requested = arguments.get("account_ref")
        if requested is not None:
            if not isinstance(requested, str) or not requested:
                raise TypeError("account_ref must be a non-empty string")
            return self._accessible_account(identity, requested, permission="write")
        enabled_accounts = self._enabled_accounts(identity)
        if len(enabled_accounts) == 1:
            return self._accessible_account(
                identity, enabled_accounts[0].account_ref, permission="write"
            )
        accounts = [
            account
            for account in enabled_accounts
            if self._can_access(identity, account, permission="write")
        ]
        if len(accounts) != 1:
            raise ValueError("contacts_create requires account_ref when access is not unambiguous")
        return accounts[0]

    def _enabled_accounts(self, identity: GatewayIdentity) -> list[GatewayAccount]:
        accounts: list[GatewayAccount] = []
        static_account = self._static_account_for_identity(identity, permission="read")
        if static_account is not None:
            accounts.append(static_account)
        if self._access_policy is not None:
            accounts.extend(
                accessible.account
                for accessible in self._access_policy.list_accessible(
                    identity, permission="read", limit=100
                )
                if accessible.account.kind == "carddav"
                and all(
                    account.account_ref != accessible.account.account_ref for account in accounts
                )
            )
        return accounts

    def _accessible_account(
        self,
        identity: GatewayIdentity,
        account_ref: str,
        *,
        permission: Literal["read", "write"],
    ) -> GatewayAccount:
        static_account = self._static_account_for_identity(identity, permission=permission)
        if static_account is not None and static_account.account_ref == account_ref:
            return static_account
        if self._access_policy is None:
            raise PermissionError("Unknown or unavailable account reference")
        accessible = self._access_policy.resolve(identity, account_ref, permission=permission)
        if accessible is None or accessible.account.kind != "carddav":
            raise PermissionError("Unknown or unavailable account reference")
        return accessible.account

    def _can_access(
        self,
        identity: GatewayIdentity,
        account: GatewayAccount,
        *,
        permission: Literal["read", "write"],
    ) -> bool:
        try:
            self._accessible_account(identity, account.account_ref, permission=permission)
        except PermissionError:
            return False
        return True

    def _static_account_for_identity(
        self,
        identity: GatewayIdentity,
        *,
        permission: Literal["read", "write"],
    ) -> GatewayAccount | None:
        template = self._account
        if template is None:
            return None
        if self._store is not None:
            access = self._store.resource_access(
                template.resource_id,
                identity.tenant_id,
                identity.user_id,
                permission=permission,
            )
            if access is True:
                return template.materialize(identity)
            if access is False or self._require_resource_grants:
                return None
        if template.owns(identity):
            return template.materialize(identity)
        return None

    def _server_for_identity(
        self, identity: GatewayIdentity, account: GatewayAccount
    ) -> _AccountServer:
        static = self._is_static_account(identity, account)
        return self._server_for(identity, account, static=static)

    def _is_static_account(self, identity: GatewayIdentity, account: GatewayAccount) -> bool:
        template = self._account
        return (
            template is not None
            and account.updated_at == template.revision
            and account.account_ref == template.materialize(identity).account_ref
        )

    def _server_for(
        self,
        identity: GatewayIdentity,
        account: GatewayAccount,
        *,
        static: bool,
    ) -> _AccountServer:
        key = (identity.tenant_id, identity.user_id, account.account_ref)
        with self._lock:
            cached = self._servers.get(key)
            if cached is not None and cached.revision == account.updated_at:
                return cached
            if len(self._servers) >= _MAX_OWNER_SERVERS:
                self._servers.pop(next(iter(self._servers)))
            if static:
                template = self._account
                if template is None:  # pragma: no cover - defensive
                    raise PermissionError("Contacts are unavailable for this identity")
                server = (
                    self._server_factory(template)
                    if self._server_factory is not None
                    else self._default_static_server(template, identity)
                )
            else:
                server = (
                    self._account_server_factory(account)
                    if self._account_server_factory is not None
                    else self._default_account_server(account, identity)
                )
            current = _AccountServer(revision=account.updated_at, server=server)
            self._servers[key] = current
            return current

    def _record_route(
        self, identity: GatewayIdentity, reference: str, account: GatewayAccount
    ) -> None:
        with self._lock:
            if len(self._routes) >= 10_000:
                self._routes.pop(next(iter(self._routes)))
            self._routes[(identity.tenant_id, identity.user_id, reference)] = _ReferenceRoute(
                account_ref=account.account_ref,
                account_updated_at=account.updated_at,
            )

    def _record_contact_references(
        self, identity: GatewayIdentity, account: GatewayAccount, result: dict[str, Any]
    ) -> None:
        structured = result.get("structuredContent")
        if not isinstance(structured, dict):
            return
        items: list[Any] = []
        contacts = structured.get("contacts")
        if isinstance(contacts, list):
            items.extend(contacts)
        items.append(structured)
        for item in items:
            reference = item.get("contact_ref") if isinstance(item, dict) else None
            if isinstance(reference, str) and reference:
                self._record_route(identity, reference, account)

    def _resolve_route(
        self,
        identity: GatewayIdentity,
        reference: str,
        *,
        permission: Literal["read", "write"],
    ) -> tuple[GatewayAccount, _AccountServer]:
        route: _ReferenceRoute | None = None
        if self._store is not None:
            stored = self._store.get_reference(identity.tenant_id, identity.user_id, reference)
            if stored is not None and stored.reference_type == "contact":
                if self._account is not None and stored.account_ref == self._account.account_id:
                    static_account = self._static_account_for_identity(
                        identity, permission=permission
                    )
                    if static_account is not None:
                        route = _ReferenceRoute(
                            account_ref=static_account.account_ref,
                            account_updated_at=stored.account_updated_at,
                        )
                else:
                    route = _ReferenceRoute(
                        account_ref=stored.account_ref,
                        account_updated_at=stored.account_updated_at,
                    )
        if route is None:
            with self._lock:
                route = self._routes.get((identity.tenant_id, identity.user_id, reference))
        if route is None:
            raise PermissionError("Unknown or expired reference")
        account = self._accessible_account(identity, route.account_ref, permission=permission)
        if account.updated_at != route.account_updated_at:
            raise PermissionError("Unknown or expired reference")
        return account, self._server_for_identity(identity, account)

    @staticmethod
    def _private_values(result: dict[str, Any]) -> dict[str, str]:
        meta = result.get("_meta")
        values = meta.get(PRIVATE_VALUES_META_KEY) if isinstance(meta, dict) else None
        if not isinstance(values, dict) or not all(
            isinstance(key, str) and isinstance(value, str) for key, value in values.items()
        ):
            return {}
        return cast(dict[str, str], values)

    def _merge_private_values(self, destination: dict[str, str], result: dict[str, Any]) -> None:
        for key, value in self._private_values(result).items():
            existing = destination.get(key)
            if existing is not None and existing != value:
                raise RuntimeError("Conflicting private metadata")
            destination[key] = value

    def _default_static_server(
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

    def _default_account_server(
        self, account: GatewayAccount, identity: GatewayIdentity
    ) -> PrivateContactsMCPServer:
        if self._store is None:  # pragma: no cover - constructor creates policy only with a store
            raise PermissionError("Contacts are unavailable for this identity")
        references = DurableReferenceCache[CachedContact](
            self._store,
            tenant_id=identity.tenant_id,
            user_id=identity.user_id,
            account_ref=account.account_ref,
            account_updated_at=account.updated_at,
            encode=_encode_contact_reference,
            decode=_decode_contact_reference,
            reference_types=frozenset({"contact"}),
        )
        return PrivateContactsMCPServer(
            contact_source=CardDAVContactSource(
                addressbook_url=account.base_url,
                username=account.credential.username,
                password=account.credential.password,
                auth_mode=account.credential.mode,
            ),
            clock=time.time,
            contact_references=references,
        )


def _private_result(
    structured_content: dict[str, Any],
    private_values: dict[str, str],
    message: str,
) -> dict[str, Any]:
    return {
        "content": [{"type": "text", "text": message}],
        "structuredContent": structured_content,
        "_meta": {PRIVATE_VALUES_META_KEY: private_values},
    }


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
