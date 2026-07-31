from __future__ import annotations

import argparse
import os
import re
import secrets
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, MutableMapping, Sequence
from dataclasses import dataclass
from typing import Any, Protocol
from urllib.parse import quote, urljoin, urlsplit
from uuid import uuid4

import httpx
import uvicorn
from fastapi import FastAPI

from private_dav_mcp import __version__
from private_dav_mcp.mcp_http import create_mcp_app
from private_dav_mcp.protocol import DEFAULT_MCP_PROTOCOL_VERSION, PRIVATE_VALUES_META_KEY
from private_dav_mcp.webdav import (
    DAV_READINESS_TIMEOUT_SECONDS,
    DAVHTTPClient,
    url_origin,
    validate_http_url,
    xml_headers,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8766
DEFAULT_CONTACT_LIMIT = 10
MAX_CONTACT_LIMIT = 50
DEFAULT_CONTACT_REFERENCE_TTL_SECONDS = 1800.0
MAX_CONTACT_REFERENCES = 1000
MAX_CARDDAV_RESPONSE_BYTES = 5_000_000
MAX_CONTACT_NAME_CHARS = 512
MAX_CONTACT_VALUES = 20
MAX_CONTACT_VALUE_CHARS = 2_048
CARDDAV_URL_ENV = "MINIGENT_CARDDAV_URL"
CARDDAV_USERNAME_ENV = "MINIGENT_CARDDAV_USERNAME"
CARDDAV_PASSWORD_ENV = "MINIGENT_CARDDAV_PASSWORD"
CARDDAV_AUTH_MODE_ENV = "MINIGENT_CARDDAV_AUTH_MODE"
CARDDAV_NAMESPACE = "urn:ietf:params:xml:ns:carddav"
DAV_NAMESPACE = "DAV:"
_PARTIAL_CONTACT_ALIAS_PREFIX_PATTERN = re.compile(
    r"(?:\b(?:call|email|contact|message|find|lookup|ask|tell)\s+|\bshow\s+me\s+)$",
    re.IGNORECASE,
)
_PARTIAL_CONTACT_ALIAS_POSSESSIVE_PATTERN = re.compile(r"^['’]s\b", re.IGNORECASE)
CARDDAV_REPORT_BODY = b"""<?xml version="1.0" encoding="utf-8" ?>
<card:addressbook-query xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop>
    <d:getetag />
    <card:address-data />
  </d:prop>
</card:addressbook-query>
"""
CARDDAV_PROPFIND_BODY = b"""<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:prop><d:resourcetype /></d:prop>
</d:propfind>
"""

CONTACTS_LIST_TOOL = {
    "name": "contacts_list",
    "description": (
        "List contacts with opaque contact_ref values and protected names. Use contacts_get "
        "to retrieve only the email or phone fields needed for the user's request. Treat "
        "contact_ref values as internal identifiers and never display them to the user."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_CONTACT_LIMIT,
                "description": f"Maximum contacts to return. Defaults to {DEFAULT_CONTACT_LIMIT}.",
            }
        },
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "contacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "contact_ref": {
                            "type": "string",
                            "description": (
                                "Internal opaque reference for contacts_get. Never display it "
                                "to the user."
                            ),
                        },
                        "name": {"type": "string"},
                        "available_fields": {
                            "type": "array",
                            "items": {"type": "string", "enum": ["emails", "phones"]},
                        },
                    },
                    "required": ["contact_ref", "name", "available_fields"],
                    "additionalProperties": False,
                },
            },
            "truncated": {"type": "boolean"},
        },
        "required": ["contacts", "truncated"],
        "additionalProperties": False,
    },
}

CONTACTS_GET_TOOL = {
    "name": "contacts_get",
    "description": (
        "Retrieve selected fields for an opaque contact_ref returned by contacts_list. "
        "Returned values are protected placeholders; preserve them exactly."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "contact_ref": {
                "type": "string",
                "description": (
                    "Opaque reference returned by contacts_list, or the REFERENCE from a "
                    "{{pii:contact:REFERENCE}} placeholder. Never display it to the user."
                ),
            },
            "fields": {
                "type": "array",
                "items": {"type": "string", "enum": ["emails", "phones"]},
                "minItems": 1,
                "uniqueItems": True,
            },
        },
        "required": ["contact_ref", "fields"],
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "contact_ref": {"type": "string"},
            "emails": {"type": "array", "items": {"type": "string"}},
            "phones": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["contact_ref"],
        "additionalProperties": False,
    },
}


def _contact_value_array_schema(kind: str) -> dict[str, Any]:
    return {
        "type": "array",
        "items": {"type": "string", "minLength": 1, "maxLength": MAX_CONTACT_VALUE_CHARS},
        "maxItems": MAX_CONTACT_VALUES,
        "uniqueItems": True,
        "description": f"Complete set of contact {kind}; an empty array clears the field.",
    }


CONTACTS_CREATE_TOOL = {
    "name": "contacts_create",
    "description": (
        "Create a contact after explicit user approval. Pass protected name, email, and phone "
        "placeholders exactly as provided; never invent contact details."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "name": {"type": "string", "minLength": 1, "maxLength": MAX_CONTACT_NAME_CHARS},
            "emails": _contact_value_array_schema("emails"),
            "phones": _contact_value_array_schema("phones"),
        },
        "required": ["name"],
        "additionalProperties": False,
    },
}

CONTACTS_UPDATE_TOOL = {
    "name": "contacts_update",
    "description": (
        "Update selected fields of a contact returned by contacts_list. Omitted fields remain "
        "unchanged; an empty emails or phones array clears that field. Requires user approval."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "contact_ref": {"type": "string", "minLength": 1},
            "name": {"type": "string", "minLength": 1, "maxLength": MAX_CONTACT_NAME_CHARS},
            "emails": _contact_value_array_schema("emails"),
            "phones": _contact_value_array_schema("phones"),
        },
        "required": ["contact_ref"],
        "additionalProperties": False,
    },
}

CONTACTS_DELETE_TOOL = {
    "name": "contacts_delete",
    "description": (
        "Permanently delete a contact returned by contacts_list. This destructive action always "
        "requires explicit user approval."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"contact_ref": {"type": "string", "minLength": 1}},
        "required": ["contact_ref"],
        "additionalProperties": False,
    },
}


CONTACTS_PROTECT_TEXT_TOOL = {
    "name": "contacts_protect_text",
    "description": (
        "Trusted runtime-only preprocessing that protects uniquely matching address-book "
        "contact names and unambiguous first or last names in contact-related contexts before "
        "model use."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {"text": {"type": "string"}},
        "required": ["text"],
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "text": {"type": "string"},
            "protected_contact_count": {"type": "integer"},
        },
        "required": ["text", "protected_contact_count"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True)
class Contact:
    name: str
    emails: tuple[str, ...] = ()
    phones: tuple[str, ...] = ()


@dataclass(frozen=True)
class ContactPatch:
    name: str | None = None
    emails: tuple[str, ...] | None = None
    phones: tuple[str, ...] | None = None


@dataclass(frozen=True)
class ContactResource:
    contact: Contact
    href: str | None = None
    etag: str | None = None
    uid: str | None = None
    raw_vcard: str | None = None


@dataclass(frozen=True)
class CachedContact:
    resource: ContactResource
    expires_at: float


DEMO_CONTACTS = (
    Contact(name="Alice Smith", emails=("alice@example.com",), phones=("+1 555 0100",)),
    Contact(name="Bob Jones", emails=("bob@example.com",), phones=("+1 555 0101",)),
)


class ContactSource(Protocol):
    def list_contact_resources(self, *, limit: int) -> tuple[list[ContactResource], bool]: ...

    def create_contact(self, contact: Contact) -> ContactResource: ...

    def update_contact(self, resource: ContactResource, patch: ContactPatch) -> ContactResource: ...

    def delete_contact(self, resource: ContactResource) -> None: ...

    def check_ready(self) -> None: ...


class StaticContactSource:
    def __init__(self, contacts: Sequence[Contact] = DEMO_CONTACTS) -> None:
        self._resources = [
            ContactResource(contact=contact, href=f"static://contact/{index}", etag='"1"')
            for index, contact in enumerate(contacts)
        ]
        self._next_id = len(self._resources)

    def list_contact_resources(self, *, limit: int) -> tuple[list[ContactResource], bool]:
        return list(self._resources[:limit]), len(self._resources) > limit

    def list_contacts(self, *, limit: int) -> tuple[list[Contact], bool]:
        resources, truncated = self.list_contact_resources(limit=limit)
        return [resource.contact for resource in resources], truncated

    def create_contact(self, contact: Contact) -> ContactResource:
        resource = ContactResource(
            contact=contact,
            href=f"static://contact/{self._next_id}",
            etag='"1"',
            uid=str(uuid4()),
            raw_vcard=serialize_vcard(contact),
        )
        self._next_id += 1
        self._resources.append(resource)
        return resource

    def update_contact(self, resource: ContactResource, patch: ContactPatch) -> ContactResource:
        index = self._resource_index(resource)
        updated_contact = apply_contact_patch(resource.contact, patch)
        version = int((resource.etag or '"0"').strip('"')) + 1
        updated = ContactResource(
            contact=updated_contact,
            href=resource.href,
            etag=f'"{version}"',
            uid=resource.uid,
            raw_vcard=patch_vcard(
                resource.raw_vcard or serialize_vcard(resource.contact),
                updated_contact,
                patch=patch,
            ),
        )
        self._resources[index] = updated
        return updated

    def delete_contact(self, resource: ContactResource) -> None:
        self._resources.pop(self._resource_index(resource))

    def check_ready(self) -> None:
        return None

    def _resource_index(self, resource: ContactResource) -> int:
        for index, current in enumerate(self._resources):
            if current.href == resource.href:
                return index
        raise RuntimeError("Contact changed or no longer exists")


class CardDAVContactSource:
    def __init__(
        self,
        *,
        addressbook_url: str,
        username: str,
        password: str,
        auth_mode: str = "auto",
        verify_tls: bool = True,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if not addressbook_url.strip():
            raise ValueError("CardDAV address-book URL is required")
        validate_http_url(addressbook_url, label="CardDAV address-book URL")
        if not username:
            raise ValueError("CardDAV username is required")
        if not password:
            raise ValueError("CardDAV password is required")
        self._addressbook_url = addressbook_url
        self._http = DAVHTTPClient(
            protocol_name="CardDAV",
            username=username,
            password=password,
            auth_mode=auth_mode,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
            max_response_bytes=MAX_CARDDAV_RESPONSE_BYTES,
            response_size_message="CardDAV response exceeded the private contacts size limit",
            changed_message="CardDAV contact changed; list it again before retrying",
            not_found_message="CardDAV contact no longer exists",
            transport=transport,
        )

    def check_ready(self) -> None:
        with self._http.client(timeout_seconds=DAV_READINESS_TIMEOUT_SECONDS) as client:
            self._discover_addressbook(client)

    def list_contact_resources(self, *, limit: int) -> tuple[list[ContactResource], bool]:
        with self._http.client() as client:
            addressbook_url, auth = self._discover_addressbook(client)
            response = self._http.request(
                client,
                "REPORT",
                addressbook_url,
                auth=auth,
                headers=xml_headers(),
                content=CARDDAV_REPORT_BODY,
            )
        self._http.check_response_size(response.content)
        resources = parse_carddav_multistatus_resources(
            response.content,
            addressbook_url=addressbook_url,
        )
        return resources[:limit], len(resources) > limit

    def list_contacts(self, *, limit: int) -> tuple[list[Contact], bool]:
        resources, truncated = self.list_contact_resources(limit=limit)
        return [resource.contact for resource in resources], truncated

    def create_contact(self, contact: Contact) -> ContactResource:
        uid = str(uuid4())
        payload = serialize_vcard(contact, uid=uid)
        with self._http.client() as client:
            addressbook_url, auth = self._discover_addressbook(client)
            href = f"{addressbook_url.rstrip('/')}/{quote(uid, safe='')}.vcf"
            _validate_resource_url(href, addressbook_url=addressbook_url)
            response = self._http.request(
                client,
                "PUT",
                href,
                auth=auth,
                headers={
                    "Content-Type": "text/vcard; charset=utf-8",
                    "If-None-Match": "*",
                },
                content=payload.encode("utf-8"),
            )
        return ContactResource(
            contact=contact,
            href=href,
            etag=response.headers.get("etag"),
            uid=uid,
            raw_vcard=payload,
        )

    def update_contact(self, resource: ContactResource, patch: ContactPatch) -> ContactResource:
        href = self._writable_href(resource)
        contact = apply_contact_patch(resource.contact, patch)
        payload = patch_vcard(
            resource.raw_vcard or serialize_vcard(resource.contact, uid=resource.uid),
            contact,
            patch=patch,
        )
        if not resource.etag:
            raise RuntimeError("Contact has no ETag; list it again before updating")
        headers = {
            "Content-Type": "text/vcard; charset=utf-8",
            "If-Match": resource.etag,
        }
        with self._http.client() as client:
            addressbook_url, auth = self._discover_addressbook(client)
            _validate_resource_url(href, addressbook_url=addressbook_url)
            response = self._http.request(
                client,
                "PUT",
                href,
                auth=auth,
                headers=headers,
                content=payload.encode("utf-8"),
            )
        return ContactResource(
            contact=contact,
            href=href,
            etag=response.headers.get("etag"),
            uid=resource.uid,
            raw_vcard=payload,
        )

    def delete_contact(self, resource: ContactResource) -> None:
        href = self._writable_href(resource)
        if not resource.etag:
            raise RuntimeError("Contact has no ETag; list it again before deleting")
        headers = {"If-Match": resource.etag}
        with self._http.client() as client:
            addressbook_url, auth = self._discover_addressbook(client)
            _validate_resource_url(href, addressbook_url=addressbook_url)
            self._http.request(client, "DELETE", href, auth=auth, headers=headers)

    def _discover_addressbook(self, client: httpx.Client) -> tuple[str, httpx.Auth | None]:
        response, auth = self._http.request_with_auth_negotiation(
            client,
            "PROPFIND",
            self._addressbook_url,
            headers=xml_headers(),
            content=CARDDAV_PROPFIND_BODY,
            operation="address-book discovery",
        )
        self._http.check_response_size(response.content)
        return (
            discover_carddav_addressbook_url(response.content, base_url=self._addressbook_url),
            auth,
        )

    @staticmethod
    def _writable_href(resource: ContactResource) -> str:
        if not resource.href:
            raise RuntimeError("Contact has no writable CardDAV resource")
        return resource.href


class PrivateContactsMCPServer:
    def __init__(
        self,
        contacts: Sequence[Contact] | None = None,
        *,
        contact_source: ContactSource | None = None,
        reference_factory: Callable[[], str] | None = None,
        contact_reference_factory: Callable[[], str] | None = None,
        contact_reference_ttl_seconds: float = DEFAULT_CONTACT_REFERENCE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
        contact_references: MutableMapping[str, CachedContact] | None = None,
    ) -> None:
        if contacts is not None and contact_source is not None:
            raise ValueError("Provide contacts or contact_source, not both")
        if contact_reference_ttl_seconds <= 0:
            raise ValueError("contact reference TTL must be positive")
        static_contacts = DEMO_CONTACTS if contacts is None else contacts
        self._contact_source = contact_source or StaticContactSource(static_contacts)
        self._reference_factory = reference_factory or (lambda: secrets.token_urlsafe(16))
        self._contact_reference_factory = contact_reference_factory or (
            lambda: secrets.token_urlsafe(18)
        )
        self._contact_reference_ttl_seconds = contact_reference_ttl_seconds
        self._clock = clock
        self._contact_references: MutableMapping[str, CachedContact] = (
            contact_references if contact_references is not None else {}
        )

    def check_ready(self) -> None:
        self._contact_source.check_ready()

    def handle(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        method = payload.get("method")
        if method == "notifications/initialized":
            return None
        if request_id is None:
            return None
        if method == "initialize":
            return self._result(
                request_id,
                {
                    "protocolVersion": DEFAULT_MCP_PROTOCOL_VERSION,
                    "serverInfo": {
                        "name": "minigent-private-contacts",
                        "version": __version__,
                    },
                    "capabilities": {"tools": {}},
                },
            )
        if method == "tools/list":
            return self._result(
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
        if method == "tools/call":
            try:
                return self._handle_tool_call(request_id, payload.get("params"))
            except Exception as exc:
                return self._error(request_id, -32000, str(exc))
        return self._error(request_id, -32601, f"Unsupported MCP method '{method}'")

    def _handle_tool_call(self, request_id: Any, params: Any) -> dict[str, Any]:
        if not isinstance(params, dict):
            return self._error(request_id, -32602, "tools/call params must be an object")
        arguments = params.get("arguments") or {}
        if not isinstance(arguments, dict):
            return self._error(request_id, -32602, "tool arguments must be an object")
        tool_name = params.get("name")
        if tool_name == "contacts_list":
            return self._handle_contacts_list(request_id, arguments)
        if tool_name == "contacts_get":
            return self._handle_contacts_get(request_id, arguments)
        if tool_name == "contacts_create":
            return self._handle_contacts_create(request_id, arguments)
        if tool_name == "contacts_update":
            return self._handle_contacts_update(request_id, arguments)
        if tool_name == "contacts_delete":
            return self._handle_contacts_delete(request_id, arguments)
        if tool_name == "contacts_protect_text":
            return self._handle_contacts_protect_text(request_id, arguments)
        return self._error(request_id, -32602, "Unknown tool")

    def _handle_contacts_list(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        unknown_arguments = set(arguments) - {"limit"}
        if unknown_arguments:
            return self._error(request_id, -32602, "contacts_list received unknown arguments")
        limit = arguments.get("limit", DEFAULT_CONTACT_LIMIT)
        if (
            not isinstance(limit, int)
            or isinstance(limit, bool)
            or not 1 <= limit <= MAX_CONTACT_LIMIT
        ):
            return self._error(
                request_id,
                -32602,
                f"limit must be an integer from 1 to {MAX_CONTACT_LIMIT}",
            )

        self._prune_contact_references()
        resources, truncated = self._contact_source.list_contact_resources(limit=limit)
        structured_content: dict[str, Any] = {"contacts": [], "truncated": truncated}
        private_values: dict[str, str] = {}
        for resource in resources:
            contact = resource.contact
            contact_reference = self._cache_contact(resource)
            available_fields = []
            if contact.emails:
                available_fields.append("emails")
            if contact.phones:
                available_fields.append("phones")
            structured_content["contacts"].append(
                {
                    "contact_ref": contact_reference,
                    "name": self._protect("name", contact.name, private_values),
                    "available_fields": available_fields,
                }
            )
        return self._private_tool_result(
            request_id,
            structured_content,
            private_values,
            message=f"Found {len(resources)} contacts.",
        )

    def _handle_contacts_get(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"contact_ref", "fields"}:
            return self._error(
                request_id,
                -32602,
                "contacts_get requires only contact_ref and fields",
            )
        contact_reference = arguments.get("contact_ref")
        fields = arguments.get("fields")
        if not isinstance(contact_reference, str) or not contact_reference:
            return self._error(request_id, -32602, "contact_ref must be a non-empty string")
        if (
            not isinstance(fields, list)
            or not fields
            or not all(field in {"emails", "phones"} for field in fields)
            or len(set(fields)) != len(fields)
        ):
            return self._error(
                request_id,
                -32602,
                "fields must contain unique emails or phones values",
            )
        self._prune_contact_references()
        cached = self._contact_references.get(contact_reference)
        if cached is None:
            return self._error(request_id, -32001, "Unknown or expired contact_ref")

        private_values: dict[str, str] = {}
        structured_content: dict[str, Any] = {"contact_ref": contact_reference}
        if "emails" in fields:
            structured_content["emails"] = [
                self._protect("email", email, private_values)
                for email in cached.resource.contact.emails
            ]
        if "phones" in fields:
            structured_content["phones"] = [
                self._protect("phone", phone, private_values)
                for phone in cached.resource.contact.phones
            ]
        return self._private_tool_result(
            request_id,
            structured_content,
            private_values,
            message="Retrieved the selected protected contact fields.",
        )

    def _handle_contacts_create(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if not set(arguments) <= {"name", "emails", "phones"} or "name" not in arguments:
            return self._error(
                request_id,
                -32602,
                "contacts_create requires name and accepts only emails and phones",
            )
        try:
            contact = _contact_from_arguments(arguments)
        except ValueError as exc:
            return self._error(request_id, -32602, str(exc))
        resource = self._contact_source.create_contact(contact)
        contact_reference = self._cache_contact(resource)
        return self._private_tool_result(
            request_id,
            {"status": "created", "contact_ref": contact_reference},
            {},
            message="Created the contact.",
        )

    def _handle_contacts_update(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if not set(arguments) <= {"contact_ref", "name", "emails", "phones"} or set(arguments) == {
            "contact_ref"
        }:
            return self._error(
                request_id,
                -32602,
                "contacts_update requires contact_ref and at least one field to update",
            )
        contact_reference = arguments.get("contact_ref")
        if not isinstance(contact_reference, str) or not contact_reference:
            return self._error(request_id, -32602, "contact_ref must be a non-empty string")
        self._prune_contact_references()
        cached = self._contact_references.get(contact_reference)
        if cached is None:
            return self._error(request_id, -32001, "Unknown or expired contact_ref")
        try:
            patch = _contact_patch_from_arguments(arguments)
        except ValueError as exc:
            return self._error(request_id, -32602, str(exc))
        updated = self._contact_source.update_contact(cached.resource, patch)
        self._invalidate_resource_references(cached.resource)
        self._contact_references[contact_reference] = CachedContact(
            resource=updated,
            expires_at=self._clock() + self._contact_reference_ttl_seconds,
        )
        return self._private_tool_result(
            request_id,
            {"status": "updated", "contact_ref": contact_reference},
            {},
            message="Updated the contact.",
        )

    def _handle_contacts_delete(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"contact_ref"}:
            return self._error(
                request_id,
                -32602,
                "contacts_delete requires only contact_ref",
            )
        contact_reference = arguments.get("contact_ref")
        if not isinstance(contact_reference, str) or not contact_reference:
            return self._error(request_id, -32602, "contact_ref must be a non-empty string")
        self._prune_contact_references()
        cached = self._contact_references.get(contact_reference)
        if cached is None:
            return self._error(request_id, -32001, "Unknown or expired contact_ref")
        self._contact_source.delete_contact(cached.resource)
        self._invalidate_resource_references(cached.resource)
        return self._private_tool_result(
            request_id,
            {"status": "deleted"},
            {},
            message="Deleted the contact.",
        )

    def _handle_contacts_protect_text(
        self, request_id: Any, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        if set(arguments) != {"text"} or not isinstance(arguments.get("text"), str):
            return self._error(
                request_id,
                -32602,
                "contacts_protect_text requires a text string",
            )
        text = arguments["text"]
        resources, _truncated = self._contact_source.list_contact_resources(
            limit=MAX_CONTACT_REFERENCES
        )
        contacts = [resource.contact for resource in resources]
        aliases: dict[str, list[tuple[str, Contact, bool]]] = {}
        for contact in contacts:
            full_name = contact.name.strip()
            if not full_name:
                continue
            contact_aliases = {full_name: True}
            name_parts = full_name.split()
            if len(name_parts) > 1:
                contact_aliases.update(
                    {part: False for part in (name_parts[0], name_parts[-1]) if len(part) >= 2}
                )
            for alias, is_full_name in contact_aliases.items():
                aliases.setdefault(alias.casefold(), []).append((alias, contact, is_full_name))

        alias_matches: list[tuple[int, int, Contact]] = []
        for entries in aliases.values():
            if len(entries) != 1:
                continue
            alias, contact, is_full_name = entries[0]
            pattern = re.compile(rf"(?<!\w){re.escape(alias)}(?!\w)", re.IGNORECASE)
            alias_matches.extend(
                (match.start(), match.end(), contact)
                for match in pattern.finditer(text)
                if is_full_name
                or _partial_contact_alias_has_context(text, match.start(), match.end())
            )

        selected: list[tuple[int, int, Contact]] = []
        occupied: list[tuple[int, int]] = []
        for start, end, contact in sorted(
            alias_matches,
            key=lambda item: (-(item[1] - item[0]), item[0]),
        ):
            if any(start < used_end and end > used_start for used_start, used_end in occupied):
                continue
            occupied.append((start, end))
            selected.append((start, end, contact))

        private_values: dict[str, str] = {}
        contact_references: dict[Contact, str] = {}
        protected_text = text
        for start, end, contact in sorted(selected, key=lambda item: item[0], reverse=True):
            contact_reference = contact_references.get(contact)
            if contact_reference is None:
                contact_reference = self._cache_contact(
                    next(resource for resource in resources if resource.contact == contact)
                )
                contact_references[contact] = contact_reference
                private_values[contact_reference] = contact.name
            protected_text = (
                protected_text[:start]
                + f"{{{{pii:contact:{contact_reference}}}}}"
                + protected_text[end:]
            )
        protected_count = len(selected)
        return self._private_tool_result(
            request_id,
            {
                "text": protected_text,
                "protected_contact_count": protected_count,
            },
            private_values,
            message=f"Protected {protected_count} contact name occurrence(s).",
        )

    def _cache_contact(self, resource: ContactResource) -> str:
        if len(self._contact_references) >= MAX_CONTACT_REFERENCES:
            oldest_reference = min(
                self._contact_references,
                key=lambda reference: self._contact_references[reference].expires_at,
            )
            self._contact_references.pop(oldest_reference, None)
        reference = self._contact_reference_factory()
        self._contact_references[reference] = CachedContact(
            resource=resource,
            expires_at=self._clock() + self._contact_reference_ttl_seconds,
        )
        return reference

    def _prune_contact_references(self) -> None:
        now = self._clock()
        expired = [
            reference
            for reference, cached in self._contact_references.items()
            if cached.expires_at <= now
        ]
        for reference in expired:
            self._contact_references.pop(reference, None)

    def _invalidate_resource_references(self, resource: ContactResource) -> None:
        matching = [
            reference
            for reference, cached in self._contact_references.items()
            if _same_contact_resource(cached.resource, resource)
        ]
        for reference in matching:
            self._contact_references.pop(reference, None)

    def _private_tool_result(
        self,
        request_id: Any,
        structured_content: dict[str, Any],
        private_values: dict[str, str],
        *,
        message: str,
    ) -> dict[str, Any]:
        return self._result(
            request_id,
            {
                "content": [{"type": "text", "text": message}],
                "structuredContent": structured_content,
                "_meta": {PRIVATE_VALUES_META_KEY: private_values},
            },
        )

    def _protect(self, kind: str, value: str, private_values: dict[str, str]) -> str:
        reference = self._reference_factory()
        private_values[reference] = value
        return f"{{{{pii:{kind}:{reference}}}}}"

    @staticmethod
    def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {
            "jsonrpc": "2.0",
            "id": request_id,
            "error": {"code": code, "message": message},
        }


def _contact_from_arguments(arguments: dict[str, Any]) -> Contact:
    name = _validate_contact_string(
        arguments.get("name"), field="name", max_chars=MAX_CONTACT_NAME_CHARS
    )
    return Contact(
        name=name,
        emails=_validate_contact_values(arguments.get("emails", []), field="emails"),
        phones=_validate_contact_values(arguments.get("phones", []), field="phones"),
    )


def _contact_patch_from_arguments(arguments: dict[str, Any]) -> ContactPatch:
    return ContactPatch(
        name=(
            _validate_contact_string(
                arguments["name"], field="name", max_chars=MAX_CONTACT_NAME_CHARS
            )
            if "name" in arguments
            else None
        ),
        emails=(
            _validate_contact_values(arguments["emails"], field="emails")
            if "emails" in arguments
            else None
        ),
        phones=(
            _validate_contact_values(arguments["phones"], field="phones")
            if "phones" in arguments
            else None
        ),
    )


def _validate_contact_values(value: Any, *, field: str) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_CONTACT_VALUES:
        raise ValueError(f"{field} must be an array with at most {MAX_CONTACT_VALUES} values")
    values = tuple(
        _validate_contact_string(item, field=field, max_chars=MAX_CONTACT_VALUE_CHARS)
        for item in value
    )
    if len(set(values)) != len(values):
        raise ValueError(f"{field} values must be unique")
    return values


def _validate_contact_string(value: Any, *, field: str, max_chars: int) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    normalized = value.strip()
    if not normalized or len(normalized) > max_chars:
        raise ValueError(f"{field} must contain from 1 to {max_chars} characters")
    if any(character in normalized for character in ("\r", "\n", "\x00")):
        raise ValueError(f"{field} must not contain control line breaks")
    return normalized


def apply_contact_patch(contact: Contact, patch: ContactPatch) -> Contact:
    return Contact(
        name=contact.name if patch.name is None else patch.name,
        emails=contact.emails if patch.emails is None else patch.emails,
        phones=contact.phones if patch.phones is None else patch.phones,
    )


def serialize_vcard(contact: Contact, *, uid: str | None = None) -> str:
    identifier = uid or str(uuid4())
    lines = [
        "BEGIN:VCARD",
        "VERSION:3.0",
        f"UID:{_escape_vcard_value(identifier)}",
        *_contact_vcard_lines(contact),
        "END:VCARD",
    ]
    return _serialize_vcard_lines(lines)


def patch_vcard(
    payload: str,
    contact: Contact,
    *,
    patch: ContactPatch | None = None,
) -> str:
    replaced_properties = {
        property_name
        for property_name, selected in (
            ("FN", patch is None or patch.name is not None),
            ("N", patch is None or patch.name is not None),
            ("EMAIL", patch is None or patch.emails is not None),
            ("TEL", patch is None or patch.phones is not None),
        )
        if selected
    }
    retained: list[str] = []
    inserted = False
    for line in _unfold_vcard_lines(payload):
        if not line:
            continue
        property_name = _vcard_property_name(line)
        if property_name in replaced_properties:
            continue
        if property_name == "END" and not inserted:
            retained.extend(_contact_vcard_lines(contact, properties=replaced_properties))
            inserted = True
        retained.append(line)
    if not inserted or not any(_vcard_property_name(line) == "BEGIN" for line in retained):
        raise RuntimeError("CardDAV contact returned an invalid vCard")
    return _serialize_vcard_lines(retained)


def _contact_vcard_lines(
    contact: Contact,
    *,
    properties: set[str] | None = None,
) -> list[str]:
    selected = {"FN", "N", "EMAIL", "TEL"} if properties is None else properties
    name_parts = contact.name.split()
    family = name_parts[-1] if len(name_parts) > 1 else ""
    given = " ".join(name_parts[:-1]) if len(name_parts) > 1 else contact.name
    lines: list[str] = []
    if "FN" in selected:
        lines.append(f"FN:{_escape_vcard_value(contact.name)}")
    if "N" in selected:
        lines.append(f"N:{_escape_vcard_value(family)};{_escape_vcard_value(given)};;;")
    if "EMAIL" in selected:
        lines.extend(f"EMAIL:{_escape_vcard_value(value)}" for value in contact.emails)
    if "TEL" in selected:
        lines.extend(f"TEL:{_escape_vcard_value(value)}" for value in contact.phones)
    return lines


def _serialize_vcard_lines(lines: Sequence[str]) -> str:
    folded = [part for line in lines for part in _fold_vcard_line(line)]
    return "\r\n".join(folded) + "\r\n"


def _fold_vcard_line(line: str) -> list[str]:
    chunks: list[str] = []
    remaining = line
    limit = 75
    while len(remaining.encode("utf-8")) > limit:
        split_at = 0
        size = 0
        for index, character in enumerate(remaining):
            encoded_size = len(character.encode("utf-8"))
            if size + encoded_size > limit:
                break
            size += encoded_size
            split_at = index + 1
        if split_at == 0:
            split_at = 1
        chunks.append((" " if chunks else "") + remaining[:split_at])
        remaining = remaining[split_at:]
        limit = 74
    chunks.append((" " if chunks else "") + remaining)
    return chunks


def _escape_vcard_value(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace(";", "\\;").replace(",", "\\,")


def _vcard_property_name(line: str) -> str:
    left = line.partition(":")[0]
    return left.split(";", 1)[0].rsplit(".", 1)[-1].upper()


def _same_contact_resource(left: ContactResource, right: ContactResource) -> bool:
    if left.href is not None and right.href is not None:
        return left.href == right.href
    return left is right


def _partial_contact_alias_has_context(text: str, start: int, end: int) -> bool:
    return bool(
        _PARTIAL_CONTACT_ALIAS_PREFIX_PATTERN.search(text[:start])
        or _PARTIAL_CONTACT_ALIAS_POSSESSIVE_PATTERN.match(text[end:])
    )


def discover_carddav_addressbook_url(payload: bytes, *, base_url: str) -> str:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CardDAV server returned invalid XML") from exc
    response_tag = f"{{{DAV_NAMESPACE}}}response"
    href_tag = f"{{{DAV_NAMESPACE}}}href"
    addressbook_tag = f"{{{CARDDAV_NAMESPACE}}}addressbook"
    for response in root.iter(response_tag):
        if next(response.iter(addressbook_tag), None) is None:
            continue
        href = response.find(href_tag)
        if href is not None and href.text:
            discovered_url = urljoin(base_url, href.text.strip())
            if url_origin(discovered_url) != url_origin(base_url):
                raise RuntimeError("CardDAV discovery returned a cross-origin address book")
            return discovered_url
    return base_url


def parse_carddav_multistatus(payload: bytes) -> list[Contact]:
    return [
        resource.contact
        for resource in parse_carddav_multistatus_resources(payload, addressbook_url=None)
    ]


def parse_carddav_multistatus_resources(
    payload: bytes,
    *,
    addressbook_url: str | None,
) -> list[ContactResource]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CardDAV server returned invalid XML") from exc
    resources: list[ContactResource] = []
    response_tag = f"{{{DAV_NAMESPACE}}}response"
    href_tag = f"{{{DAV_NAMESPACE}}}href"
    etag_tag = f"{{{DAV_NAMESPACE}}}getetag"
    address_data_tag = f"{{{CARDDAV_NAMESPACE}}}address-data"
    for response in root.iter(response_tag):
        address_data = next(response.iter(address_data_tag), None)
        if address_data is None or not address_data.text:
            continue
        contact = parse_vcard(address_data.text)
        if contact is None:
            continue
        href_element = response.find(href_tag)
        href = None
        if href_element is not None and href_element.text and addressbook_url is not None:
            href = urljoin(addressbook_url, href_element.text.strip())
            _validate_resource_url(href, addressbook_url=addressbook_url)
        etag_element = next(response.iter(etag_tag), None)
        etag = etag_element.text.strip() if etag_element is not None and etag_element.text else None
        resources.append(
            ContactResource(
                contact=contact,
                href=href,
                etag=etag,
                uid=_vcard_uid(address_data.text),
                raw_vcard=address_data.text,
            )
        )
    return resources


def _validate_resource_url(resource_url: str, *, addressbook_url: str) -> None:
    if url_origin(resource_url) != url_origin(addressbook_url):
        raise RuntimeError("CardDAV returned a cross-origin contact resource")
    resource_path = urlsplit(resource_url).path
    addressbook_path = urlsplit(addressbook_url).path.rstrip("/") + "/"
    if not resource_path.startswith(addressbook_path):
        raise RuntimeError("CardDAV contact resource escaped the address book")


def _vcard_uid(payload: str) -> str | None:
    for line in _unfold_vcard_lines(payload):
        if _vcard_property_name(line) == "UID":
            value = line.partition(":")[2].strip()
            return _unescape_vcard_value(value) or None
    return None


def parse_vcard(payload: str) -> Contact | None:
    fields: dict[str, list[str]] = {}
    for line in _unfold_vcard_lines(payload):
        left, separator, raw_value = line.partition(":")
        if not separator:
            continue
        property_name = left.split(";", 1)[0].rsplit(".", 1)[-1].upper()
        if property_name not in {"FN", "N", "EMAIL", "TEL"}:
            continue
        fields.setdefault(property_name, []).append(_unescape_vcard_value(raw_value))

    name = next((value.strip() for value in fields.get("FN", []) if value.strip()), "")
    if not name:
        name = _name_from_structured_value(fields.get("N", []))
    emails = _unique_nonempty(fields.get("EMAIL", []))
    phones = _unique_nonempty(fields.get("TEL", []))
    if not name and not emails and not phones:
        return None
    return Contact(name=name or "Unnamed contact", emails=emails, phones=phones)


def _unfold_vcard_lines(payload: str) -> list[str]:
    unfolded: list[str] = []
    for line in payload.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return unfolded


def _unescape_vcard_value(value: str) -> str:
    return re.sub(
        r"\\([nN,;\\])",
        lambda match: "\n" if match.group(1).lower() == "n" else match.group(1),
        value,
    )


def _name_from_structured_value(values: Sequence[str]) -> str:
    for value in values:
        parts = value.split(";")
        family = parts[0].strip() if parts else ""
        given = parts[1].strip() if len(parts) > 1 else ""
        name = " ".join(part for part in (given, family) if part)
        if name:
            return name
    return ""


def _unique_nonempty(values: Sequence[str]) -> tuple[str, ...]:
    return tuple(dict.fromkeys(value.strip() for value in values if value.strip()))


def create_app(server: PrivateContactsMCPServer | None = None) -> FastAPI:
    private_contacts = server or PrivateContactsMCPServer()
    return create_mcp_app(
        title="Minigent private contacts MCP",
        handler=private_contacts.handle,
        readiness_check=private_contacts.check_ready,
    )


app = create_app()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run a local MCP server with private contact placeholders."
    )
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable CardDAV TLS verification. Use only for trusted local development.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    addressbook_url = os.environ.get(CARDDAV_URL_ENV, "").strip()
    if addressbook_url:
        contact_source: ContactSource = CardDAVContactSource(
            addressbook_url=addressbook_url,
            username=os.environ.get(CARDDAV_USERNAME_ENV, ""),
            password=os.environ.get(CARDDAV_PASSWORD_ENV, ""),
            auth_mode=os.environ.get(CARDDAV_AUTH_MODE_ENV, "auto"),
            verify_tls=not args.insecure_skip_tls_verify,
        )
        server = PrivateContactsMCPServer(contact_source=contact_source)
    else:
        server = PrivateContactsMCPServer()
    uvicorn.run(create_app(server), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
