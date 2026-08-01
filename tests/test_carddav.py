from __future__ import annotations

import base64

import httpx
import pytest

from private_dav_mcp.carddav import (
    CardDAVContactSource,
    Contact,
    ContactPatch,
    ContactResource,
    PrivateContactsMCPServer,
    discover_carddav_addressbook_url,
    parse_carddav_multistatus,
    parse_carddav_multistatus_resources,
    parse_vcard,
)
from private_dav_mcp.mcp_sdk import MCPToolCallFailure
from private_dav_mcp.protocol import PRIVATE_VALUES_META_KEY


def test_parse_vcard_reads_unfolded_name_emails_and_phones() -> None:
    contact = parse_vcard(
        "\r\n".join(
            [
                "BEGIN:VCARD",
                "VERSION:3.0",
                "FN:Alice\\, Example",
                "EMAIL;TYPE=HOME:alice@example.com",
                "item1.EMAIL;TYPE=WORK:alice@work.example",
                "TEL;TYPE=CELL:+1 555 0100",
                "TEL;TYPE=WORK:+1 555",
                " 0101",
                "END:VCARD",
            ]
        )
    )

    assert contact == Contact(
        name="Alice, Example",
        emails=("alice@example.com", "alice@work.example"),
        phones=("+1 555 0100", "+1 5550101"),
    )


def test_parse_vcard_falls_back_to_structured_name() -> None:
    contact = parse_vcard("BEGIN:VCARD\nN:Example;Alice;;;\nEND:VCARD\n")

    assert contact == Contact(name="Alice Example")


def test_discover_carddav_addressbook_url_resolves_relative_href() -> None:
    result = discover_carddav_addressbook_url(
        b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/dav.php/addressbooks/user/default/</d:href>
    <d:propstat><d:prop><d:resourcetype><d:collection /><card:addressbook />
    </d:resourcetype></d:prop></d:propstat>
  </d:response>
</d:multistatus>""",
        base_url="https://baikal.example/dav.php/addressbooks/user/",
    )

    assert result == "https://baikal.example/dav.php/addressbooks/user/default/"


def test_discover_carddav_addressbook_url_rejects_cross_origin_href() -> None:
    with pytest.raises(RuntimeError, match="cross-origin"):
        discover_carddav_addressbook_url(
            b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>https://attacker.example/contacts/</d:href><d:propstat><d:prop>
    <d:resourcetype><card:addressbook /></d:resourcetype>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
            base_url="https://baikal.example/dav.php/addressbooks/user/",
        )


def test_parse_carddav_multistatus_extracts_address_data() -> None:
    contacts = parse_carddav_multistatus(
        b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:propstat><d:prop><card:address-data><![CDATA[
BEGIN:VCARD
VERSION:3.0
FN:Alice Smith
EMAIL:alice@example.com
TEL:+1 555 0100
END:VCARD
  ]]></card:address-data></d:prop></d:propstat></d:response>
</d:multistatus>"""
    )

    assert contacts == [
        Contact(
            name="Alice Smith",
            emails=("alice@example.com",),
            phones=("+1 555 0100",),
        )
    ]


def test_carddav_source_discovers_collection_and_reports_with_basic_auth() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PROPFIND":
            return httpx.Response(
                207,
                headers={"content-type": "application/xml"},
                content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>/dav.php/addressbooks/user/default/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection /><card:addressbook /></d:resourcetype>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
            )
        assert request.method == "REPORT"
        assert str(request.url) == "https://baikal.example/dav.php/addressbooks/user/default/"
        return httpx.Response(
            207,
            headers={"content-type": "application/xml"},
            content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:propstat><d:prop><card:address-data><![CDATA[
BEGIN:VCARD
FN:Alice Smith
EMAIL:alice@example.com
END:VCARD
]]></card:address-data></d:prop></d:propstat></d:response>
  <d:response><d:propstat><d:prop><card:address-data><![CDATA[
BEGIN:VCARD
FN:Bob Jones
EMAIL:bob@example.com
END:VCARD
]]></card:address-data></d:prop></d:propstat></d:response>
</d:multistatus>""",
        )

    source = CardDAVContactSource(
        addressbook_url="https://baikal.example/dav.php/addressbooks/user/",
        username="user",
        password="password",
        auth_mode="basic",
        transport=httpx.MockTransport(handler),
    )

    contacts, truncated = source.list_contacts(limit=1)

    assert contacts == [Contact(name="Alice Smith", emails=("alice@example.com",))]
    assert truncated is True
    assert len(requests) == 2
    discovery_request, report_request = requests
    assert discovery_request.method == "PROPFIND"
    assert discovery_request.headers["depth"] == "1"
    assert b"propfind" in discovery_request.content
    assert report_request.method == "REPORT"
    assert report_request.headers["depth"] == "1"
    expected_auth = base64.b64encode(b"user:password").decode()
    assert discovery_request.headers["authorization"] == f"Basic {expected_auth}"
    assert report_request.headers["authorization"] == f"Basic {expected_auth}"
    assert b"addressbook-query" in report_request.content


def test_carddav_source_auto_negotiates_digest_auth() -> None:
    authorization_headers: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        authorization = request.headers.get("authorization", "")
        authorization_headers.append(authorization)
        if not authorization:
            return httpx.Response(
                401,
                headers={
                    "www-authenticate": (
                        'Digest realm="BaikalDAV",qop="auth",nonce="test-nonce",'
                        'opaque="test-opaque",algorithm=MD5'
                    )
                },
            )
        assert authorization.startswith("Digest ")
        if request.method == "PROPFIND":
            return httpx.Response(
                207,
                content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>/contacts/</d:href><d:propstat><d:prop>
    <d:resourcetype><card:addressbook /></d:resourcetype>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
            )
        return httpx.Response(
            207,
            content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav" />""",
        )

    source = CardDAVContactSource(
        addressbook_url="https://baikal.example/contacts/",
        username="user",
        password="password",
        transport=httpx.MockTransport(handler),
    )

    contacts, truncated = source.list_contacts(limit=1)

    assert contacts == []
    assert truncated is False
    assert any(header.startswith("Digest ") for header in authorization_headers)


def test_private_contacts_server_lists_refs_then_gets_selected_private_fields() -> None:
    value_references = iter(("name-ref", "email-ref", "phone-ref"))
    server = PrivateContactsMCPServer(
        contacts=[
            Contact(
                name="Alice Smith",
                emails=("alice@example.com",),
                phones=("+1 555 0100",),
            )
        ],
        reference_factory=lambda: next(value_references),
        contact_reference_factory=lambda: "contact-ref",
    )

    listed = server.call_tool("contacts_list", {})

    assert listed is not None
    listed_result = listed
    assert listed_result["structuredContent"] == {
        "contacts": [
            {
                "contact_ref": "contact-ref",
                "name": "{{pii:name:name-ref}}",
                "available_fields": ["emails", "phones"],
            }
        ],
        "truncated": False,
    }
    assert listed_result["_meta"][PRIVATE_VALUES_META_KEY] == {"name-ref": "Alice Smith"}

    fetched = server.call_tool(
        "contacts_get",
        {
            "contact_ref": "contact-ref",
            "fields": ["emails", "phones"],
        },
    )

    assert fetched is not None
    fetched_result = fetched
    assert fetched_result["structuredContent"] == {
        "contact_ref": "contact-ref",
        "emails": ["{{pii:email:email-ref}}"],
        "phones": ["{{pii:phone:phone-ref}}"],
    }
    assert fetched_result["_meta"][PRIVATE_VALUES_META_KEY] == {
        "email-ref": "alice@example.com",
        "phone-ref": "+1 555 0100",
    }
    assert "alice@example.com" not in str(fetched_result["structuredContent"])
    assert "+1 555 0100" not in str(fetched_result["structuredContent"])


def test_private_contacts_server_protects_unique_contact_names_for_model_input() -> None:
    server = PrivateContactsMCPServer(
        contacts=[Contact(name="Alice Smith", emails=("alice@example.com",))],
        contact_reference_factory=lambda: "contact-ref",
    )

    response = server.call_tool("contacts_protect_text", {"text": "What is Alice Smith's email?"})

    assert response is not None
    result = response
    assert result["structuredContent"] == {
        "text": "What is {{pii:contact:contact-ref}}'s email?",
        "protected_contact_count": 1,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {"contact-ref": "Alice Smith"}
    assert "Alice Smith" not in str(result["structuredContent"])


def test_private_contacts_server_protects_unambiguous_first_and_last_names() -> None:
    server = PrivateContactsMCPServer(
        contacts=[Contact(name="Gabe Zurita", emails=("gabe@example.com",))],
        contact_reference_factory=lambda: "contact-ref",
    )

    response = server.call_tool(
        "contacts_protect_text", {"text": "Show me Gabe's email, then call Zurita."}
    )

    assert response is not None
    result = response
    assert result["structuredContent"] == {
        "text": (
            "Show me {{pii:contact:contact-ref}}'s email, then call {{pii:contact:contact-ref}}."
        ),
        "protected_contact_count": 2,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {"contact-ref": "Gabe Zurita"}


def test_private_contacts_server_does_not_protect_partial_name_without_contact_context() -> None:
    server = PrivateContactsMCPServer(contacts=[Contact(name="Will Smith")])

    response = server.call_tool("contacts_protect_text", {"text": "Will this work in May?"})

    assert response is not None
    result = response
    assert result["structuredContent"] == {
        "text": "Will this work in May?",
        "protected_contact_count": 0,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {}


def test_private_contacts_server_does_not_guess_ambiguous_partial_names() -> None:
    server = PrivateContactsMCPServer(
        contacts=[Contact(name="Alex Doe"), Contact(name="Alex Smith")]
    )

    response = server.call_tool("contacts_protect_text", {"text": "Call Alex"})

    assert response is not None
    result = response
    assert result["structuredContent"] == {
        "text": "Call Alex",
        "protected_contact_count": 0,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {}


def test_private_contacts_server_does_not_guess_ambiguous_contact_names() -> None:
    server = PrivateContactsMCPServer(contacts=[Contact(name="Alex Doe"), Contact(name="Alex Doe")])

    response = server.call_tool("contacts_protect_text", {"text": "Call Alex Doe"})

    assert response is not None
    result = response
    assert result["structuredContent"] == {
        "text": "Call Alex Doe",
        "protected_contact_count": 0,
    }
    assert result["_meta"][PRIVATE_VALUES_META_KEY] == {}


def test_private_contacts_server_expires_contact_references() -> None:
    now = [100.0]
    server = PrivateContactsMCPServer(
        contacts=[Contact(name="Alice Smith", emails=("alice@example.com",))],
        contact_reference_factory=lambda: "contact-ref",
        contact_reference_ttl_seconds=5,
        clock=lambda: now[0],
    )
    server.call_tool("contacts_list", {})
    now[0] = 106.0

    with pytest.raises(MCPToolCallFailure) as exc_info:
        server.call_tool("contacts_get", {"contact_ref": "contact-ref", "fields": ["emails"]})

    assert exc_info.value.code == -32001
    assert exc_info.value.message == "Unknown or expired contact_ref"


def test_parse_carddav_resources_keeps_href_etag_uid_and_raw_vcard() -> None:
    resources = parse_carddav_multistatus_resources(
        b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>/addressbooks/user/default/alice.vcf</d:href><d:propstat><d:prop>
    <d:getetag>"version-1"</d:getetag><card:address-data><![CDATA[
BEGIN:VCARD
VERSION:3.0
UID:alice-id
FN:Alice Smith
NOTE:preserve me
END:VCARD
]]></card:address-data></d:prop></d:propstat></d:response>
</d:multistatus>""",
        addressbook_url="https://baikal.example/addressbooks/user/default/",
    )

    assert len(resources) == 1
    resource = resources[0]
    assert resource.contact == Contact(name="Alice Smith")
    assert resource.href == "https://baikal.example/addressbooks/user/default/alice.vcf"
    assert resource.etag == '"version-1"'
    assert resource.uid == "alice-id"
    assert resource.raw_vcard is not None and "NOTE:preserve me" in resource.raw_vcard


def test_carddav_create_uses_if_none_match_and_serializes_vcard() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PROPFIND":
            return _addressbook_discovery_response()
        assert request.method == "PUT"
        return httpx.Response(201, headers={"etag": '"created"'})

    source = _carddav_source(handler)
    created = source.create_contact(
        Contact(name="Jane Doe", emails=("jane@example.com",), phones=("+1 555 0102",))
    )

    put = requests[-1]
    assert put.headers["if-none-match"] == "*"
    assert put.url.path.startswith("/addressbooks/user/default/")
    assert put.url.path.endswith(".vcf")
    assert b"FN:Jane Doe\r\n" in put.content
    assert b"EMAIL:jane@example.com\r\n" in put.content
    assert created.etag == '"created"'


def test_carddav_update_uses_etag_and_preserves_unknown_vcard_fields() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PROPFIND":
            return _addressbook_discovery_response()
        assert request.method == "PUT"
        return httpx.Response(204, headers={"etag": '"version-2"'})

    source = _carddav_source(handler)
    resource = ContactResource(
        contact=Contact(name="Jane Doe", emails=("old@example.com",)),
        href="https://baikal.example/addressbooks/user/default/jane.vcf",
        etag='"version-1"',
        uid="jane-id",
        raw_vcard=(
            "BEGIN:VCARD\r\nVERSION:3.0\r\nUID:jane-id\r\nFN:Jane Doe\r\n"
            "N:Doe;Jane;;;\r\nEMAIL;TYPE=HOME:old@example.com\r\n"
            "TEL;TYPE=CELL:+1 555 0102\r\nNOTE:preserve me\r\nEND:VCARD\r\n"
        ),
    )

    updated = source.update_contact(resource, ContactPatch(emails=("new@example.com",)))

    put = requests[-1]
    assert put.headers["if-match"] == '"version-1"'
    assert b"EMAIL:new@example.com\r\n" in put.content
    assert b"old@example.com" not in put.content
    assert b"FN:Jane Doe\r\n" in put.content
    assert b"TEL;TYPE=CELL:+1 555 0102\r\n" in put.content
    assert b"NOTE:preserve me\r\n" in put.content
    assert updated.etag == '"version-2"'


def test_carddav_delete_uses_etag_and_rejects_stale_contact() -> None:
    delete_status = [204]
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PROPFIND":
            return _addressbook_discovery_response()
        assert request.method == "DELETE"
        return httpx.Response(delete_status[0])

    source = _carddav_source(handler)
    resource = ContactResource(
        contact=Contact(name="Jane Doe"),
        href="https://baikal.example/addressbooks/user/default/jane.vcf",
        etag='"version-1"',
    )

    source.delete_contact(resource)
    assert requests[-1].headers["if-match"] == '"version-1"'

    delete_status[0] = 412
    with pytest.raises(RuntimeError, match="changed"):
        source.delete_contact(resource)


def test_private_contacts_server_supports_create_update_delete() -> None:
    references = iter(("created-ref", "listed-ref"))
    server = PrivateContactsMCPServer(
        contacts=[],
        contact_reference_factory=lambda: next(references),
    )

    created = server.call_tool(
        "contacts_create",
        {
            "name": "Jane Doe",
            "emails": ["jane@example.com"],
            "phones": ["+1 555 0102"],
        },
    )
    assert created is not None
    assert created["structuredContent"] == {
        "status": "created",
        "contact_ref": "created-ref",
    }

    updated = server.call_tool("contacts_update", {"contact_ref": "created-ref", "emails": []})
    assert updated is not None
    assert updated["structuredContent"]["status"] == "updated"

    listed = server.call_tool("contacts_list", {})
    assert listed is not None
    assert listed["structuredContent"]["contacts"][0]["available_fields"] == ["phones"]

    deleted = server.call_tool("contacts_delete", {"contact_ref": "created-ref"})
    assert deleted is not None
    assert deleted["structuredContent"] == {"status": "deleted"}


def _addressbook_discovery_response() -> httpx.Response:
    return httpx.Response(
        207,
        content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>/addressbooks/user/default/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection /><card:addressbook /></d:resourcetype>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
    )


def _carddav_source(handler: object) -> CardDAVContactSource:
    return CardDAVContactSource(
        addressbook_url="https://baikal.example/addressbooks/user/",
        username="user",
        password="password",
        auth_mode="basic",
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )
