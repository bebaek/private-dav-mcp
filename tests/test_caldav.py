from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from private_dav_mcp.caldav import (
    CalDAVCalendarSource,
    Calendar,
    Event,
    EventPatch,
    PrivateCalendarMCPServer,
    discover_caldav_home_urls,
    parse_caldav_calendars,
    parse_caldav_event_resources,
    parse_icalendar,
    patch_icalendar,
    serialize_icalendar,
)
from private_dav_mcp.protocol import PRIVATE_VALUES_META_KEY


def test_parse_caldav_calendars_protects_origin_and_reads_metadata() -> None:
    calendars = parse_caldav_calendars(
        b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav"
 xmlns:ical="http://apple.com/ns/ical/">
  <d:response><d:href>/dav.php/calendars/user/personal/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
    <d:displayname>Personal</d:displayname><ical:calendar-color>#00AAFFFF</ical:calendar-color>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
        base_url="https://baikal.example/dav.php/calendars/user/",
    )

    assert calendars == [
        Calendar(
            name="Personal",
            href="https://baikal.example/dav.php/calendars/user/personal/",
            color="#00AAFFFF",
        )
    ]

    with pytest.raises(RuntimeError, match="cross-origin"):
        parse_caldav_calendars(
            b"""<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
<d:response><d:href>https://attacker.example/calendar/</d:href><d:propstat><d:prop>
<d:resourcetype><cal:calendar/></d:resourcetype></d:prop></d:propstat></d:response>
</d:multistatus>""",
            base_url="https://baikal.example/dav.php/calendars/user/",
        )


def test_caldav_source_discovers_principal_then_calendar_home() -> None:
    requests: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.url.path == "/dav.php":
            return httpx.Response(
                207,
                content=b"""<d:multistatus xmlns:d="DAV:"><d:response><d:propstat><d:prop>
<d:current-user-principal><d:href>/dav.php/principals/user/</d:href></d:current-user-principal>
</d:prop></d:propstat></d:response></d:multistatus>""",
            )
        if request.url.path == "/dav.php/principals/user/":
            return httpx.Response(
                207,
                content=b"""<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
<d:response><d:propstat><d:prop><cal:calendar-home-set>
<d:href>/dav.php/calendars/user/</d:href></cal:calendar-home-set>
</d:prop></d:propstat></d:response></d:multistatus>""",
            )
        assert request.url.path == "/dav.php/calendars/user/"
        return _calendar_discovery_response()

    source = CalDAVCalendarSource(
        calendar_url="https://baikal.example/dav.php",
        username="user",
        password="password",
        auth_mode="basic",
        transport=httpx.MockTransport(handler),
    )

    calendars = source.list_calendars()

    assert calendars[0].name == "Personal"
    assert [request.headers["depth"] for request in requests] == ["0", "0", "1"]
    assert b"current-user-principal" in requests[0].content
    assert b"calendar-home-set" in requests[1].content


def test_discover_caldav_home_urls_rejects_cross_origin() -> None:
    with pytest.raises(RuntimeError, match="cross-origin"):
        discover_caldav_home_urls(
            b"""<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
<d:response><d:propstat><d:prop><cal:calendar-home-set>
<d:href>https://attacker.example/calendars/</d:href></cal:calendar-home-set>
</d:prop></d:propstat></d:response></d:multistatus>""",
            base_url="https://baikal.example/dav.php",
        )


def test_parse_icalendar_handles_timezone_all_day_private_fields_and_recurrence() -> None:
    timed = parse_icalendar(
        "\r\n".join(
            [
                "BEGIN:VCALENDAR",
                "BEGIN:VEVENT",
                "UID:event-1",
                "DTSTART;TZID=America/New_York:20260301T090000",
                "DTEND;TZID=America/New_York:20260301T100000",
                "SUMMARY:Planning\\, private",
                "DESCRIPTION:Line one\\nLine two",
                "LOCATION:Room 1",
                "ATTENDEE;CN=Alice:mailto:alice@example.com",
                "RRULE:FREQ=WEEKLY",
                "END:VEVENT",
                "END:VCALENDAR",
            ]
        )
    )

    assert timed == Event(
        summary="Planning, private",
        start="2026-03-01T09:00:00",
        end="2026-03-01T10:00:00",
        description="Line one\nLine two",
        location="Room 1",
        attendees=("alice@example.com",),
        timezone="America/New_York",
        recurring=True,
    )

    all_day = parse_icalendar(
        "BEGIN:VCALENDAR\nBEGIN:VEVENT\nDTSTART;VALUE=DATE:20260301\n"
        "DTEND;VALUE=DATE:20260302\nSUMMARY:Away\nEND:VEVENT\nEND:VCALENDAR\n"
    )
    assert all_day is not None
    assert all_day.start == "2026-03-01"
    assert all_day.end == "2026-03-02"
    assert all_day.all_day is True


def test_parse_caldav_event_resources_keeps_etag_href_uid_and_raw_payload() -> None:
    resources = parse_caldav_event_resources(
        b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response><d:href>/dav.php/calendars/user/personal/event.ics</d:href>
  <d:propstat><d:prop><d:getetag>"v1"</d:getetag><cal:calendar-data><![CDATA[
BEGIN:VCALENDAR
BEGIN:VEVENT
UID:event-id
DTSTART:20260301T090000Z
DTEND:20260301T100000Z
SUMMARY:Planning
X-CUSTOM:preserve me
END:VEVENT
END:VCALENDAR
]]></cal:calendar-data></d:prop></d:propstat></d:response>
</d:multistatus>""",
        calendar_url="https://baikal.example/dav.php/calendars/user/personal/",
    )

    assert len(resources) == 1
    resource = resources[0]
    assert resource.event.summary == "Planning"
    assert resource.href == "https://baikal.example/dav.php/calendars/user/personal/event.ics"
    assert resource.etag == '"v1"'
    assert resource.uid == "event-id"
    assert resource.raw_icalendar is not None and "X-CUSTOM:preserve me" in resource.raw_icalendar


def test_serialize_and_patch_icalendar_preserve_unknown_and_recurring_properties() -> None:
    event = Event(
        summary="Planning",
        start="2026-03-01T09:00:00-05:00",
        end="2026-03-01T10:00:00-05:00",
        description="Private, notes",
        attendees=("alice@example.com",),
    )
    payload = serialize_icalendar(event, uid="event-id")

    assert "UID:event-id\r\n" in payload
    assert "DTSTART:20260301T140000Z\r\n" in payload
    assert "DESCRIPTION:Private\\, notes\r\n" in payload
    assert "ATTENDEE:mailto:alice@example.com\r\n" in payload

    original = payload.replace("END:VEVENT", "RRULE:FREQ=WEEKLY\r\nX-CUSTOM:keep\r\nEND:VEVENT")
    patched = patch_icalendar(
        original,
        Event(**{**event.__dict__, "summary": "Updated"}),
        patch=EventPatch(summary="Updated"),
    )
    assert "SUMMARY:Updated\r\n" in patched
    assert "SUMMARY:Planning" not in patched
    assert "RRULE:FREQ=WEEKLY\r\n" in patched
    assert "X-CUSTOM:keep\r\n" in patched


def test_caldav_source_uses_bounded_report_and_etag_writes() -> None:
    requests: list[httpx.Request] = []
    write_status = {"PUT": 201, "DELETE": 204}

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        if request.method == "PROPFIND":
            return _calendar_discovery_response()
        if request.method == "REPORT":
            return httpx.Response(207, content=_event_report_payload())
        return httpx.Response(write_status[request.method], headers={"etag": '"new"'})

    source = _source(handler)
    calendars = source.list_calendars()
    start = datetime(2026, 3, 1, tzinfo=timezone.utc)
    end = datetime(2026, 3, 2, tzinfo=timezone.utc)
    resources, truncated = source.list_event_resources(calendars[0], start=start, end=end, limit=10)

    assert truncated is False
    assert resources[0].event.summary == "Planning"
    report = next(request for request in requests if request.method == "REPORT")
    assert b' start="20260301T000000Z" end="20260302T000000Z"' in report.content
    assert b"calendar-query" in report.content

    created = source.create_event(
        calendars[0],
        Event("Created", "2026-03-01T09:00:00Z", "2026-03-01T10:00:00Z"),
    )
    create_request = requests[-1]
    assert create_request.headers["if-none-match"] == "*"
    assert create_request.url.path.endswith(".ics")
    assert created.etag == '"new"'

    resource = resources[0]
    updated = source.update_event(resource, EventPatch(summary="Updated"))
    update_request = requests[-1]
    assert update_request.headers["if-match"] == '"v1"'
    assert b"SUMMARY:Updated\r\n" in update_request.content
    assert b"X-CUSTOM:keep\r\n" in update_request.content
    assert updated.etag == '"new"'

    source.delete_event(resource)
    assert requests[-1].headers["if-match"] == '"v1"'

    write_status["DELETE"] = 412
    with pytest.raises(RuntimeError, match="changed"):
        source.delete_event(resource)


def test_private_calendar_mcp_protects_reads_and_supports_crud() -> None:
    references = iter(("calendar-ref", "event-ref", "created-ref"))
    private_references = iter(
        ("calendar-name", "event-summary", "description", "location", "attendee")
    )
    server = PrivateCalendarMCPServer(
        events=[
            Event(
                summary="Private planning",
                start="2026-03-01T09:00:00Z",
                end="2026-03-01T10:00:00Z",
                description="Discuss launch",
                location="Secret room",
                attendees=("alice@example.com",),
            )
        ],
        reference_factory=lambda: next(references),
        private_reference_factory=lambda: next(private_references),
    )

    calendars = _call(server, "calendars_list", {})
    assert calendars["structuredContent"] == {
        "calendars": [
            {
                "calendar_ref": "calendar-ref",
                "name": "{{pii:calendar:calendar-name}}",
                "color": None,
            }
        ]
    }
    assert calendars["_meta"][PRIVATE_VALUES_META_KEY] == {"calendar-name": "Personal"}

    listed = _call(
        server,
        "events_list",
        {
            "calendar_ref": "calendar-ref",
            "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-02T00:00:00Z",
        },
    )
    listed_event = listed["structuredContent"]["events"][0]
    assert listed_event["event_ref"] == "event-ref"
    assert listed_event["summary"] == "{{pii:event:event-summary}}"
    assert listed_event["available_fields"] == ["description", "location", "attendees"]
    assert "Private planning" not in str(listed["structuredContent"])

    fetched = _call(
        server,
        "events_get",
        {"event_ref": "event-ref", "fields": ["description", "location", "attendees"]},
    )
    assert fetched["structuredContent"] == {
        "event_ref": "event-ref",
        "description": "{{pii:description:description}}",
        "location": "{{pii:location:location}}",
        "attendees": ["{{pii:email:attendee}}"],
    }
    assert fetched["_meta"][PRIVATE_VALUES_META_KEY] == {
        "description": "Discuss launch",
        "location": "Secret room",
        "attendee": "alice@example.com",
    }

    created = _call(
        server,
        "events_create",
        {
            "calendar_ref": "calendar-ref",
            "summary": "New event",
            "start": "2026-03-01T11:00:00Z",
            "end": "2026-03-01T12:00:00Z",
        },
    )
    assert created["structuredContent"] == {"status": "created", "event_ref": "created-ref"}

    updated = _call(
        server,
        "events_update",
        {"event_ref": "created-ref", "description": "Changed"},
    )
    assert updated["structuredContent"]["status"] == "updated"

    deleted = _call(server, "events_delete", {"event_ref": "created-ref"})
    assert deleted["structuredContent"] == {"status": "deleted"}


def test_private_calendar_mcp_rejects_unbounded_queries_and_recurring_updates() -> None:
    references = iter(("calendar-ref", "event-ref"))
    server = PrivateCalendarMCPServer(
        events=[
            Event(
                "Weekly",
                "2026-03-01T09:00:00Z",
                "2026-03-01T10:00:00Z",
                recurring=True,
            )
        ],
        reference_factory=lambda: next(references),
    )
    _call(server, "calendars_list", {})

    missing_end = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "events_list",
                "arguments": {"calendar_ref": "calendar-ref", "start": "2026-03-01T00:00:00Z"},
            },
        }
    )
    assert missing_end is not None
    assert missing_end["error"]["code"] == -32602

    excessive_range = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "events_list",
                "arguments": {
                    "calendar_ref": "calendar-ref",
                    "start": "2026-01-01T00:00:00Z",
                    "end": "2028-01-01T00:00:00Z",
                },
            },
        }
    )
    assert excessive_range is not None
    assert "must not exceed" in excessive_range["error"]["message"]

    _call(
        server,
        "events_list",
        {
            "calendar_ref": "calendar-ref",
            "start": "2026-03-01T00:00:00Z",
            "end": "2026-03-02T00:00:00Z",
        },
    )
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "events_update",
                "arguments": {"event_ref": "event-ref", "summary": "Changed"},
            },
        }
    )
    assert response is not None
    assert response["error"]["code"] == -32602
    assert "Recurring" in response["error"]["message"]


def _call(server: PrivateCalendarMCPServer, name: str, arguments: dict[str, object]) -> dict:
    response = server.handle(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
    )
    assert response is not None and "result" in response, response
    return response["result"]


def _calendar_discovery_response() -> httpx.Response:
    return httpx.Response(
        207,
        content=b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response><d:href>/dav.php/calendars/user/personal/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
    <d:displayname>Personal</d:displayname>
  </d:prop></d:propstat></d:response>
</d:multistatus>""",
    )


def _event_report_payload() -> bytes:
    return b"""<?xml version="1.0"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response><d:href>/dav.php/calendars/user/personal/event.ics</d:href><d:propstat><d:prop>
    <d:getetag>"v1"</d:getetag><cal:calendar-data><![CDATA[
BEGIN:VCALENDAR
BEGIN:VEVENT
UID:event-id
DTSTART:20260301T090000Z
DTEND:20260301T100000Z
SUMMARY:Planning
X-CUSTOM:keep
END:VEVENT
END:VCALENDAR
]]></cal:calendar-data>
  </d:prop></d:propstat></d:response>
</d:multistatus>"""


def _source(handler: object) -> CalDAVCalendarSource:
    return CalDAVCalendarSource(
        calendar_url="https://baikal.example/dav.php/calendars/user/",
        username="user",
        password="password",
        auth_mode="basic",
        transport=httpx.MockTransport(handler),  # type: ignore[arg-type]
    )
