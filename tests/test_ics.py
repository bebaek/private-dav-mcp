from __future__ import annotations

from datetime import datetime, timezone

import httpx
import pytest

from private_dav_mcp.ics import ICSSubscriptionCalendarSource

ICS = b"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Private DAV Test//EN
BEGIN:VEVENT
UID:recurring-1
DTSTAMP:20260701T000000Z
DTSTART:20260801T140000Z
DTEND:20260801T150000Z
RRULE:FREQ=DAILY;COUNT=3
SUMMARY:Recurring private event
DESCRIPTION:Sensitive description
LOCATION:Private location
ATTENDEE:mailto:person@example.com
END:VEVENT
BEGIN:VEVENT
UID:all-day-1
DTSTAMP:20260701T000000Z
DTSTART;VALUE=DATE:20260805
DTEND;VALUE=DATE:20260806
SUMMARY:Private all day event
TRANSP:TRANSPARENT
END:VEVENT
BEGIN:VEVENT
UID:no-end-1
DTSTAMP:20260701T000000Z
DTSTART:20260806T120000Z
SUMMARY:Zero duration informational event
END:VEVENT
BEGIN:VEVENT
UID:timezone-1
DTSTAMP:20260701T000000Z
DTSTART;TZID=America/New_York:20260806T090000
DTEND;TZID=America/New_York:20260806T100000
SUMMARY:Timezone event
END:VEVENT
END:VCALENDAR
"""


ICS_SECONDLY = b"""BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:pathological-1
DTSTART:20260801T000000Z
DTEND:20260801T000001Z
RRULE:FREQ=SECONDLY
SUMMARY:Pathological event
END:VEVENT
END:VCALENDAR
"""


def test_ics_subscription_fetches_caches_and_expands_events() -> None:
    requests = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal requests
        requests += 1
        assert request.url == "https://calendar.example/public/basic.ics"
        assert request.headers["accept"] == "text/calendar"
        return httpx.Response(200, content=ICS, headers={"content-type": "text/calendar"})

    now = [100.0]
    source = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public/basic.ics",
        label="Public events",
        cache_ttl_seconds=300,
        clock=lambda: now[0],
        transport=httpx.MockTransport(handler),
    )

    calendars = source.list_calendars()
    resources, truncated = source.list_event_resources(
        calendars[0],
        start=datetime(2026, 8, 1, tzinfo=timezone.utc),
        end=datetime(2026, 8, 7, tzinfo=timezone.utc),
        limit=20,
    )

    assert requests == 1
    assert truncated is False
    assert len(resources) == 6
    assert [resource.event.summary for resource in resources[:3]] == [
        "Recurring private event",
        "Recurring private event",
        "Recurring private event",
    ]
    assert resources[0].event.description == "Sensitive description"
    assert resources[0].event.location == "Private location"
    assert resources[0].event.attendees == ("person@example.com",)
    assert resources[3].event.all_day is True
    assert resources[3].event.transparent is True
    assert resources[4].event.start == resources[4].event.end
    assert resources[5].event.timezone == "America/New_York"
    assert resources[5].event.start == "2026-08-06T09:00:00"

    busy, busy_truncated = source.list_busy_events(
        calendars[0],
        start=datetime(2026, 8, 1, tzinfo=timezone.utc),
        end=datetime(2026, 8, 7, tzinfo=timezone.utc),
        limit=20,
    )
    assert requests == 1
    assert busy_truncated is False
    assert len(busy) == 4

    now[0] = 401.0
    source.check_ready()
    assert requests == 2


def test_ics_subscription_revalidates_and_serves_bounded_stale_cache() -> None:
    now = [100.0]
    requests: list[httpx.Request] = []
    responses = iter(
        (
            httpx.Response(
                200,
                content=ICS,
                headers={
                    "etag": '"feed-v1"',
                    "last-modified": "Wed, 01 Jul 2026 00:00:00 GMT",
                },
            ),
            httpx.Response(503),
            httpx.Response(304),
            httpx.Response(503),
            httpx.Response(503),
        )
    )

    def handler(request: httpx.Request) -> httpx.Response:
        requests.append(request)
        return next(responses)

    source = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public/basic.ics",
        label="Public events",
        cache_ttl_seconds=300,
        stale_if_error_seconds=600,
        clock=lambda: now[0],
        transport=httpx.MockTransport(handler),
    )

    source.check_ready()
    assert source.health_status() == "healthy"
    now[0] = 401.0
    source.check_ready()
    assert source.health_status() == "stale"
    assert len(requests) == 2
    assert requests[1].headers["if-none-match"] == '"feed-v1"'
    assert requests[1].headers["if-modified-since"] == "Wed, 01 Jul 2026 00:00:00 GMT"

    now[0] = 450.0
    source.check_ready()
    assert len(requests) == 2
    assert source.health_status() == "stale"

    now[0] = 462.0
    source.check_ready()
    assert len(requests) == 3
    assert source.health_status() == "healthy"

    now[0] = 1_050.0
    source.check_ready()
    assert source.health_status() == "stale"

    now[0] = 1_063.0
    with pytest.raises(RuntimeError, match="fetch failed"):
        source.check_ready()
    assert source.health_status() == "unavailable"


def test_ics_subscription_rejects_pathological_recurrence_expansion() -> None:
    source = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public/basic.ics",
        label="Public events",
        max_expanded_occurrences=100,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=ICS_SECONDLY)),
    )
    calendar = source.list_calendars()[0]

    with pytest.raises(RuntimeError, match="expansion limit exceeded"):
        source.list_event_resources(
            calendar,
            start=datetime(2026, 8, 1, tzinfo=timezone.utc),
            end=datetime(2026, 8, 2, tzinfo=timezone.utc),
            limit=20,
        )


def test_ics_subscription_is_read_only_and_bounds_response_size() -> None:
    source = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public/basic.ics",
        label="Public events",
        max_response_bytes=10,
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=ICS)),
    )
    with pytest.raises(RuntimeError, match="too large"):
        source.check_ready()

    readable = ICSSubscriptionCalendarSource(
        url="https://calendar.example/public/basic.ics",
        label="Public events",
        transport=httpx.MockTransport(lambda _request: httpx.Response(200, content=ICS)),
    )
    calendar = readable.list_calendars()[0]
    with pytest.raises(PermissionError, match="read-only"):
        readable.create_event(calendar, None)  # type: ignore[arg-type]
