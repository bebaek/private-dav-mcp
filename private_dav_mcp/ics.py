from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from datetime import date, datetime, timedelta, timezone
from datetime import time as datetime_time
from typing import Any

import httpx
import recurring_ical_events
from icalendar import Calendar as ICalendar

from private_dav_mcp.caldav import Calendar, Event, EventPatch, EventResource

DEFAULT_ICS_CACHE_TTL_SECONDS = 300.0
DEFAULT_ICS_TIMEOUT_SECONDS = 15.0
MAX_ICS_RESPONSE_BYTES = 5_000_000


class ICSSubscriptionCalendarSource:
    def __init__(
        self,
        *,
        url: str,
        label: str,
        cache_ttl_seconds: float = DEFAULT_ICS_CACHE_TTL_SECONDS,
        timeout_seconds: float = DEFAULT_ICS_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_ICS_RESPONSE_BYTES,
        clock: Callable[[], float] = time.monotonic,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if cache_ttl_seconds <= 0 or timeout_seconds <= 0 or max_response_bytes <= 0:
            raise ValueError("ICS subscription cache, timeout, and response limit must be positive")
        self._url = url
        self._label = label
        self._cache_ttl = cache_ttl_seconds
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._clock = clock
        self._transport = transport
        self._lock = threading.RLock()
        self._cached_calendar: ICalendar | None = None
        self._cached_at = 0.0
        digest = hashlib.sha256(url.encode()).hexdigest()[:24]
        self._calendar = Calendar(name=label, href=f"ics-subscription://{digest}/")

    def list_calendars(self) -> list[Calendar]:
        self._load_calendar()
        return [self._calendar]

    def list_event_resources(
        self,
        calendar: Calendar,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[EventResource], bool]:
        self._require_calendar(calendar)
        parsed = self._load_calendar()
        try:
            components = recurring_ical_events.of(parsed).between(start, end)
        except Exception as exc:
            raise RuntimeError("ICS subscription recurrence expansion failed") from exc
        resources_with_start: list[tuple[datetime, EventResource]] = []
        for component in components:
            try:
                event, event_start = _event_from_component(component)
                uid = (
                    _component_text(component, "UID")
                    or hashlib.sha256(component.to_ical()).hexdigest()
                )
                occurrence_key = f"{uid}\0{event.start}"
                occurrence_id = hashlib.sha256(occurrence_key.encode()).hexdigest()[:32]
                resources_with_start.append(
                    (
                        event_start,
                        EventResource(
                            event=event,
                            calendar_href=self._calendar.href,
                            href=f"{self._calendar.href}{occurrence_id}.ics",
                            etag=None,
                            uid=uid,
                            raw_icalendar=component.to_ical().decode(errors="replace"),
                        ),
                    )
                )
            except (TypeError, ValueError):
                continue
        resources_with_start.sort(key=lambda item: item[0])
        resources = [resource for _, resource in resources_with_start]
        return resources[:limit], len(resources) > limit

    def list_busy_events(
        self,
        calendar: Calendar,
        *,
        start: datetime,
        end: datetime,
        limit: int,
    ) -> tuple[list[Event], bool]:
        resources, truncated = self.list_event_resources(
            calendar,
            start=start,
            end=end,
            limit=limit,
        )
        return [
            resource.event
            for resource in resources
            if not resource.event.transparent and not resource.event.cancelled
        ], truncated

    def create_event(self, calendar: Calendar, event: Event) -> EventResource:
        _ = calendar, event
        raise PermissionError("ICS calendar subscriptions are read-only")

    def update_event(self, resource: EventResource, patch: EventPatch) -> EventResource:
        _ = resource, patch
        raise PermissionError("ICS calendar subscriptions are read-only")

    def delete_event(self, resource: EventResource) -> None:
        _ = resource
        raise PermissionError("ICS calendar subscriptions are read-only")

    def check_ready(self) -> None:
        self._load_calendar()

    def _require_calendar(self, calendar: Calendar) -> None:
        if calendar.href != self._calendar.href:
            raise PermissionError("Unknown calendar")

    def _load_calendar(self) -> ICalendar:
        now = self._clock()
        with self._lock:
            if self._cached_calendar is not None and now - self._cached_at < self._cache_ttl:
                return self._cached_calendar
        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            try:
                with client.stream(
                    "GET", self._url, headers={"Accept": "text/calendar"}
                ) as response:
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self._max_response_bytes:
                            raise RuntimeError("ICS subscription response is too large")
            except httpx.HTTPError as exc:
                raise RuntimeError("ICS subscription fetch failed") from exc
        try:
            parsed = ICalendar.from_ical(bytes(content).decode("utf-8-sig"))
        except Exception as exc:
            raise RuntimeError("ICS subscription returned invalid calendar data") from exc
        if not isinstance(parsed, ICalendar):
            raise RuntimeError("ICS subscription returned invalid calendar data")
        with self._lock:
            self._cached_calendar = parsed
            self._cached_at = now
        return parsed


def _event_from_component(component: Any) -> tuple[Event, datetime]:
    raw_start = component.decoded("DTSTART")
    raw_end = component.decoded("DTEND", None)
    duration = component.decoded("DURATION", None)
    all_day = isinstance(raw_start, date) and not isinstance(raw_start, datetime)
    start, start_sort = _temporal_value(raw_start)
    if raw_end is None:
        if isinstance(duration, timedelta):
            raw_end = raw_start + duration
        elif all_day:
            raw_end = raw_start + timedelta(days=1)
        else:
            raw_end = raw_start
    end, _ = _temporal_value(raw_end)
    timezone_name: str | None = None
    dtstart = component.get("DTSTART")
    if dtstart is not None:
        raw_timezone = dtstart.params.get("TZID")
        if raw_timezone:
            timezone_name = str(raw_timezone)
    raw_attendees = component.get("ATTENDEE") or []
    if not isinstance(raw_attendees, list):
        raw_attendees = [raw_attendees]
    attendees = tuple(
        str(value).removeprefix("mailto:").removeprefix("MAILTO:") for value in raw_attendees
    )
    event = Event(
        summary=_component_text(component, "SUMMARY"),
        start=start,
        end=end,
        description=_component_text(component, "DESCRIPTION"),
        location=_component_text(component, "LOCATION"),
        attendees=attendees,
        all_day=all_day,
        timezone=timezone_name,
        recurring=component.get("RRULE") is not None or component.get("RECURRENCE-ID") is not None,
        transparent=_component_text(component, "TRANSP").upper() == "TRANSPARENT",
        cancelled=_component_text(component, "STATUS").upper() == "CANCELLED",
    )
    return event, start_sort


def _component_text(component: Any, key: str) -> str:
    value = component.get(key)
    return "" if value is None else str(value)


def _temporal_value(value: Any) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        sortable = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return value.isoformat(), sortable.astimezone(timezone.utc)
    if isinstance(value, date):
        return value.isoformat(), datetime.combine(value, datetime_time.min, timezone.utc)
    raise TypeError("Unsupported ICS event date-time")
