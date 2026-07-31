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
DEFAULT_ICS_STALE_IF_ERROR_SECONDS = 86_400.0
DEFAULT_ICS_TIMEOUT_SECONDS = 15.0
MAX_ICS_RESPONSE_BYTES = 5_000_000
MAX_ICS_EXPANDED_OCCURRENCES = 10_000


class ICSSubscriptionCalendarSource:
    def __init__(
        self,
        *,
        url: str,
        label: str,
        cache_ttl_seconds: float = DEFAULT_ICS_CACHE_TTL_SECONDS,
        stale_if_error_seconds: float = DEFAULT_ICS_STALE_IF_ERROR_SECONDS,
        timeout_seconds: float = DEFAULT_ICS_TIMEOUT_SECONDS,
        max_response_bytes: int = MAX_ICS_RESPONSE_BYTES,
        max_expanded_occurrences: int = MAX_ICS_EXPANDED_OCCURRENCES,
        clock: Callable[[], float] = time.monotonic,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        if (
            cache_ttl_seconds <= 0
            or stale_if_error_seconds < cache_ttl_seconds
            or timeout_seconds <= 0
            or max_response_bytes <= 0
            or max_expanded_occurrences <= 0
        ):
            raise ValueError(
                "ICS subscription cache, stale window, timeout, response limit, and expansion "
                "limit are invalid"
            )
        self._url = url
        self._label = label
        self._cache_ttl = cache_ttl_seconds
        self._stale_if_error = stale_if_error_seconds
        self._timeout = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._max_expanded_occurrences = max_expanded_occurrences
        self._clock = clock
        self._transport = transport
        self._lock = threading.RLock()
        self._cached_calendar: ICalendar | None = None
        self._cached_at = 0.0
        self._refresh_after = 0.0
        self._etag: str | None = None
        self._last_modified: str | None = None
        self._health = "configured"
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
            _validate_expansion_bound(
                parsed,
                start=start,
                end=end,
                max_occurrences=self._max_expanded_occurrences,
            )
            components = recurring_ical_events.of(parsed).between(start, end)
            if len(components) > self._max_expanded_occurrences:
                raise RuntimeError("ICS subscription recurrence expansion limit exceeded")
        except RuntimeError:
            raise
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
            if not resource.event.transparent
            and not resource.event.cancelled
            and _has_positive_duration(resource.event)
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

    def health_status(self) -> str:
        with self._lock:
            return self._health

    def _require_calendar(self, calendar: Calendar) -> None:
        if calendar.href != self._calendar.href:
            raise PermissionError("Unknown calendar")

    def _load_calendar(self) -> ICalendar:
        now = self._clock()
        with self._lock:
            if (
                self._cached_calendar is not None
                and now < self._refresh_after
                and (self._health != "stale" or now - self._cached_at <= self._stale_if_error)
            ):
                return self._cached_calendar
            headers = {"Accept": "text/calendar"}
            if self._etag:
                headers["If-None-Match"] = self._etag
            if self._last_modified:
                headers["If-Modified-Since"] = self._last_modified
            try:
                content, response_headers, not_modified = self._fetch(headers)
                if not_modified:
                    if self._cached_calendar is None:
                        raise RuntimeError(
                            "ICS subscription returned not-modified without cached data"
                        )
                    parsed = self._cached_calendar
                else:
                    try:
                        parsed = ICalendar.from_ical(content.decode("utf-8-sig"))
                    except Exception as exc:
                        raise RuntimeError(
                            "ICS subscription returned invalid calendar data"
                        ) from exc
                    if not isinstance(parsed, ICalendar):
                        raise RuntimeError("ICS subscription returned invalid calendar data")
                    self._etag = response_headers.get("etag")
                    self._last_modified = response_headers.get("last-modified")
            except RuntimeError:
                if (
                    self._cached_calendar is not None
                    and now - self._cached_at <= self._stale_if_error
                ):
                    self._health = "stale"
                    self._refresh_after = now + min(self._cache_ttl, 60.0)
                    return self._cached_calendar
                self._health = "unavailable"
                raise
            self._cached_calendar = parsed
            self._cached_at = now
            self._refresh_after = now + self._cache_ttl
            self._health = "healthy"
            return parsed

    def _fetch(self, headers: dict[str, str]) -> tuple[bytes, httpx.Headers, bool]:
        with httpx.Client(
            timeout=self._timeout,
            follow_redirects=False,
            transport=self._transport,
        ) as client:
            try:
                with client.stream("GET", self._url, headers=headers) as response:
                    if response.status_code == 304:
                        return b"", response.headers, True
                    response.raise_for_status()
                    content = bytearray()
                    for chunk in response.iter_bytes():
                        content.extend(chunk)
                        if len(content) > self._max_response_bytes:
                            raise RuntimeError("ICS subscription response is too large")
            except httpx.HTTPError as exc:
                raise RuntimeError("ICS subscription fetch failed") from exc
        return bytes(content), response.headers, False


def _validate_expansion_bound(
    calendar: ICalendar, *, start: datetime, end: datetime, max_occurrences: int
) -> None:
    """Reject recurrence sets that can exceed the configured bounded expansion."""
    estimated = 0
    for component in calendar.walk("VEVENT"):
        rule = component.get("RRULE")
        if rule is None or component.get("RECURRENCE-ID") is not None:
            continue
        frequency_values = rule.get("FREQ", [])
        frequency = str(frequency_values[0]).upper() if frequency_values else ""
        interval_values = rule.get("INTERVAL", [1])
        interval = max(1, int(interval_values[0]))
        estimate_unit_seconds = {
            "SECONDLY": 1.0,
            "MINUTELY": 60.0,
            "HOURLY": 3_600.0,
            "DAILY": 86_400.0,
            "WEEKLY": 604_800.0,
            "MONTHLY": 2_419_200.0,
            "YEARLY": 31_536_000.0,
        }.get(frequency)
        if estimate_unit_seconds is None:
            raise RuntimeError("ICS subscription uses an unsupported recurrence frequency")
        window_start, window_end = _recurrence_window(
            component,
            rule,
            start=start,
            end=end,
            frequency=frequency,
            interval=interval,
        )
        if window_end <= window_start:
            continue
        span_seconds = (window_end - window_start).total_seconds()
        occurrences = int(span_seconds / (estimate_unit_seconds * interval)) + 2
        if frequency == "WEEKLY":
            occurrences *= max(1, len(rule.get("BYDAY", [])))
        elif frequency == "MONTHLY":
            occurrences *= max(
                1,
                len(rule.get("BYMONTHDAY", [])),
                len(rule.get("BYDAY", [])) * 5,
            )
        elif frequency == "YEARLY":
            occurrences *= max(
                1,
                len(rule.get("BYYEARDAY", [])),
                len(rule.get("BYMONTHDAY", [])) * max(1, len(rule.get("BYMONTH", []))),
                len(rule.get("BYDAY", [])) * 53,
            )
        frequency_rank = {
            "SECONDLY": 0,
            "MINUTELY": 1,
            "HOURLY": 2,
            "DAILY": 3,
            "WEEKLY": 4,
            "MONTHLY": 5,
            "YEARLY": 6,
        }[frequency]
        for key, rank in (("BYSECOND", 1), ("BYMINUTE", 2), ("BYHOUR", 3)):
            values = rule.get(key, [])
            if values and frequency_rank >= rank:
                occurrences *= len(values)
        count_values = rule.get("COUNT", [])
        if count_values:
            occurrences = min(occurrences, int(count_values[0]))
        estimated += occurrences + _rdate_count(component.get("RDATE"))
        if estimated > max_occurrences:
            raise RuntimeError("ICS subscription recurrence expansion limit exceeded")


def _recurrence_window(
    component: Any,
    rule: Any,
    *,
    start: datetime,
    end: datetime,
    frequency: str,
    interval: int,
) -> tuple[datetime, datetime]:
    series_start = _utc_temporal(component.decoded("DTSTART"))
    window_start = max(start.astimezone(timezone.utc), series_start)
    window_end = end.astimezone(timezone.utc)
    until_values = rule.get("UNTIL", [])
    if until_values:
        window_end = min(window_end, _utc_temporal(until_values[0]))
    count_values = rule.get("COUNT", [])
    if count_values:
        end_unit_seconds = {
            "SECONDLY": 1.0,
            "MINUTELY": 60.0,
            "HOURLY": 3_600.0,
            "DAILY": 86_400.0,
            "WEEKLY": 604_800.0,
            "MONTHLY": 2_678_400.0,
            "YEARLY": 31_622_400.0,
        }[frequency]
        count_end = series_start + timedelta(
            seconds=end_unit_seconds * interval * int(count_values[0])
        )
        window_end = min(window_end, count_end)
    return window_start, window_end


def _utc_temporal(value: date | datetime) -> datetime:
    if not isinstance(value, datetime):
        return datetime.combine(value, datetime_time.min, timezone.utc)
    if value.tzinfo is None:
        return value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _rdate_count(value: Any) -> int:
    if value is None:
        return 0
    values = value if isinstance(value, list) else [value]
    return sum(len(getattr(item, "dts", ())) for item in values)


def _has_positive_duration(event: Event) -> bool:
    try:
        if event.all_day:
            return date.fromisoformat(event.end) > date.fromisoformat(event.start)
        start = datetime.fromisoformat(event.start.replace("Z", "+00:00"))
        end = datetime.fromisoformat(event.end.replace("Z", "+00:00"))
        if start.tzinfo is None:
            start = start.replace(tzinfo=timezone.utc)
        if end.tzinfo is None:
            end = end.replace(tzinfo=timezone.utc)
        return end.astimezone(timezone.utc) > start.astimezone(timezone.utc)
    except ValueError:
        return False


def _event_from_component(component: Any) -> tuple[Event, datetime]:
    raw_start = component.decoded("DTSTART")
    raw_end = component.decoded("DTEND", None)
    duration = component.decoded("DURATION", None)
    timezone_name: str | None = None
    dtstart = component.get("DTSTART")
    if dtstart is not None:
        raw_timezone = dtstart.params.get("TZID")
        if raw_timezone:
            timezone_name = str(raw_timezone)
    all_day = isinstance(raw_start, date) and not isinstance(raw_start, datetime)
    start, start_sort = _temporal_value(raw_start, preserve_local=timezone_name is not None)
    if raw_end is None:
        if isinstance(duration, timedelta):
            raw_end = raw_start + duration
        elif all_day:
            raw_end = raw_start + timedelta(days=1)
        else:
            raw_end = raw_start
    end, _ = _temporal_value(raw_end, preserve_local=timezone_name is not None)
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


def _temporal_value(value: Any, *, preserve_local: bool) -> tuple[str, datetime]:
    if isinstance(value, datetime):
        sortable = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        serialized = value.replace(tzinfo=None).isoformat() if preserve_local else value.isoformat()
        return serialized, sortable.astimezone(timezone.utc)
    if isinstance(value, date):
        return value.isoformat(), datetime.combine(value, datetime_time.min, timezone.utc)
    raise TypeError("Unsupported ICS event date-time")
