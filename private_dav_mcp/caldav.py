from __future__ import annotations

import argparse
import os
import secrets
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import date, datetime, timezone
from typing import Any, Protocol
from urllib.parse import quote, urljoin, urlsplit
from uuid import uuid4
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

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
    validate_same_origin_url,
    xml_headers,
)

DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8768
DEFAULT_EVENT_LIMIT = 25
MAX_EVENT_LIMIT = 100
DEFAULT_FREE_BUSY_LIMIT = 100
MAX_FREE_BUSY_LIMIT = 500
MAX_EVENT_QUERY_DAYS = 366
DEFAULT_REFERENCE_TTL_SECONDS = 1800.0
MAX_REFERENCES = 1000
MAX_CALDAV_RESPONSE_BYTES = 10_000_000
MAX_PRIVATE_FIELD_CHARS = 10_000
MAX_ATTENDEES = 100
CALDAV_URL_ENV = "MINIGENT_CALDAV_URL"
CALDAV_USERNAME_ENV = "MINIGENT_CALDAV_USERNAME"
CALDAV_PASSWORD_ENV = "MINIGENT_CALDAV_PASSWORD"
CALDAV_AUTH_MODE_ENV = "MINIGENT_CALDAV_AUTH_MODE"
DAV_NAMESPACE = "DAV:"
CALDAV_NAMESPACE = "urn:ietf:params:xml:ns:caldav"
APPLE_NAMESPACE = "http://apple.com/ns/ical/"

CALENDAR_PROPFIND_BODY = b"""<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav"
 xmlns:ical="http://apple.com/ns/ical/">
  <d:prop>
    <d:resourcetype />
    <d:displayname />
    <ical:calendar-color />
  </d:prop>
</d:propfind>
"""
CALDAV_HOME_PROPFIND_BODY = b"""<?xml version="1.0" encoding="utf-8" ?>
<d:propfind xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop>
    <d:current-user-principal />
    <cal:calendar-home-set />
  </d:prop>
</d:propfind>
"""


def _calendar_query_body(start: datetime, end: datetime, *, expand: bool = False) -> bytes:
    start_value = start.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    end_value = end.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    calendar_data = (
        f'<cal:calendar-data><cal:expand start="{start_value}" end="{end_value}" />'
        "</cal:calendar-data>"
        if expand
        else "<cal:calendar-data />"
    )
    return f"""<?xml version="1.0" encoding="utf-8" ?>
<cal:calendar-query xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:prop><d:getetag />{calendar_data}</d:prop>
  <cal:filter>
    <cal:comp-filter name="VCALENDAR">
      <cal:comp-filter name="VEVENT">
        <cal:time-range start="{start_value}" end="{end_value}" />
      </cal:comp-filter>
    </cal:comp-filter>
  </cal:filter>
</cal:calendar-query>
""".encode()


CALENDARS_LIST_TOOL = {
    "name": "calendars_list",
    "description": (
        "List calendars with opaque calendar_ref values and protected names. Treat references "
        "as internal identifiers and never display them to the user."
    ),
    "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
}

EVENTS_LIST_TOOL = {
    "name": "events_list",
    "description": (
        "List events in a calendar over a required bounded time range. Event summaries are "
        "protected placeholders. Use events_get for additional selected private fields."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "calendar_ref": {"type": "string", "minLength": 1},
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
            "limit": {"type": "integer", "minimum": 1, "maximum": MAX_EVENT_LIMIT},
        },
        "required": ["calendar_ref", "start", "end"],
        "additionalProperties": False,
    },
}

EVENTS_GET_TOOL = {
    "name": "events_get",
    "description": (
        "Retrieve selected protected fields for an event_ref returned by events_list. Preserve "
        "private placeholders exactly and never display event_ref."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "event_ref": {"type": "string", "minLength": 1},
            "fields": {
                "type": "array",
                "items": {
                    "type": "string",
                    "enum": ["description", "location", "attendees"],
                },
                "minItems": 1,
                "uniqueItems": True,
            },
        },
        "required": ["event_ref", "fields"],
        "additionalProperties": False,
    },
}


FREE_BUSY_TOOL = {
    "name": "free_busy",
    "description": (
        "Return merged UTC busy intervals for one calendar over a required bounded range. "
        "Event titles and other private fields are never returned."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "calendar_ref": {"type": "string", "minLength": 1},
            "start": {"type": "string", "format": "date-time"},
            "end": {"type": "string", "format": "date-time"},
            "limit": {
                "type": "integer",
                "minimum": 1,
                "maximum": MAX_FREE_BUSY_LIMIT,
            },
        },
        "required": ["calendar_ref", "start", "end"],
        "additionalProperties": False,
    },
    "outputSchema": {
        "type": "object",
        "properties": {
            "busy": {
                "type": "array",
                "items": {
                    "type": "object",
                    "properties": {
                        "start": {"type": "string", "format": "date-time"},
                        "end": {"type": "string", "format": "date-time"},
                    },
                    "required": ["start", "end"],
                    "additionalProperties": False,
                },
            },
            "truncated": {"type": "boolean"},
        },
        "required": ["busy", "truncated"],
        "additionalProperties": False,
    },
}


def _private_string_schema(*, allow_empty: bool = True) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "string", "maxLength": MAX_PRIVATE_FIELD_CHARS}
    if not allow_empty:
        schema["minLength"] = 1
    return schema


EVENTS_CREATE_TOOL = {
    "name": "events_create",
    "description": (
        "Create a non-recurring event after explicit user approval. Timed values must be RFC "
        "3339 with an offset; all-day values must be YYYY-MM-DD."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "calendar_ref": {"type": "string", "minLength": 1},
            "summary": _private_string_schema(allow_empty=False),
            "start": {"type": "string"},
            "end": {"type": "string"},
            "description": _private_string_schema(),
            "location": _private_string_schema(),
            "attendees": {
                "type": "array",
                "items": {"type": "string", "format": "email"},
                "maxItems": MAX_ATTENDEES,
                "uniqueItems": True,
            },
        },
        "required": ["calendar_ref", "summary", "start", "end"],
        "additionalProperties": False,
    },
}

EVENTS_UPDATE_TOOL = {
    "name": "events_update",
    "description": (
        "Update selected fields of an event. Omitted fields remain unchanged and an empty "
        "description, location, or attendee list clears that field. For an event with a timezone, "
        "change start and end together using local date-times without offsets; its TZID is "
        "preserved. For a recurring event, set scope to series; recurring time changes are not "
        "supported. Requires explicit approval."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "event_ref": {"type": "string", "minLength": 1},
            "scope": {
                "type": "string",
                "enum": ["series"],
                "description": "Required when updating a recurring event's whole series.",
            },
            "summary": _private_string_schema(allow_empty=False),
            "start": {"type": "string"},
            "end": {"type": "string"},
            "description": _private_string_schema(),
            "location": _private_string_schema(),
            "attendees": {
                "type": "array",
                "items": {"type": "string", "format": "email"},
                "maxItems": MAX_ATTENDEES,
                "uniqueItems": True,
            },
        },
        "required": ["event_ref"],
        "additionalProperties": False,
    },
}

EVENTS_DELETE_TOOL = {
    "name": "events_delete",
    "description": (
        "Permanently delete an event. Set scope to series when deleting a recurring event's "
        "whole series. This always requires explicit user approval."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "event_ref": {"type": "string", "minLength": 1},
            "scope": {
                "type": "string",
                "enum": ["series"],
                "description": "Required when deleting a recurring event's whole series.",
            },
        },
        "required": ["event_ref"],
        "additionalProperties": False,
    },
}


@dataclass(frozen=True)
class Calendar:
    name: str
    href: str
    color: str | None = None


@dataclass(frozen=True)
class Event:
    summary: str
    start: str
    end: str
    description: str = ""
    location: str = ""
    attendees: tuple[str, ...] = ()
    all_day: bool = False
    timezone: str | None = None
    recurring: bool = False
    transparent: bool = False
    cancelled: bool = False


@dataclass(frozen=True)
class EventPatch:
    summary: str | None = None
    start: str | None = None
    end: str | None = None
    description: str | None = None
    location: str | None = None
    attendees: tuple[str, ...] | None = None


@dataclass(frozen=True)
class EventResource:
    event: Event
    calendar_href: str
    href: str | None = None
    etag: str | None = None
    uid: str | None = None
    raw_icalendar: str | None = None


@dataclass(frozen=True)
class CachedReference:
    value: Calendar | EventResource
    expires_at: float


class CalendarSource(Protocol):
    def list_calendars(self) -> list[Calendar]: ...

    def list_event_resources(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[EventResource], bool]: ...

    def list_busy_events(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[Event], bool]: ...

    def create_event(self, calendar: Calendar, event: Event) -> EventResource: ...

    def update_event(self, resource: EventResource, patch: EventPatch) -> EventResource: ...

    def delete_event(self, resource: EventResource) -> None: ...

    def check_ready(self) -> None: ...


class StaticCalendarSource:
    def __init__(
        self,
        calendars: Sequence[Calendar] | None = None,
        events: Sequence[Event] = (),
    ) -> None:
        self._calendars = list(calendars or [Calendar("Personal", "static://calendar/personal/")])
        default_href = self._calendars[0].href
        self._resources = [
            EventResource(
                event=event,
                calendar_href=default_href,
                href=f"{default_href}{index}.ics",
                etag='"1"',
                uid=str(index),
                raw_icalendar=serialize_icalendar(event, uid=str(index)),
            )
            for index, event in enumerate(events)
        ]
        self._next_id = len(self._resources)

    def list_calendars(self) -> list[Calendar]:
        return list(self._calendars)

    def list_event_resources(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[EventResource], bool]:
        resources = [
            resource
            for resource in self._resources
            if resource.calendar_href == calendar.href
            and _event_overlaps(resource.event, start=start, end=end)
        ]
        resources.sort(key=lambda resource: resource.event.start)
        return resources[:limit], len(resources) > limit

    def list_busy_events(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[Event], bool]:
        events = [
            resource.event
            for resource in self._resources
            if resource.calendar_href == calendar.href
            and _event_overlaps(resource.event, start=start, end=end)
            and not resource.event.transparent
            and not resource.event.cancelled
        ]
        events.sort(
            key=lambda event: (
                _event_datetime(event.start, timezone_name=event.timezone, field="start")
                if not event.all_day
                else datetime.combine(
                    date.fromisoformat(event.start), datetime.min.time(), timezone.utc
                )
            )
        )
        return events[:limit], len(events) > limit

    def create_event(self, calendar: Calendar, event: Event) -> EventResource:
        uid = str(uuid4())
        resource = EventResource(
            event=event,
            calendar_href=calendar.href,
            href=f"{calendar.href}{self._next_id}.ics",
            etag='"1"',
            uid=uid,
            raw_icalendar=serialize_icalendar(event, uid=uid),
        )
        self._next_id += 1
        self._resources.append(resource)
        return resource

    def update_event(self, resource: EventResource, patch: EventPatch) -> EventResource:
        index = self._resource_index(resource)
        event = apply_event_patch(resource.event, patch)
        version = int((resource.etag or '"0"').strip('"')) + 1
        updated = EventResource(
            event=event,
            calendar_href=resource.calendar_href,
            href=resource.href,
            etag=f'"{version}"',
            uid=resource.uid,
            raw_icalendar=patch_icalendar(
                resource.raw_icalendar or serialize_icalendar(resource.event, uid=resource.uid),
                event,
                patch=patch,
            ),
        )
        self._resources[index] = updated
        return updated

    def delete_event(self, resource: EventResource) -> None:
        self._resources.pop(self._resource_index(resource))

    def check_ready(self) -> None:
        return None

    def _resource_index(self, resource: EventResource) -> int:
        for index, current in enumerate(self._resources):
            if current.href == resource.href:
                return index
        raise RuntimeError("Event changed or no longer exists")


class CalDAVCalendarSource:
    def __init__(
        self,
        *,
        calendar_url: str,
        username: str,
        password: str,
        auth_mode: str = "auto",
        verify_tls: bool = True,
        timeout_seconds: float = 30.0,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        validate_http_url(calendar_url, label="CalDAV URL")
        if not username or not password:
            raise ValueError("CalDAV username and password are required")
        self._calendar_url = calendar_url
        self._http = DAVHTTPClient(
            protocol_name="CalDAV",
            username=username,
            password=password,
            auth_mode=auth_mode,
            verify_tls=verify_tls,
            timeout_seconds=timeout_seconds,
            max_response_bytes=MAX_CALDAV_RESPONSE_BYTES,
            response_size_message="CalDAV response exceeded the private calendar size limit",
            changed_message="CalDAV event changed; list it again before retrying",
            not_found_message="CalDAV calendar or event no longer exists",
            transport=transport,
        )

    def check_ready(self) -> None:
        with self._http.client(timeout_seconds=DAV_READINESS_TIMEOUT_SECONDS) as client:
            self._discover(client)

    def list_calendars(self) -> list[Calendar]:
        with self._http.client() as client:
            response, _auth, home_url = self._discover(client)
        return parse_caldav_calendars(response.content, base_url=home_url)

    def list_event_resources(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[EventResource], bool]:
        with self._http.client() as client:
            _response, auth, home_url = self._discover(client)
            _validate_collection_url(calendar.href, base_url=home_url)
            response = self._http.request(
                client,
                "REPORT",
                calendar.href,
                auth=auth,
                headers=xml_headers(),
                content=_calendar_query_body(start, end),
            )
        self._http.check_response_size(response.content)
        resources = parse_caldav_event_resources(response.content, calendar_url=calendar.href)
        return resources[:limit], len(resources) > limit

    def list_busy_events(
        self, calendar: Calendar, *, start: datetime, end: datetime, limit: int
    ) -> tuple[list[Event], bool]:
        with self._http.client() as client:
            _response, auth, home_url = self._discover(client)
            _validate_collection_url(calendar.href, base_url=home_url)
            response = self._http.request(
                client,
                "REPORT",
                calendar.href,
                auth=auth,
                headers=xml_headers(),
                content=_calendar_query_body(start, end, expand=True),
            )
        self._http.check_response_size(response.content)
        events = [
            event
            for event in parse_caldav_expanded_events(response.content, calendar_url=calendar.href)
            if not event.transparent and not event.cancelled
        ]
        return events[:limit], len(events) > limit

    def create_event(self, calendar: Calendar, event: Event) -> EventResource:
        uid = str(uuid4())
        payload = serialize_icalendar(event, uid=uid)
        href = f"{calendar.href.rstrip('/')}/{quote(uid, safe='')}.ics"
        with self._http.client() as client:
            _response, auth, home_url = self._discover(client)
            _validate_collection_url(calendar.href, base_url=home_url)
            _validate_resource_url(href, calendar_url=calendar.href)
            response = self._http.request(
                client,
                "PUT",
                href,
                auth=auth,
                headers={"Content-Type": "text/calendar; charset=utf-8", "If-None-Match": "*"},
                content=payload.encode(),
            )
        return EventResource(event, calendar.href, href, response.headers.get("etag"), uid, payload)

    def update_event(self, resource: EventResource, patch: EventPatch) -> EventResource:
        if not resource.href or not resource.etag:
            raise RuntimeError("Event has no writable resource or ETag; list it again")
        event = apply_event_patch(resource.event, patch)
        payload = patch_icalendar(
            resource.raw_icalendar or serialize_icalendar(resource.event, uid=resource.uid),
            event,
            patch=patch,
        )
        with self._http.client() as client:
            _response, auth, home_url = self._discover(client)
            _validate_collection_url(resource.calendar_href, base_url=home_url)
            _validate_resource_url(resource.href, calendar_url=resource.calendar_href)
            response = self._http.request(
                client,
                "PUT",
                resource.href,
                auth=auth,
                headers={
                    "Content-Type": "text/calendar; charset=utf-8",
                    "If-Match": resource.etag,
                },
                content=payload.encode(),
            )
        return EventResource(
            event,
            resource.calendar_href,
            resource.href,
            response.headers.get("etag"),
            resource.uid,
            payload,
        )

    def delete_event(self, resource: EventResource) -> None:
        if not resource.href or not resource.etag:
            raise RuntimeError("Event has no writable resource or ETag; list it again")
        with self._http.client() as client:
            _response, auth, home_url = self._discover(client)
            _validate_collection_url(resource.calendar_href, base_url=home_url)
            _validate_resource_url(resource.href, calendar_url=resource.calendar_href)
            self._http.request(
                client,
                "DELETE",
                resource.href,
                auth=auth,
                headers={"If-Match": resource.etag},
            )

    def _discover(self, client: httpx.Client) -> tuple[httpx.Response, httpx.Auth | None, str]:
        response, auth = self._http.request_with_auth_negotiation(
            client,
            "PROPFIND",
            self._calendar_url,
            headers=xml_headers(depth="0"),
            content=CALDAV_HOME_PROPFIND_BODY,
            operation="calendar-home discovery",
        )
        self._http.check_response_size(response.content)
        home_url, principal_url = discover_caldav_home_urls(
            response.content, base_url=self._calendar_url
        )
        if home_url is None and principal_url is not None:
            principal_response = self._http.request(
                client,
                "PROPFIND",
                principal_url,
                auth=auth,
                headers=xml_headers(depth="0"),
                content=CALDAV_HOME_PROPFIND_BODY,
            )
            self._http.check_response_size(principal_response.content)
            home_url, _unused_principal = discover_caldav_home_urls(
                principal_response.content, base_url=self._calendar_url
            )
        if home_url is None:
            home_url = self._calendar_url
        validate_same_origin_url(home_url, base_url=self._calendar_url, label="calendar home")
        calendar_response = self._http.request(
            client,
            "PROPFIND",
            home_url,
            auth=auth,
            headers=xml_headers(depth="1"),
            content=CALENDAR_PROPFIND_BODY,
        )
        self._http.check_response_size(calendar_response.content)
        return calendar_response, auth, home_url


class PrivateCalendarMCPServer:
    def __init__(
        self,
        *,
        calendar_source: CalendarSource | None = None,
        calendars: Sequence[Calendar] | None = None,
        events: Sequence[Event] = (),
        reference_factory: Callable[[], str] | None = None,
        private_reference_factory: Callable[[], str] | None = None,
        reference_ttl_seconds: float = DEFAULT_REFERENCE_TTL_SECONDS,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if calendar_source is not None and calendars is not None:
            raise ValueError("Provide calendar_source or calendars, not both")
        if reference_ttl_seconds <= 0:
            raise ValueError("reference TTL must be positive")
        self._source = calendar_source or StaticCalendarSource(calendars, events)
        self._reference_factory = reference_factory or (lambda: secrets.token_urlsafe(18))
        self._private_reference_factory = private_reference_factory or (
            lambda: secrets.token_urlsafe(16)
        )
        self._ttl = reference_ttl_seconds
        self._clock = clock
        self._references: dict[str, CachedReference] = {}

    def check_ready(self) -> None:
        self._source.check_ready()

    def handle(self, payload: dict[str, Any]) -> dict[str, Any] | None:
        request_id = payload.get("id")
        method = payload.get("method")
        if method == "notifications/initialized" or request_id is None:
            return None
        if method == "initialize":
            return self._result(
                request_id,
                {
                    "protocolVersion": DEFAULT_MCP_PROTOCOL_VERSION,
                    "serverInfo": {"name": "minigent-private-calendar", "version": __version__},
                    "capabilities": {"tools": {}},
                },
            )
        if method == "tools/list":
            return self._result(
                request_id,
                {
                    "tools": [
                        CALENDARS_LIST_TOOL,
                        EVENTS_LIST_TOOL,
                        EVENTS_GET_TOOL,
                        FREE_BUSY_TOOL,
                        EVENTS_CREATE_TOOL,
                        EVENTS_UPDATE_TOOL,
                        EVENTS_DELETE_TOOL,
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
        handlers = {
            "calendars_list": self._handle_calendars_list,
            "events_list": self._handle_events_list,
            "events_get": self._handle_events_get,
            "free_busy": self._handle_free_busy,
            "events_create": self._handle_events_create,
            "events_update": self._handle_events_update,
            "events_delete": self._handle_events_delete,
        }
        tool_name = params.get("name")
        handler = handlers.get(tool_name) if isinstance(tool_name, str) else None
        if handler is None:
            return self._error(request_id, -32602, "Unknown tool")
        return handler(request_id, arguments)

    def _handle_calendars_list(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if arguments:
            return self._error(request_id, -32602, "calendars_list accepts no arguments")
        self._prune()
        private_values: dict[str, str] = {}
        calendars = []
        for calendar in self._source.list_calendars():
            calendars.append(
                {
                    "calendar_ref": self._cache(calendar),
                    "name": self._protect("calendar", calendar.name, private_values),
                    "color": calendar.color,
                }
            )
        return self._private_result(
            request_id, {"calendars": calendars}, private_values, "Listed calendars."
        )

    def _handle_events_list(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if not {"calendar_ref", "start", "end"} <= set(arguments) or not set(arguments) <= {
            "calendar_ref",
            "start",
            "end",
            "limit",
        }:
            return self._error(
                request_id, -32602, "events_list requires calendar_ref, start, and end"
            )
        try:
            calendar = self._resolve(arguments["calendar_ref"], Calendar)
            start = _parse_query_datetime(arguments["start"], field="start")
            end = _parse_query_datetime(arguments["end"], field="end")
            limit = _validate_limit(arguments.get("limit", DEFAULT_EVENT_LIMIT))
            if end <= start:
                raise ValueError("end must be after start")
            if (end - start).total_seconds() > MAX_EVENT_QUERY_DAYS * 86_400:
                raise ValueError(f"event query range must not exceed {MAX_EVENT_QUERY_DAYS} days")
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc))
        resources, truncated = self._source.list_event_resources(
            calendar, start=start, end=end, limit=limit
        )
        private_values: dict[str, str] = {}
        events = []
        for resource in resources:
            event = resource.event
            events.append(
                {
                    "event_ref": self._cache(resource),
                    "summary": self._protect("event", event.summary, private_values),
                    "start": event.start,
                    "end": event.end,
                    "all_day": event.all_day,
                    "timezone": event.timezone,
                    "recurring": event.recurring,
                    "available_fields": [
                        field
                        for field, present in (
                            ("description", bool(event.description)),
                            ("location", bool(event.location)),
                            ("attendees", bool(event.attendees)),
                        )
                        if present
                    ],
                }
            )
        return self._private_result(
            request_id,
            {"events": events, "truncated": truncated},
            private_values,
            f"Found {len(events)} events.",
        )

    def _handle_events_get(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if set(arguments) != {"event_ref", "fields"}:
            return self._error(request_id, -32602, "events_get requires event_ref and fields")
        fields = arguments.get("fields")
        allowed = {"description", "location", "attendees"}
        if (
            not isinstance(fields, list)
            or not fields
            or not all(isinstance(field, str) and field in allowed for field in fields)
            or len(set(fields)) != len(fields)
        ):
            return self._error(request_id, -32602, "fields must contain unique supported fields")
        try:
            resource = self._resolve(arguments.get("event_ref"), EventResource)
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32001, str(exc))
        private_values: dict[str, str] = {}
        content: dict[str, Any] = {"event_ref": arguments["event_ref"]}
        for field in fields:
            value = getattr(resource.event, field)
            if field == "attendees":
                content[field] = [
                    self._protect("email", attendee, private_values) for attendee in value
                ]
            else:
                content[field] = self._protect(field, value, private_values) if value else ""
        return self._private_result(
            request_id, content, private_values, "Retrieved selected protected event fields."
        )

    def _handle_free_busy(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if not {"calendar_ref", "start", "end"} <= set(arguments) or not set(arguments) <= {
            "calendar_ref",
            "start",
            "end",
            "limit",
        }:
            return self._error(
                request_id, -32602, "free_busy requires calendar_ref, start, and end"
            )
        try:
            calendar = self._resolve(arguments["calendar_ref"], Calendar)
            start = _parse_query_datetime(arguments["start"], field="start")
            end = _parse_query_datetime(arguments["end"], field="end")
            limit = _validate_free_busy_limit(arguments.get("limit", DEFAULT_FREE_BUSY_LIMIT))
            if end <= start:
                raise ValueError("end must be after start")
            if (end - start).total_seconds() > MAX_EVENT_QUERY_DAYS * 86_400:
                raise ValueError(f"free/busy range must not exceed {MAX_EVENT_QUERY_DAYS} days")
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc))
        events, truncated = self._source.list_busy_events(
            calendar, start=start, end=end, limit=limit
        )
        busy = _merge_busy_intervals(events, range_start=start, range_end=end)
        return self._private_result(
            request_id,
            {"busy": busy, "truncated": truncated},
            {},
            f"Found {len(busy)} busy intervals.",
        )

    def _handle_events_create(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        allowed = {
            "calendar_ref",
            "summary",
            "start",
            "end",
            "description",
            "location",
            "attendees",
        }
        if (
            not {"calendar_ref", "summary", "start", "end"} <= set(arguments)
            or not set(arguments) <= allowed
        ):
            return self._error(request_id, -32602, "events_create has invalid arguments")
        try:
            calendar = self._resolve(arguments["calendar_ref"], Calendar)
            event = _event_from_arguments(arguments)
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc))
        resource = self._source.create_event(calendar, event)
        return self._private_result(
            request_id,
            {"status": "created", "event_ref": self._cache(resource)},
            {},
            "Created the event.",
        )

    def _handle_events_update(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        mutable_fields = {"summary", "start", "end", "description", "location", "attendees"}
        allowed = {"event_ref", "scope", *mutable_fields}
        if (
            "event_ref" not in arguments
            or not set(arguments) & mutable_fields
            or not set(arguments) <= allowed
        ):
            return self._error(
                request_id, -32602, "events_update requires event_ref and at least one field"
            )
        try:
            resource = self._resolve(arguments["event_ref"], EventResource)
            scope = arguments.get("scope")
            if scope is not None and scope != "series":
                raise ValueError("scope must be series")
            if resource.event.recurring:
                if scope != "series":
                    raise ValueError("Recurring event updates require scope=series")
                if "start" in arguments or "end" in arguments:
                    raise ValueError("Recurring event time updates are not supported")
            elif scope is not None:
                raise ValueError("scope is only valid for recurring events")
            patch = _event_patch_from_arguments(arguments)
            apply_event_patch(resource.event, patch)
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc))
        updated = self._source.update_event(resource, patch)
        self._invalidate_resource(resource)
        self._references[arguments["event_ref"]] = CachedReference(
            updated, self._clock() + self._ttl
        )
        return self._private_result(
            request_id,
            {"status": "updated", "event_ref": arguments["event_ref"]},
            {},
            "Updated the event.",
        )

    def _handle_events_delete(self, request_id: Any, arguments: dict[str, Any]) -> dict[str, Any]:
        if "event_ref" not in arguments or not set(arguments) <= {"event_ref", "scope"}:
            return self._error(
                request_id, -32602, "events_delete requires event_ref and optional scope"
            )
        try:
            resource = self._resolve(arguments["event_ref"], EventResource)
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32001, str(exc))
        try:
            scope = arguments.get("scope")
            if scope is not None and scope != "series":
                raise ValueError("scope must be series")
            if resource.event.recurring and scope != "series":
                raise ValueError("Recurring event deletion requires scope=series")
            if not resource.event.recurring and scope is not None:
                raise ValueError("scope is only valid for recurring events")
        except (TypeError, ValueError) as exc:
            return self._error(request_id, -32602, str(exc))
        self._source.delete_event(resource)
        self._invalidate_resource(resource)
        return self._private_result(request_id, {"status": "deleted"}, {}, "Deleted the event.")

    def _cache(self, value: Calendar | EventResource) -> str:
        self._prune()
        if len(self._references) >= MAX_REFERENCES:
            oldest = min(self._references, key=lambda ref: self._references[ref].expires_at)
            self._references.pop(oldest, None)
        reference = self._reference_factory()
        self._references[reference] = CachedReference(value, self._clock() + self._ttl)
        return reference

    def _resolve(self, reference: Any, expected_type: type[Calendar] | type[EventResource]) -> Any:
        self._prune()
        if not isinstance(reference, str) or not reference:
            raise TypeError("reference must be a non-empty string")
        cached = self._references.get(reference)
        if cached is None or not isinstance(cached.value, expected_type):
            raise ValueError("Unknown or expired reference")
        return cached.value

    def _prune(self) -> None:
        now = self._clock()
        for reference in [
            reference for reference, cached in self._references.items() if cached.expires_at <= now
        ]:
            self._references.pop(reference, None)

    def _invalidate_resource(self, resource: EventResource) -> None:
        for reference in [
            reference
            for reference, cached in self._references.items()
            if isinstance(cached.value, EventResource)
            and _same_event_resource(cached.value, resource)
        ]:
            self._references.pop(reference, None)

    def _protect(self, kind: str, value: str, private_values: dict[str, str]) -> str:
        reference = self._private_reference_factory()
        private_values[reference] = value
        return f"{{{{pii:{kind}:{reference}}}}}"

    def _private_result(
        self,
        request_id: Any,
        structured_content: dict[str, Any],
        private_values: dict[str, str],
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

    @staticmethod
    def _result(request_id: Any, result: dict[str, Any]) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "result": result}

    @staticmethod
    def _error(request_id: Any, code: int, message: str) -> dict[str, Any]:
        return {"jsonrpc": "2.0", "id": request_id, "error": {"code": code, "message": message}}


def _validate_collection_url(value: str, *, base_url: str) -> None:
    if url_origin(value) != url_origin(base_url):
        raise RuntimeError("CalDAV discovery returned a cross-origin calendar")
    base_path = urlsplit(base_url).path.rstrip("/") + "/"
    if not urlsplit(value).path.startswith(base_path):
        raise RuntimeError("CalDAV calendar escaped the configured calendar home")


def _validate_resource_url(value: str, *, calendar_url: str) -> None:
    if url_origin(value) != url_origin(calendar_url):
        raise RuntimeError("CalDAV returned a cross-origin event resource")
    calendar_path = urlsplit(calendar_url).path.rstrip("/") + "/"
    if not urlsplit(value).path.startswith(calendar_path):
        raise RuntimeError("CalDAV event resource escaped the calendar")


def discover_caldav_home_urls(payload: bytes, *, base_url: str) -> tuple[str | None, str | None]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CalDAV server returned invalid XML") from exc

    def property_href(namespace: str, name: str) -> str | None:
        property_element = next(root.iter(f"{{{namespace}}}{name}"), None)
        if property_element is None:
            return None
        href_element = next(property_element.iter(f"{{{DAV_NAMESPACE}}}href"), None)
        if href_element is None or not href_element.text:
            return None
        value = urljoin(base_url, href_element.text.strip())
        validate_same_origin_url(value, base_url=base_url, label=name)
        return value

    return (
        property_href(CALDAV_NAMESPACE, "calendar-home-set"),
        property_href(DAV_NAMESPACE, "current-user-principal"),
    )


def parse_caldav_calendars(payload: bytes, *, base_url: str) -> list[Calendar]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CalDAV server returned invalid XML") from exc
    calendars: list[Calendar] = []
    for response in root.iter(f"{{{DAV_NAMESPACE}}}response"):
        if next(response.iter(f"{{{CALDAV_NAMESPACE}}}calendar"), None) is None:
            continue
        href_element = response.find(f"{{{DAV_NAMESPACE}}}href")
        if href_element is None or not href_element.text:
            continue
        href = urljoin(base_url, href_element.text.strip())
        _validate_collection_url(href, base_url=base_url)
        display = next(response.iter(f"{{{DAV_NAMESPACE}}}displayname"), None)
        color = next(response.iter(f"{{{APPLE_NAMESPACE}}}calendar-color"), None)
        name = display.text.strip() if display is not None and display.text else "Unnamed calendar"
        calendars.append(
            Calendar(
                name=name,
                href=href,
                color=color.text.strip() if color is not None and color.text else None,
            )
        )
    return calendars


def parse_caldav_event_resources(payload: bytes, *, calendar_url: str) -> list[EventResource]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CalDAV server returned invalid XML") from exc
    resources: list[EventResource] = []
    for response in root.iter(f"{{{DAV_NAMESPACE}}}response"):
        data = next(response.iter(f"{{{CALDAV_NAMESPACE}}}calendar-data"), None)
        if data is None or not data.text:
            continue
        event = parse_icalendar(data.text)
        if event is None:
            continue
        href_element = response.find(f"{{{DAV_NAMESPACE}}}href")
        if href_element is None or not href_element.text:
            continue
        href = urljoin(calendar_url, href_element.text.strip())
        _validate_resource_url(href, calendar_url=calendar_url)
        etag_element = next(response.iter(f"{{{DAV_NAMESPACE}}}getetag"), None)
        etag = etag_element.text.strip() if etag_element is not None and etag_element.text else None
        resources.append(
            EventResource(
                event=event,
                calendar_href=calendar_url,
                href=href,
                etag=etag,
                uid=_ical_property_value(data.text, "UID"),
                raw_icalendar=data.text,
            )
        )
    return resources


def parse_caldav_expanded_events(payload: bytes, *, calendar_url: str) -> list[Event]:
    try:
        root = ET.fromstring(payload)
    except ET.ParseError as exc:
        raise RuntimeError("CalDAV server returned invalid XML") from exc
    events: list[Event] = []
    for response in root.iter(f"{{{DAV_NAMESPACE}}}response"):
        href_element = response.find(f"{{{DAV_NAMESPACE}}}href")
        if href_element is None or not href_element.text:
            continue
        href = urljoin(calendar_url, href_element.text.strip())
        _validate_resource_url(href, calendar_url=calendar_url)
        data = next(response.iter(f"{{{CALDAV_NAMESPACE}}}calendar-data"), None)
        if data is not None and data.text:
            events.extend(parse_icalendar_instances(data.text))
    return events


def parse_icalendar(payload: str) -> Event | None:
    component = next(
        (
            item
            for item in _vevent_components(payload)
            if _component_property(item, "RECURRENCE-ID") is None
        ),
        None,
    )
    return _event_from_ical_component(component) if component is not None else None


def parse_icalendar_instances(payload: str) -> list[Event]:
    return [
        event
        for component in _vevent_components(payload)
        if (event := _event_from_ical_component(component)) is not None
    ]


def _event_from_ical_component(component: Sequence[str]) -> Event | None:
    start_line = _component_property(component, "DTSTART")
    end_line = _component_property(component, "DTEND")
    if start_line is None or end_line is None:
        return None
    start, all_day, timezone_name = _parse_ical_datetime_line(start_line)
    end, end_all_day, end_timezone = _parse_ical_datetime_line(end_line)
    if all_day != end_all_day:
        raise RuntimeError("CalDAV event mixes all-day and timed values")
    summary = _unescape_ical_text(_line_value(_component_property(component, "SUMMARY") or ""))
    description = _unescape_ical_text(
        _line_value(_component_property(component, "DESCRIPTION") or "")
    )
    location = _unescape_ical_text(_line_value(_component_property(component, "LOCATION") or ""))
    attendees = tuple(
        dict.fromkeys(
            _attendee_email(_line_value(line))
            for line in component
            if _property_name(line) == "ATTENDEE" and _attendee_email(_line_value(line))
        )
    )
    return Event(
        summary=summary or "Untitled event",
        start=start,
        end=end,
        description=description,
        location=location,
        attendees=attendees,
        all_day=all_day,
        timezone=timezone_name or end_timezone,
        recurring=_component_property(component, "RRULE") is not None,
        transparent=(
            _line_value(_component_property(component, "TRANSP") or "").upper() == "TRANSPARENT"
        ),
        cancelled=(
            _line_value(_component_property(component, "STATUS") or "").upper() == "CANCELLED"
        ),
    )


def serialize_icalendar(event: Event, *, uid: str | None = None) -> str:
    _validate_event(event)
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//Minigent//Private Calendar MCP//EN",
        "CALSCALE:GREGORIAN",
        "BEGIN:VEVENT",
        f"UID:{_escape_ical_text(uid or str(uuid4()))}",
        f"DTSTAMP:{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}",
        *_event_property_lines(event),
        "END:VEVENT",
        "END:VCALENDAR",
    ]
    return _serialize_ical_lines(lines)


def patch_icalendar(payload: str, event: Event, *, patch: EventPatch) -> str:
    _validate_event(event)
    replaced = {
        name
        for name, selected in (
            ("SUMMARY", patch.summary is not None),
            ("DTSTART", patch.start is not None or patch.end is not None),
            ("DTEND", patch.start is not None or patch.end is not None),
            ("DESCRIPTION", patch.description is not None),
            ("LOCATION", patch.location is not None),
            ("ATTENDEE", patch.attendees is not None),
        )
        if selected
    }
    lines = _unfold_ical_lines(payload)
    for start_index, line in enumerate(lines):
        if _property_name(line) != "BEGIN" or _line_value(line).upper() != "VEVENT":
            continue
        end_index = next(
            (
                index
                for index in range(start_index + 1, len(lines))
                if _property_name(lines[index]) == "END"
                and _line_value(lines[index]).upper() == "VEVENT"
            ),
            None,
        )
        if end_index is None:
            break
        component = lines[start_index + 1 : end_index]
        if _component_property(component, "RECURRENCE-ID") is not None:
            continue
        preserved = [line for line in component if _property_name(line) not in replaced]
        return _serialize_ical_lines(
            [
                *lines[: start_index + 1],
                *preserved,
                *_event_property_lines(event, properties=replaced),
                *lines[end_index:],
            ]
        )
    raise RuntimeError("CalDAV returned an invalid iCalendar event")


def apply_event_patch(event: Event, patch: EventPatch) -> Event:
    if event.timezone and (patch.start is None) != (patch.end is None):
        raise ValueError("Changing a TZID event requires both start and end")
    updated_timezone = event.timezone
    updated = Event(
        summary=event.summary if patch.summary is None else patch.summary,
        start=event.start if patch.start is None else patch.start,
        end=event.end if patch.end is None else patch.end,
        description=event.description if patch.description is None else patch.description,
        location=event.location if patch.location is None else patch.location,
        attendees=event.attendees if patch.attendees is None else patch.attendees,
        recurring=event.recurring,
        transparent=event.transparent,
        cancelled=event.cancelled,
    )
    start_kind = _event_temporal_kind(updated.start, timezone_name=updated_timezone, field="start")
    end_kind = _event_temporal_kind(updated.end, timezone_name=updated_timezone, field="end")
    updated = Event(
        **{
            **updated.__dict__,
            "all_day": start_kind == "date",
            "timezone": updated_timezone,
        }
    )
    if start_kind != end_kind:
        raise ValueError("start and end must both be dates or date-times")
    _validate_event(updated)
    return updated


def _event_from_arguments(arguments: dict[str, Any]) -> Event:
    summary = _validate_text(arguments.get("summary"), field="summary", allow_empty=False)
    start = _validate_temporal(arguments.get("start"), field="start")
    end = _validate_temporal(arguments.get("end"), field="end")
    kind = _temporal_kind(start, field="start")
    if _temporal_kind(end, field="end") != kind:
        raise ValueError("start and end must both be dates or date-times")
    event = Event(
        summary=summary,
        start=start,
        end=end,
        description=_validate_text(arguments.get("description", ""), field="description"),
        location=_validate_text(arguments.get("location", ""), field="location"),
        attendees=_validate_attendees(arguments.get("attendees", [])),
        all_day=kind == "date",
    )
    _validate_event(event)
    return event


def _event_patch_from_arguments(arguments: dict[str, Any]) -> EventPatch:
    return EventPatch(
        summary=_validate_text(arguments["summary"], field="summary", allow_empty=False)
        if "summary" in arguments
        else None,
        start=_validate_patch_temporal(arguments["start"], field="start")
        if "start" in arguments
        else None,
        end=_validate_patch_temporal(arguments["end"], field="end") if "end" in arguments else None,
        description=_validate_text(arguments["description"], field="description")
        if "description" in arguments
        else None,
        location=_validate_text(arguments["location"], field="location")
        if "location" in arguments
        else None,
        attendees=_validate_attendees(arguments["attendees"]) if "attendees" in arguments else None,
    )


def _validate_event(event: Event) -> None:
    _validate_text(event.summary, field="summary", allow_empty=False)
    start_kind = _event_temporal_kind(event.start, timezone_name=event.timezone, field="start")
    if _event_temporal_kind(event.end, timezone_name=event.timezone, field="end") != start_kind:
        raise ValueError("start and end must both be dates or date-times")
    if start_kind == "date":
        if event.timezone:
            raise ValueError("all-day events must not set a timezone")
        if date.fromisoformat(event.end) <= date.fromisoformat(event.start):
            raise ValueError("end must be after start")
    elif _event_datetime(event.end, timezone_name=event.timezone, field="end") <= _event_datetime(
        event.start, timezone_name=event.timezone, field="start"
    ):
        raise ValueError("end must be after start")


def _validate_text(value: Any, *, field: str, allow_empty: bool = True) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a string")
    if len(value) > MAX_PRIVATE_FIELD_CHARS or "\x00" in value:
        raise ValueError(f"{field} exceeds its safe size or contains NUL")
    normalized = value.strip()
    if not allow_empty and not normalized:
        raise ValueError(f"{field} must not be empty")
    return normalized


def _validate_attendees(value: Any) -> tuple[str, ...]:
    if not isinstance(value, list) or len(value) > MAX_ATTENDEES:
        raise ValueError(f"attendees must be an array of at most {MAX_ATTENDEES} emails")
    attendees = tuple(_validate_text(item, field="attendee", allow_empty=False) for item in value)
    if len(set(attendees)) != len(attendees) or any("@" not in item for item in attendees):
        raise ValueError("attendees must contain unique email addresses")
    return attendees


def _validate_temporal(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a date or RFC 3339 date-time string")
    _temporal_kind(value, field=field)
    return value


def _validate_patch_temporal(value: Any, *, field: str) -> str:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be a date or date-time string")
    if len(value) == 10:
        try:
            date.fromisoformat(value)
            return value
        except ValueError:
            pass
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be a date or date-time string") from exc
    return value


def _temporal_kind(value: str, *, field: str) -> str:
    try:
        date.fromisoformat(value)
        if len(value) == 10:
            return "date"
    except ValueError:
        pass
    _parse_query_datetime(value, field=field)
    return "date-time"


def _event_temporal_kind(value: str, *, timezone_name: str | None, field: str) -> str:
    if timezone_name and len(value) > 10:
        try:
            datetime.fromisoformat(value)
        except ValueError as exc:
            raise ValueError(f"{field} contains an invalid local date-time") from exc
        return "date-time"
    return _temporal_kind(value, field=field)


def _event_datetime(value: str, *, timezone_name: str | None, field: str) -> datetime:
    if not timezone_name:
        return _parse_query_datetime(value, field=field)
    try:
        zone = ZoneInfo(timezone_name)
    except ZoneInfoNotFoundError as exc:
        raise ValueError(f"{field} uses an unknown timezone") from exc
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError as exc:
        raise ValueError(f"{field} contains an invalid local date-time") from exc
    if parsed.tzinfo is not None:
        raise ValueError(f"{field} must be local when timezone is set")
    return parsed.replace(tzinfo=zone)


def _parse_query_datetime(value: Any, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError(f"{field} must be an RFC 3339 date-time with an offset")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError(f"{field} must be an RFC 3339 date-time with an offset") from exc
    if parsed.tzinfo is None:
        raise ValueError(f"{field} must include a UTC offset")
    return parsed


def _validate_limit(value: Any) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or not 1 <= value <= MAX_EVENT_LIMIT:
        raise ValueError(f"limit must be an integer from 1 to {MAX_EVENT_LIMIT}")
    return value


def _validate_free_busy_limit(value: Any) -> int:
    if (
        isinstance(value, bool)
        or not isinstance(value, int)
        or not 1 <= value <= MAX_FREE_BUSY_LIMIT
    ):
        raise ValueError(f"limit must be an integer from 1 to {MAX_FREE_BUSY_LIMIT}")
    return value


def _event_bounds_utc(event: Event) -> tuple[datetime, datetime]:
    if event.all_day:
        start = datetime.combine(date.fromisoformat(event.start), datetime.min.time(), timezone.utc)
        end = datetime.combine(date.fromisoformat(event.end), datetime.min.time(), timezone.utc)
    else:
        start = _event_datetime(event.start, timezone_name=event.timezone, field="start")
        end = _event_datetime(event.end, timezone_name=event.timezone, field="end")
    return start.astimezone(timezone.utc), end.astimezone(timezone.utc)


def _merge_busy_intervals(
    events: Sequence[Event], *, range_start: datetime, range_end: datetime
) -> list[dict[str, str]]:
    intervals = []
    for event in events:
        if event.transparent or event.cancelled:
            continue
        start, end = _event_bounds_utc(event)
        start = max(start, range_start.astimezone(timezone.utc))
        end = min(end, range_end.astimezone(timezone.utc))
        if start < end:
            intervals.append((start, end))
    intervals.sort()
    merged: list[tuple[datetime, datetime]] = []
    for start, end in intervals:
        if merged and start <= merged[-1][1]:
            merged[-1] = (merged[-1][0], max(merged[-1][1], end))
        else:
            merged.append((start, end))
    return [
        {"start": _utc_datetime_string(start), "end": _utc_datetime_string(end)}
        for start, end in merged
    ]


def _utc_datetime_string(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def _event_overlaps(event: Event, *, start: datetime, end: datetime) -> bool:
    event_start, event_end = _event_bounds_utc(event)
    return event_start < end and event_end > start


def _event_property_lines(event: Event, *, properties: set[str] | None = None) -> list[str]:
    selected = (
        {"SUMMARY", "DTSTART", "DTEND", "DESCRIPTION", "LOCATION", "ATTENDEE"}
        if properties is None
        else properties
    )
    lines: list[str] = []
    if "SUMMARY" in selected:
        lines.append(f"SUMMARY:{_escape_ical_text(event.summary)}")
    if "DTSTART" in selected:
        lines.append(_serialize_temporal("DTSTART", event.start, timezone_name=event.timezone))
    if "DTEND" in selected:
        lines.append(_serialize_temporal("DTEND", event.end, timezone_name=event.timezone))
    if "DESCRIPTION" in selected and event.description:
        lines.append(f"DESCRIPTION:{_escape_ical_text(event.description)}")
    if "LOCATION" in selected and event.location:
        lines.append(f"LOCATION:{_escape_ical_text(event.location)}")
    if "ATTENDEE" in selected:
        lines.extend(f"ATTENDEE:mailto:{_escape_ical_text(value)}" for value in event.attendees)
    return lines


def _serialize_temporal(name: str, value: str, *, timezone_name: str | None = None) -> str:
    kind = _event_temporal_kind(value, timezone_name=timezone_name, field=name.lower())
    if kind == "date":
        return f"{name};VALUE=DATE:{date.fromisoformat(value).strftime('%Y%m%d')}"
    if timezone_name:
        parsed = datetime.fromisoformat(value)
        return f"{name};TZID={timezone_name}:{parsed.strftime('%Y%m%dT%H%M%S')}"
    parsed = _parse_query_datetime(value, field=name.lower()).astimezone(timezone.utc)
    return f"{name}:{parsed.strftime('%Y%m%dT%H%M%SZ')}"


def _parse_ical_datetime_line(line: str) -> tuple[str, bool, str | None]:
    left, _, raw = line.partition(":")
    parameters = _property_parameters(left)
    timezone_name = parameters.get("TZID")
    try:
        if parameters.get("VALUE", "").upper() == "DATE" or len(raw) == 8:
            return datetime.strptime(raw, "%Y%m%d").date().isoformat(), True, None
        if raw.endswith("Z"):
            parsed = datetime.strptime(raw, "%Y%m%dT%H%M%SZ").replace(tzinfo=timezone.utc)
            return parsed.isoformat().replace("+00:00", "Z"), False, None
        parsed = datetime.strptime(raw, "%Y%m%dT%H%M%S")
        return parsed.isoformat(), False, timezone_name
    except ValueError as exc:
        raise RuntimeError("CalDAV event contains an unsupported date-time") from exc


def _vevent_components(payload: str) -> list[list[str]]:
    components: list[list[str]] = []
    current: list[str] | None = None
    for line in _unfold_ical_lines(payload):
        if _property_name(line) == "BEGIN" and _line_value(line).upper() == "VEVENT":
            current = []
        elif _property_name(line) == "END" and _line_value(line).upper() == "VEVENT":
            if current is not None:
                components.append(current)
            current = None
        elif current is not None:
            current.append(line)
    return components


def _component_property(component: Sequence[str], name: str) -> str | None:
    return next((line for line in component if _property_name(line) == name), None)


def _ical_property_value(payload: str, name: str) -> str | None:
    for component in _vevent_components(payload):
        line = _component_property(component, name)
        if line is not None:
            return _unescape_ical_text(_line_value(line)) or None
    return None


def _unfold_ical_lines(payload: str) -> list[str]:
    unfolded: list[str] = []
    for line in payload.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += line[1:]
        elif line:
            unfolded.append(line)
    return unfolded


def _serialize_ical_lines(lines: Sequence[str]) -> str:
    return "\r\n".join(part for line in lines for part in _fold_ical_line(line)) + "\r\n"


def _fold_ical_line(line: str) -> list[str]:
    chunks: list[str] = []
    remaining = line
    limit = 75
    while len(remaining.encode()) > limit:
        size = 0
        split_at = 0
        for index, character in enumerate(remaining):
            encoded_size = len(character.encode())
            if size + encoded_size > limit:
                break
            size += encoded_size
            split_at = index + 1
        chunks.append((" " if chunks else "") + remaining[:split_at])
        remaining = remaining[split_at:]
        limit = 74
    chunks.append((" " if chunks else "") + remaining)
    return chunks


def _property_name(line: str) -> str:
    return line.partition(":")[0].split(";", 1)[0].upper()


def _property_parameters(left: str) -> dict[str, str]:
    parameters: dict[str, str] = {}
    for item in left.split(";")[1:]:
        key, separator, value = item.partition("=")
        if separator:
            parameters[key.upper()] = value.strip('"')
    return parameters


def _line_value(line: str) -> str:
    return line.partition(":")[2]


def _escape_ical_text(value: str) -> str:
    return value.replace("\\", "\\\\").replace("\n", "\\n").replace(";", "\\;").replace(",", "\\,")


def _unescape_ical_text(value: str) -> str:
    result = ""
    index = 0
    while index < len(value):
        if value[index] == "\\" and index + 1 < len(value):
            next_character = value[index + 1]
            result += "\n" if next_character.lower() == "n" else next_character
            index += 2
        else:
            result += value[index]
            index += 1
    return result


def _attendee_email(value: str) -> str:
    return value[7:] if value.lower().startswith("mailto:") else value


def _same_event_resource(left: EventResource, right: EventResource) -> bool:
    return left.href == right.href if left.href and right.href else left is right


def create_app(server: PrivateCalendarMCPServer | None = None) -> FastAPI:
    private_calendar = server or PrivateCalendarMCPServer()
    return create_mcp_app(
        title="Minigent private calendar MCP",
        handler=private_calendar.handle,
        readiness_check=private_calendar.check_ready,
    )


app = create_app()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Run the private CalDAV calendar MCP server.")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument(
        "--insecure-skip-tls-verify",
        action="store_true",
        help="Disable CalDAV TLS verification. Use only for trusted local development.",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> None:
    args = parse_args(argv)
    calendar_url = os.environ.get(CALDAV_URL_ENV, "").strip()
    if calendar_url:
        source: CalendarSource = CalDAVCalendarSource(
            calendar_url=calendar_url,
            username=os.environ.get(CALDAV_USERNAME_ENV, ""),
            password=os.environ.get(CALDAV_PASSWORD_ENV, ""),
            auth_mode=os.environ.get(CALDAV_AUTH_MODE_ENV, "auto"),
            verify_tls=not args.insecure_skip_tls_verify,
        )
        server = PrivateCalendarMCPServer(calendar_source=source)
    else:
        server = PrivateCalendarMCPServer()
    uvicorn.run(create_app(server), host=args.host, port=args.port)


if __name__ == "__main__":
    main()
