#!/usr/bin/env python3
"""Serve deterministic HTTPS CardDAV, CalDAV, and ICS fixtures for container contracts."""

from __future__ import annotations

import argparse
import base64
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

_EXPECTED_AUTHORIZATION = "Basic " + base64.b64encode(b"contract-user:contract-password").decode()

_CONTACTS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response>
    <d:href>/carddav/contact-1.vcf</d:href>
    <d:propstat><d:prop>
      <d:getetag>"contact-v1"</d:getetag>
      <card:address-data><![CDATA[BEGIN:VCARD
VERSION:3.0
UID:contact-1
FN:Contract Contact
EMAIL:contact@example.test
TEL:+1 555 0198
END:VCARD
]]></card:address-data>
    </d:prop></d:propstat>
  </d:response>
</d:multistatus>
"""

_ADDRESSBOOK_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:card="urn:ietf:params:xml:ns:carddav">
  <d:response><d:href>/carddav/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection/><card:addressbook/></d:resourcetype>
  </d:prop></d:propstat></d:response>
</d:multistatus>
"""

_CALENDARS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav"
 xmlns:ical="http://apple.com/ns/ical/">
  <d:response><d:href>/caldav/personal/</d:href><d:propstat><d:prop>
    <d:resourcetype><d:collection/><cal:calendar/></d:resourcetype>
    <d:displayname>Contract Calendar</d:displayname>
    <ical:calendar-color>#336699FF</ical:calendar-color>
  </d:prop></d:propstat></d:response>
</d:multistatus>
"""

_EVENTS_XML = b"""<?xml version="1.0" encoding="utf-8"?>
<d:multistatus xmlns:d="DAV:" xmlns:cal="urn:ietf:params:xml:ns:caldav">
  <d:response><d:href>/caldav/personal/event-1.ics</d:href><d:propstat><d:prop>
    <d:getetag>"event-v1"</d:getetag>
    <cal:calendar-data><![CDATA[BEGIN:VCALENDAR
VERSION:2.0
BEGIN:VEVENT
UID:event-1
DTSTAMP:20260101T000000Z
DTSTART:20260801T140000Z
DTEND:20260801T150000Z
SUMMARY:Contract Calendar Event
DESCRIPTION:Calendar contract details
LOCATION:Contract room
ATTENDEE:mailto:calendar-attendee@example.test
END:VEVENT
END:VCALENDAR
]]></cal:calendar-data>
  </d:prop></d:propstat></d:response>
</d:multistatus>
"""

_ICS_BODY = b"""BEGIN:VCALENDAR
VERSION:2.0
PRODID:-//Private DAV MCP//Contract//EN
BEGIN:VEVENT
UID:subscription-event-1
DTSTAMP:20260101T000000Z
DTSTART:20260802T160000Z
DTEND:20260802T170000Z
SUMMARY:Contract Subscription Event
DESCRIPTION:Subscription contract details
END:VEVENT
END:VCALENDAR
"""


class ContractDAVHandler(BaseHTTPRequestHandler):
    server_version = "PrivateDAVContract/1"

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._send(HTTPStatus.OK, b"ok\n", content_type="text/plain")
            return
        if self.path == "/feed.ics":
            self._send(
                HTTPStatus.OK,
                _ICS_BODY,
                content_type="text/calendar; charset=utf-8",
                extra_headers={"ETag": '"feed-v1"'},
            )
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", content_type="text/plain")

    def do_PROPFIND(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        if self.path.rstrip("/") == "/carddav":
            self._send(207, _ADDRESSBOOK_XML, content_type="application/xml")
            return
        if self.path.rstrip("/") == "/caldav":
            self._send(207, _CALENDARS_XML, content_type="application/xml")
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", content_type="text/plain")

    def do_REPORT(self) -> None:  # noqa: N802
        if not self._authorized():
            return
        if self.path.rstrip("/") == "/carddav":
            self._send(207, _CONTACTS_XML, content_type="application/xml")
            return
        if self.path.rstrip("/") == "/caldav/personal":
            self._send(207, _EVENTS_XML, content_type="application/xml")
            return
        self._send(HTTPStatus.NOT_FOUND, b"not found\n", content_type="text/plain")

    def log_message(self, format: str, *args: object) -> None:
        print(f"contract-dav: {format % args}", flush=True)

    def _authorized(self) -> bool:
        if self.headers.get("Authorization") == _EXPECTED_AUTHORIZATION:
            return True
        self.send_response(HTTPStatus.UNAUTHORIZED)
        self.send_header("WWW-Authenticate", 'Basic realm="contract-dav"')
        self.send_header("Content-Length", "0")
        self.end_headers()
        return False

    def _send(
        self,
        status: int,
        body: bytes,
        *,
        content_type: str,
        extra_headers: dict[str, str] | None = None,
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        for name, value in (extra_headers or {}).items():
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(body)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=19443)
    parser.add_argument("--cert", type=Path, required=True)
    parser.add_argument("--key", type=Path, required=True)
    args = parser.parse_args()

    server = ThreadingHTTPServer((args.host, args.port), ContractDAVHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(args.cert, args.key)
    server.socket = context.wrap_socket(server.socket, server_side=True)
    server.serve_forever()


if __name__ == "__main__":
    main()
