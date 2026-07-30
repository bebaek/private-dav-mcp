from __future__ import annotations

from urllib.parse import urlsplit

import httpx

DAV_AUTH_MODES = {"auto", "basic", "digest"}


class DAVHTTPClient:
    """Shared authenticated HTTP transport for CardDAV and CalDAV sources."""

    def __init__(
        self,
        *,
        protocol_name: str,
        username: str,
        password: str,
        auth_mode: str,
        verify_tls: bool,
        timeout_seconds: float,
        max_response_bytes: int,
        response_size_message: str,
        changed_message: str,
        not_found_message: str,
        transport: httpx.BaseTransport | None = None,
    ) -> None:
        normalized_auth_mode = auth_mode.strip().lower()
        if normalized_auth_mode not in DAV_AUTH_MODES:
            raise ValueError(f"{protocol_name} auth mode must be auto, basic, or digest")
        self._protocol_name = protocol_name
        self._username = username
        self._password = password
        self._auth_mode = normalized_auth_mode
        self._verify_tls = verify_tls
        self._timeout_seconds = timeout_seconds
        self._max_response_bytes = max_response_bytes
        self._response_size_message = response_size_message
        self._changed_message = changed_message
        self._not_found_message = not_found_message
        self._transport = transport

    def client(self) -> httpx.Client:
        return httpx.Client(
            verify=self._verify_tls,
            timeout=self._timeout_seconds,
            transport=self._transport,
        )

    def request(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        auth: httpx.Auth | None,
        headers: dict[str, str],
        content: bytes | None = None,
    ) -> httpx.Response:
        response = self._send(
            client,
            method,
            url,
            auth=auth,
            headers=headers,
            content=content,
        )
        self._raise_for_status(response, operation=method.lower())
        return response

    def request_with_auth_negotiation(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        headers: dict[str, str],
        content: bytes | None = None,
        operation: str,
    ) -> tuple[httpx.Response, httpx.Auth | None]:
        auth = self._configured_auth()
        response = self._send(
            client,
            method,
            url,
            auth=auth,
            headers=headers,
            content=content,
        )
        if self._auth_mode == "auto" and response.status_code == 401:
            auth = self._auth_from_challenge(response.headers.get("www-authenticate", ""))
            response = self._send(
                client,
                method,
                url,
                auth=auth,
                headers=headers,
                content=content,
            )
        self._raise_for_status(response, operation=operation)
        return response, auth

    def check_response_size(self, content: bytes) -> None:
        if len(content) > self._max_response_bytes:
            raise RuntimeError(self._response_size_message)

    def _send(
        self,
        client: httpx.Client,
        method: str,
        url: str,
        *,
        auth: httpx.Auth | None,
        headers: dict[str, str],
        content: bytes | None,
    ) -> httpx.Response:
        try:
            return client.request(method, url, auth=auth, headers=headers, content=content)
        except httpx.HTTPError as exc:
            raise RuntimeError(f"{self._protocol_name} request failed") from exc

    def _raise_for_status(self, response: httpx.Response, *, operation: str) -> None:
        if response.status_code == 412:
            raise RuntimeError(self._changed_message)
        if response.status_code == 404:
            raise RuntimeError(self._not_found_message)
        try:
            response.raise_for_status()
        except httpx.HTTPStatusError as exc:
            raise RuntimeError(
                f"{self._protocol_name} {operation} failed with HTTP {response.status_code}"
            ) from exc

    def _configured_auth(self) -> httpx.Auth | None:
        if self._auth_mode == "basic":
            return httpx.BasicAuth(self._username, self._password)
        if self._auth_mode == "digest":
            return httpx.DigestAuth(self._username, self._password)
        return None

    def _auth_from_challenge(self, challenge: str) -> httpx.Auth:
        scheme = challenge.partition(" ")[0].strip().lower()
        if scheme == "digest":
            return httpx.DigestAuth(self._username, self._password)
        if scheme == "basic":
            return httpx.BasicAuth(self._username, self._password)
        raise RuntimeError(
            f"{self._protocol_name} server returned an unsupported authentication challenge"
        )


def xml_headers(*, depth: str = "1") -> dict[str, str]:
    return {
        "Depth": depth,
        "Content-Type": "application/xml; charset=utf-8",
        "Accept": "application/xml",
    }


def url_origin(value: str) -> tuple[str, str | None, int | None]:
    parsed = urlsplit(value)
    default_port = 443 if parsed.scheme.lower() == "https" else 80
    return parsed.scheme.lower(), parsed.hostname, parsed.port or default_port


def validate_same_origin_url(value: str, *, base_url: str, label: str) -> None:
    if url_origin(value) != url_origin(base_url):
        raise RuntimeError(f"{label} resolved to a cross-origin URL")


def validate_http_url(value: str, *, label: str) -> None:
    parsed = urlsplit(value)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ValueError(f"{label} must use HTTP or HTTPS")
    if parsed.username or parsed.password:
        raise ValueError(f"{label} must not include embedded credentials")
