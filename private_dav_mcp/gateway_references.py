from __future__ import annotations

import json
from collections.abc import Callable, Iterator, MutableMapping
from typing import Generic, TypeVar

from private_dav_mcp.gateway_store import AccountStore

T = TypeVar("T")


class DurableReferenceCache(MutableMapping[str, T], Generic[T]):
    """Encrypted SQLite-backed mapping for owner-scoped opaque DAV references."""

    def __init__(
        self,
        store: AccountStore,
        *,
        tenant_id: str,
        user_id: str,
        account_ref: str,
        account_updated_at: str,
        encode: Callable[[T], tuple[str, dict[str, object], float]],
        decode: Callable[[str, dict[str, object], float], T],
        reference_types: frozenset[str],
    ) -> None:
        self._store = store
        self._tenant_id = tenant_id
        self._user_id = user_id
        self._account_ref = account_ref
        self._account_updated_at = account_updated_at
        self._encode = encode
        self._decode = decode
        self._reference_types = reference_types

    def __getitem__(self, reference: str) -> T:
        stored = self._store.get_reference(self._tenant_id, self._user_id, reference)
        if (
            stored is None
            or stored.account_ref != self._account_ref
            or stored.account_updated_at != self._account_updated_at
            or stored.reference_type not in self._reference_types
        ):
            raise KeyError(reference)
        payload = _payload_object(stored.payload)
        return self._decode(stored.reference_type, payload, stored.expires_at)

    def __setitem__(self, reference: str, value: T) -> None:
        reference_type, payload, expires_at = self._encode(value)
        if reference_type not in self._reference_types:
            raise ValueError("Reference codec returned an unsupported type")
        encoded = json.dumps(
            {"reference": reference, "value": payload},
            ensure_ascii=True,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        self._store.put_reference(
            reference=reference,
            tenant_id=self._tenant_id,
            user_id=self._user_id,
            account_ref=self._account_ref,
            account_updated_at=self._account_updated_at,
            reference_type=reference_type,
            payload=encoded,
            expires_at=expires_at,
        )

    def __delitem__(self, reference: str) -> None:
        if self._store.get_reference(self._tenant_id, self._user_id, reference) is None:
            raise KeyError(reference)
        self._store.delete_reference(self._tenant_id, self._user_id, reference)

    def __iter__(self) -> Iterator[str]:
        for stored in self._store.list_references(
            self._tenant_id, self._user_id, self._account_ref
        ):
            if (
                stored.account_updated_at == self._account_updated_at
                and stored.reference_type in self._reference_types
            ):
                yield stored.reference

    def __len__(self) -> int:
        return sum(1 for _reference in self)


def _payload_object(payload: bytes) -> dict[str, object]:
    decoded = json.loads(payload)
    value = decoded.get("value") if isinstance(decoded, dict) else None
    if not isinstance(value, dict):
        raise RuntimeError("Stored reference payload is invalid")
    return value
