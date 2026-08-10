from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Literal

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


@dataclass(frozen=True, repr=False)
class PasswordCredential:
    username: str
    password: str
    mode: str


@dataclass(frozen=True, repr=False)
class GatewayAccount:
    account_ref: str
    tenant_id: str
    owner_type: str
    owner_user_id: str | None
    kind: str
    label: str
    base_url: str
    credential: PasswordCredential
    status: str
    enabled: bool
    last_checked_at: str | None
    last_error: str | None
    created_at: str
    updated_at: str

    def __post_init__(self) -> None:
        if self.owner_type == "user":
            if not self.owner_user_id:
                raise ValueError("User-owned accounts require an owner user ID")
        elif self.owner_type == "tenant":
            if self.owner_user_id is not None:
                raise ValueError("Tenant-owned accounts cannot have an owner user ID")
        else:
            raise ValueError("Account owner type must be user or tenant")

    @property
    def user_id(self) -> str:
        if self.owner_type != "user" or self.owner_user_id is None:
            raise RuntimeError("Tenant-owned accounts do not have an owner user ID")
        return self.owner_user_id


@dataclass(frozen=True)
class TenantAccountAudit:
    audit_id: int
    tenant_id: str
    account_ref: str
    actor_user_id: str
    operation: str
    outcome: str
    created_at: str


@dataclass(frozen=True)
class AccountGrant:
    account_ref: str
    tenant_id: str
    user_id: str
    permission: str
    enabled: bool
    updated_by: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class AccountGrantAudit:
    audit_id: int
    account_ref: str
    tenant_id: str
    user_id: str
    actor_id: str
    operation: str
    previous_permission: str | None
    previous_enabled: bool | None
    resulting_permission: str | None
    resulting_enabled: bool | None
    created_at: str


@dataclass(frozen=True)
class ResourceGrant:
    resource_id: str
    tenant_id: str
    user_id: str
    permission: str
    enabled: bool
    updated_by: str
    created_at: str
    updated_at: str


@dataclass(frozen=True)
class ResourceGrantAudit:
    audit_id: int
    resource_id: str
    tenant_id: str
    user_id: str
    actor_id: str
    operation: str
    previous_permission: str | None
    previous_enabled: bool | None
    resulting_permission: str | None
    resulting_enabled: bool | None
    created_at: str


@dataclass(frozen=True)
class StoredReference:
    reference: str
    tenant_id: str
    user_id: str
    account_ref: str
    account_updated_at: str
    reference_type: str
    payload: bytes
    expires_at: float


class AccountCipher:
    def __init__(self, *, keyring: dict[int, bytes], active_version: int) -> None:
        if active_version not in keyring:
            raise ValueError("Active gateway encryption key is not present in the keyring")
        if any(len(key) != 32 for key in keyring.values()):
            raise ValueError("Gateway encryption keys must be 32 bytes")
        self._keyring = dict(keyring)
        self._active_version = active_version

    @property
    def active_version(self) -> int:
        return self._active_version

    def new_data_key(self) -> bytes:
        return secrets.token_bytes(32)

    def wrap_data_key(self, data_key: bytes, *, owner_aad: bytes) -> tuple[int, bytes]:
        return self._active_version, self._encrypt(
            self._keyring[self._active_version], data_key, owner_aad + b"|dek"
        )

    def unwrap_data_key(self, wrapped: bytes, *, key_version: int, owner_aad: bytes) -> bytes:
        try:
            key = self._keyring[key_version]
        except KeyError as exc:
            raise RuntimeError("Account encryption key version is unavailable") from exc
        return self._decrypt(key, wrapped, owner_aad + b"|dek")

    @staticmethod
    def encrypt_field(data_key: bytes, value: str, *, aad: bytes) -> bytes:
        return AccountCipher._encrypt(data_key, value.encode(), aad)

    @staticmethod
    def decrypt_field(data_key: bytes, value: bytes, *, aad: bytes) -> str:
        return AccountCipher._decrypt(data_key, value, aad).decode()

    @staticmethod
    def _encrypt(key: bytes, plaintext: bytes, aad: bytes) -> bytes:
        nonce = secrets.token_bytes(12)
        return nonce + AESGCM(key).encrypt(nonce, plaintext, aad)

    @staticmethod
    def _decrypt(key: bytes, ciphertext: bytes, aad: bytes) -> bytes:
        if len(ciphertext) < 29:
            raise RuntimeError("Encrypted account value is invalid")
        return AESGCM(key).decrypt(ciphertext[:12], ciphertext[12:], aad)

    def fingerprint(self, value: bytes) -> str:
        return hmac.new(
            self._keyring[self._active_version],
            b"private-dav|idempotency|" + value,
            hashlib.sha256,
        ).hexdigest()

    def encrypt_reference(self, value: bytes, *, aad: bytes) -> tuple[int, bytes]:
        return self._active_version, self._encrypt(
            self._keyring[self._active_version], value, aad + b"|reference"
        )

    def decrypt_reference(self, value: bytes, *, key_version: int, aad: bytes) -> bytes:
        try:
            key = self._keyring[key_version]
        except KeyError as exc:
            raise RuntimeError("Reference encryption key version is unavailable") from exc
        return self._decrypt(key, value, aad + b"|reference")

    @staticmethod
    def decode_keyring(encoded: dict[str, str]) -> dict[int, bytes]:
        result: dict[int, bytes] = {}
        for version, value in encoded.items():
            try:
                result[int(version)] = base64.urlsafe_b64decode(value)
            except (ValueError, TypeError) as exc:
                raise ValueError("Gateway encryption keyring is invalid") from exc
        return result


class AccountStore:
    def __init__(
        self,
        path: str | Path,
        *,
        cipher: AccountCipher,
        max_accounts_per_user: int = 10,
        max_accounts_per_tenant: int = 50,
    ) -> None:
        if max_accounts_per_user < 1 or max_accounts_per_tenant < 1:
            raise ValueError("Account limit must be positive")
        self._path = str(path)
        self._cipher = cipher
        self._max_accounts_per_user = max_accounts_per_user
        self._max_accounts_per_tenant = max_accounts_per_tenant
        Path(self._path).parent.mkdir(parents=True, exist_ok=True)
        self._migrate()
        os.chmod(self._path, 0o600)

    def check_ready(self) -> None:
        with self._connect() as connection:
            connection.execute("SELECT 1").fetchone()

    def create_account(
        self,
        *,
        tenant_id: str,
        user_id: str,
        kind: str,
        label: str,
        base_url: str,
        credential: PasswordCredential,
        enabled: bool,
        status: str,
        last_error: str | None,
        idempotency_key: str | None,
        request_hash: str | None,
    ) -> tuple[GatewayAccount, bool]:
        now = _utc_now()
        account_ref = f"acct_{secrets.token_urlsafe(24)}"
        account = GatewayAccount(
            account_ref=account_ref,
            tenant_id=tenant_id,
            owner_type="user",
            owner_user_id=user_id,
            kind=kind,
            label=label,
            base_url=base_url,
            credential=credential,
            status=status,
            enabled=enabled,
            last_checked_at=now,
            last_error=last_error,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key is not None:
                existing = connection.execute(
                    """
                    SELECT request_hash, account_ref FROM account_idempotency
                    WHERE tenant_id = ? AND user_id = ? AND idempotency_key = ?
                    """,
                    (tenant_id, user_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise ValueError("Idempotency key was already used for another request")
                    stored = self._get_account(
                        connection, tenant_id, user_id, existing["account_ref"]
                    )
                    if stored is None:
                        raise RuntimeError("Idempotent account result is unavailable")
                    connection.commit()
                    return stored, False
            account_count = connection.execute(
                """
                SELECT COUNT(*) FROM dav_accounts
                WHERE tenant_id = ? AND user_id = ?
                """,
                (tenant_id, user_id),
            ).fetchone()[0]
            if account_count >= self._max_accounts_per_user:
                raise OverflowError("Account limit reached")
            self._insert_account(connection, account)
            if idempotency_key is not None:
                connection.execute(
                    """
                    INSERT INTO account_idempotency
                      (tenant_id, user_id, idempotency_key, request_hash, account_ref, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (tenant_id, user_id, idempotency_key, request_hash, account_ref, now),
                )
            self._audit(connection, account, "account.create", "success")
            connection.commit()
        return account, True

    def create_tenant_account(
        self,
        *,
        tenant_id: str,
        actor_user_id: str,
        kind: str,
        label: str,
        base_url: str,
        credential: PasswordCredential,
        enabled: bool,
        status: str,
        last_error: str | None,
        idempotency_key: str | None,
        request_hash: str | None,
        initial_access: tuple[str, str] | None = None,
        initial_accesses: tuple[tuple[str, str], ...] = (),
        audit_operation: str = "tenant_account.create",
    ) -> tuple[GatewayAccount, bool]:
        if not tenant_id or not actor_user_id:
            raise ValueError("Tenant account identifiers are required")
        if idempotency_key is not None and request_hash is None:
            raise ValueError("Tenant account idempotency requires a request hash")
        access_entries = (
            (initial_access,) if initial_access is not None else ()
        ) + initial_accesses
        if len(access_entries) > 500 or len({entry[0] for entry in access_entries}) != len(
            access_entries
        ):
            raise ValueError("Initial account access is invalid")
        for initial_user_id, initial_permission in access_entries:
            if not initial_user_id or initial_permission not in {"read", "read_write"}:
                raise ValueError("Initial account access is invalid")
        now = _utc_now()
        account_ref = f"acct_{secrets.token_urlsafe(24)}"
        account = GatewayAccount(
            account_ref=account_ref,
            tenant_id=tenant_id,
            owner_type="tenant",
            owner_user_id=None,
            kind=kind,
            label=label,
            base_url=base_url,
            credential=credential,
            status=status,
            enabled=enabled,
            last_checked_at=now,
            last_error=last_error,
            created_at=now,
            updated_at=now,
        )
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            if idempotency_key is not None:
                existing = connection.execute(
                    """
                    SELECT request_hash, account_ref FROM tenant_account_idempotency
                    WHERE tenant_id = ? AND idempotency_key = ?
                    """,
                    (tenant_id, idempotency_key),
                ).fetchone()
                if existing is not None:
                    if existing["request_hash"] != request_hash:
                        raise ValueError("Idempotency key was already used for another request")
                    stored = self._get_account_for_tenant(
                        connection, tenant_id, str(existing["account_ref"])
                    )
                    if stored is None or stored.owner_type != "tenant":
                        raise RuntimeError("Idempotent tenant account result is unavailable")
                    connection.commit()
                    return stored, False
            account_count = int(
                connection.execute(
                    """
                    SELECT COUNT(*) FROM dav_accounts
                    WHERE tenant_id = ? AND owner_type = 'tenant'
                    """,
                    (tenant_id,),
                ).fetchone()[0]
            )
            if account_count >= self._max_accounts_per_tenant:
                raise OverflowError("Tenant account limit reached")
            self._insert_account(connection, account)
            if idempotency_key is not None:
                connection.execute(
                    """
                    INSERT INTO tenant_account_idempotency
                      (tenant_id, idempotency_key, request_hash, account_ref, created_at)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (tenant_id, idempotency_key, request_hash, account_ref, now),
                )
            for initial_user_id, initial_permission in access_entries:
                connection.execute(
                    """
                    INSERT INTO dav_account_grants (
                      account_ref, tenant_id, user_id, permission, enabled,
                      updated_by, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, 1, ?, ?, ?)
                    """,
                    (
                        account_ref,
                        tenant_id,
                        initial_user_id,
                        initial_permission,
                        actor_user_id,
                        now,
                        now,
                    ),
                )
                resulting = connection.execute(
                    """
                    SELECT * FROM dav_account_grants
                    WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                    """,
                    (account_ref, tenant_id, initial_user_id),
                ).fetchone()
                if resulting is None:  # pragma: no cover - defensive
                    raise RuntimeError("Initial account grant was not saved")
                self._audit_account_grant(
                    connection,
                    account_ref=account_ref,
                    tenant_id=tenant_id,
                    user_id=initial_user_id,
                    actor_id=actor_user_id,
                    operation="account_grant.create",
                    previous=None,
                    resulting=resulting,
                    created_at=now,
                )
            self._audit_tenant_account(
                connection,
                account,
                actor_user_id=actor_user_id,
                operation=audit_operation,
                outcome="success",
            )
            connection.commit()
        return account, True

    def list_tenant_accounts(self, tenant_id: str, *, limit: int) -> list[GatewayAccount]:
        if limit < 1:
            raise ValueError("Tenant account limit must be positive")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM dav_accounts
                WHERE tenant_id = ? AND owner_type = 'tenant'
                ORDER BY created_at, account_ref LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [self._decode_account(row) for row in rows]

    def list_tenant_account_audit(self, tenant_id: str, *, limit: int) -> list[TenantAccountAudit]:
        if limit < 1:
            raise ValueError("Tenant account audit limit must be positive")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM tenant_account_audit
                WHERE tenant_id = ? ORDER BY id DESC LIMIT ?
                """,
                (tenant_id, limit),
            ).fetchall()
        return [_tenant_account_audit_from_row(row) for row in rows]

    def list_accounts(self, tenant_id: str, user_id: str, *, limit: int) -> list[GatewayAccount]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM dav_accounts
                WHERE tenant_id = ? AND user_id = ?
                ORDER BY created_at, account_ref LIMIT ?
                """,
                (tenant_id, user_id, limit),
            ).fetchall()
            return [self._decode_account(row) for row in rows]

    def get_account(self, tenant_id: str, user_id: str, account_ref: str) -> GatewayAccount | None:
        with self._connect() as connection:
            return self._get_account(connection, tenant_id, user_id, account_ref)

    def get_account_for_tenant(self, tenant_id: str, account_ref: str) -> GatewayAccount | None:
        with self._connect() as connection:
            return self._get_account_for_tenant(connection, tenant_id, account_ref)

    def list_accounts_for_subject(
        self,
        tenant_id: str,
        user_id: str,
        *,
        permission: Literal["read", "write"],
        limit: int,
    ) -> list[GatewayAccount]:
        if permission not in {"read", "write"}:
            raise ValueError("Account permission must be read or write")
        if limit < 1:
            raise ValueError("Account access limit must be positive")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT account.* FROM dav_accounts AS account
                WHERE account.tenant_id = ?
                  AND account.enabled = 1
                  AND (
                    (
                      account.owner_type = 'user'
                      AND account.owner_user_id = ?
                    )
                    OR (
                      account.owner_type = 'tenant'
                      AND EXISTS (
                        SELECT 1 FROM dav_account_grants AS account_grant
                        WHERE account_grant.account_ref = account.account_ref
                          AND account_grant.tenant_id = account.tenant_id
                          AND account_grant.user_id IN (?, '*')
                          AND account_grant.enabled = 1
                          AND (? = 'read' OR account_grant.permission = 'read_write')
                      )
                    )
                  )
                ORDER BY account.created_at, account.account_ref
                LIMIT ?
                """,
                (tenant_id, user_id, user_id, permission, limit),
            ).fetchall()
        return [self._decode_account(row) for row in rows]

    def account_grant_access(
        self, account_ref: str, tenant_id: str, user_id: str
    ) -> tuple[Literal["read", "read_write"], Literal["exact_grant", "tenant_grant"]] | None:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT user_id, permission FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ?
                  AND user_id IN (?, '*') AND enabled = 1
                """,
                (account_ref, tenant_id, user_id),
            ).fetchall()
        if not rows:
            return None
        permission: Literal["read", "read_write"] = (
            "read_write" if any(str(row["permission"]) == "read_write" for row in rows) else "read"
        )
        source: Literal["exact_grant", "tenant_grant"] = (
            "exact_grant"
            if any(
                str(row["user_id"]) == user_id and str(row["permission"]) == permission
                for row in rows
            )
            else "tenant_grant"
        )
        return permission, source

    def update_account(self, account: GatewayAccount, *, audit_operation: str) -> GatewayAccount:
        updated = replace(account, updated_at=_utc_now())
        encrypted = self._encrypt_account(updated)
        with self._connect() as connection:
            cursor = connection.execute(
                """
                UPDATE dav_accounts SET
                  label_cipher = ?, base_url_cipher = ?, auth_cipher = ?, wrapped_dek = ?,
                  key_version = ?, aad_version = ?, auth_type = ?, auth_mode = ?, status = ?,
                  enabled = ?, last_checked_at = ?, last_error = ?, updated_at = ?
                WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                """,
                (
                    encrypted["label_cipher"],
                    encrypted["base_url_cipher"],
                    encrypted["auth_cipher"],
                    encrypted["wrapped_dek"],
                    encrypted["key_version"],
                    encrypted["aad_version"],
                    "password",
                    updated.credential.mode,
                    updated.status,
                    int(updated.enabled),
                    updated.last_checked_at,
                    updated.last_error,
                    updated.updated_at,
                    updated.account_ref,
                    updated.tenant_id,
                    updated.user_id,
                ),
            )
            if cursor.rowcount != 1:
                raise LookupError("Account not found")
            connection.execute(
                "DELETE FROM dav_references WHERE tenant_id = ? AND user_id = ? AND account_ref = ?",
                (updated.tenant_id, updated.user_id, updated.account_ref),
            )
            self._audit(connection, updated, audit_operation, "success")
            connection.commit()
        return updated

    def delete_account(self, tenant_id: str, user_id: str, account_ref: str) -> bool:
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            account = self._get_account(connection, tenant_id, user_id, account_ref)
            if account is None:
                connection.rollback()
                return False
            self._audit(connection, account, "account.delete", "success")
            connection.execute(
                "DELETE FROM dav_references WHERE tenant_id = ? AND user_id = ? AND account_ref = ?",
                (tenant_id, user_id, account_ref),
            )
            connection.execute(
                "DELETE FROM dav_accounts WHERE account_ref = ? AND tenant_id = ? AND user_id = ?",
                (account_ref, tenant_id, user_id),
            )
            connection.commit()
            return True

    def update_tenant_account(
        self,
        account: GatewayAccount,
        *,
        actor_user_id: str,
        audit_operation: str,
    ) -> GatewayAccount:
        if account.owner_type != "tenant" or account.owner_user_id is not None:
            raise ValueError("Tenant account ownership is required")
        if not actor_user_id:
            raise ValueError("Tenant account actor is required")
        updated = replace(account, updated_at=_utc_now())
        encrypted = self._encrypt_account(updated)
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            cursor = connection.execute(
                """
                UPDATE dav_accounts SET
                  label_cipher = ?, base_url_cipher = ?, auth_cipher = ?, wrapped_dek = ?,
                  key_version = ?, aad_version = ?, auth_type = ?, auth_mode = ?, status = ?,
                  enabled = ?, last_checked_at = ?, last_error = ?, updated_at = ?
                WHERE account_ref = ? AND tenant_id = ? AND owner_type = 'tenant'
                """,
                (
                    encrypted["label_cipher"],
                    encrypted["base_url_cipher"],
                    encrypted["auth_cipher"],
                    encrypted["wrapped_dek"],
                    encrypted["key_version"],
                    encrypted["aad_version"],
                    "password",
                    updated.credential.mode,
                    updated.status,
                    int(updated.enabled),
                    updated.last_checked_at,
                    updated.last_error,
                    updated.updated_at,
                    updated.account_ref,
                    updated.tenant_id,
                ),
            )
            if cursor.rowcount != 1:
                raise LookupError("Tenant account not found")
            connection.execute(
                "DELETE FROM dav_references WHERE tenant_id = ? AND account_ref = ?",
                (updated.tenant_id, updated.account_ref),
            )
            self._audit_tenant_account(
                connection,
                updated,
                actor_user_id=actor_user_id,
                operation=audit_operation,
                outcome="success",
            )
            connection.commit()
        return updated

    def delete_tenant_account(
        self, tenant_id: str, account_ref: str, *, actor_user_id: str
    ) -> bool:
        if not actor_user_id:
            raise ValueError("Tenant account actor is required")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            account = self._get_account_for_tenant(connection, tenant_id, account_ref)
            if account is None or account.owner_type != "tenant":
                connection.rollback()
                return False
            self._audit_tenant_account(
                connection,
                account,
                actor_user_id=actor_user_id,
                operation="tenant_account.delete",
                outcome="success",
            )
            connection.execute(
                "DELETE FROM dav_references WHERE tenant_id = ? AND account_ref = ?",
                (tenant_id, account_ref),
            )
            connection.execute(
                """
                DELETE FROM dav_accounts
                WHERE account_ref = ? AND tenant_id = ? AND owner_type = 'tenant'
                """,
                (account_ref, tenant_id),
            )
            connection.commit()
            return True

    def _insert_account(self, connection: sqlite3.Connection, account: GatewayAccount) -> None:
        encrypted = self._encrypt_account(account)
        connection.execute(
            """
            INSERT INTO dav_accounts (
              account_ref, tenant_id, user_id, owner_type, owner_user_id, aad_version, kind,
              label_cipher, base_url_cipher, auth_cipher, wrapped_dek, key_version, auth_type,
              auth_mode, status, enabled, last_checked_at, last_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account.account_ref,
                account.tenant_id,
                account.owner_user_id or "",
                account.owner_type,
                account.owner_user_id,
                encrypted["aad_version"],
                account.kind,
                encrypted["label_cipher"],
                encrypted["base_url_cipher"],
                encrypted["auth_cipher"],
                encrypted["wrapped_dek"],
                encrypted["key_version"],
                "password",
                account.credential.mode,
                account.status,
                int(account.enabled),
                account.last_checked_at,
                account.last_error,
                account.created_at,
                account.updated_at,
            ),
        )

    def _get_account_for_tenant(
        self, connection: sqlite3.Connection, tenant_id: str, account_ref: str
    ) -> GatewayAccount | None:
        row = connection.execute(
            """
            SELECT * FROM dav_accounts
            WHERE tenant_id = ? AND account_ref = ?
            """,
            (tenant_id, account_ref),
        ).fetchone()
        return self._decode_account(row) if row is not None else None

    def _get_account(
        self, connection: sqlite3.Connection, tenant_id: str, user_id: str, account_ref: str
    ) -> GatewayAccount | None:
        row = connection.execute(
            """
            SELECT * FROM dav_accounts
            WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
            """,
            (account_ref, tenant_id, user_id),
        ).fetchone()
        return self._decode_account(row) if row is not None else None

    def _encrypt_account(self, account: GatewayAccount) -> dict[str, bytes | int]:
        data_key = self._cipher.new_data_key()
        owner_aad = _account_aad_v2(
            account.tenant_id,
            account.owner_type,
            account.owner_user_id,
            account.account_ref,
        )
        key_version, wrapped = self._cipher.wrap_data_key(data_key, owner_aad=owner_aad)
        auth = json.dumps(
            {
                "username": account.credential.username,
                "password": account.credential.password,
                "mode": account.credential.mode,
            },
            separators=(",", ":"),
        )
        return {
            "label_cipher": self._cipher.encrypt_field(
                data_key, account.label, aad=owner_aad + b"|label"
            ),
            "base_url_cipher": self._cipher.encrypt_field(
                data_key, account.base_url, aad=owner_aad + b"|base_url"
            ),
            "auth_cipher": self._cipher.encrypt_field(data_key, auth, aad=owner_aad + b"|auth"),
            "wrapped_dek": wrapped,
            "key_version": key_version,
            "aad_version": 2,
        }

    def _decode_account(self, row: sqlite3.Row) -> GatewayAccount:
        owner_type = str(row["owner_type"])
        owner_user_id = str(row["owner_user_id"]) if row["owner_user_id"] is not None else None
        aad_version = int(row["aad_version"])
        if aad_version == 1:
            owner_aad = _account_aad_v1(
                str(row["tenant_id"]), str(row["user_id"]), str(row["account_ref"])
            )
        elif aad_version == 2:
            owner_aad = _account_aad_v2(
                str(row["tenant_id"]), owner_type, owner_user_id, str(row["account_ref"])
            )
        else:
            raise RuntimeError("Account encryption AAD version is unsupported")
        data_key = self._cipher.unwrap_data_key(
            row["wrapped_dek"], key_version=row["key_version"], owner_aad=owner_aad
        )
        auth = json.loads(
            self._cipher.decrypt_field(data_key, row["auth_cipher"], aad=owner_aad + b"|auth")
        )
        return GatewayAccount(
            account_ref=row["account_ref"],
            tenant_id=row["tenant_id"],
            owner_type=owner_type,
            owner_user_id=owner_user_id,
            kind=row["kind"],
            label=self._cipher.decrypt_field(
                data_key, row["label_cipher"], aad=owner_aad + b"|label"
            ),
            base_url=self._cipher.decrypt_field(
                data_key, row["base_url_cipher"], aad=owner_aad + b"|base_url"
            ),
            credential=PasswordCredential(
                username=auth["username"], password=auth["password"], mode=auth["mode"]
            ),
            status=row["status"],
            enabled=bool(row["enabled"]),
            last_checked_at=row["last_checked_at"],
            last_error=row["last_error"],
            created_at=row["created_at"],
            updated_at=row["updated_at"],
        )

    def list_account_grants(self, account_ref: str, tenant_id: str) -> list[AccountGrant]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ?
                ORDER BY user_id
                """,
                (account_ref, tenant_id),
            ).fetchall()
        return [_account_grant_from_row(row) for row in rows]

    def list_account_grant_audit(
        self,
        tenant_id: str,
        *,
        limit: int,
        before_id: int | None = None,
    ) -> list[AccountGrantAudit]:
        if limit < 1:
            raise ValueError("Account grant audit limit must be positive")
        if before_id is not None and before_id < 1:
            raise ValueError("Account grant audit cursor must be positive")
        query = """
            SELECT * FROM dav_account_grant_audit
            WHERE tenant_id = ?
        """
        parameters: list[str | int] = [tenant_id]
        if before_id is not None:
            query += " AND id < ?"
            parameters.append(before_id)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_account_grant_audit_from_row(row) for row in rows]

    def upsert_account_grant(
        self,
        *,
        account_ref: str,
        tenant_id: str,
        user_id: str,
        permission: str,
        enabled: bool,
        updated_by: str,
    ) -> AccountGrant:
        if not account_ref or not tenant_id or not user_id or not updated_by:
            raise ValueError("Account grant identifiers are required")
        if permission not in {"read", "read_write"}:
            raise ValueError("Account grant permission must be read or read_write")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_tenant_account(connection, account_ref, tenant_id)
            previous = connection.execute(
                """
                SELECT * FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                """,
                (account_ref, tenant_id, user_id),
            ).fetchone()
            if previous is None:
                grant_count = int(
                    connection.execute(
                        """
                        SELECT COUNT(*) FROM dav_account_grants
                        WHERE account_ref = ? AND tenant_id = ?
                        """,
                        (account_ref, tenant_id),
                    ).fetchone()[0]
                )
                if grant_count >= 500:
                    raise OverflowError("Account grant limit reached")
            connection.execute(
                """
                INSERT INTO dav_account_grants (
                  account_ref, tenant_id, user_id, permission, enabled,
                  updated_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(account_ref, tenant_id, user_id) DO UPDATE SET
                  permission = excluded.permission,
                  enabled = excluded.enabled,
                  updated_by = excluded.updated_by,
                  updated_at = excluded.updated_at
                """,
                (
                    account_ref,
                    tenant_id,
                    user_id,
                    permission,
                    int(enabled),
                    updated_by,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                """,
                (account_ref, tenant_id, user_id),
            ).fetchone()
            if row is None:  # pragma: no cover - defensive
                raise RuntimeError("Account grant was not saved")
            self._audit_account_grant(
                connection,
                account_ref=account_ref,
                tenant_id=tenant_id,
                user_id=user_id,
                actor_id=updated_by,
                operation=_account_grant_operation(previous, row),
                previous=previous,
                resulting=row,
                created_at=now,
            )
            connection.commit()
        return _account_grant_from_row(row)

    def delete_account_grant(
        self,
        account_ref: str,
        tenant_id: str,
        user_id: str,
        *,
        deleted_by: str,
    ) -> bool:
        if not deleted_by:
            raise ValueError("Account grant actor is required")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            self._require_tenant_account(connection, account_ref, tenant_id)
            previous = connection.execute(
                """
                SELECT * FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                """,
                (account_ref, tenant_id, user_id),
            ).fetchone()
            if previous is None:
                connection.rollback()
                return False
            cursor = connection.execute(
                """
                DELETE FROM dav_account_grants
                WHERE account_ref = ? AND tenant_id = ? AND user_id = ?
                """,
                (account_ref, tenant_id, user_id),
            )
            self._audit_account_grant(
                connection,
                account_ref=account_ref,
                tenant_id=tenant_id,
                user_id=user_id,
                actor_id=deleted_by,
                operation="account_grant.delete",
                previous=previous,
                resulting=None,
                created_at=_utc_now(),
            )
            connection.commit()
        return cursor.rowcount > 0

    @staticmethod
    def _require_tenant_account(
        connection: sqlite3.Connection, account_ref: str, tenant_id: str
    ) -> None:
        row = connection.execute(
            """
            SELECT owner_type FROM dav_accounts
            WHERE account_ref = ? AND tenant_id = ?
            """,
            (account_ref, tenant_id),
        ).fetchone()
        if row is None or str(row["owner_type"]) != "tenant":
            raise LookupError("Tenant-owned account not found")

    def resource_access(
        self,
        resource_id: str,
        tenant_id: str,
        user_id: str,
        *,
        permission: str,
    ) -> bool | None:
        if permission not in {"read", "write"}:
            raise ValueError("Resource permission must be read or write")
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT tenant_id, user_id, permission, enabled
                FROM dav_resource_grants
                WHERE resource_id = ?
                """,
                (resource_id,),
            ).fetchall()
        if not rows:
            return None
        for row in rows:
            if not bool(row["enabled"]):
                continue
            if str(row["tenant_id"]) != tenant_id or str(row["user_id"]) not in {"*", user_id}:
                continue
            granted = str(row["permission"])
            if permission == "read" or granted == "read_write":
                return True
        return False

    def list_resource_grants(self, tenant_id: str) -> list[ResourceGrant]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT * FROM dav_resource_grants
                WHERE tenant_id = ?
                ORDER BY resource_id, user_id
                """,
                (tenant_id,),
            ).fetchall()
        return [_resource_grant_from_row(row) for row in rows]

    def list_resource_grant_audit(
        self,
        tenant_id: str,
        *,
        limit: int,
        before_id: int | None = None,
    ) -> list[ResourceGrantAudit]:
        if limit < 1:
            raise ValueError("Resource grant audit limit must be positive")
        if before_id is not None and before_id < 1:
            raise ValueError("Resource grant audit cursor must be positive")
        query = """
            SELECT * FROM dav_resource_grant_audit
            WHERE tenant_id = ?
        """
        parameters: list[str | int] = [tenant_id]
        if before_id is not None:
            query += " AND id < ?"
            parameters.append(before_id)
        query += " ORDER BY id DESC LIMIT ?"
        parameters.append(limit)
        with self._connect() as connection:
            rows = connection.execute(query, parameters).fetchall()
        return [_resource_grant_audit_from_row(row) for row in rows]

    def upsert_resource_grant(
        self,
        *,
        resource_id: str,
        tenant_id: str,
        user_id: str,
        permission: str,
        enabled: bool,
        updated_by: str,
    ) -> ResourceGrant:
        if not resource_id or not tenant_id or not user_id or not updated_by:
            raise ValueError("Resource grant identifiers are required")
        if permission not in {"read", "read_write"}:
            raise ValueError("Resource grant permission must be read or read_write")
        now = _utc_now()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                """
                SELECT * FROM dav_resource_grants
                WHERE resource_id = ? AND tenant_id = ? AND user_id = ?
                """,
                (resource_id, tenant_id, user_id),
            ).fetchone()
            connection.execute(
                """
                INSERT INTO dav_resource_grants (
                  resource_id, tenant_id, user_id, permission, enabled,
                  updated_by, created_at, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(resource_id, tenant_id, user_id) DO UPDATE SET
                  permission = excluded.permission,
                  enabled = excluded.enabled,
                  updated_by = excluded.updated_by,
                  updated_at = excluded.updated_at
                """,
                (
                    resource_id,
                    tenant_id,
                    user_id,
                    permission,
                    int(enabled),
                    updated_by,
                    now,
                    now,
                ),
            )
            row = connection.execute(
                """
                SELECT * FROM dav_resource_grants
                WHERE resource_id = ? AND tenant_id = ? AND user_id = ?
                """,
                (resource_id, tenant_id, user_id),
            ).fetchone()
            if row is None:  # pragma: no cover - defensive
                raise RuntimeError("Resource grant was not saved")
            self._audit_resource_grant(
                connection,
                resource_id=resource_id,
                tenant_id=tenant_id,
                user_id=user_id,
                actor_id=updated_by,
                operation=_resource_grant_operation(previous, row),
                previous=previous,
                resulting=row,
                created_at=now,
            )
            connection.commit()
        return _resource_grant_from_row(row)

    def delete_resource_grant(
        self,
        resource_id: str,
        tenant_id: str,
        user_id: str,
        *,
        deleted_by: str,
    ) -> bool:
        if not deleted_by:
            raise ValueError("Resource grant actor is required")
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            previous = connection.execute(
                """
                SELECT * FROM dav_resource_grants
                WHERE resource_id = ? AND tenant_id = ? AND user_id = ?
                """,
                (resource_id, tenant_id, user_id),
            ).fetchone()
            if previous is None:
                connection.rollback()
                return False
            cursor = connection.execute(
                """
                DELETE FROM dav_resource_grants
                WHERE resource_id = ? AND tenant_id = ? AND user_id = ?
                """,
                (resource_id, tenant_id, user_id),
            )
            self._audit_resource_grant(
                connection,
                resource_id=resource_id,
                tenant_id=tenant_id,
                user_id=user_id,
                actor_id=deleted_by,
                operation="resource_grant.delete",
                previous=previous,
                resulting=None,
                created_at=_utc_now(),
            )
            connection.commit()
        return cursor.rowcount > 0

    def request_hash(self, payload: dict[str, Any]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return self._cipher.fingerprint(encoded)

    def put_reference(
        self,
        *,
        reference: str,
        tenant_id: str,
        user_id: str,
        account_ref: str,
        account_updated_at: str,
        reference_type: str,
        payload: bytes,
        expires_at: float,
    ) -> None:
        token_hash = _reference_hash(reference)
        aad = _reference_aad(
            tenant_id,
            user_id,
            account_ref,
            account_updated_at,
            reference_type,
            token_hash,
        )
        key_version, payload_cipher = self._cipher.encrypt_reference(payload, aad=aad)
        now = time.time()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute("DELETE FROM dav_references WHERE expires_at <= ?", (now,))
            count = int(
                connection.execute(
                    "SELECT COUNT(*) FROM dav_references WHERE tenant_id = ? AND user_id = ?",
                    (tenant_id, user_id),
                ).fetchone()[0]
            )
            if count >= 10_000:
                connection.execute(
                    """
                    DELETE FROM dav_references WHERE token_hash = (
                      SELECT token_hash FROM dav_references
                      WHERE tenant_id = ? AND user_id = ? ORDER BY expires_at, created_at LIMIT 1
                    )
                    """,
                    (tenant_id, user_id),
                )
            connection.execute(
                """
                INSERT INTO dav_references (
                  token_hash, tenant_id, user_id, account_ref, account_updated_at,
                  reference_type, key_version, payload_cipher, expires_at, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(token_hash) DO UPDATE SET
                  tenant_id = excluded.tenant_id,
                  user_id = excluded.user_id,
                  account_ref = excluded.account_ref,
                  account_updated_at = excluded.account_updated_at,
                  reference_type = excluded.reference_type,
                  key_version = excluded.key_version,
                  payload_cipher = excluded.payload_cipher,
                  expires_at = excluded.expires_at,
                  created_at = excluded.created_at
                """,
                (
                    token_hash,
                    tenant_id,
                    user_id,
                    account_ref,
                    account_updated_at,
                    reference_type,
                    key_version,
                    payload_cipher,
                    expires_at,
                    now,
                ),
            )
            connection.commit()

    def get_reference(self, tenant_id: str, user_id: str, reference: str) -> StoredReference | None:
        token_hash = _reference_hash(reference)
        now = time.time()
        with self._connect() as connection:
            row = connection.execute(
                """
                SELECT * FROM dav_references
                WHERE token_hash = ? AND tenant_id = ? AND user_id = ?
                """,
                (token_hash, tenant_id, user_id),
            ).fetchone()
            if row is None:
                return None
            if float(row["expires_at"]) <= now:
                connection.execute("DELETE FROM dav_references WHERE token_hash = ?", (token_hash,))
                connection.commit()
                return None
        return self._decode_reference(reference, row)

    def list_references(
        self, tenant_id: str, user_id: str, account_ref: str
    ) -> list[StoredReference]:
        now = time.time()
        with self._connect() as connection:
            connection.execute("DELETE FROM dav_references WHERE expires_at <= ?", (now,))
            rows = connection.execute(
                """
                SELECT * FROM dav_references
                WHERE tenant_id = ? AND user_id = ? AND account_ref = ?
                ORDER BY created_at
                """,
                (tenant_id, user_id, account_ref),
            ).fetchall()
            connection.commit()
        references: list[StoredReference] = []
        for row in rows:
            payload = self._decode_reference_payload(row)
            decoded = json.loads(payload)
            reference = decoded.get("reference")
            if not isinstance(reference, str) or not reference:
                raise RuntimeError("Stored reference payload is invalid")
            references.append(self._stored_reference(reference, row, payload))
        return references

    def delete_reference(self, tenant_id: str, user_id: str, reference: str) -> None:
        with self._connect() as connection:
            connection.execute(
                "DELETE FROM dav_references WHERE token_hash = ? AND tenant_id = ? AND user_id = ?",
                (_reference_hash(reference), tenant_id, user_id),
            )
            connection.commit()

    def rotate_references_to_active_key(self) -> int:
        rotated = 0
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute(
                "SELECT * FROM dav_references WHERE key_version != ?",
                (self._cipher.active_version,),
            ).fetchall()
            for row in rows:
                payload = self._decode_reference_payload(row)
                aad = _reference_aad(
                    str(row["tenant_id"]),
                    str(row["user_id"]),
                    str(row["account_ref"]),
                    str(row["account_updated_at"]),
                    str(row["reference_type"]),
                    str(row["token_hash"]),
                )
                key_version, payload_cipher = self._cipher.encrypt_reference(payload, aad=aad)
                connection.execute(
                    "UPDATE dav_references SET key_version = ?, payload_cipher = ? WHERE token_hash = ?",
                    (key_version, payload_cipher, str(row["token_hash"])),
                )
                rotated += 1
            connection.commit()
        return rotated

    def _decode_reference(self, reference: str, row: sqlite3.Row) -> StoredReference:
        payload = self._decode_reference_payload(row)
        decoded = json.loads(payload)
        if decoded.get("reference") != reference:
            raise RuntimeError("Stored reference token authentication failed")
        return self._stored_reference(reference, row, payload)

    def _decode_reference_payload(self, row: sqlite3.Row) -> bytes:
        aad = _reference_aad(
            str(row["tenant_id"]),
            str(row["user_id"]),
            str(row["account_ref"]),
            str(row["account_updated_at"]),
            str(row["reference_type"]),
            str(row["token_hash"]),
        )
        return self._cipher.decrypt_reference(
            bytes(row["payload_cipher"]),
            key_version=int(row["key_version"]),
            aad=aad,
        )

    @staticmethod
    def _stored_reference(reference: str, row: sqlite3.Row, payload: bytes) -> StoredReference:
        return StoredReference(
            reference=reference,
            tenant_id=str(row["tenant_id"]),
            user_id=str(row["user_id"]),
            account_ref=str(row["account_ref"]),
            account_updated_at=str(row["account_updated_at"]),
            reference_type=str(row["reference_type"]),
            payload=payload,
            expires_at=float(row["expires_at"]),
        )

    @staticmethod
    def _audit_tenant_account(
        connection: sqlite3.Connection,
        account: GatewayAccount,
        *,
        actor_user_id: str,
        operation: str,
        outcome: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO tenant_account_audit
              (tenant_id, account_ref, actor_user_id, operation, outcome, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account.tenant_id,
                account.account_ref,
                actor_user_id,
                operation,
                outcome,
                _utc_now(),
            ),
        )

    @staticmethod
    def _audit_account_grant(
        connection: sqlite3.Connection,
        *,
        account_ref: str,
        tenant_id: str,
        user_id: str,
        actor_id: str,
        operation: str,
        previous: sqlite3.Row | None,
        resulting: sqlite3.Row | None,
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO dav_account_grant_audit (
              account_ref, tenant_id, user_id, actor_id, operation,
              previous_permission, previous_enabled,
              resulting_permission, resulting_enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_ref,
                tenant_id,
                user_id,
                actor_id,
                operation,
                str(previous["permission"]) if previous is not None else None,
                int(previous["enabled"]) if previous is not None else None,
                str(resulting["permission"]) if resulting is not None else None,
                int(resulting["enabled"]) if resulting is not None else None,
                created_at,
            ),
        )

    @staticmethod
    def _audit_resource_grant(
        connection: sqlite3.Connection,
        *,
        resource_id: str,
        tenant_id: str,
        user_id: str,
        actor_id: str,
        operation: str,
        previous: sqlite3.Row | None,
        resulting: sqlite3.Row | None,
        created_at: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO dav_resource_grant_audit (
              resource_id, tenant_id, user_id, actor_id, operation,
              previous_permission, previous_enabled,
              resulting_permission, resulting_enabled, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                resource_id,
                tenant_id,
                user_id,
                actor_id,
                operation,
                str(previous["permission"]) if previous is not None else None,
                int(previous["enabled"]) if previous is not None else None,
                str(resulting["permission"]) if resulting is not None else None,
                int(resulting["enabled"]) if resulting is not None else None,
                created_at,
            ),
        )

    @staticmethod
    def _audit(
        connection: sqlite3.Connection,
        account: GatewayAccount,
        operation: str,
        outcome: str,
    ) -> None:
        connection.execute(
            """
            INSERT INTO gateway_audit
              (tenant_id, user_id, account_ref, operation, outcome, created_at)
            VALUES (?, ?, ?, ?, ?, ?)
            """,
            (
                account.tenant_id,
                account.user_id,
                account.account_ref,
                operation,
                outcome,
                _utc_now(),
            ),
        )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, timeout=10)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        return connection

    def _migrate(self) -> None:
        with self._connect() as connection:
            connection.executescript(
                """
                PRAGMA journal_mode = WAL;
                CREATE TABLE IF NOT EXISTS dav_accounts (
                  account_ref TEXT PRIMARY KEY,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  owner_type TEXT NOT NULL DEFAULT 'user'
                    CHECK (owner_type IN ('user', 'tenant')),
                  owner_user_id TEXT,
                  aad_version INTEGER NOT NULL DEFAULT 1 CHECK (aad_version IN (1, 2)),
                  kind TEXT NOT NULL CHECK (kind = 'caldav'),
                  label_cipher BLOB NOT NULL,
                  base_url_cipher BLOB NOT NULL,
                  auth_cipher BLOB NOT NULL,
                  wrapped_dek BLOB NOT NULL,
                  key_version INTEGER NOT NULL,
                  auth_type TEXT NOT NULL CHECK (auth_type = 'password'),
                  auth_mode TEXT NOT NULL,
                  status TEXT NOT NULL,
                  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                  last_checked_at TEXT,
                  last_error TEXT,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS dav_accounts_owner
                  ON dav_accounts (tenant_id, user_id, created_at);
                CREATE UNIQUE INDEX IF NOT EXISTS dav_accounts_tenant_ref
                  ON dav_accounts (account_ref, tenant_id);

                CREATE TABLE IF NOT EXISTS account_idempotency (
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL,
                  request_hash TEXT NOT NULL,
                  account_ref TEXT NOT NULL REFERENCES dav_accounts(account_ref) ON DELETE CASCADE,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY (tenant_id, user_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS tenant_account_idempotency (
                  tenant_id TEXT NOT NULL,
                  idempotency_key TEXT NOT NULL,
                  request_hash TEXT NOT NULL,
                  account_ref TEXT NOT NULL REFERENCES dav_accounts(account_ref) ON DELETE CASCADE,
                  created_at TEXT NOT NULL,
                  PRIMARY KEY (tenant_id, idempotency_key)
                );

                CREATE TABLE IF NOT EXISTS dav_account_grants (
                  account_ref TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  permission TEXT NOT NULL CHECK (permission IN ('read', 'read_write')),
                  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                  updated_by TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  PRIMARY KEY (account_ref, tenant_id, user_id),
                  FOREIGN KEY (account_ref, tenant_id)
                    REFERENCES dav_accounts(account_ref, tenant_id) ON DELETE CASCADE
                );
                CREATE INDEX IF NOT EXISTS dav_account_grants_subject
                  ON dav_account_grants (tenant_id, user_id, account_ref);

                CREATE TABLE IF NOT EXISTS dav_account_grant_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  account_ref TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  actor_id TEXT NOT NULL,
                  operation TEXT NOT NULL,
                  previous_permission TEXT CHECK (
                    previous_permission IS NULL OR previous_permission IN ('read', 'read_write')
                  ),
                  previous_enabled INTEGER CHECK (
                    previous_enabled IS NULL OR previous_enabled IN (0, 1)
                  ),
                  resulting_permission TEXT CHECK (
                    resulting_permission IS NULL OR resulting_permission IN ('read', 'read_write')
                  ),
                  resulting_enabled INTEGER CHECK (
                    resulting_enabled IS NULL OR resulting_enabled IN (0, 1)
                  ),
                  created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS dav_account_grant_audit_tenant
                  ON dav_account_grant_audit (tenant_id, id DESC);
                CREATE TRIGGER IF NOT EXISTS dav_account_grant_audit_no_update
                  BEFORE UPDATE ON dav_account_grant_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'account grant audit is append-only');
                  END;
                CREATE TRIGGER IF NOT EXISTS dav_account_grant_audit_no_delete
                  BEFORE DELETE ON dav_account_grant_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'account grant audit is append-only');
                  END;

                CREATE TABLE IF NOT EXISTS dav_references (
                  token_hash TEXT PRIMARY KEY,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  account_ref TEXT NOT NULL,
                  account_updated_at TEXT NOT NULL,
                  reference_type TEXT NOT NULL,
                  key_version INTEGER NOT NULL,
                  payload_cipher BLOB NOT NULL,
                  expires_at REAL NOT NULL,
                  created_at REAL NOT NULL
                );
                CREATE INDEX IF NOT EXISTS dav_references_owner
                  ON dav_references (tenant_id, user_id, account_ref, reference_type);

                CREATE TABLE IF NOT EXISTS dav_resource_grants (
                  resource_id TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  permission TEXT NOT NULL CHECK (permission IN ('read', 'read_write')),
                  enabled INTEGER NOT NULL CHECK (enabled IN (0, 1)),
                  updated_by TEXT NOT NULL,
                  created_at TEXT NOT NULL,
                  updated_at TEXT NOT NULL,
                  PRIMARY KEY (resource_id, tenant_id, user_id)
                );
                CREATE INDEX IF NOT EXISTS dav_resource_grants_subject
                  ON dav_resource_grants (tenant_id, user_id, resource_id);

                CREATE TABLE IF NOT EXISTS dav_resource_grant_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  resource_id TEXT NOT NULL,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  actor_id TEXT NOT NULL,
                  operation TEXT NOT NULL,
                  previous_permission TEXT CHECK (
                    previous_permission IS NULL OR previous_permission IN ('read', 'read_write')
                  ),
                  previous_enabled INTEGER CHECK (
                    previous_enabled IS NULL OR previous_enabled IN (0, 1)
                  ),
                  resulting_permission TEXT CHECK (
                    resulting_permission IS NULL OR resulting_permission IN ('read', 'read_write')
                  ),
                  resulting_enabled INTEGER CHECK (
                    resulting_enabled IS NULL OR resulting_enabled IN (0, 1)
                  ),
                  created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS dav_resource_grant_audit_tenant
                  ON dav_resource_grant_audit (tenant_id, id DESC);
                CREATE TRIGGER IF NOT EXISTS dav_resource_grant_audit_no_update
                  BEFORE UPDATE ON dav_resource_grant_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'resource grant audit is append-only');
                  END;
                CREATE TRIGGER IF NOT EXISTS dav_resource_grant_audit_no_delete
                  BEFORE DELETE ON dav_resource_grant_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'resource grant audit is append-only');
                  END;

                CREATE TABLE IF NOT EXISTS tenant_account_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  tenant_id TEXT NOT NULL,
                  account_ref TEXT NOT NULL,
                  actor_user_id TEXT NOT NULL,
                  operation TEXT NOT NULL,
                  outcome TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS tenant_account_audit_tenant
                  ON tenant_account_audit (tenant_id, id DESC);
                CREATE TRIGGER IF NOT EXISTS tenant_account_audit_no_update
                  BEFORE UPDATE ON tenant_account_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'tenant account audit is append-only');
                  END;
                CREATE TRIGGER IF NOT EXISTS tenant_account_audit_no_delete
                  BEFORE DELETE ON tenant_account_audit
                  BEGIN
                    SELECT RAISE(ABORT, 'tenant account audit is append-only');
                  END;

                CREATE TABLE IF NOT EXISTS gateway_audit (
                  id INTEGER PRIMARY KEY AUTOINCREMENT,
                  tenant_id TEXT NOT NULL,
                  user_id TEXT NOT NULL,
                  account_ref TEXT,
                  operation TEXT NOT NULL,
                  outcome TEXT NOT NULL,
                  created_at TEXT NOT NULL
                );
                PRAGMA user_version = 6;
                """
            )
            account_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(dav_accounts)")
            }
            if "owner_type" not in account_columns:
                connection.execute(
                    """
                    ALTER TABLE dav_accounts ADD COLUMN owner_type TEXT NOT NULL DEFAULT 'user'
                    CHECK (owner_type IN ('user', 'tenant'))
                    """
                )
            if "owner_user_id" not in account_columns:
                connection.execute("ALTER TABLE dav_accounts ADD COLUMN owner_user_id TEXT")
            if "aad_version" not in account_columns:
                connection.execute(
                    """
                    ALTER TABLE dav_accounts ADD COLUMN aad_version INTEGER NOT NULL DEFAULT 1
                    CHECK (aad_version IN (1, 2))
                    """
                )
            connection.execute(
                """
                UPDATE dav_accounts SET owner_user_id = user_id
                WHERE owner_type = 'user' AND owner_user_id IS NULL
                """
            )
            connection.execute(
                """
                CREATE INDEX IF NOT EXISTS dav_accounts_ownership
                ON dav_accounts (tenant_id, owner_type, owner_user_id, created_at)
                """
            )
            reference_columns = {
                str(row[1]) for row in connection.execute("PRAGMA table_info(dav_references)")
            }
            if "payload_cipher" not in reference_columns:
                connection.executescript(
                    """
                    DROP TABLE dav_references;
                    CREATE TABLE dav_references (
                      token_hash TEXT PRIMARY KEY,
                      tenant_id TEXT NOT NULL,
                      user_id TEXT NOT NULL,
                      account_ref TEXT NOT NULL,
                      account_updated_at TEXT NOT NULL,
                      reference_type TEXT NOT NULL,
                      key_version INTEGER NOT NULL,
                      payload_cipher BLOB NOT NULL,
                      expires_at REAL NOT NULL,
                      created_at REAL NOT NULL
                    );
                    CREATE INDEX dav_references_owner
                      ON dav_references (tenant_id, user_id, account_ref, reference_type);
                    """
                )
            connection.execute("PRAGMA user_version = 6")


def _tenant_account_audit_from_row(row: sqlite3.Row) -> TenantAccountAudit:
    return TenantAccountAudit(
        audit_id=int(row["id"]),
        tenant_id=str(row["tenant_id"]),
        account_ref=str(row["account_ref"]),
        actor_user_id=str(row["actor_user_id"]),
        operation=str(row["operation"]),
        outcome=str(row["outcome"]),
        created_at=str(row["created_at"]),
    )


def _account_grant_from_row(row: sqlite3.Row) -> AccountGrant:
    return AccountGrant(
        account_ref=str(row["account_ref"]),
        tenant_id=str(row["tenant_id"]),
        user_id=str(row["user_id"]),
        permission=str(row["permission"]),
        enabled=bool(row["enabled"]),
        updated_by=str(row["updated_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _account_grant_audit_from_row(row: sqlite3.Row) -> AccountGrantAudit:
    return AccountGrantAudit(
        audit_id=int(row["id"]),
        account_ref=str(row["account_ref"]),
        tenant_id=str(row["tenant_id"]),
        user_id=str(row["user_id"]),
        actor_id=str(row["actor_id"]),
        operation=str(row["operation"]),
        previous_permission=(
            str(row["previous_permission"]) if row["previous_permission"] is not None else None
        ),
        previous_enabled=(
            bool(row["previous_enabled"]) if row["previous_enabled"] is not None else None
        ),
        resulting_permission=(
            str(row["resulting_permission"]) if row["resulting_permission"] is not None else None
        ),
        resulting_enabled=(
            bool(row["resulting_enabled"]) if row["resulting_enabled"] is not None else None
        ),
        created_at=str(row["created_at"]),
    )


def _account_grant_operation(previous: sqlite3.Row | None, resulting: sqlite3.Row) -> str:
    if previous is None:
        return "account_grant.create"
    permission_changed = previous["permission"] != resulting["permission"]
    enabled_changed = bool(previous["enabled"]) != bool(resulting["enabled"])
    if permission_changed and enabled_changed:
        return "account_grant.update"
    if permission_changed:
        return "account_grant.permission_change"
    if enabled_changed:
        return "account_grant.enable" if bool(resulting["enabled"]) else "account_grant.disable"
    return "account_grant.touch"


def _resource_grant_from_row(row: sqlite3.Row) -> ResourceGrant:
    return ResourceGrant(
        resource_id=str(row["resource_id"]),
        tenant_id=str(row["tenant_id"]),
        user_id=str(row["user_id"]),
        permission=str(row["permission"]),
        enabled=bool(row["enabled"]),
        updated_by=str(row["updated_by"]),
        created_at=str(row["created_at"]),
        updated_at=str(row["updated_at"]),
    )


def _resource_grant_audit_from_row(row: sqlite3.Row) -> ResourceGrantAudit:
    return ResourceGrantAudit(
        audit_id=int(row["id"]),
        resource_id=str(row["resource_id"]),
        tenant_id=str(row["tenant_id"]),
        user_id=str(row["user_id"]),
        actor_id=str(row["actor_id"]),
        operation=str(row["operation"]),
        previous_permission=(
            str(row["previous_permission"]) if row["previous_permission"] is not None else None
        ),
        previous_enabled=(
            bool(row["previous_enabled"]) if row["previous_enabled"] is not None else None
        ),
        resulting_permission=(
            str(row["resulting_permission"]) if row["resulting_permission"] is not None else None
        ),
        resulting_enabled=(
            bool(row["resulting_enabled"]) if row["resulting_enabled"] is not None else None
        ),
        created_at=str(row["created_at"]),
    )


def _resource_grant_operation(previous: sqlite3.Row | None, resulting: sqlite3.Row) -> str:
    if previous is None:
        return "resource_grant.create"
    permission_changed = previous["permission"] != resulting["permission"]
    enabled_changed = bool(previous["enabled"]) != bool(resulting["enabled"])
    if permission_changed and enabled_changed:
        return "resource_grant.update"
    if permission_changed:
        return "resource_grant.permission_change"
    if enabled_changed:
        return "resource_grant.enable" if bool(resulting["enabled"]) else "resource_grant.disable"
    return "resource_grant.touch"


def _account_aad_v1(tenant_id: str, user_id: str, account_ref: str) -> bytes:
    return f"private-dav|{tenant_id}|{user_id}|{account_ref}".encode()


def _account_aad_v2(
    tenant_id: str,
    owner_type: str,
    owner_user_id: str | None,
    account_ref: str,
) -> bytes:
    ownership = json.dumps(
        [tenant_id, owner_type, owner_user_id, account_ref],
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode()
    return b"private-dav-account-v2|" + ownership


def _reference_hash(reference: str) -> str:
    return hashlib.sha256(reference.encode()).hexdigest()


def _reference_aad(
    tenant_id: str,
    user_id: str,
    account_ref: str,
    account_updated_at: str,
    reference_type: str,
    token_hash: str,
) -> bytes:
    return (
        f"private-dav-reference|{tenant_id}|{user_id}|{account_ref}|{account_updated_at}|"
        f"{reference_type}|{token_hash}"
    ).encode()


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
