from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from pathlib import Path

import pytest
from cryptography.exceptions import InvalidTag

from private_dav_mcp.gateway_store import (
    AccountCipher,
    AccountStore,
    GatewayAccount,
    PasswordCredential,
)


def _cipher() -> AccountCipher:
    return AccountCipher(keyring={1: b"k" * 32}, active_version=1)


def _create_v4_account_database(path: Path, cipher: AccountCipher) -> bytes:
    account_ref = "acct_legacy"
    tenant_id = "tenant-a"
    user_id = "user-a"
    owner_aad = f"private-dav|{tenant_id}|{user_id}|{account_ref}".encode()
    data_key = cipher.new_data_key()
    key_version, wrapped_dek = cipher.wrap_data_key(data_key, owner_aad=owner_aad)
    auth = json.dumps(
        {"username": "legacy-user", "password": "legacy-secret", "mode": "basic"},
        separators=(",", ":"),
    )

    with sqlite3.connect(path) as connection:
        connection.executescript(
            """
            CREATE TABLE dav_accounts (
              account_ref TEXT PRIMARY KEY,
              tenant_id TEXT NOT NULL,
              user_id TEXT NOT NULL,
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
            PRAGMA user_version = 4;
            """
        )
        connection.execute(
            """
            INSERT INTO dav_accounts (
              account_ref, tenant_id, user_id, kind, label_cipher, base_url_cipher, auth_cipher,
              wrapped_dek, key_version, auth_type, auth_mode, status, enabled, last_checked_at,
              last_error, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                account_ref,
                tenant_id,
                user_id,
                "caldav",
                cipher.encrypt_field(data_key, "Legacy calendar", aad=owner_aad + b"|label"),
                cipher.encrypt_field(
                    data_key, "https://dav.example/legacy/", aad=owner_aad + b"|base_url"
                ),
                cipher.encrypt_field(data_key, auth, aad=owner_aad + b"|auth"),
                wrapped_dek,
                key_version,
                "password",
                "basic",
                "ready",
                1,
                "2026-08-10T00:00:00Z",
                None,
                "2026-08-10T00:00:00Z",
                "2026-08-10T00:00:00Z",
            ),
        )
    return wrapped_dek


def test_gateway_account_requires_explicit_valid_ownership() -> None:
    common = {
        "account_ref": "acct_test",
        "tenant_id": "tenant-a",
        "kind": "caldav",
        "label": "Test",
        "base_url": "https://dav.example/",
        "credential": PasswordCredential(username="user", password="secret", mode="basic"),
        "status": "ready",
        "enabled": True,
        "last_checked_at": None,
        "last_error": None,
        "created_at": "2026-08-10T00:00:00Z",
        "updated_at": "2026-08-10T00:00:00Z",
    }

    user_account = GatewayAccount(
        **common,
        owner_type="user",
        owner_user_id="user-a",
    )
    assert user_account.user_id == "user-a"

    tenant_account = GatewayAccount(
        **common,
        owner_type="tenant",
        owner_user_id=None,
    )
    with pytest.raises(RuntimeError, match="do not have an owner user ID"):
        _ = tenant_account.user_id

    with pytest.raises(ValueError, match="require an owner user ID"):
        GatewayAccount(**common, owner_type="user", owner_user_id=None)
    with pytest.raises(ValueError, match="cannot have an owner user ID"):
        GatewayAccount(**common, owner_type="tenant", owner_user_id="user-a")
    with pytest.raises(ValueError, match="must be user or tenant"):
        GatewayAccount(**common, owner_type="shared", owner_user_id=None)


def test_v4_account_migration_backfills_ownership_without_reencrypting(tmp_path: Path) -> None:
    database = tmp_path / "legacy.db"
    cipher = _cipher()
    original_wrapped_dek = _create_v4_account_database(database, cipher)

    store = AccountStore(database, cipher=cipher)
    account = store.get_account("tenant-a", "user-a", "acct_legacy")

    assert account is not None
    assert account.owner_type == "user"
    assert account.owner_user_id == "user-a"
    assert account.label == "Legacy calendar"
    assert account.credential.password == "legacy-secret"
    with sqlite3.connect(database) as connection:
        row = connection.execute(
            """
            SELECT owner_type, owner_user_id, aad_version, wrapped_dek
            FROM dav_accounts WHERE account_ref = 'acct_legacy'
            """
        ).fetchone()
        assert row == ("user", "user-a", 1, original_wrapped_dek)
        assert connection.execute("PRAGMA user_version").fetchone()[0] == 5
        tables = {
            item[0]
            for item in connection.execute(
                "SELECT name FROM sqlite_master WHERE type = 'table'"
            ).fetchall()
        }
        assert {"dav_account_grants", "dav_account_grant_audit"} <= tables

    # The migration is idempotent, and the next account write upgrades encryption AAD to v2.
    AccountStore(database, cipher=cipher)
    updated = store.update_account(
        replace(account, label="Migrated calendar"), audit_operation="account.update"
    )
    assert updated.label == "Migrated calendar"
    with sqlite3.connect(database) as connection:
        assert (
            connection.execute(
                "SELECT aad_version FROM dav_accounts WHERE account_ref = 'acct_legacy'"
            ).fetchone()[0]
            == 2
        )


def test_new_account_ciphertext_is_bound_to_explicit_ownership(tmp_path: Path) -> None:
    database = tmp_path / "gateway.db"
    store = AccountStore(database, cipher=_cipher())
    account, created = store.create_account(
        tenant_id="tenant-a",
        user_id="user-a",
        kind="caldav",
        label="Personal",
        base_url="https://dav.example/personal/",
        credential=PasswordCredential(username="user", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
    )

    assert created is True
    assert account.owner_type == "user"
    assert account.owner_user_id == "user-a"
    with sqlite3.connect(database) as connection:
        assert connection.execute(
            """
            SELECT owner_type, owner_user_id, aad_version FROM dav_accounts
            WHERE account_ref = ?
            """,
            (account.account_ref,),
        ).fetchone() == ("user", "user-a", 2)
        connection.execute(
            "UPDATE dav_accounts SET owner_user_id = 'user-b' WHERE account_ref = ?",
            (account.account_ref,),
        )

    with pytest.raises(InvalidTag):
        store.get_account("tenant-a", "user-a", account.account_ref)


def _insert_tenant_account(store: AccountStore, account_ref: str, tenant_id: str) -> GatewayAccount:
    account = GatewayAccount(
        account_ref=account_ref,
        tenant_id=tenant_id,
        owner_type="tenant",
        owner_user_id=None,
        kind="caldav",
        label="Tenant calendar",
        base_url="https://dav.example/tenant/",
        credential=PasswordCredential(
            username="tenant-user", password="tenant-secret", mode="basic"
        ),
        status="ready",
        enabled=True,
        last_checked_at=None,
        last_error=None,
        created_at="2026-08-10T00:00:00Z",
        updated_at="2026-08-10T00:00:00Z",
    )
    with store._connect() as connection:  # noqa: SLF001 - storage integration fixture
        store._insert_account(connection, account)  # noqa: SLF001 - storage integration fixture
        connection.commit()
    return account


def test_account_grant_mutations_are_tenant_scoped_and_audited(tmp_path: Path) -> None:
    store = AccountStore(tmp_path / "account-grants.db", cipher=_cipher())
    account = _insert_tenant_account(store, "acct_tenant", "tenant-a")
    personal, _created = store.create_account(
        tenant_id="tenant-a",
        user_id="user-a",
        kind="caldav",
        label="Personal",
        base_url="https://dav.example/personal/",
        credential=PasswordCredential(username="user", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
    )

    created = store.upsert_account_grant(
        account_ref=account.account_ref,
        tenant_id="tenant-a",
        user_id="user-b",
        permission="read",
        enabled=True,
        updated_by="admin-a",
    )
    assert created.permission == "read"
    assert created.enabled is True

    updated = store.upsert_account_grant(
        account_ref=account.account_ref,
        tenant_id="tenant-a",
        user_id="user-b",
        permission="read_write",
        enabled=False,
        updated_by="admin-b",
    )
    assert updated.permission == "read_write"
    assert updated.enabled is False
    assert updated.created_at == created.created_at
    assert updated.updated_by == "admin-b"

    store.upsert_account_grant(
        account_ref=account.account_ref,
        tenant_id="tenant-a",
        user_id="user-b",
        permission="read_write",
        enabled=False,
        updated_by="admin-b",
    )
    assert store.delete_account_grant(
        account.account_ref,
        "tenant-a",
        "user-b",
        deleted_by="admin-a",
    )
    assert store.list_account_grants(account.account_ref, "tenant-a") == []

    audit = store.list_account_grant_audit("tenant-a", limit=10)
    assert [entry.operation for entry in audit] == [
        "account_grant.delete",
        "account_grant.touch",
        "account_grant.update",
        "account_grant.create",
    ]
    assert audit[0].actor_id == "admin-a"
    assert audit[0].previous_permission == "read_write"
    assert audit[0].resulting_permission is None
    assert (
        store.list_account_grant_audit("tenant-a", limit=10, before_id=audit[1].audit_id)
        == audit[2:]
    )
    assert store.list_account_grant_audit("tenant-b", limit=10) == []

    with pytest.raises(LookupError, match="Tenant-owned account not found"):
        store.upsert_account_grant(
            account_ref=account.account_ref,
            tenant_id="tenant-b",
            user_id="user-b",
            permission="read",
            enabled=True,
            updated_by="admin-b",
        )
    with pytest.raises(LookupError, match="Tenant-owned account not found"):
        store.upsert_account_grant(
            account_ref=personal.account_ref,
            tenant_id="tenant-a",
            user_id="user-b",
            permission="read",
            enabled=True,
            updated_by="admin-a",
        )


def test_account_grant_schema_enforces_tenant_fk_audit_and_cascade(tmp_path: Path) -> None:
    database = tmp_path / "grants.db"
    store = AccountStore(database, cipher=_cipher())
    account, _created = store.create_account(
        tenant_id="tenant-a",
        user_id="user-a",
        kind="caldav",
        label="Personal",
        base_url="https://dav.example/personal/",
        credential=PasswordCredential(username="user", password="secret", mode="basic"),
        enabled=True,
        status="ready",
        last_error=None,
        idempotency_key=None,
        request_hash=None,
    )
    now = "2026-08-10T00:00:00Z"

    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO dav_account_grants (
              account_ref, tenant_id, user_id, permission, enabled,
              updated_by, created_at, updated_at
            ) VALUES (?, 'tenant-a', 'user-b', 'read', 1, 'admin-a', ?, ?)
            """,
            (account.account_ref, now, now),
        )
        with pytest.raises(sqlite3.IntegrityError):
            connection.execute(
                """
                INSERT INTO dav_account_grants (
                  account_ref, tenant_id, user_id, permission, enabled,
                  updated_by, created_at, updated_at
                ) VALUES (?, 'tenant-b', 'user-b', 'read', 1, 'admin-b', ?, ?)
                """,
                (account.account_ref, now, now),
            )
        connection.execute(
            """
            INSERT INTO dav_account_grant_audit (
              account_ref, tenant_id, user_id, actor_id, operation,
              resulting_permission, resulting_enabled, created_at
            ) VALUES (?, 'tenant-a', 'user-b', 'admin-a', 'account_grant.create', 'read', 1, ?)
            """,
            (account.account_ref, now),
        )
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("UPDATE dav_account_grant_audit SET operation = 'changed'")
        with pytest.raises(sqlite3.IntegrityError, match="append-only"):
            connection.execute("DELETE FROM dav_account_grant_audit")
        connection.commit()

    assert store.delete_account("tenant-a", "user-a", account.account_ref) is True
    with sqlite3.connect(database) as connection:
        assert connection.execute("SELECT COUNT(*) FROM dav_account_grants").fetchone()[0] == 0
        assert connection.execute("SELECT COUNT(*) FROM dav_account_grant_audit").fetchone()[0] == 1
