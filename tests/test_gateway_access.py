from __future__ import annotations

import sqlite3
from dataclasses import replace
from pathlib import Path
from typing import Literal, cast

import pytest

from private_dav_mcp.gateway_access import AccountAccessPolicy
from private_dav_mcp.gateway_identity import GatewayIdentity
from private_dav_mcp.gateway_store import (
    AccountCipher,
    AccountStore,
    GatewayAccount,
    PasswordCredential,
)

GrantAccess = tuple[Literal["read", "read_write"], Literal["exact_grant", "tenant_grant"]]


def _account(
    account_ref: str,
    *,
    tenant_id: str = "tenant-a",
    owner_type: str = "user",
    owner_user_id: str | None = "user-a",
    enabled: bool = True,
    created_at: str = "2026-08-10T00:00:00Z",
) -> GatewayAccount:
    return GatewayAccount(
        account_ref=account_ref,
        tenant_id=tenant_id,
        owner_type=owner_type,
        owner_user_id=owner_user_id,
        kind="caldav",
        label=account_ref,
        base_url=f"https://dav.example/{account_ref}/",
        credential=PasswordCredential(username="user", password="secret", mode="basic"),
        status="ready" if enabled else "disabled",
        enabled=enabled,
        last_checked_at=None,
        last_error=None,
        created_at=created_at,
        updated_at=created_at,
    )


def _identity(tenant_id: str = "tenant-a", user_id: str = "user-a") -> GatewayIdentity:
    return GatewayIdentity(
        tenant_id=tenant_id,
        user_id=user_id,
        scopes=frozenset(),
        token_id=f"token-{tenant_id}-{user_id}",
    )


class FakeAccountRepository:
    def __init__(
        self,
        accounts: list[GatewayAccount],
        grants: dict[tuple[str, str, str], GrantAccess] | None = None,
    ) -> None:
        self.accounts = accounts
        self.grants = grants or {}

    def get_account_for_tenant(self, tenant_id: str, account_ref: str) -> GatewayAccount | None:
        return next(
            (
                account
                for account in self.accounts
                if account.tenant_id == tenant_id and account.account_ref == account_ref
            ),
            None,
        )

    def list_accounts_for_subject(
        self,
        tenant_id: str,
        user_id: str,
        *,
        permission: Literal["read", "write"],
        limit: int,
    ) -> list[GatewayAccount]:
        candidates = []
        for account in self.accounts:
            if account.tenant_id != tenant_id:
                continue
            if account.owner_type == "user" and account.owner_user_id == user_id:
                candidates.append(account)
                continue
            grant = self.grants.get((account.account_ref, tenant_id, user_id))
            if grant is not None and (permission == "read" or grant[0] == "read_write"):
                candidates.append(account)
        return candidates[:limit]

    def account_grant_access(
        self, account_ref: str, tenant_id: str, user_id: str
    ) -> GrantAccess | None:
        return self.grants.get((account_ref, tenant_id, user_id))

    def get_account(self, tenant_id: str, user_id: str, account_ref: str) -> GatewayAccount | None:
        account = self.get_account_for_tenant(tenant_id, account_ref)
        if account is None or account.owner_user_id != user_id:
            return None
        return account

    def list_accounts(self, tenant_id: str, user_id: str, *, limit: int) -> list[GatewayAccount]:
        return [
            account
            for account in self.accounts
            if account.tenant_id == tenant_id and account.owner_user_id == user_id
        ][:limit]


def test_personal_account_access_is_owner_and_tenant_scoped() -> None:
    account = _account("acct_personal")
    policy = AccountAccessPolicy(FakeAccountRepository([account]))

    readable = policy.resolve(_identity(), account.account_ref, permission="read")
    writable = policy.resolve(_identity(), account.account_ref, permission="write")

    assert readable is not None
    assert readable.permission == "read_write"
    assert readable.access_source == "owner"
    assert writable is not None
    assert (
        policy.resolve(_identity(user_id="user-b"), account.account_ref, permission="read") is None
    )
    assert (
        policy.resolve(_identity(tenant_id="tenant-b"), account.account_ref, permission="read")
        is None
    )


def test_tenant_account_access_composes_grant_permission_and_state() -> None:
    read_account = _account("acct_shared_read", owner_type="tenant", owner_user_id=None)
    write_account = _account(
        "acct_shared_write",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:00:01Z",
    )
    disabled_account = replace(
        _account("acct_disabled", owner_type="tenant", owner_user_id=None),
        enabled=False,
        status="disabled",
    )
    repository = FakeAccountRepository(
        [read_account, write_account, disabled_account],
        {
            (read_account.account_ref, "tenant-a", "user-a"): ("read", "exact_grant"),
            (write_account.account_ref, "tenant-a", "user-a"): (
                "read_write",
                "tenant_grant",
            ),
            (disabled_account.account_ref, "tenant-a", "user-a"): (
                "read_write",
                "exact_grant",
            ),
        },
    )
    policy = AccountAccessPolicy(repository)
    identity = _identity()

    read_access = policy.resolve(identity, read_account.account_ref, permission="read")
    assert read_access is not None
    assert read_access.permission == "read"
    assert read_access.access_source == "exact_grant"
    assert policy.resolve(identity, read_account.account_ref, permission="write") is None

    write_access = policy.resolve(identity, write_account.account_ref, permission="write")
    assert write_access is not None
    assert write_access.access_source == "tenant_grant"
    assert policy.resolve(identity, disabled_account.account_ref, permission="read") is None
    assert (
        policy.resolve(_identity(user_id="user-b"), write_account.account_ref, permission="read")
        is None
    )

    assert [
        access.account.account_ref for access in policy.list_accessible(identity, permission="read")
    ] == [read_account.account_ref, write_account.account_ref]
    assert [
        access.account.account_ref
        for access in policy.list_accessible(identity, permission="write")
    ] == [write_account.account_ref]


def test_personal_management_lookup_excludes_tenant_accounts_and_disabled_use() -> None:
    personal = _account("acct_personal")
    disabled = _account("acct_disabled", enabled=False, created_at="2026-08-10T00:00:01Z")
    tenant = _account(
        "acct_tenant",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:00:02Z",
    )
    policy = AccountAccessPolicy(FakeAccountRepository([personal, disabled, tenant]))
    identity = _identity()

    assert policy.get_personal_account(identity, personal.account_ref) == personal
    assert policy.get_personal_account(identity, disabled.account_ref) == disabled
    assert policy.get_personal_account(identity, disabled.account_ref, require_enabled=True) is None
    assert policy.get_personal_account(identity, tenant.account_ref) is None
    assert policy.list_personal_accounts(identity, limit=10) == [personal, disabled]
    assert policy.list_personal_accounts(identity, limit=10, enabled_only=True) == [personal]

    with pytest.raises(ValueError, match="permission must be read or write"):
        policy.resolve(
            identity,
            personal.account_ref,
            permission=cast(Literal["read", "write"], "manage"),
        )
    with pytest.raises(ValueError, match="limit must be positive"):
        policy.list_accessible(identity, permission="read", limit=0)


def _insert_account(store: AccountStore, account: GatewayAccount) -> None:
    with store._connect() as connection:  # noqa: SLF001 - storage integration fixture
        store._insert_account(connection, account)  # noqa: SLF001 - storage integration fixture
        connection.commit()


def _insert_grant(
    database: Path,
    account_ref: str,
    *,
    tenant_id: str,
    user_id: str,
    permission: str,
    enabled: bool = True,
) -> None:
    now = "2026-08-10T00:01:00Z"
    with sqlite3.connect(database) as connection:
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute(
            """
            INSERT INTO dav_account_grants (
              account_ref, tenant_id, user_id, permission, enabled,
              updated_by, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, 'admin-a', ?, ?)
            """,
            (account_ref, tenant_id, user_id, permission, int(enabled), now, now),
        )


def test_sqlite_account_access_queries_apply_tenant_and_grant_filters(tmp_path: Path) -> None:
    database = tmp_path / "gateway.db"
    store = AccountStore(
        database,
        cipher=AccountCipher(keyring={1: b"k" * 32}, active_version=1),
    )
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
    exact = _account(
        "acct_exact",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:02:00Z",
    )
    wildcard = _account(
        "acct_wildcard",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:03:00Z",
    )
    other_tenant = _account(
        "acct_other_tenant",
        tenant_id="tenant-b",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:04:00Z",
    )
    disabled_grant = _account(
        "acct_disabled_grant",
        owner_type="tenant",
        owner_user_id=None,
        created_at="2026-08-10T00:05:00Z",
    )
    for account in (exact, wildcard, other_tenant, disabled_grant):
        _insert_account(store, account)
    _insert_grant(
        database,
        exact.account_ref,
        tenant_id="tenant-a",
        user_id="user-a",
        permission="read",
    )
    _insert_grant(
        database,
        wildcard.account_ref,
        tenant_id="tenant-a",
        user_id="*",
        permission="read_write",
    )
    _insert_grant(
        database,
        wildcard.account_ref,
        tenant_id="tenant-a",
        user_id="user-a",
        permission="read",
    )
    _insert_grant(
        database,
        other_tenant.account_ref,
        tenant_id="tenant-b",
        user_id="user-a",
        permission="read_write",
    )

    _insert_grant(
        database,
        disabled_grant.account_ref,
        tenant_id="tenant-a",
        user_id="user-a",
        permission="read_write",
        enabled=False,
    )

    policy = AccountAccessPolicy(store)
    identity = _identity()
    read_access = policy.list_accessible(identity, permission="read")
    write_access = policy.list_accessible(identity, permission="write")

    assert {access.account.account_ref for access in read_access} == {
        personal.account_ref,
        exact.account_ref,
        wildcard.account_ref,
    }
    assert {access.account.account_ref for access in write_access} == {
        personal.account_ref,
        wildcard.account_ref,
    }
    assert policy.resolve(identity, exact.account_ref, permission="write") is None
    wildcard_access = policy.resolve(identity, wildcard.account_ref, permission="write")
    assert wildcard_access is not None
    assert wildcard_access.access_source == "tenant_grant"
    assert policy.resolve(identity, disabled_grant.account_ref, permission="read") is None
    assert policy.resolve(identity, other_tenant.account_ref, permission="read") is None
