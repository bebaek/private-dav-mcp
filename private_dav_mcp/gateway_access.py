from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Protocol

from .gateway_identity import GatewayIdentity
from .gateway_store import GatewayAccount

AccountPermission = Literal["read", "write"]
EffectiveAccountPermission = Literal["read", "read_write"]


class AccountAccessRepository(Protocol):
    def get_account_for_tenant(self, tenant_id: str, account_ref: str) -> GatewayAccount | None: ...

    def list_accounts_for_subject(
        self,
        tenant_id: str,
        user_id: str,
        *,
        permission: AccountPermission,
        limit: int,
    ) -> list[GatewayAccount]: ...

    def account_grant_access(
        self, account_ref: str, tenant_id: str, user_id: str
    ) -> tuple[EffectiveAccountPermission, Literal["exact_grant", "tenant_grant"]] | None: ...

    def get_account(
        self, tenant_id: str, user_id: str, account_ref: str
    ) -> GatewayAccount | None: ...

    def list_accounts(
        self, tenant_id: str, user_id: str, *, limit: int
    ) -> list[GatewayAccount]: ...


@dataclass(frozen=True)
class AccessibleAccount:
    account: GatewayAccount
    permission: EffectiveAccountPermission
    access_source: Literal["owner", "exact_grant", "tenant_grant"]


class AccountAccessPolicy:
    def __init__(self, repository: AccountAccessRepository) -> None:
        self._repository = repository

    def resolve(
        self,
        identity: GatewayIdentity,
        account_ref: str,
        *,
        permission: AccountPermission,
    ) -> AccessibleAccount | None:
        _validate_permission(permission)
        account = self._repository.get_account_for_tenant(identity.tenant_id, account_ref)
        if account is None or not account.enabled:
            return None
        accessible = self._effective_access(identity, account)
        if accessible is None or not _allows(accessible.permission, permission):
            return None
        return accessible

    def list_accessible(
        self,
        identity: GatewayIdentity,
        *,
        permission: AccountPermission,
        limit: int = 100,
    ) -> list[AccessibleAccount]:
        _validate_permission(permission)
        if limit < 1:
            raise ValueError("Account access limit must be positive")
        candidates = self._repository.list_accounts_for_subject(
            identity.tenant_id,
            identity.user_id,
            permission=permission,
            limit=limit,
        )
        accessible: list[AccessibleAccount] = []
        for account in candidates:
            if not account.enabled:
                continue
            effective = self._effective_access(identity, account)
            if effective is not None and _allows(effective.permission, permission):
                accessible.append(effective)
        return accessible

    def get_personal_account(
        self,
        identity: GatewayIdentity,
        account_ref: str,
        *,
        require_enabled: bool = False,
    ) -> GatewayAccount | None:
        account = self._repository.get_account(identity.tenant_id, identity.user_id, account_ref)
        if account is None or account.owner_type != "user":
            return None
        if account.owner_user_id != identity.user_id:
            return None
        if require_enabled and not account.enabled:
            return None
        return account

    def list_personal_accounts(
        self,
        identity: GatewayIdentity,
        *,
        limit: int,
        enabled_only: bool = False,
    ) -> list[GatewayAccount]:
        if limit < 1:
            raise ValueError("Account access limit must be positive")
        accounts = self._repository.list_accounts(identity.tenant_id, identity.user_id, limit=limit)
        return [
            account
            for account in accounts
            if account.owner_type == "user"
            and account.owner_user_id == identity.user_id
            and (account.enabled or not enabled_only)
        ]

    def _effective_access(
        self, identity: GatewayIdentity, account: GatewayAccount
    ) -> AccessibleAccount | None:
        if account.tenant_id != identity.tenant_id:
            return None
        if account.owner_type == "user":
            if account.owner_user_id != identity.user_id:
                return None
            return AccessibleAccount(
                account=account,
                permission="read_write",
                access_source="owner",
            )
        if account.owner_type != "tenant":
            return None
        grant = self._repository.account_grant_access(
            account.account_ref,
            identity.tenant_id,
            identity.user_id,
        )
        if grant is None:
            return None
        permission, source = grant
        return AccessibleAccount(account=account, permission=permission, access_source=source)


def _validate_permission(permission: str) -> None:
    if permission not in {"read", "write"}:
        raise ValueError("Account permission must be read or write")


def _allows(effective: EffectiveAccountPermission, requested: AccountPermission) -> bool:
    return requested == "read" or effective == "read_write"
