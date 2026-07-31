from __future__ import annotations

from dataclasses import dataclass
from typing import Any

import jwt
from jwt import InvalidTokenError


class IdentityError(ValueError):
    """Raised when a gateway identity token cannot be authenticated."""


@dataclass(frozen=True)
class GatewayIdentity:
    tenant_id: str
    user_id: str
    scopes: frozenset[str]
    token_id: str

    def require(self, scope: str) -> None:
        if scope not in self.scopes:
            raise PermissionError(f"Missing required scope: {scope}")


class IdentityVerifier:
    def __init__(
        self,
        *,
        issuer: str,
        audience: str,
        public_keys: dict[str, str],
        algorithms: tuple[str, ...] = ("RS256", "ES256", "EdDSA"),
        leeway_seconds: int = 5,
    ) -> None:
        if not issuer or not audience:
            raise ValueError("JWT issuer and audience are required")
        if not public_keys or any(not key for key in public_keys.values()):
            raise ValueError("At least one JWT public key is required")
        self._issuer = issuer
        self._audience = audience
        self._public_keys = dict(public_keys)
        self._algorithms = algorithms
        self._leeway_seconds = leeway_seconds

    def verify(self, token: str) -> GatewayIdentity:
        if not token:
            raise IdentityError("Identity token is required")
        try:
            header = jwt.get_unverified_header(token)
            key = self._select_key(header)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=list(self._algorithms),
                audience=self._audience,
                issuer=self._issuer,
                leeway=self._leeway_seconds,
                options={"require": ["iss", "aud", "sub", "tenant_id", "iat", "exp", "jti"]},
            )
            return self._identity_from_claims(claims)
        except (InvalidTokenError, KeyError, TypeError, ValueError) as exc:
            raise IdentityError("Identity token is invalid") from exc

    def _select_key(self, header: dict[str, Any]) -> str:
        algorithm = header.get("alg")
        if algorithm not in self._algorithms:
            raise IdentityError("Identity token algorithm is not allowed")
        key_id = header.get("kid")
        if isinstance(key_id, str) and key_id:
            try:
                return self._public_keys[key_id]
            except KeyError as exc:
                raise IdentityError("Identity token key is unknown") from exc
        if len(self._public_keys) == 1:
            return next(iter(self._public_keys.values()))
        raise IdentityError("Identity token key ID is required")

    @staticmethod
    def _identity_from_claims(claims: dict[str, Any]) -> GatewayIdentity:
        tenant_id = claims.get("tenant_id")
        user_id = claims.get("sub")
        token_id = claims.get("jti")
        raw_scope = claims.get("scope", "")
        if not isinstance(tenant_id, str) or not tenant_id:
            raise IdentityError("Identity token tenant claim is invalid")
        if not isinstance(user_id, str) or not user_id:
            raise IdentityError("Identity token subject claim is invalid")
        if not isinstance(token_id, str) or not token_id:
            raise IdentityError("Identity token ID claim is invalid")
        if isinstance(raw_scope, str):
            scopes = frozenset(part for part in raw_scope.split() if part)
        elif isinstance(raw_scope, list) and all(
            isinstance(value, str) and value for value in raw_scope
        ):
            scopes = frozenset(raw_scope)
        else:
            raise IdentityError("Identity token scope is invalid")
        return GatewayIdentity(
            tenant_id=tenant_id,
            user_id=user_id,
            scopes=scopes,
            token_id=token_id,
        )
