"""Generic OIDC Authorization Code + PKCE client.

The provider is discovered from ``<issuer>/.well-known/openid-configuration``.
Discovery and JWKS documents are cached for the life of the process. An ID
token whose key id is unknown triggers a JWKS refetch, coordinated by a
single-flight lock and a minimum refresh interval, so a burst of unknown key
ids cannot amplify provider load while key rotation is still picked up.

Only asymmetric signature algorithms are accepted. ``none`` and the HMAC
family are rejected before any key is selected, so a public JWKS document can
never be used as an HMAC secret.
"""

from __future__ import annotations

import asyncio
import secrets
import time
from collections.abc import Callable
from dataclasses import dataclass
from datetime import timedelta
from typing import Any
from urllib.parse import urlencode

import httpx
import jwt

from db_gateway.settings import Settings

# Asymmetric algorithms only. RS*/PS* are RSA, ES* is ECDSA, EdDSA is Ed25519.
ALLOWED_ALGORITHMS = frozenset(
    {
        "RS256",
        "RS384",
        "RS512",
        "PS256",
        "PS384",
        "PS512",
        "ES256",
        "ES384",
        "ES512",
        "EdDSA",
    }
)
CLOCK_LEEWAY = timedelta(seconds=30)


class OidcError(Exception):
    """Base class for OIDC failures."""


class OidcUnavailable(OidcError):
    """The provider cannot be reached or its configuration is unusable."""


class OidcRejected(OidcError):
    """The provider answered, but the login attempt is not acceptable."""


@dataclass(frozen=True, slots=True)
class ProviderMetadata:
    issuer: str
    authorization_endpoint: str
    token_endpoint: str
    jwks_uri: str
    userinfo_endpoint: str | None
    end_session_endpoint: str | None


@dataclass(frozen=True, slots=True)
class OidcIdentity:
    """The claims needed to map an ID token to a gateway user."""

    login_key: str
    subject: str
    email: str | None
    display_name: str | None
    sid: str | None


@dataclass(frozen=True, slots=True)
class _Tokens:
    access_token: str | None
    id_token: str


def _required_endpoint(document: dict[str, Any], name: str) -> str:
    value = document.get(name)
    if not isinstance(value, str) or not value:
        raise OidcUnavailable(f"OIDC discovery is missing {name}")
    return value


def _optional_endpoint(document: dict[str, Any], name: str) -> str | None:
    value = document.get(name)
    return value if isinstance(value, str) and value else None


class OidcClient:
    """One configured OIDC client.

    ``transport`` is injectable so tests can run a complete fake provider
    without network I/O. One instance owns one ``httpx.AsyncClient`` and must
    be closed by the application lifespan.
    """

    def __init__(
        self,
        *,
        issuer: str,
        client_id: str,
        client_secret: str | None,
        redirect_uri: str,
        scopes: str,
        login_claim: str,
        timeout_s: float,
        jwks_min_refresh_s: float,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret or None
        self.redirect_uri = redirect_uri
        self.scopes = scopes
        self.login_claim = login_claim
        self.jwks_min_refresh_s = jwks_min_refresh_s
        self._http = httpx.AsyncClient(timeout=timeout_s, transport=transport)
        self._provider: ProviderMetadata | None = None
        self._jwks: dict[str, dict[str, Any]] | None = None
        self._jwks_lock = asyncio.Lock()
        self._jwks_refreshed_at: float | None = None
        self._clock = clock

    @classmethod
    def from_settings(
        cls,
        settings: Settings,
        *,
        transport: httpx.AsyncBaseTransport | None = None,
        clock: Callable[[], float] | None = None,
    ) -> OidcClient:
        assert settings.oidc_issuer is not None
        return cls(
            issuer=settings.oidc_issuer,
            client_id=settings.oidc_client_id,
            client_secret=(
                settings.oidc_client_secret.get_secret_value()
                if settings.oidc_client_secret is not None
                else None
            ),
            redirect_uri=settings.oidc_redirect_uri or "",
            scopes=settings.oidc_scopes,
            login_claim=settings.oidc_login_claim,
            timeout_s=settings.oidc_http_timeout_s,
            jwks_min_refresh_s=settings.oidc_jwks_min_refresh_s,
            transport=transport,
            clock=clock or time.monotonic,
        )

    @property
    def ready(self) -> bool:
        """True when discovery and the callback have the config they need."""
        return bool(self.issuer and self.client_id and self.redirect_uri)

    async def aclose(self) -> None:
        await self._http.aclose()

    async def discover(self) -> ProviderMetadata:
        """Fetch and cache the provider metadata, checking its issuer exactly."""
        if self._provider is not None:
            return self._provider
        if not self.ready:
            raise OidcUnavailable("OIDC login is not configured")
        url = self.issuer.rstrip("/") + "/.well-known/openid-configuration"
        document = await self._get_json(url)
        if document.get("issuer") != self.issuer:
            raise OidcUnavailable("OIDC discovery issuer does not match the configured issuer")
        self._provider = ProviderMetadata(
            issuer=self.issuer,
            authorization_endpoint=_required_endpoint(document, "authorization_endpoint"),
            token_endpoint=_required_endpoint(document, "token_endpoint"),
            jwks_uri=_required_endpoint(document, "jwks_uri"),
            userinfo_endpoint=_optional_endpoint(document, "userinfo_endpoint"),
            end_session_endpoint=_optional_endpoint(document, "end_session_endpoint"),
        )
        return self._provider

    async def authorization_url(self, *, state: str, nonce: str, code_challenge: str) -> str:
        """Build the authorization redirect for a fresh login state."""
        provider = await self.discover()
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": self.scopes,
            "state": state,
            "nonce": nonce,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        separator = "&" if "?" in provider.authorization_endpoint else "?"
        return provider.authorization_endpoint + separator + urlencode(params)

    async def authenticate(self, *, code: str, code_verifier: str, nonce: str) -> OidcIdentity:
        """Exchange a code and validate the resulting ID token and login claim."""
        provider = await self.discover()
        tokens = await self._exchange_code(provider, code, code_verifier)
        claims = await self._validate_id_token(provider, tokens.id_token, nonce)

        login_key = _claim_string(claims, self.login_claim)
        userinfo: dict[str, Any] | None = None
        if login_key is None:
            if tokens.access_token is None:
                raise OidcRejected("ID token has no login claim and there is no access token")
            userinfo = await self._userinfo(provider, tokens.access_token)
            subject = claims["sub"]
            if userinfo.get("sub") != subject:
                raise OidcRejected("userinfo subject does not match the ID token")
            login_key = _claim_string(userinfo, self.login_claim)
        if login_key is None:
            raise OidcRejected(f"login claim {self.login_claim!r} is missing")

        return OidcIdentity(
            login_key=login_key,
            subject=claims["sub"],
            email=_first_claim(claims, userinfo, "email"),
            display_name=_first_claim(claims, userinfo, "name"),
            sid=_claim_string(claims, "sid"),
        )

    async def _get_json(self, url: str) -> dict[str, Any]:
        try:
            response = await self._http.get(url, headers={"Accept": "application/json"})
        except httpx.HTTPError:
            raise OidcUnavailable("OIDC provider is unreachable") from None
        if response.status_code != 200:
            raise OidcUnavailable("OIDC provider returned an error")
        try:
            document = response.json()
        except ValueError:
            raise OidcUnavailable("OIDC provider returned invalid JSON") from None
        if not isinstance(document, dict):
            raise OidcUnavailable("OIDC provider returned an invalid document")
        return document

    async def _exchange_code(
        self, provider: ProviderMetadata, code: str, code_verifier: str
    ) -> _Tokens:
        data = {
            "grant_type": "authorization_code",
            "code": code,
            "redirect_uri": self.redirect_uri,
            "code_verifier": code_verifier,
        }
        auth: httpx.BasicAuth | None = None
        if self.client_secret is None:
            data["client_id"] = self.client_id
        else:
            auth = httpx.BasicAuth(self.client_id, self.client_secret)
        try:
            if auth is None:
                response = await self._http.post(
                    provider.token_endpoint,
                    data=data,
                    headers={"Accept": "application/json"},
                )
            else:
                response = await self._http.post(
                    provider.token_endpoint,
                    data=data,
                    auth=auth,
                    headers={"Accept": "application/json"},
                )
        except httpx.HTTPError:
            raise OidcUnavailable("OIDC token endpoint is unreachable") from None
        if response.status_code >= 500:
            raise OidcUnavailable("OIDC token endpoint returned an error")
        if response.status_code != 200:
            raise OidcRejected("authorization code exchange failed")
        try:
            body = response.json()
        except ValueError:
            raise OidcRejected("token endpoint returned invalid JSON") from None
        if not isinstance(body, dict):
            raise OidcRejected("token endpoint returned an invalid document")
        id_token = body.get("id_token")
        if not isinstance(id_token, str) or not id_token:
            raise OidcRejected("token response has no ID token")
        access_token = body.get("access_token")
        return _Tokens(
            access_token=access_token if isinstance(access_token, str) and access_token else None,
            id_token=id_token,
        )

    async def _validate_id_token(
        self, provider: ProviderMetadata, token: str, nonce: str
    ) -> dict[str, Any]:
        try:
            header = jwt.get_unverified_header(token)
        except jwt.PyJWTError:
            raise OidcRejected("malformed ID token") from None
        algorithm = header.get("alg")
        if not isinstance(algorithm, str) or algorithm not in ALLOWED_ALGORITHMS:
            raise OidcRejected("ID token algorithm is not allowed")
        key_id = header.get("kid")
        if not isinstance(key_id, str) or not key_id:
            raise OidcRejected("ID token has no key id")

        key_data = await self._lookup_jwk(provider, key_id)
        if key_data is None:
            raise OidcRejected("ID token was signed by an unknown key")
        if key_data.get("use") not in (None, "sig"):
            raise OidcRejected("JWKS key is not a signing key")
        jwk_algorithm = key_data.get("alg")
        if jwk_algorithm is not None and jwk_algorithm != algorithm:
            raise OidcRejected("ID token algorithm does not match the signing key")

        try:
            key = jwt.PyJWK(key_data, algorithm=algorithm)
            claims = jwt.decode(
                token,
                key=key,
                algorithms=[algorithm],
                audience=self.client_id,
                issuer=self.issuer,
                leeway=CLOCK_LEEWAY,
                options={"require": ["exp", "iat", "aud", "iss", "sub"]},
            )
        except jwt.PyJWTError:
            raise OidcRejected("ID token validation failed") from None

        subject = claims.get("sub")
        if not isinstance(subject, str) or not subject:
            raise OidcRejected("ID token has no subject")
        token_nonce = claims.get("nonce")
        if not isinstance(token_nonce, str) or not secrets.compare_digest(token_nonce, nonce):
            raise OidcRejected("ID token nonce does not match")
        audiences = claims.get("aud")
        audience_count = 1 if isinstance(audiences, str) else len(audiences or [])
        if "azp" in claims:
            # Membership, not value: an explicit null azp is still a present
            # authorized party and must be this client.
            azp = claims["azp"]
            if not isinstance(azp, str) or azp != self.client_id:
                raise OidcRejected("ID token authorized party does not match")
        elif audience_count > 1:
            raise OidcRejected("ID token with multiple audiences has no authorized party")
        return claims

    async def _lookup_jwk(
        self, provider: ProviderMetadata, key_id: str
    ) -> dict[str, Any] | None:
        """Find a signing key, refreshing JWKS at most once per minimum interval.

        The refresh is single-flight: concurrent callbacks with unknown key ids
        share one fetch. The attempt clock is advanced before the request, so a
        cold-start failure or an invalid/empty JWKS is rate-limited too: inside
        the interval with no usable cache this raises ``OidcUnavailable``
        without making another request.
        """
        cached = self._jwks
        if cached is not None and key_id in cached:
            return cached[key_id]
        async with self._jwks_lock:
            cached = self._jwks
            if cached is not None and key_id in cached:
                return cached[key_id]
            now = self._clock()
            last = self._jwks_refreshed_at
            if last is not None and now - last < self.jwks_min_refresh_s:
                if not cached:
                    raise OidcUnavailable(
                        "JWKS refresh is rate-limited and no signing keys are cached"
                    )
                return cached.get(key_id)
            self._jwks_refreshed_at = now
            self._jwks = await self._fetch_jwks(provider)
            return self._jwks.get(key_id)

    async def _fetch_jwks(self, provider: ProviderMetadata) -> dict[str, dict[str, Any]]:
        document = await self._get_json(provider.jwks_uri)
        keys = document.get("keys")
        if not isinstance(keys, list):
            raise OidcUnavailable("OIDC JWKS has no keys")
        by_kid: dict[str, dict[str, Any]] = {}
        for key in keys:
            if isinstance(key, dict):
                key_id = key.get("kid")
                if isinstance(key_id, str) and key_id:
                    by_kid[key_id] = key
        if not by_kid:
            raise OidcUnavailable("OIDC JWKS has no usable signing keys")
        return by_kid

    async def _userinfo(
        self, provider: ProviderMetadata, access_token: str
    ) -> dict[str, Any]:
        if provider.userinfo_endpoint is None:
            raise OidcRejected("provider has no userinfo endpoint")
        try:
            response = await self._http.get(
                provider.userinfo_endpoint,
                headers={
                    "Accept": "application/json",
                    "Authorization": f"Bearer {access_token}",
                },
            )
        except httpx.HTTPError:
            raise OidcUnavailable("OIDC userinfo endpoint is unreachable") from None
        if response.status_code in (401, 403):
            raise OidcRejected("userinfo endpoint rejected the access token")
        if response.status_code != 200:
            raise OidcUnavailable("OIDC userinfo endpoint returned an error")
        try:
            document = response.json()
        except ValueError:
            raise OidcRejected("userinfo endpoint returned invalid JSON") from None
        if not isinstance(document, dict):
            raise OidcRejected("userinfo endpoint returned an invalid document")
        return document


def _claim_string(claims: dict[str, Any] | None, name: str) -> str | None:
    if claims is None:
        return None
    value = claims.get(name)
    return value if isinstance(value, str) and value else None


def _first_claim(
    primary: dict[str, Any], secondary: dict[str, Any] | None, name: str
) -> str | None:
    return _claim_string(primary, name) or _claim_string(secondary, name)
