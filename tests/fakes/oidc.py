"""A small in-process OIDC provider for end-to-end login tests.

It implements discovery, JWKS, the token endpoint (including client
authentication and PKCE verification) and userinfo. The authorization
endpoint is not served: tests start a login through the gateway, take the
issued ``state``/``nonce``/``code_challenge`` from the redirect, and then ask
this fake to issue a code for the callback.
"""

from __future__ import annotations

import base64
import hashlib
import secrets
import time
from dataclasses import dataclass
from typing import Any

import httpx
import jwt
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from db_gateway.auth.state import code_challenge as s256_challenge


@dataclass(slots=True)
class IssuedCode:
    nonce: str
    code_challenge: str
    id_token: str
    access_token: str
    userinfo: dict[str, Any] | None
    token_status: int | None


class FakeOidcProvider:
    """A deterministic provider whose HTTP surface is an ``httpx`` transport."""

    def __init__(
        self,
        *,
        issuer: str = "https://issuer.test",
        client_id: str = "db-gateway",
        client_secret: str | None = "client-secret",
        redirect_uri: str = "https://gateway.test/auth/callback",
        login_claim: str = "preferred_username",
    ) -> None:
        self.issuer = issuer
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.login_claim = login_claim
        self.kid = "test-key"
        self.private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwks_keys = [self._public_jwk(self.private_key, self.kid)]
        self.jwks_status = 200
        self.discovery_document: dict[str, Any] = {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/authorize",
            "token_endpoint": f"{issuer}/token",
            "jwks_uri": f"{issuer}/jwks",
            "userinfo_endpoint": f"{issuer}/userinfo",
            "end_session_endpoint": f"{issuer}/logout",
        }
        self.codes: dict[str, IssuedCode] = {}
        self.access_tokens: dict[str, dict[str, Any] | None] = {}
        self.discovery_requests = 0
        self.jwks_requests = 0
        self.token_requests = 0
        self.userinfo_requests = 0

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle)

    def add_signing_key(self, kid: str) -> Any:
        """Generate a new RSA key, publish its JWK and return the private key."""
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        self.jwks_keys.append(self._public_jwk(private_key, kid))
        return private_key

    def issue_code(
        self,
        *,
        nonce: str,
        code_challenge: str,
        claims: dict[str, Any] | None = None,
        userinfo: dict[str, Any] | None = None,
        access_token: str | None = None,
        algorithm: str = "RS256",
        signing_key: Any | None = None,
        kid: str | None = None,
        token_status: int | None = None,
    ) -> str:
        """Issue a one-time authorization code for the fake token endpoint."""
        code = secrets.token_urlsafe(24)
        now = int(time.time())
        claim_set: dict[str, Any] = {
            "iss": self.issuer,
            "aud": self.client_id,
            "sub": "subject-1",
            "iat": now,
            "exp": now + 300,
            "nonce": nonce,
            self.login_claim: "andyjjrt",
            "email": "andy@example.test",
            "name": "Andy",
            "sid": "sid-1",
        }
        if claims is not None:
            claim_set.update(claims)
        if algorithm == "none":
            key: Any = ""
        elif algorithm.startswith("HS"):
            key = "shared-secret-key-with-at-least-32-bytes"
        else:
            key = signing_key if signing_key is not None else self.private_key
        id_token = jwt.encode(
            claim_set,
            key,
            algorithm=algorithm,
            headers={"kid": kid or self.kid},
        )
        token = access_token or secrets.token_urlsafe(16)
        self.codes[code] = IssuedCode(
            nonce=nonce,
            code_challenge=code_challenge,
            id_token=id_token,
            access_token=token,
            userinfo=userinfo,
            token_status=token_status,
        )
        self.access_tokens[token] = userinfo
        return code

    @staticmethod
    def _public_jwk(private_key: Any, kid: str) -> dict[str, Any]:
        jwk = RSAAlgorithm.to_jwk(private_key.public_key(), as_dict=True)
        jwk.update({"kid": kid, "use": "sig", "alg": "RS256"})
        return jwk

    @staticmethod
    def _form_value(request: httpx.Request, name: str) -> str | None:
        values = httpx.QueryParams(request.content.decode("ascii")).get_list(name)
        return values[0] if values else None

    def _handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if path == "/.well-known/openid-configuration":
            self.discovery_requests += 1
            return httpx.Response(200, json=self.discovery_document)
        if path == "/jwks":
            self.jwks_requests += 1
            if self.jwks_status != 200:
                return httpx.Response(self.jwks_status, json={"error": "jwks_error"})
            return httpx.Response(200, json={"keys": self.jwks_keys})
        if path == "/token" and request.method == "POST":
            return self._token(request)
        if path == "/userinfo" and request.method == "GET":
            return self._userinfo(request)
        return httpx.Response(404, json={"error": "not_found"})

    def _token(self, request: httpx.Request) -> httpx.Response:
        self.token_requests += 1
        if self._form_value(request, "grant_type") != "authorization_code":
            return httpx.Response(400, json={"error": "unsupported_grant_type"})
        code = self._form_value(request, "code") or ""
        issued = self.codes.pop(code, None)
        if issued is None:
            return httpx.Response(400, json={"error": "invalid_grant"})
        if issued.token_status is not None:
            return httpx.Response(issued.token_status, json={"error": "token_error"})
        if self._form_value(request, "redirect_uri") != self.redirect_uri:
            return httpx.Response(400, json={"error": "invalid_redirect_uri"})
        if self.client_secret is not None:
            authorization = request.headers.get("authorization", "")
            expected = base64.b64encode(
                f"{self.client_id}:{self.client_secret}".encode()
            ).decode("ascii")
            if not secrets.compare_digest(authorization, f"Basic {expected}"):
                return httpx.Response(401, json={"error": "invalid_client"})
        elif self._form_value(request, "client_id") != self.client_id:
            return httpx.Response(400, json={"error": "invalid_client"})
        verifier = self._form_value(request, "code_verifier") or ""
        if not secrets.compare_digest(s256_challenge(verifier), issued.code_challenge):
            return httpx.Response(400, json={"error": "invalid_grant"})
        return httpx.Response(
            200,
            json={
                "access_token": issued.access_token,
                "token_type": "Bearer",
                "expires_in": 300,
                "id_token": issued.id_token,
            },
        )

    def _userinfo(self, request: httpx.Request) -> httpx.Response:
        self.userinfo_requests += 1
        authorization = request.headers.get("authorization", "")
        prefix = "Bearer "
        if not authorization.startswith(prefix):
            return httpx.Response(401, json={"error": "invalid_token"})
        token = authorization[len(prefix) :]
        document = self.access_tokens.get(token)
        if document is None:
            return httpx.Response(401, json={"error": "invalid_token"})
        return httpx.Response(200, json=document)


def challenge_for(verifier: str) -> str:
    """A local helper mirroring the fake's validation for tests."""
    digest = hashlib.sha256(verifier.encode("ascii")).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
