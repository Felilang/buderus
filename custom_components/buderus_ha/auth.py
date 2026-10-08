from __future__ import annotations

import base64
import hashlib
import logging
import secrets
import time
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse

import aiohttp

from .api import BuderusApiError, BuderusAuthError
from .const import (
    DEFAULT_USER_AGENT,
    OAUTH_AUTHORIZE_URL,
    OAUTH_CLIENT_ID,
    OAUTH_REDIRECT_URI,
    OAUTH_SCOPES,
    OAUTH_STYLE_ID,
    OAUTH_TOKEN_URL,
)

_LOGGER = logging.getLogger(__name__)

def create_code_verifier() -> str:
    return base64.urlsafe_b64encode(secrets.token_bytes(64)).rstrip(b"=").decode()


def create_code_challenge(code_verifier: str) -> str:
    digest = hashlib.sha256(code_verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def create_state() -> str:
    return secrets.token_urlsafe(32)


def build_authorization_url(code_verifier: str, state: str) -> str:
    query = {
        "client_id": OAUTH_CLIENT_ID,
        "redirect_uri": OAUTH_REDIRECT_URI,
        "response_type": "code",
        "scope": " ".join(OAUTH_SCOPES),
        "state": state,
        "code_challenge": create_code_challenge(code_verifier),
        "code_challenge_method": "S256",
        "prompt": "login",
        "style_id": OAUTH_STYLE_ID,
    }
    return f"{OAUTH_AUTHORIZE_URL}?{urlencode(query)}"


def parse_authorization_response(value: str, expected_state: str | None = None) -> str:
    value = value.strip()
    if value.startswith("http") or value.startswith(OAUTH_REDIRECT_URI):
        parsed = urlparse(value)
        params = parse_qs(parsed.query or parsed.fragment)
        if "error" in params:
            description = params.get("error_description", params["error"])[0]
            raise BuderusAuthError(
                description,
                0
            )
        if expected_state and params.get("state", [None])[0] != expected_state:
            raise BuderusAuthError(
                "OAuth state did not match",
                0
            )
        code = params.get("code", [None])[0]
        if not code:
            raise BuderusAuthError(
                "No authorization code found in redirect URL",
                0
            )
        return code
    return value


class BuderusOAuthClient:
    def __init__(self, session: aiohttp.ClientSession) -> None:
        self._session = session

    async def exchange_code(self, code: str, code_verifier: str) -> dict[str, Any]:
        return await self._token_request(
            {
                "grant_type": "authorization_code",
                "client_id": OAUTH_CLIENT_ID,
                "code": code,
                "code_verifier": code_verifier,
                "redirect_uri": OAUTH_REDIRECT_URI,
            }
        )

    async def refresh(self, refresh_token: str) -> dict[str, Any]:
        _LOGGER.info(
            "Starting Buderus OAuth token refresh"
        )
        return await self._token_request(
            {
                "grant_type": "refresh_token",
                "client_id": OAUTH_CLIENT_ID,
                "refresh_token": refresh_token,
            }
        )

    async def _token_request(self, data: dict[str, str]) -> dict[str, Any]:
        grant_type = data.get(
            "grant_type",
            "unknown",
        )
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": DEFAULT_USER_AGENT,
        }
        _LOGGER.debug(
            "Buderus OAuth request started "
            "(grant_type=%s)",
            grant_type,
        )
        async with self._session.post(OAUTH_TOKEN_URL, data=data, headers=headers) as response:
            body = await response.text()
            status = response.status

            _LOGGER.debug(
                "Buderus OAuth response received "
                "(grant_type=%s, status=%s)",
                grant_type,
                status,
            )
            if response.status in (400, 401, 403):
                # Do NOT log the complete response body here.
                # It could potentially contain sensitive
                # authentication information.
                _LOGGER.warning(
                    "Buderus OAuth authentication "
                    "request failed "
                    "(grant_type=%s, status=%s)",
                    grant_type,
                    status,
                )
                raise BuderusAuthError(
                    f"Token request failed: {response.status} {body}",
                    status
                )
            if response.status >= 400:
                _LOGGER.warning(
                    "Buderus OAuth request failed "
                    "(grant_type=%s, status=%s)",
                    grant_type,
                    status,
                )
                raise BuderusApiError(
                    f"Token request failed: {response.status} {body}"                    
                )
            try:
                token_data = (
                    await response.json(
                        content_type=None
                    )
                )
            except Exception as err:
                raise BuderusApiError(
                    "Invalid JSON response from "
                    "OAuth token endpoint"
                ) from err

        if "access_token" not in token_data:
            _LOGGER.warning(
                "Buderus OAuth response did not "
                "contain an access token "
                "(grant_type=%s)",
                grant_type,
            )
            raise BuderusAuthError(
                "Token response did not include an access token",
                status
            )

        expires_in = token_data.get(
            "expires_in"
        )

        if expires_in is not None:
            token_data["expires_at"] = (
                int(time.time())
                + int(expires_in)
            )

        _LOGGER.info(
            "Buderus OAuth request successful: "
            "grant_type=%s, "
            "expires_in=%s, "
            "refresh_token_returned=%s",
            grant_type,
            expires_in,
            bool(
                token_data.get(
                    "refresh_token"
                )
            ),
        )
        return token_data
