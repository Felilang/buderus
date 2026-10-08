from __future__ import annotations

import asyncio
import logging
import time

from homeassistant.config_entries import ConfigEntry
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import ConfigEntryAuthFailed
from homeassistant.helpers.aiohttp_client import async_get_clientsession

from .api import BuderusAuthError, BuderusPointTClient
from .auth import BuderusOAuthClient
from .const import CONF_ACCESS_TOKEN, CONF_EXPIRES_AT, CONF_GATEWAY_ID, CONF_REFRESH_TOKEN, DOMAIN, PLATFORMS
from .coordinator import BuderusDataUpdateCoordinator

_LOGGER = logging.getLogger(__name__)

async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    session = async_get_clientsession(hass)
    oauth_client = BuderusOAuthClient(session)

    # Prevent multiple simultaneous API calls from
    # refreshing the same refresh token in parallel.
    token_refresh_lock = asyncio.Lock()

    async def async_get_access_token() -> str:
        expires_at = entry.data.get(
            CONF_EXPIRES_AT,
            0,
        )
        if time.time() < expires_at - 60:
            return entry.data[
                CONF_ACCESS_TOKEN
            ]
        _LOGGER.debug(
            "Buderus access token needs refresh "
            "(expires_at=%s)",
            expires_at,
        )
        async with token_refresh_lock:
            # IMPORTANT:
            # Another request may have refreshed the
            # token while this request was waiting for
            # the lock. Therefore check again.
            expires_at = entry.data.get(
                CONF_EXPIRES_AT,
                0,
            )
            if time.time() < expires_at - 60:
                _LOGGER.debug(
                    "Buderus access token was "
                    "already refreshed by another "
                    "request"
                )
                return entry.data[
                    CONF_ACCESS_TOKEN
                ]
            _LOGGER.info(
                "Refreshing Buderus access token"
            )
            try:
                token_data = (
                    await oauth_client.refresh(
                        entry.data[
                            CONF_REFRESH_TOKEN
                        ]
                    )
                )
            except BuderusAuthError as err:
                _LOGGER.warning(
                    "Buderus token refresh failed "
                    "(status=%s). "
                    "Reauthentication required.",
                    getattr(
                        err,
                        "status",
                        None,
                    ),
                )
                raise ConfigEntryAuthFailed(
                    "Buderus authentication "
                    f"failed: {err}"
                ) from err
            old_refresh_token = (
                entry.data[
                    CONF_REFRESH_TOKEN
                ]
            )
            returned_refresh_token = (
                token_data.get(
                    CONF_REFRESH_TOKEN
                )
            )
            new_data = {
                **entry.data,
                CONF_ACCESS_TOKEN:
                    token_data[
                        CONF_ACCESS_TOKEN
                    ],
                CONF_EXPIRES_AT:
                    token_data.get(
                        CONF_EXPIRES_AT,
                        entry.data.get(
                            CONF_EXPIRES_AT,
                            0,
                        ),
                    ),
            }
            if returned_refresh_token:
                new_data[
                    CONF_REFRESH_TOKEN
                ] = returned_refresh_token

            # We deliberately compare the tokens but
            # NEVER write either token to the log.
            refresh_token_rotated = bool(
                returned_refresh_token
                and returned_refresh_token
                != old_refresh_token
            )

            hass.config_entries.async_update_entry(
                entry,
                data=new_data,
            )

            _LOGGER.info(
                "Buderus token refresh successful: "
                "expires_at=%s, "
                "refresh_token_returned=%s, "
                "refresh_token_rotated=%s",
                new_data.get(
                    CONF_EXPIRES_AT
                ),
                bool(
                    returned_refresh_token
                ),
                refresh_token_rotated,
            )

            return new_data[
                CONF_ACCESS_TOKEN
            ]

    client = BuderusPointTClient(
        session,
        async_get_access_token,
    )

    coordinator = (
        BuderusDataUpdateCoordinator(
            hass,
            client,
            entry.data[
                CONF_GATEWAY_ID
            ],
        )
    )

    try:
        await (
            coordinator
            .async_config_entry_first_refresh()
        )

    except BuderusAuthError as err:
        _LOGGER.warning(
            "Buderus API authentication "
            "failed during initial refresh "
            "(status=%s)",
            getattr(
                err,
                "status",
                None,
            ),
        )

        raise ConfigEntryAuthFailed(
            "Buderus authentication "
            f"failed: {err}"
        ) from err

    hass.data.setdefault(
        DOMAIN,
        {},
    )[entry.entry_id] = coordinator

    await (
        hass.config_entries
        .async_forward_entry_setups(
            entry,
            PLATFORMS,
        )
    )

    return True

async def async_unload_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
) -> bool:
    unload_ok = (
        await hass.config_entries
        .async_unload_platforms(
            entry,
            PLATFORMS,
        )
    )
    if unload_ok:
        hass.data.get(
            DOMAIN,
            {},
        ).pop(
            entry.entry_id,
            None,
        )
    return unload_ok
