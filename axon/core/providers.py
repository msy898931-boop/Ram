# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 msy898931-boop
# Part of the AXON open core. See NOTICE for the license map.
"""Deprecated import path — use `axon.providers` instead.

Kept so existing `from axon.core.providers import ...` keeps working.
"""

from __future__ import annotations

from axon.providers import (
    PRICES,
    AnthropicProvider,
    AuthError,
    Completion,
    MockProvider,
    OpenAICompatibleProvider,
    ProviderError,
    RateLimitError,
    TransientError,
    Usage,
    available_providers,
    default_provider,
    get_provider,
    price_for,
    register_price,
)

__all__ = [
    "PRICES",
    "AnthropicProvider",
    "AuthError",
    "Completion",
    "MockProvider",
    "OpenAICompatibleProvider",
    "ProviderError",
    "RateLimitError",
    "TransientError",
    "Usage",
    "available_providers",
    "default_provider",
    "get_provider",
    "price_for",
    "register_price",
]
