"""HTTP transport with bounded retries, timeouts, and typed error mapping.

Kept dependency-free (stdlib urllib) so AXON installs anywhere, including
air-gapped environments where pulling a large HTTP stack is unacceptable.
"""

from __future__ import annotations

import json
import random
import time
import urllib.error
import urllib.request

from .base import AuthError, ProviderError, RateLimitError, TransientError

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504, 529}


def _classify(status: int, body: str) -> ProviderError:
    detail = body[:400].replace("\n", " ")
    if status in (401, 403):
        return AuthError(f"HTTP {status}: {detail}")
    if status == 429:
        return RateLimitError(f"HTTP 429: {detail}")
    if status >= 500:
        return TransientError(f"HTTP {status}: {detail}")
    return ProviderError(f"HTTP {status}: {detail}")


def post_json(
    url: str,
    payload: dict,
    headers: dict[str, str],
    *,
    timeout: float = 60.0,
    max_retries: int = 4,
    backoff: float = 0.5,
) -> dict:
    """POST JSON with exponential backoff + jitter on retryable failures."""
    body = json.dumps(payload).encode()
    last: Exception | None = None

    for attempt in range(max_retries + 1):
        req = urllib.request.Request(url, data=body, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode())
        except urllib.error.HTTPError as exc:
            err = _classify(exc.code, exc.read().decode(errors="replace"))
            if not isinstance(err, (RateLimitError, TransientError)) or attempt == max_retries:
                raise err from exc
            last = err
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            last = TransientError(f"network error: {exc}")
            if attempt == max_retries:
                raise last from exc

        sleep = backoff * (2**attempt) + random.uniform(0, backoff)
        retry_after = getattr(getattr(last, "__cause__", None), "headers", None)
        if retry_after is not None:
            try:
                sleep = max(sleep, float(retry_after.get("Retry-After", 0)))
            except (TypeError, ValueError):
                pass
        time.sleep(min(sleep, 30.0))

    raise last or ProviderError("request failed")
