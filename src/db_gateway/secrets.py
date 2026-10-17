import os
import re
from typing import Protocol


class SecretLookup(Protocol):
    def __call__(self, ref: str) -> str: ...


def get_secret(ref: str) -> str:
    """Read a dev secret after uppercasing and replacing non-alphanumerics with _.

    References such as prod-admin and prod_admin resolve to the same environment
    variable. Empty references or empty normalized names are rejected.
    """
    normalized = re.sub(r"[^A-Z0-9]", "_", ref.upper())
    if not ref or not normalized:
        raise ValueError("Secret reference must not be empty")
    env_name = "DBGW_SECRET_" + normalized
    try:
        return os.environ[env_name]
    except KeyError:
        raise KeyError(f"Secret {ref!r} is missing: set environment variable {env_name}") from None
