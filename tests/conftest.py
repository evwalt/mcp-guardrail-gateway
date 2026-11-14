"""Shared fixtures.

All secrets are generated here at runtime so nothing secret-shaped is ever
committed to the repository (keeps Gitleaks clean).
"""

from __future__ import annotations

import secrets as _secrets

import pytest

from src.db import seed as seed_mod
from src.security import middleware as mw


@pytest.fixture
def jwt_secret() -> str:
    return _secrets.token_hex(32)


@pytest.fixture
def api_keys() -> dict[str, str]:
    # Deterministic shape (sk-live-...) but freshly random values per run.
    return {uid: "sk-live-" + _secrets.token_hex(16) for uid in ("user_101", "user_102", "admin_001")}


@pytest.fixture
def db_path(tmp_path, api_keys):
    path = tmp_path / "customers.db"
    seed_mod.seed(path, api_keys=api_keys)
    return path


@pytest.fixture
def token_user_101(jwt_secret) -> str:
    return mw.issue_token("user_101", jwt_secret)


@pytest.fixture
def auth_user_101(token_user_101, jwt_secret) -> mw.AuthContext:
    return mw.authenticate(f"Bearer {token_user_101}", jwt_secret)
