"""Tests for auth.py — GATE-M runs these post-write."""
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from src.auth import validate_user, get_user_role, logout
from src.models import User


def test_validate_active_user():
    u = User("alice", is_active=True)
    assert validate_user(u) is True


def test_validate_inactive_user():
    u = User("bob", is_active=False)
    assert validate_user(u) is False


def test_get_role():
    u = User("carol", role="admin")
    assert get_user_role(u) == "admin"


def test_logout_clears_session():
    u = User("dave")
    u.session_token = "tok_abc"
    logout(u)
    assert u.session_token is None
