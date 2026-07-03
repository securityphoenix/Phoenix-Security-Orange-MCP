"""Tests for the zero-dependency .env loader."""

import os

from phoenix_mcp.dotenv import find_dotenv, load_dotenv


def _write(path, text):
    path.write_text(text, encoding="utf-8")
    return str(path)


def test_loads_pairs_without_override(tmp_path, monkeypatch):
    env = _write(tmp_path / ".env",
                 "PHOENIX_CLIENT_ID=abc\n"
                 "export PHOENIX_CLIENT_SECRET='sh h'\n"
                 '# a comment\n'
                 'PHOENIX_API_BASE_URL="https://api.demo.appsecphx.io"\n'
                 "\n")
    monkeypatch.delenv("PHOENIX_CLIENT_ID", raising=False)
    monkeypatch.delenv("PHOENIX_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("PHOENIX_API_BASE_URL", raising=False)
    applied = load_dotenv(env)
    assert applied["PHOENIX_CLIENT_ID"] == "abc"
    assert os.environ["PHOENIX_CLIENT_SECRET"] == "sh h"        # quotes + export
    assert os.environ["PHOENIX_API_BASE_URL"].endswith("appsecphx.io")


def test_real_env_wins(tmp_path, monkeypatch):
    env = _write(tmp_path / ".env", "PHOENIX_CLIENT_ID=from_file\n")
    monkeypatch.setenv("PHOENIX_CLIENT_ID", "from_os")
    load_dotenv(env)                       # no override
    assert os.environ["PHOENIX_CLIENT_ID"] == "from_os"
    load_dotenv(env, override=True)        # explicit override
    assert os.environ["PHOENIX_CLIENT_ID"] == "from_file"


def test_missing_file_is_safe(tmp_path):
    assert load_dotenv(str(tmp_path / "nope.env")) == {}


def test_find_walks_parents(tmp_path):
    _write(tmp_path / ".env", "X=1\n")
    nested = tmp_path / "a" / "b"
    nested.mkdir(parents=True)
    assert find_dotenv(str(nested)) == str(tmp_path / ".env")
