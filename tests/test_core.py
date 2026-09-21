"""Минимальные тесты ядра (без внешних зависимостей)."""
import sys
from pathlib import Path

# Чтобы можно было запускать файл напрямую
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from modules.passwords import _hash_candidates, identify_hash  # noqa: F401
from utils.helpers import extract_host, is_ip, normalize_url


def test_extract_host() -> None:
    assert extract_host("https://example.com/path") == "example.com"
    assert extract_host("example.com:8080") == "example.com"
    assert extract_host("http://1.2.3.4:8000/x") == "1.2.3.4"


def test_is_ip() -> None:
    assert is_ip("127.0.0.1") is True
    assert is_ip("::1") is True
    assert is_ip("example.com") is False
    assert is_ip("999.999.999.999") is False


def test_normalize_url() -> None:
    assert normalize_url("example.com") == "http://example.com"
    assert normalize_url("https://example.com") == "https://example.com"


def test_hash_candidates() -> None:
    h = _hash_candidates("admin")
    assert h["md5"] == "21232f297a57a5a743894a0e4a801fc3"
    assert h["sha1"] == "d033e22ae348aeb5660fc2140aec35850c4da997"
    assert h["sha256"] == (
        "8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918"
    )


def test_b64_roundtrip() -> None:
    from modules.utils_tools import b64_encode, b64_decode
    src = "hello world"
    assert b64_decode(b64_encode(src)) == src


if __name__ == "__main__":
    test_extract_host()
    test_is_ip()
    test_normalize_url()
    test_hash_candidates()
    test_b64_roundtrip()
    print("[OK] Все тесты прошли.")