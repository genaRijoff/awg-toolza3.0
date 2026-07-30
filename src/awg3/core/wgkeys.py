"""Ключи WireGuard/AmneziaWG.

Сознательно не вызываем `awg genkey`: пакет amneziawg-tools системный, и
деинсталлятор AWG 2.0 его сносит. Всё делаем сами через cryptography.

Два представления одного ключа:
    .conf  — base64 (то, что видит пользователь и клиентское приложение)
    UAPI   — hex    (то, что принимает сокет amneziawg-go)
Путать их — самая частая ошибка при ручной работе с UAPI, поэтому
конвертация здесь одна и с проверкой длины.
"""

from __future__ import annotations

import base64
import binascii
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)

KEY_BYTES = 32


class KeyError_(ValueError):
    """Некорректный ключ."""


def _decode_b64(value: str, label: str) -> bytes:
    try:
        raw = base64.b64decode(value, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise KeyError_(f"{label}: не base64") from exc
    if len(raw) != KEY_BYTES:
        raise KeyError_(f"{label}: длина {len(raw)} байт, ожидается {KEY_BYTES}")
    return raw


def generate_private_key() -> str:
    """Приватный ключ X25519 в base64 (эквивалент `awg genkey`)."""
    raw = X25519PrivateKey.generate().private_bytes(
        encoding=Encoding.Raw,
        format=PrivateFormat.Raw,
        encryption_algorithm=NoEncryption(),
    )
    return base64.b64encode(raw).decode("ascii")


def public_key(private_b64: str) -> str:
    """Публичный ключ из приватного (эквивалент `awg pubkey`)."""
    raw = _decode_b64(private_b64, "приватный ключ")
    pub = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        encoding=Encoding.Raw,
        format=PublicFormat.Raw,
    )
    return base64.b64encode(pub).decode("ascii")


def generate_symmetric_key() -> str:
    """32 случайных байта в base64.

    Используется и для PresharedKey, и для HeaderProtectionKey: оба —
    симметричные секреты, а не пары X25519.
    """
    return base64.b64encode(secrets.token_bytes(KEY_BYTES)).decode("ascii")


def to_uapi_hex(key_b64: str, label: str = "ключ") -> str:
    """base64 (.conf) -> hex (UAPI)."""
    return _decode_b64(key_b64, label).hex()


def from_uapi_hex(key_hex: str, label: str = "ключ") -> str:
    """hex (UAPI) -> base64 (.conf)."""
    try:
        raw = bytes.fromhex(key_hex)
    except ValueError as exc:
        raise KeyError_(f"{label}: не hex") from exc
    if len(raw) != KEY_BYTES:
        raise KeyError_(f"{label}: длина {len(raw)} байт, ожидается {KEY_BYTES}")
    return base64.b64encode(raw).decode("ascii")


def is_valid_b64_key(value: str) -> bool:
    try:
        _decode_b64(value, "ключ")
    except KeyError_:
        return False
    return True
