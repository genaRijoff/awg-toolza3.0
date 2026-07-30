"""Реестр UAPI-ключей.

Зачем отдельный модуль: имена ключей в UAPI и имена в .conf — разные вещи.
README amneziawg-go документирует конфиговые имена (HeaderProtectionKey),
а через сокет идут сокращённые. Для AWG 2.0 конвенция подтверждена
(s3/s4 обрабатываются в device/uapi.go), для AWG 3 — нет.

Поэтому каждый ключ несёт Confidence. Ключи со статусом ASSUMED нельзя
применять вслепую: их проверяет `awg3 doctor` (см. probe.py) на реально
установленном бинаре, результат кладётся в БД, и дальше используется
только подтверждённое подмножество.

Так тулза переживает переименование ключей в upstream: сломается доктор
с внятным сообщением, а не рантайм с "errno=-22".
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Confidence(Enum):
    """Насколько мы уверены в имени ключа."""

    VERIFIED = "verified"          # спецификация WireGuard UAPI или исходники amneziawg-go
    CORROBORATED = "corroborated"  # то же имя в независимой реализации, но не в UAPI
    ASSUMED = "assumed"            # выведено по конвенции, ничем не подтверждено


class Scope(Enum):
    DEVICE = "device"
    PEER = "peer"


@dataclass(frozen=True, slots=True)
class UAPIKey:
    """Описание одного ключа UAPI."""

    uapi: str
    conf: str
    scope: Scope
    confidence: Confidence
    awg_version: str
    note: str = ""

    @property
    def needs_probe(self) -> bool:
        """VERIFIED пропускаем, всё остальное проверяем на живом бинаре.

        CORROBORATED тоже проверяется: подтверждение получено из другого
        потребителя параметров (sing-box), а не из UAPI amneziawg-go.
        """
        return self.confidence is not Confidence.VERIFIED


def _k(
    uapi: str,
    conf: str,
    scope: Scope,
    confidence: Confidence,
    awg_version: str,
    note: str = "",
) -> UAPIKey:
    return UAPIKey(uapi, conf, scope, confidence, awg_version, note)


# ── Базовый WireGuard: стабильная кросс-платформенная спецификация UAPI ──
BASE_KEYS: tuple[UAPIKey, ...] = (
    _k("private_key", "PrivateKey", Scope.DEVICE, Confidence.VERIFIED, "wg",
       "hex, не base64 — конвертация обязательна"),
    _k("listen_port", "ListenPort", Scope.DEVICE, Confidence.VERIFIED, "wg"),
    _k("fwmark", "FwMark", Scope.DEVICE, Confidence.VERIFIED, "wg"),
    _k("replace_peers", "-", Scope.DEVICE, Confidence.VERIFIED, "wg"),
    _k("public_key", "PublicKey", Scope.PEER, Confidence.VERIFIED, "wg",
       "hex; открывает блок пира — все последующие ключи относятся к нему"),
    _k("preshared_key", "PresharedKey", Scope.PEER, Confidence.VERIFIED, "wg"),
    _k("endpoint", "Endpoint", Scope.PEER, Confidence.VERIFIED, "wg"),
    _k("allowed_ip", "AllowedIPs", Scope.PEER, Confidence.VERIFIED, "wg",
       "по одной строке на подсеть"),
    _k("replace_allowed_ips", "-", Scope.PEER, Confidence.VERIFIED, "wg"),
    _k("persistent_keepalive_interval", "PersistentKeepalive",
       Scope.PEER, Confidence.VERIFIED, "wg"),
    _k("remove", "-", Scope.PEER, Confidence.VERIFIED, "wg"),
)

# ── AWG 1.5 / 2.0: обфускация ───────────────────────────────────────
# Сокращённая нижнерегистровая конвенция; для s3/s4 подтверждена исходниками.
AWG2_KEYS: tuple[UAPIKey, ...] = (
    _k("jc", "Jc", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("jmin", "Jmin", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("jmax", "Jmax", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("s1", "S1", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("s2", "S2", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("s3", "S3", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("s4", "S4", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("h1", "H1", Scope.DEVICE, Confidence.VERIFIED, "2.0", "диапазон вида a-b"),
    _k("h2", "H2", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("h3", "H3", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    _k("h4", "H4", Scope.DEVICE, Confidence.VERIFIED, "2.0"),
    *(
        _k(f"i{n}", f"I{n}", Scope.DEVICE, Confidence.VERIFIED, "2.0",
           "строка CPS-тегов")
        for n in range(1, 6)
    ),
)

# ── AWG 3.0 ─────────────────────────────────────────────────────────
# Все семь имён подтверждены probe на живом amneziawg-go/v3 (Ubuntu 24.04,
# сборка из master): каждое принято через UAPI при выставленных S1-S4 >= 8.
#
# Важно про header_protection_key: принимается как hex 32 байта, как и
# остальные ключи WireGuard в UAPI. В JSON sing-box тот же параметр идёт
# base64 — представления разные, не перепутать.
#
# Предусловие критично: S1-S4 должны быть >= 12 — nonce для ChaCha20 берётся
# из crypto-паддинга и требует ровно 12 байт. При меньших значениях (и на
# голом устройстве, где они равны нулю) ключ отвергается с EINVAL по причине,
# не связанной с его именем. README amneziawg-go называет цифру 8 — неверно.
AWG3_KEYS: tuple[UAPIKey, ...] = (
    _k("header_protection_key", "HeaderProtectionKey", Scope.DEVICE,
       Confidence.VERIFIED, "3.0",
       "server-side, hex 32 байта в UAPI; обязан совпадать на обеих сторонах; "
       "требует S1-S4 >= 12: nonce ChaCha20 берётся из первых 12 байт "
       "S-паддинга, при меньшем срез залезает в тело сообщения"),
    _k("content_padding_addition", "ContentPaddingAddition", Scope.DEVICE,
       Confidence.VERIFIED, "3.0", "client-side, диапазон uint32"),
    _k("rekey_after_time", "RekeyAfterTime", Scope.DEVICE,
       Confidence.VERIFIED, "3.0",
       "client-side, сек, диапазон; сток 120. Инвариант: < reject_after_time"),
    _k("rekey_timeout", "RekeyTimeout", Scope.DEVICE,
       Confidence.VERIFIED, "3.0", "client-side, сек, диапазон; сток 5"),
    _k("reject_after_time", "RejectAfterTime", Scope.DEVICE,
       Confidence.VERIFIED, "3.0",
       "client-side, сек, диапазон; сток 180. Инвариант: > rekey_after_time"),
    _k("keepalive_timeout", "KeepaliveTimeout", Scope.DEVICE,
       Confidence.VERIFIED, "3.0", "client-side, сек, диапазон; сток 10"),
    _k("max_handshake_attempts", "MaxHandshakeAttempts", Scope.DEVICE,
       Confidence.VERIFIED, "3.0", "client-side, количество, диапазон; сток 18"),
)

ALL_KEYS: tuple[UAPIKey, ...] = BASE_KEYS + AWG2_KEYS + AWG3_KEYS

BY_UAPI: dict[str, UAPIKey] = {key.uapi: key for key in ALL_KEYS}
BY_CONF: dict[str, UAPIKey] = {
    key.conf.lower(): key for key in ALL_KEYS if key.conf != "-"
}


def keys_needing_probe() -> tuple[UAPIKey, ...]:
    """Ключи, чьи имена надо подтвердить на установленном бинаре."""
    return tuple(key for key in ALL_KEYS if key.needs_probe)


def conf_to_uapi(conf_name: str) -> str:
    """Имя из .conf -> имя в UAPI. KeyError, если ключ неизвестен."""
    return BY_CONF[conf_name.lower()].uapi
