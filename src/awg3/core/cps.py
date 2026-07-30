"""Генератор CPS (Client Packet Signature) — параметры I1-I5.

Jc/Jmin/Jmax шлют случайный мусор: пакеты правдоподобного размера, но без
формы. Для DPI поток пакетов со случайным содержимым перед хендшейком сам
по себе аномалия. I1-I5 задают junk-пакеты, которые выглядят как начало
настоящего протокола — TLS ClientHello, QUIC Initial, DNS-запрос.

Главное отличие от подхода AWG Toolza: там весь пакет сбрасывается в один
статический `<b 0x...>`, из-за чего I1 клиента побайтово одинаков при каждом
хендшейке — и это готовая сигнатура. Здесь фиксированной остаётся только
структурная часть заголовка, а случайные поля (client_random, session_id,
connection ID, transaction ID) заполняются тегами и меняются каждый раз.

Словарь тегов amneziawg-go:
    <b 0xHH..>  литеральные байты, длина hex обязана быть чётной
    <r N>       N случайных байт          максимум 1000 на тег
    <rc N>      N случайных букв [a-zA-Z] максимум 1000 на тег
    <rd N>      N случайных цифр          максимум 1000 на тег
    <t>         4-байтовый UNIX-таймстемп

Сознательно НЕ используются:
    <c>              ломается в старых amneziawg-go (ErrorCode 1000),
                     разработчики Amnezia от него отказались;
    <d>, <ds>, <dz>  в 3.0.1 разбираются, но к отправке пакетов не подключены —
                     это задел под AWG 4.0.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from enum import Enum

_rand = secrets.SystemRandom()

TAG_MAX_BYTES = 1000
TIMESTAMP_BYTES = 4

# Домены для SNI-подобных участков. Реальные хосты нужны потому, что длина
# имени влияет на размер пакета, а неправдоподобная длина — тоже признак.
_TLS_HOSTS = (
    "www.google.com", "www.cloudflare.com", "cdn.jsdelivr.net",
    "www.microsoft.com", "static.licdn.com", "www.apple.com",
)
_QUIC_HOSTS = (
    "fastly.net", "cdn-apple.com", "yastatic.net",
    "www.google.com", "cloudflare-quic.com",
)
_DNS_HOSTS = (
    "ya.ru", "google.com", "cloudflare.com", "apple.com", "microsoft.com",
)


class TagSet(str, Enum):
    """Какие теги использовать.

    BASIC — только <b> и <r>, они есть со времён AWG 1.5 и разбираются любой
    сборкой. EXTENDED добавляет <rc>, <rd> и <t>: пакет получается лучше, но
    клиент со старой встроенной сборкой amneziawg-go отвечает ErrorCode 1000
    на незнакомый тег. Android тянет свою сборку, и она бывает старше сервера.
    """

    BASIC = "basic"
    EXTENDED = "extended"


class Profile(str, Enum):
    """Профиль мимикрии."""

    TLS = "tls"
    QUIC = "quic"
    DNS = "dns"
    NOISE = "noise"


PROFILE_TITLES: dict[Profile, str] = {
    Profile.TLS: "TLS 1.3 ClientHello",
    Profile.QUIC: "QUIC Initial (RFC 9000)",
    Profile.DNS: "DNS-запрос",
    Profile.NOISE: "Случайный шум",
}


class CPSError(ValueError):
    """Некорректная цепочка CPS."""


@dataclass(frozen=True, slots=True)
class Intensity:
    """Сколько паддинга добавлять. Больше — заметнее по трафику."""

    name: str
    scale: float


LOW = Intensity("low", 0.6)
MEDIUM = Intensity("medium", 1.0)
HIGH = Intensity("high", 1.5)


# ── примитивы ───────────────────────────────────────────────────────


def _hex_bytes(count: int) -> str:
    return secrets.token_bytes(max(0, count)).hex()


def _hex_int(value: int, byte_length: int) -> str:
    """Целое в hex фиксированной длины. Длина hex всегда чётная."""
    if value < 0:
        raise CPSError(f"отрицательное значение: {value}")
    limit = 1 << (8 * byte_length)
    if value >= limit:
        raise CPSError(f"{value} не помещается в {byte_length} байт")
    return value.to_bytes(byte_length, "big").hex()


def _split_pad(total: int, tag: str = "r") -> str:
    """Режет паддинг на теги по 1000 байт — предел amneziawg-go."""
    total = max(0, int(total))
    if total == 0:
        return ""
    parts: list[str] = []
    while total > TAG_MAX_BYTES:
        parts.append(f"<{tag} {TAG_MAX_BYTES}>")
        total -= TAG_MAX_BYTES
    parts.append(f"<{tag} {total}>")
    return "".join(parts)


def _dns_name_hex(host: str) -> str:
    """Доменное имя в формате DNS: длина метки, метка, ..., нулевой байт."""
    out = ""
    for label in host.split("."):
        encoded = label.encode("ascii", errors="ignore")[:63]
        out += _hex_int(len(encoded), 1) + encoded.hex()
    return out + "00"


# ── профили ─────────────────────────────────────────────────────────


def _make_tls(mtu: int, intensity: Intensity, tags: TagSet) -> str:
    """TLS 1.3 ClientHello.

    Структура фиксирована, client_random заполняется тегом <r 32> — именно
    поэтому пакет не повторяется. В Toolza он был литеральным и одинаковым.

    Объявленная длина записи считается ОТ фактического размера, а не берётся
    случайно: иначе заголовок обещает 500 байт, а приходит 120, и DPI,
    разбирающий TLS, видит несоответствие вместо правдоподобного хендшейка.
    """
    host = _rand.choice(_TLS_HOSTS)
    sni_len = min(2 + 2 + 2 + 1 + 2 + len(host), 64)

    # 5 байт заголовка записи + 6 байт заголовка хендшейка + client_version
    fixed = 5 + 4 + 2 + 32 + sni_len + TIMESTAMP_BYTES
    pad = min(int(_rand.randint(60, 240) * intensity.scale), 500, max(0, mtu - fixed))

    # Всё, что идёт после 5-байтового заголовка записи.
    record_len = 4 + 2 + 32 + sni_len + pad
    handshake_len = record_len - 4

    header = (
        "160301"                          # TLS record: handshake, версия 3.1
        + _hex_int(record_len, 2)
        + "01"                            # тип: ClientHello
        + _hex_int(handshake_len, 3)
        + "0303"                          # client_version TLS 1.2 (как у TLS 1.3)
    )

    extended = tags is TagSet.EXTENDED
    return (
        f"<b 0x{header}>"
        f"<r 32>"                         # client_random — свежий каждый раз
        + (f"<rc {sni_len}>" if extended else f"<r {sni_len}>")
        + _split_pad(pad)
        + ("<t>" if extended else "")
    )


def _make_quic(mtu: int, intensity: Intensity, tags: TagSet) -> str:
    """QUIC Initial по RFC 9000: long header, версия 1."""
    host = _rand.choice(_QUIC_HOSTS)
    dcid_len = _rand.randint(8, 20)
    scid_len = _rand.randint(0, 20)
    token_len = 0 if _rand.randint(0, 1) == 0 else _rand.randint(8, 32)
    sni_len = min(len(host) + _rand.randint(0, 6), 64)

    first_byte = 0xC0 | _rand.randint(0, 3)   # long header, тип Initial
    header = (
        _hex_int(first_byte, 1)
        + "00000001"                          # версия QUIC 1
        + _hex_int(dcid_len, 1) + _hex_bytes(dcid_len)
        + _hex_int(scid_len, 1) + _hex_bytes(scid_len)
        + _hex_int(token_len, 1) + _hex_bytes(token_len)
    )

    overhead = len(header) // 2 + 4 + sni_len + TIMESTAMP_BYTES
    pad = min(int(_rand.randint(20, 80) * intensity.scale), 500, max(0, mtu - overhead))

    extended = tags is TagSet.EXTENDED
    return (
        f"<b 0x{header}>"
        f"<r 4>"                              # длина пакета и номер
        + (f"<rc {sni_len}>" if extended else f"<r {sni_len}>")
        + ("<t>" if extended else "")
        + _split_pad(pad)
    )


def _make_dns(mtu: int, intensity: Intensity, tags: TagSet) -> str:
    """DNS-запрос. Transaction ID — тег, иначе он был бы константой.

    К домену добавляется случайная метка: без неё литеральная часть пакета
    меняется только по хосту и типу записи, и наборы для разных серверов
    начинают повторяться. Настоящие CDN-запросы так и выглядят.
    """
    label_len = _rand.randint(6, 14)
    alphabet = "abcdefghijklmnopqrstuvwxyz0123456789"
    prefix = "".join(_rand.choice(alphabet) for _ in range(label_len))
    host = f"{prefix}.{_rand.choice(_DNS_HOSTS)}"
    qtype = "0001" if _rand.randint(0, 1) == 0 else "001c"   # A либо AAAA

    header = (
        "0100"          # flags: стандартный запрос, рекурсия
        "0001"          # QDCOUNT
        "0000" "0000" "0000"
        + _dns_name_hex(host)
        + qtype
        + "0001"        # QCLASS = IN
    )

    overhead = 2 + len(header) // 2 + TIMESTAMP_BYTES
    target = _rand.randint(64, min(512, max(80, mtu - 20)))
    pad = min(max(0, target - overhead), 200, max(0, mtu - overhead))
    pad = int(pad * intensity.scale)

    extended = tags is TagSet.EXTENDED
    return (
        (f"<rd 2>" if extended else f"<r 2>")   # transaction ID, меняется каждый раз
        + f"<b 0x{header}>"
        + _split_pad(pad)
        + ("<t>" if extended else "")
    )


def _make_noise(mtu: int, intensity: Intensity, tags: TagSet) -> str:
    """Просто случайные байты. Запасной вариант, формы не имитирует."""
    size = min(int(_rand.randint(40, 200) * intensity.scale), max(8, mtu - 8))
    return _split_pad(size) + ("<t>" if tags is TagSet.EXTENDED else "")


_MAKERS = {
    Profile.TLS: _make_tls,
    Profile.QUIC: _make_quic,
    Profile.DNS: _make_dns,
    Profile.NOISE: _make_noise,
}


# ── публичный интерфейс ─────────────────────────────────────────────


def generate(
    profile: Profile,
    mtu: int = 1420,
    intensity: Intensity = MEDIUM,
    tags: TagSet = TagSet.EXTENDED,
) -> str:
    """Одна цепочка CPS для указанного профиля."""
    maker = _MAKERS.get(profile)
    if maker is None:
        raise CPSError(f"неизвестный профиль: {profile}")
    return maker(mtu, intensity, tags)


def generate_set(
    profile: Profile,
    count: int = 5,
    mtu: int = 1420,
    intensity: Intensity = MEDIUM,
    tags: TagSet = TagSet.EXTENDED,
) -> list[str]:
    """Набор I1-I5. Каждый элемент независим — одинаковых быть не должно."""
    if not 1 <= count <= 5:
        raise CPSError(f"I-параметров может быть от 1 до 5, запрошено {count}")
    return [generate(profile, mtu, intensity, tags) for _ in range(count)]


def estimate_size(cps: str) -> int:
    """Оценка размера пакета в байтах.

    Нужна, чтобы поймать превышение MTU до того, как пакет начнёт
    фрагментироваться — фрагментация junk-трафика демаскирует туннель.
    """
    import re

    total = 0
    for match in re.finditer(r"<(b 0x([0-9a-fA-F]*)|([rc]|rc|rd|r) (\d+)|t)>", cps):
        token = match.group(0)
        if token.startswith("<b 0x"):
            total += len(match.group(2)) // 2
        elif token == "<t>":
            total += TIMESTAMP_BYTES
        else:
            total += int(match.group(4))
    return total


def errors(cps: str, mtu: int = 1420) -> list[str]:
    """Проверка цепочки. Пустой список — всё в порядке."""
    import re

    problems: list[str] = []

    if not cps.strip():
        problems.append("пустая цепочка CPS")
        return problems

    for name in ("<c>", "<d>", "<ds>", "<dz>"):
        if name in cps:
            problems.append(f"тег {name} использовать нельзя — не работает в 3.0.1")

    for match in re.finditer(r"<b 0x([0-9a-fA-F]*)>", cps):
        payload = match.group(1)
        if len(payload) % 2 != 0:
            problems.append(f"нечётная длина hex в <b 0x{payload[:16]}...>")
        if not payload:
            problems.append("пустой тег <b 0x>")

    for match in re.finditer(r"<(r|rc|rd) (\d+)>", cps):
        size = int(match.group(2))
        if size > TAG_MAX_BYTES:
            problems.append(
                f"<{match.group(1)} {size}> превышает предел {TAG_MAX_BYTES} байт на тег"
            )

    size = estimate_size(cps)
    if size > mtu:
        problems.append(
            f"пакет {size} байт больше MTU {mtu}: фрагментация демаскирует туннель"
        )

    return problems


def used_tags(cps: str) -> set[str]:
    """Какие теги встречаются в цепочке — для диагностики совместимости."""
    import re

    return {m.group(1) for m in re.finditer(r"<(b|r|rc|rd|t)[ >]", cps)}


def profile_choices() -> list[tuple[Profile, str]]:
    """Профили для меню."""
    return [(profile, PROFILE_TITLES[profile]) for profile in Profile]
