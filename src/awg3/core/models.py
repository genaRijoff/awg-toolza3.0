"""Доменные модели и инварианты.

Валидация собрана здесь целиком, а не размазана по вызовам. Каждая модель
умеет `errors()` — список проблем на русском. Список, а не исключение на
первой же ошибке: в меню оператору надо показать всё сразу.

Источники инвариантов:
  * мануал AmneziaWG — S1+56 != S2, уникальность H1-H4, границы Jc/Jmin/Jmax;
  * header protection требует S1-S4 >= 12 (nonce ChaCha20 берётся из
    crypto-паддинга); README обещает 8, но это неверно — проверено на живом
    демоне;
  * поведение протокола — Jmax ниже MTU, иначе пакет фрагментируется, а
    фрагментация со стороны цензора выглядит подозрительно;
  * связь таймеров AWG 3 — сессия обязана перевыпустить ключи раньше, чем
    будет отвергнута, то есть rekey_after_time < reject_after_time.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from . import cps, wgkeys

# ── границы из мануала ──────────────────────────────────────────────
JC_MIN, JC_MAX = 1, 128
S_MAX = 1132              # 1280 - 148 (размер Init-пакета)
H_MIN, H_MAX = 5, 2**31 - 1
# 12, а не 8, как обещает README amneziawg-go.
#
# HeaderCipherNonceSize = 12 (device/noise-types.go). В send.go строится
# crypt := buf[:padding], а затем crypt[:HeaderCipherNonceSize] берётся как
# nonce для ChaCha20. При padding < 12 срез уходит за границу паддинга в тело
# сообщения — в Go это легально, пока внутри cap, поэтому демон не падает.
# Nonce просто перестаёт быть случайным, и шифр молча слабеет.
#
# Подтверждено трижды: probe проходил при S3=16, живой сервер отдавал EINVAL
# при S3=10, исходники AmneziaWG Architect называют ту же константу.
S_MIN_FOR_HEADER_PROTECTION = 12
MTU_MIN, MTU_MAX = 1280, 1500
DEFAULT_MTU = 1320        # с запасом под ContentPaddingAddition AWG 3

RANGE_OFF = "(off)"


class ValidationFailed(ValueError):
    """Модель не прошла проверку."""

    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


@dataclass(frozen=True, slots=True)
class Range:
    """Диапазон UAPI. Формат "a-b", либо одиночное "a", либо "(off)".

    Одиночное значение представляем как lo == hi — так все проверки
    пересечений и границ пишутся один раз.
    """

    lo: int
    hi: int

    def __post_init__(self) -> None:
        if self.lo > self.hi:
            raise ValueError(f"диапазон вывернут: {self.lo} > {self.hi}")

    @classmethod
    def parse(cls, raw: str) -> Range | None:
        """Разбирает строку. Возвращает None для "(off)"."""
        text = raw.strip()
        if not text or text == RANGE_OFF:
            return None
        if "-" in text:
            lo_text, _, hi_text = text.partition("-")
            return cls(_to_int(lo_text, raw), _to_int(hi_text, raw))
        value = _to_int(text, raw)
        return cls(value, value)

    def render(self) -> str:
        return str(self.lo) if self.lo == self.hi else f"{self.lo}-{self.hi}"

    def overlaps(self, other: Range) -> bool:
        return self.lo <= other.hi and other.lo <= self.hi

    def __str__(self) -> str:
        return self.render()


def _to_int(text: str, original: str) -> int:
    try:
        return int(text.strip())
    except ValueError as exc:
        raise ValueError(f"не диапазон: {original!r}") from exc


# ── AWG 2.0: обфускация ─────────────────────────────────────────────


@dataclass(slots=True)
class ObfParams:
    """Jc/Jmin/Jmax, S1-S4, H1-H4."""

    jc: int
    jmin: int
    jmax: int
    s1: int
    s2: int
    s3: int
    s4: int
    h1: Range
    h2: Range
    h3: Range
    h4: Range
    # I1-I5: junk-пакеты, маскирующиеся под настоящие протоколы. Пустой список
    # означает, что мимикрия выключена и шлётся только случайный мусор Jc.
    i: list[str] = field(default_factory=list)

    @property
    def s_values(self) -> tuple[int, int, int, int]:
        return (self.s1, self.s2, self.s3, self.s4)

    def errors(self, mtu: int = DEFAULT_MTU) -> list[str]:
        problems: list[str] = []

        if not JC_MIN <= self.jc <= JC_MAX:
            problems.append(f"Jc={self.jc} вне диапазона {JC_MIN}..{JC_MAX}")
        if self.jmin >= self.jmax:
            problems.append(f"Jmin={self.jmin} должен быть строго меньше Jmax={self.jmax}")
        if self.jmax >= mtu:
            problems.append(
                f"Jmax={self.jmax} >= MTU={mtu}: junk-пакет фрагментируется, "
                "фрагментация демаскирует туннель"
            )

        for name, value in zip(("S1", "S2", "S3", "S4"), self.s_values, strict=True):
            if value < 0:
                problems.append(f"{name}={value}: отрицательное значение")
            elif value > S_MAX:
                problems.append(f"{name}={value} > {S_MAX}")

        if self.s1 + 56 == self.s2:
            problems.append(
                f"S1+56 == S2 ({self.s1}+56=={self.s2}): запрещено мануалом"
            )

        h_named = (("H1", self.h1), ("H2", self.h2), ("H3", self.h3), ("H4", self.h4))
        for name, rng in h_named:
            if rng.lo < H_MIN or rng.hi > H_MAX:
                problems.append(
                    f"{name}={rng} вне рекомендованного {H_MIN}..{H_MAX}"
                )
        if len(self.i) > 5:
            problems.append(f"I-параметров может быть не больше 5, задано {len(self.i)}")
        for index, chain in enumerate(self.i[:5], start=1):
            for problem in cps.errors(chain, mtu):
                problems.append(f"I{index}: {problem}")

        for i, (name_a, rng_a) in enumerate(h_named):
            for name_b, rng_b in h_named[i + 1:]:
                if rng_a.overlaps(rng_b):
                    problems.append(
                        f"{name_a}={rng_a} и {name_b}={rng_b} пересекаются: "
                        "заголовки станут неразличимы"
                    )
        return problems


# ── AWG 3.0 ─────────────────────────────────────────────────────────


@dataclass(slots=True)
class AWG3Params:
    """Параметры AWG 3. Любой может отсутствовать — тогда он не пишется."""

    header_protection_key: str | None = None
    content_padding_addition: Range | None = None
    rekey_after_time: Range | None = None
    rekey_timeout: Range | None = None
    reject_after_time: Range | None = None
    keepalive_timeout: Range | None = None
    max_handshake_attempts: Range | None = None

    @property
    def enabled(self) -> bool:
        """AWG 3 считается включённым по наличию ключа header protection.

        Остальные параметры client-side и сами по себе версию не поднимают.
        """
        return bool(self.header_protection_key)

    def errors(self, s_values: tuple[int, int, int, int]) -> list[str]:
        problems: list[str] = []

        if self.header_protection_key is not None:
            if not wgkeys.is_valid_b64_key(self.header_protection_key):
                problems.append(
                    "HeaderProtectionKey: не base64-ключ на 32 байта"
                )
            too_small = [
                f"S{i}={v}"
                for i, v in enumerate(s_values, start=1)
                if v < S_MIN_FOR_HEADER_PROTECTION
            ]
            if too_small:
                problems.append(
                    "header protection требует S1-S4 >= "
                    f"{S_MIN_FOR_HEADER_PROTECTION}, а сейчас: {', '.join(too_small)}"
                )

        if self.rekey_after_time and self.reject_after_time:
            if self.rekey_after_time.hi >= self.reject_after_time.lo:
                problems.append(
                    f"RekeyAfterTime={self.rekey_after_time} пересекается с "
                    f"RejectAfterTime={self.reject_after_time}: сессию отвергнет "
                    "раньше, чем она успеет сменить ключи"
                )

        for name, rng in (
            ("RekeyAfterTime", self.rekey_after_time),
            ("RekeyTimeout", self.rekey_timeout),
            ("RejectAfterTime", self.reject_after_time),
            ("KeepaliveTimeout", self.keepalive_timeout),
            ("MaxHandshakeAttempts", self.max_handshake_attempts),
            ("ContentPaddingAddition", self.content_padding_addition),
        ):
            if rng is not None and rng.lo < 0:
                problems.append(f"{name}={rng}: отрицательное значение")

        return problems


# ── Пиры и сервер ───────────────────────────────────────────────────


@dataclass(slots=True)
class Peer:
    name: str
    public_key: str
    allowed_ips: list[str]
    preshared_key: str | None = None

    def errors(self) -> list[str]:
        problems: list[str] = []
        if not self.name.strip():
            problems.append("имя пира пустое")
        if not wgkeys.is_valid_b64_key(self.public_key):
            problems.append(f"{self.name}: PublicKey не является ключом на 32 байта")
        if self.preshared_key is not None and not wgkeys.is_valid_b64_key(
            self.preshared_key
        ):
            problems.append(f"{self.name}: PresharedKey некорректен")
        if not self.allowed_ips:
            problems.append(f"{self.name}: пустой AllowedIPs")
        return problems


@dataclass(slots=True)
class ServerConfig:
    private_key: str
    listen_port: int
    address: str
    obf: ObfParams
    mtu: int = DEFAULT_MTU
    awg3: AWG3Params = field(default_factory=AWG3Params)
    peers: list[Peer] = field(default_factory=list)

    def errors(self) -> list[str]:
        problems: list[str] = []

        if not wgkeys.is_valid_b64_key(self.private_key):
            problems.append("PrivateKey сервера некорректен")
        if not 1 <= self.listen_port <= 65535:
            problems.append(f"ListenPort={self.listen_port} вне 1..65535")
        if not MTU_MIN <= self.mtu <= MTU_MAX:
            problems.append(f"MTU={self.mtu} вне {MTU_MIN}..{MTU_MAX}")
        if "/" not in self.address:
            problems.append(f"Address={self.address!r}: нужен CIDR, например 10.200.0.1/24")

        problems += self.obf.errors(self.mtu)
        problems += self.awg3.errors(self.obf.s_values)

        seen: set[str] = set()
        for peer in self.peers:
            problems += peer.errors()
            if peer.public_key in seen:
                problems.append(f"дубликат PublicKey у пира {peer.name}")
            seen.add(peer.public_key)

        return problems

    def ensure_valid(self) -> None:
        problems = self.errors()
        if problems:
            raise ValidationFailed(problems)

    def to_uapi_pairs(self, allowed_keys: set[str]) -> list[tuple[str, str]]:
        """Рендер в последовательность UAPI key=value.

        allowed_keys — подтверждённое пробой подмножество имён. Ключ, которого
        там нет, молча пропускается: лучше поднять туннель без параметра, чем
        уронить весь `set` из-за одного незнакомого имени.

        Порядок значим: ключи пира идут после его public_key.
        """
        pairs: list[tuple[str, str]] = [
            ("private_key", wgkeys.to_uapi_hex(self.private_key, "PrivateKey")),
            ("listen_port", str(self.listen_port)),
            ("replace_peers", "true"),
        ]

        obf_values: dict[str, str] = {
            "jc": str(self.obf.jc),
            "jmin": str(self.obf.jmin),
            "jmax": str(self.obf.jmax),
            "s1": str(self.obf.s1),
            "s2": str(self.obf.s2),
            "s3": str(self.obf.s3),
            "s4": str(self.obf.s4),
            "h1": self.obf.h1.render(),
            "h2": self.obf.h2.render(),
            "h3": self.obf.h3.render(),
            "h4": self.obf.h4.render(),
        }
        for index, chain in enumerate(self.obf.i[:5], start=1):
            obf_values[f"i{index}"] = chain
        pairs += [(k, v) for k, v in obf_values.items() if k in allowed_keys]

        awg3_values: dict[str, str | None] = {
            "header_protection_key": (
                wgkeys.to_uapi_hex(self.awg3.header_protection_key, "HeaderProtectionKey")
                if self.awg3.header_protection_key
                else None
            ),
            "content_padding_addition": _render(self.awg3.content_padding_addition),
            "rekey_after_time": _render(self.awg3.rekey_after_time),
            "rekey_timeout": _render(self.awg3.rekey_timeout),
            "reject_after_time": _render(self.awg3.reject_after_time),
            "keepalive_timeout": _render(self.awg3.keepalive_timeout),
            "max_handshake_attempts": _render(self.awg3.max_handshake_attempts),
        }
        pairs += [
            (k, v) for k, v in awg3_values.items() if v is not None and k in allowed_keys
        ]

        for peer in self.peers:
            pairs.append(("public_key", wgkeys.to_uapi_hex(peer.public_key, peer.name)))
            if peer.preshared_key:
                pairs.append(
                    ("preshared_key", wgkeys.to_uapi_hex(peer.preshared_key, peer.name))
                )
            pairs.append(("replace_allowed_ips", "true"))
            pairs += [("allowed_ip", cidr) for cidr in peer.allowed_ips]

        return pairs


def _render(rng: Range | None) -> str | None:
    return rng.render() if rng is not None else None
