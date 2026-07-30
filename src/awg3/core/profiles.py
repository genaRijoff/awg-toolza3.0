"""Генерация параметров обфускации.

Каждый сгенерированный набор обязан проходить валидацию models.ObfParams —
это проверяется тестом на тысяче генераций. Генератор, который иногда выдаёт
невалидное, хуже отсутствующего: ошибка всплывёт у клиента, а не при создании.

H1-H4 разводятся по четырём непересекающимся четвертям диапазона. Это
единственный способ гарантировать уникальность без перебора с откатом:
случайные значения в общем диапазоне рано или поздно столкнутся.
"""

from __future__ import annotations

import secrets
from dataclasses import dataclass

from . import cps, wgkeys
from .models import (
    H_MAX,
    H_MIN,
    S_MIN_FOR_HEADER_PROTECTION,
    AWG3Params,
    ObfParams,
    Range,
)

_rand = secrets.SystemRandom()


@dataclass(frozen=True, slots=True)
class Profile:
    """Профиль обфускации: чем выше, тем больше мусора и накладных расходов."""

    name: str
    title: str
    description: str
    jc: tuple[int, int]
    jmin: tuple[int, int]
    jmax: tuple[int, int]
    s1: tuple[int, int]
    s2: tuple[int, int]
    s3: tuple[int, int]
    s4: tuple[int, int]


PROFILES: dict[str, Profile] = {
    "lite": Profile(
        name="lite",
        title="Lite",
        description="минимум мусора, максимум скорости; для слабого DPI",
        jc=(3, 5), jmin=(30, 60), jmax=(200, 400),
        s1=(15, 40), s2=(15, 40), s3=(12, 24), s4=(12, 24),
    ),
    "standard": Profile(
        name="standard",
        title="Standard",
        description="баланс; рекомендуется по умолчанию",
        jc=(4, 8), jmin=(50, 100), jmax=(400, 700),
        s1=(30, 70), s2=(30, 70), s3=(14, 34), s4=(14, 34),
    ),
    "pro": Profile(
        name="pro",
        title="Pro",
        description="агрессивная маскировка; заметнее по трафику и задержкам",
        jc=(8, 12), jmin=(80, 150), jmax=(700, 1100),
        s1=(60, 120), s2=(60, 120), s3=(20, 50), s4=(20, 50),
    ),
}

DEFAULT_PROFILE = "standard"

# Минимальный зазор между S1+56 и S2. Мануал запрещает точное равенство;
# зазор берём с запасом, чтобы не упереться в границу из-за округлений.
_S_GAP = 10


def _pick(bounds: tuple[int, int]) -> int:
    return _rand.randint(bounds[0], bounds[1])


def generate_obf(
    profile_name: str = DEFAULT_PROFILE,
    *,
    awg3: bool = True,
    mimicry: cps.Profile | None = cps.Profile.QUIC,
    mtu: int = 1420,
    i_count: int = 5,
    tags: cps.TagSet = cps.TagSet.EXTENDED,
) -> ObfParams:
    """Параметры AWG 2.0 для профиля.

    awg3=True поднимает нижнюю границу S1-S4 до 12: без этого header protection
    отвергается демоном с EINVAL, а узнать об этом при создании сервера лучше,
    чем при первом подключении клиента.
    """
    profile = PROFILES.get(profile_name)
    if profile is None:
        raise ValueError(
            f"неизвестный профиль '{profile_name}'; есть: {', '.join(PROFILES)}"
        )

    floor = S_MIN_FOR_HEADER_PROTECTION if awg3 else 0

    s1 = max(_pick(profile.s1), floor)
    s2 = max(_pick(profile.s2), floor)
    # S1 + 56 == S2 запрещено мануалом. Раздвигаем, а не перегенерируем:
    # цикл перегенерации может не сойтись на узком диапазоне профиля.
    if abs((s1 + 56) - s2) < _S_GAP:
        s2 = s1 + 56 + _S_GAP

    jmin = _pick(profile.jmin)
    jmax = _pick(profile.jmax)
    if jmax <= jmin:
        jmax = jmin + 100

    intensity = {"lite": cps.LOW, "standard": cps.MEDIUM, "pro": cps.HIGH}[profile_name]
    chains = (
        cps.generate_set(mimicry, i_count, mtu, intensity, tags) if mimicry else []
    )

    return ObfParams(
        jc=_pick(profile.jc),
        jmin=jmin,
        jmax=jmax,
        s1=s1,
        s2=s2,
        s3=max(_pick(profile.s3), floor),
        s4=max(_pick(profile.s4), floor),
        h1=_h_quadrant(0),
        h2=_h_quadrant(1),
        h3=_h_quadrant(2),
        h4=_h_quadrant(3),
        i=chains,
    )


def _h_quadrant(index: int) -> Range:
    """Диапазон H внутри своей четверти общего пространства.

    Четверти не пересекаются по построению, поэтому проверка на пересечение
    в ObfParams.errors() никогда не сработает — она там как страховка на
    случай ручной правки конфига.
    """
    span = (H_MAX - H_MIN) // 4
    low = H_MIN + span * index
    high = low + span - 1
    start = _rand.randint(low, high - 1_000_000)
    return Range(start, start + _rand.randint(100_000, 900_000))


def generate_awg3(*, enable_header_protection: bool = True) -> AWG3Params:
    """Параметры AWG 3.

    Тайминги рандомизируются, но инвариант rekey_after < reject_after
    соблюдается по построению: reject считается от верхней границы rekey.
    Стоковые значения amneziawg-go — 120 / 180 / 5 / 10 / 18.
    """
    rekey_lo = _rand.randint(100, 130)
    rekey_hi = rekey_lo + _rand.randint(10, 30)
    reject_lo = rekey_hi + _rand.randint(20, 40)
    reject_hi = reject_lo + _rand.randint(10, 30)

    return AWG3Params(
        header_protection_key=(
            wgkeys.generate_symmetric_key() if enable_header_protection else None
        ),
        content_padding_addition=Range(
            _rand.randint(1, 30), _rand.randint(40, 120)
        ),
        rekey_after_time=Range(rekey_lo, rekey_hi),
        rekey_timeout=Range(_rand.randint(4, 6), _rand.randint(7, 10)),
        reject_after_time=Range(reject_lo, reject_hi),
        keepalive_timeout=Range(_rand.randint(8, 12), _rand.randint(15, 25)),
        max_handshake_attempts=Range(_rand.randint(5, 10), _rand.randint(12, 20)),
    )


def profile_choices() -> list[Profile]:
    """Профили в порядке возрастания агрессивности — для меню."""
    return [PROFILES["lite"], PROFILES["standard"], PROFILES["pro"]]
