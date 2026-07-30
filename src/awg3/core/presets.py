"""Шаблоны настроек.

Смысл: на создании сервера человек отвечает на один вопрос вместо семи.
Значения, которые в 95% случаев одинаковы, не должны запрашиваться.
"""

from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True, slots=True)
class DnsPreset:
    key: str
    title: str
    value: str
    note: str


DNS_PRESETS: tuple[DnsPreset, ...] = (
    DnsPreset("cloudflare", "Cloudflare", "1.1.1.1, 1.0.0.1",
              "без фильтрации"),
    DnsPreset("google", "Google", "8.8.8.8, 8.8.4.4",
              "стабильный"),
    DnsPreset("quad9", "Quad9", "9.9.9.9, 149.112.112.112",
              "режет вредоносные домены"),
    DnsPreset("adguard", "AdGuard", "94.140.14.14, 94.140.15.15",
              "режет рекламу"),
)

DEFAULT_DNS = DNS_PRESETS[0]


@dataclass(frozen=True, slots=True)
class MtuPreset:
    key: str
    title: str
    value: int
    note: str


# Диапазон 1280-1320. Выше начинается фрагментация: AWG 3 добавляет
# ContentPaddingAddition к каждому транспортному пакету, и то, что влезало
# при 1420 без обфускации, при ней уже не влезает. Фрагментированный трафик
# и медленнее, и заметнее для DPI.
MTU_PRESETS: tuple[MtuPreset, ...] = (
    MtuPreset("1320", "1320", 1320, ""),
    MtuPreset("1300", "1300", 1300, ""),
    MtuPreset("1280", "1280", 1280, ""),
)

DEFAULT_MTU = MTU_PRESETS[0]


@dataclass(frozen=True, slots=True)
class SetupTemplate:
    """Готовый набор для создания сервера одним нажатием."""

    key: str
    title: str
    description: str
    profile: str
    awg3: bool
    dns: str
    mtu: int


TEMPLATES: tuple[SetupTemplate, ...] = (
    SetupTemplate(
        key="recommended",
        title="Рекомендуемый",
        description="standard, AWG3, Cloudflare, MTU 1320",
        profile="standard",
        awg3=True,
        dns=DEFAULT_DNS.value,
        mtu=DEFAULT_MTU.value,
    ),
    SetupTemplate(
        key="stealth",
        title="Максимальная маскировка",
        description="pro, AWG3, Quad9, MTU 1280",
        profile="pro",
        awg3=True,
        dns="9.9.9.9, 149.112.112.112",
        mtu=1280,
    ),
    SetupTemplate(
        key="fast",
        title="Скорость",
        description="lite, AWG3, Cloudflare, MTU 1320",
        profile="lite",
        awg3=True,
        dns=DEFAULT_DNS.value,
        mtu=DEFAULT_MTU.value,
    ),
)


def template_by_key(key: str) -> SetupTemplate | None:
    for template in TEMPLATES:
        if template.key == key:
            return template
    return None
