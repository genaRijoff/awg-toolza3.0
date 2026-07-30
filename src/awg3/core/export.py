"""Клиентские конфиги в формате .conf.

Параметры обфускации (Jc/Jmin/Jmax, S1-S4, H1-H4) и HeaderProtectionKey
обязаны совпадать с серверными: это параметры протокола, а не предпочтения
клиента. Тайминги AWG 3 помечены в README как client-side и в принципе могут
отличаться, но мы пишем серверные — так поведение предсказуемо, а отладка
не превращается в гадание, чей таймер сработал.
"""

from __future__ import annotations

import logging
from pathlib import Path

from .models import ServerConfig
from .storage import ClientRow, ServerRow

logger = logging.getLogger(__name__)

# Только IPv4: в туннеле IPv6-адресов не выдаём. Добавить сюда ::/0 значит
# отправить весь IPv6-трафик в интерфейс без IPv6-адреса — соединения к
# AAAA-хостам будут висеть до таймаута вместо того, чтобы идти напрямую.
DEFAULT_ALLOWED_IPS = "0.0.0.0/0"

# Одиночное значение, а не диапазон: диапазон понимает только AWG 3, а конфиг
# должен открываться и у клиента без его поддержки.
DEFAULT_KEEPALIVE = "25"
KEEPALIVE_RANGE_AWG3 = "22-30"


def render_client_conf(
    server: ServerRow,
    client: ClientRow,
    config: ServerConfig,
    *,
    allowed_ips: str = DEFAULT_ALLOWED_IPS,
    keepalive: str | None = None,
) -> str:
    """Собирает текст .conf для клиента.

    keepalive=None — выбрать автоматически: диапазон при включённом AWG 3,
    иначе одиночное значение.
    """
    obf = config.obf
    awg3 = config.awg3
    if keepalive is None:
        keepalive = KEEPALIVE_RANGE_AWG3 if awg3.enabled else DEFAULT_KEEPALIVE

    lines: list[str] = [
        "[Interface]",
        f"PrivateKey = {client.private_key}",
        f"Address = {client.address}",
        f"DNS = {server.dns}",
        f"MTU = {server.mtu}",
        "",
        "# Обфускация AWG 2.0 — должна совпадать с сервером",
        f"Jc = {obf.jc}",
        f"Jmin = {obf.jmin}",
        f"Jmax = {obf.jmax}",
        f"S1 = {obf.s1}",
        f"S2 = {obf.s2}",
        f"S3 = {obf.s3}",
        f"S4 = {obf.s4}",
        f"H1 = {obf.h1.render()}",
        f"H2 = {obf.h2.render()}",
        f"H3 = {obf.h3.render()}",
        f"H4 = {obf.h4.render()}",
    ]

    if obf.i:
        lines += ["", "# CPS: junk-пакеты под видом настоящего протокола"]
        lines += [f"I{index} = {chain}" for index, chain in enumerate(obf.i[:5], start=1)]

    if awg3.enabled:
        lines += ["", "# AWG 3.0"]
        lines.append(f"HeaderProtectionKey = {awg3.header_protection_key}")
        for label, rng in (
            ("ContentPaddingAddition", awg3.content_padding_addition),
            ("RekeyAfterTime", awg3.rekey_after_time),
            ("RekeyTimeout", awg3.rekey_timeout),
            ("RejectAfterTime", awg3.reject_after_time),
            ("KeepaliveTimeout", awg3.keepalive_timeout),
            ("MaxHandshakeAttempts", awg3.max_handshake_attempts),
        ):
            if rng is not None:
                lines.append(f"{label} = {rng.render()}")

    lines += [
        "",
        "[Peer]",
        f"PublicKey = {server.public_key}",
    ]
    if client.preshared_key:
        lines.append(f"PresharedKey = {client.preshared_key}")
    lines += [
        f"Endpoint = {server.endpoint_host}:{server.listen_port}",
        f"AllowedIPs = {allowed_ips}",
        f"PersistentKeepalive = {keepalive}",
        "",
    ]
    return "\n".join(lines)


def write_client_conf(directory: Path, client_name: str, content: str) -> Path:
    """Пишет .conf с правами 0600 — внутри приватный ключ."""
    directory.mkdir(parents=True, exist_ok=True)
    directory.chmod(0o700)
    target = directory / f"{client_name}.conf"
    target.write_text(content, encoding="utf-8")
    target.chmod(0o600)
    logger.info("Конфиг клиента записан: %s", target)
    return target
