"""Неинтерактивные операции: поднять, погасить, показать состояние.

Вынесены из меню, чтобы их мог вызывать systemd. Меню и юнит дёргают один и
тот же код — иначе автозапуск неизбежно разъедется с ручным запуском, и
поведение после ребута начнёт отличаться от поведения после «пункт 3».
"""

from __future__ import annotations

import logging

from .. import paths
from ..core import network
from ..core.backend import BackendError, GoBackend
from ..core.keys import ALL_KEYS
from ..core.models import ValidationFailed
from ..core.storage import Storage, StorageError
from ..core.uapi import UAPIError

logger = logging.getLogger(__name__)


class ActionError(RuntimeError):
    """Операция не выполнена."""


def _allowed_uapi_keys() -> set[str]:
    return {key.uapi for key in ALL_KEYS}


def apply_config(backend: GoBackend, storage: Storage) -> int:
    """Заливает конфигурацию из БД в UAPI. Возвращает число пиров."""
    try:
        config = storage.to_server_config()
        config.ensure_valid()
    except (StorageError, ValidationFailed) as exc:
        raise ActionError(f"конфигурация не прошла проверку: {exc}") from exc

    if not backend.is_running():
        raise ActionError(f"{backend.iface} не запущен")

    try:
        backend.apply_diagnosed(config.to_uapi_pairs(_allowed_uapi_keys()))
    except (BackendError, UAPIError) as exc:
        raise ActionError(str(exc)) from exc
    return len(config.peers)


def bring_up(storage: Storage | None = None) -> list[str]:
    """Полный подъём: демон, адрес, конфигурация, сеть.

    Возвращает строки отчёта — меню печатает их с оформлением, systemd
    отправляет в журнал.
    """
    storage = storage or Storage()
    server = storage.get_server()
    if server is None:
        raise ActionError("сервер не создан")

    report: list[str] = []
    backend = GoBackend(iface=server.iface)

    backend.start()
    report.append(f"демон запущен: {server.iface}")

    backend.configure_link(server.address, server.mtu)
    report.append(f"адрес {server.address}, MTU {server.mtu}, линк UP")

    peers = apply_config(backend, storage)
    report.append(f"конфигурация применена, пиров: {peers}")

    network.enable_ip_forward()
    added = network.apply_rules(server.subnet, server.iface, port=server.listen_port)
    report.append(f"правила сети: добавлено {len(added)}")

    if network.ufw_allow(server.listen_port):
        report.append(f"ufw: открыт {server.listen_port}/udp")

    if network.port_listening(server.listen_port):
        report.append(f"порт {server.listen_port}/udp слушается")
    else:
        report.append(f"ВНИМАНИЕ: порт {server.listen_port}/udp не слушается")

    return report


def bring_down(storage: Storage | None = None) -> list[str]:
    """Гасит интерфейс. Правила сети остаются — их снимает полное удаление."""
    storage = storage or Storage()
    server = storage.get_server()
    iface = server.iface if server else paths.DEFAULT_IFACE

    backend = GoBackend(iface=iface)
    backend.stop()
    return [f"интерфейс {iface} остановлен"]


def run_up() -> int:
    """Точка входа для systemd ExecStart."""
    try:
        for line in bring_up():
            print(line)
            logger.info(line)
    except (ActionError, BackendError, network.NetworkError) as exc:
        print(f"ОШИБКА: {exc}")
        logger.error("Подъём не удался: %s", exc)
        return 1
    return 0


def run_down() -> int:
    """Точка входа для systemd ExecStop."""
    try:
        for line in bring_down():
            print(line)
            logger.info(line)
    except (ActionError, BackendError) as exc:
        print(f"ОШИБКА: {exc}")
        logger.error("Остановка не удалась: %s", exc)
        return 1
    return 0
