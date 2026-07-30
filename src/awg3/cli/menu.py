"""Интерактивное меню.

ANSI напрямую, без rich: на root-тулзе меньше зависимостей, а визуально это
то же самое, что в AWG Toolza.

Правила из ТЗ соблюдаются буквально:
  * «0» — всегда Назад или Выход;
  * любой ввод обрабатывается, аварийного завершения нет;
  * опасные действия требуют подтверждения словом, а не Enter;
  * сообщения объясняют, что произошло и что делать дальше.
"""

from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

from .. import __version__, paths
from . import actions
from ..core import backup, cps, export, network, presets, profiles, wgkeys
from ..core.backend import BackendError, GoBackend
from ..core.keys import ALL_KEYS
from ..core.models import ValidationFailed
from ..core.storage import ServerRow, Storage, StorageError
from ..core.uapi import UAPIError

logger = logging.getLogger(__name__)

R = "\033[0;31m"; G = "\033[0;32m"; Y = "\033[1;33m"
C = "\033[0;36m"; W = "\033[1;37m"; D = "\033[0;90m"; N = "\033[0m"


def ok(msg: str) -> None:
    print(f"{G}  √ {msg}{N}")


def err(msg: str) -> None:
    print(f"{R}  × {msg}{N}")


def warn(msg: str) -> None:
    print(f"{Y}  ▲ {msg}{N}")


def info(msg: str) -> None:
    print(f"{C}  → {msg}{N}")


def human_bytes(value: int) -> str:
    """Байты в читаемый вид."""
    step = 1024.0
    amount = float(value)
    for unit in ("Б", "КБ", "МБ", "ГБ"):
        if amount < step:
            return f"{amount:.0f} {unit}" if unit == "Б" else f"{amount:.1f} {unit}"
        amount /= step
    return f"{amount:.1f} ТБ"


def human_age(timestamp: int) -> str:
    """Сколько прошло с момента хендшейка."""
    if timestamp == 0:
        return "никогда"
    delta = int(time.time()) - timestamp
    if delta < 0:
        return "только что"
    if delta < 60:
        return f"{delta} с назад"
    if delta < 3600:
        return f"{delta // 60} мин назад"
    if delta < 86400:
        return f"{delta // 3600} ч назад"
    return f"{delta // 86400} д назад"


def head(title: str) -> None:
    print(f"\n{W}{title}{N}\n{D}{'─' * 48}{N}")


def ask(prompt: str, default: str = "") -> str:
    """Ввод с умолчанием. EOF и Ctrl-C не роняют программу."""
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {prompt}{suffix}: ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return default
    return value or default


def confirm(prompt: str) -> bool:
    """Подтверждение y/N. Умолчание — нет, Enter ничего не ломает.

    Латиница намеренно: на телефоне раскладка может быть любой, и требовать
    ввод кириллического слова для подтверждения — издевательство.
    """
    try:
        answer = input(f"  {Y}{prompt} [y/N]: {N}").strip().lower()
    except (EOFError, KeyboardInterrupt):
        print()
        return False
    return answer in ("y", "yes", "д", "да")


def pause() -> None:
    """Пауза перед возвратом в меню, чтобы вывод можно было прочитать."""
    try:
        input(f"\n  {D}Enter — вернуться в меню{N}")
    except (EOFError, KeyboardInterrupt):
        print()


class Menu:
    """Состояние сессии меню."""

    def __init__(self) -> None:
        self.storage = Storage()
        self.backend = GoBackend(iface=self._iface())

    # ── вспомогательное ─────────────────────────────────────────────

    def _iface(self) -> str:
        server = self.storage.get_server()
        return server.iface if server else paths.DEFAULT_IFACE

    def _reserved(self) -> dict[str, str]:
        """Значения, зарезервированные установщиком."""
        data: dict[str, str] = {}
        reserved = paths.CONF_DIR / "reserved.env"
        try:
            content = reserved.read_text(encoding="utf-8") if reserved.is_file() else ""
        except OSError as exc:
            logger.warning("Не прочитать %s: %s", reserved, exc)
            content = ""
        if content:
            for line in content.splitlines():
                if "=" in line and not line.startswith("#"):
                    key, _, value = line.partition("=")
                    data[key.strip()] = value.strip()
        return data

    def _save_reserved(self, iface: str, port: int, subnet: str, address: str) -> None:
        """Обновляет reserved.env, чтобы установщик и удаление знали актуальное."""
        target = paths.CONF_DIR / "reserved.env"
        content = (
            "# Обновлено при создании сервера.\n"
            f"AWG3_IFACE={iface}\n"
            f"AWG3_PORT={port}\n"
            f"AWG3_SUBNET={subnet}\n"
            f"AWG3_ADDRESS={address}\n"
            f"AWG3_ROUTE_TABLE={paths.ROUTE_TABLE}\n"
        )
        try:
            paths.CONF_DIR.mkdir(parents=True, exist_ok=True)
            target.write_text(content, encoding="utf-8")
            target.chmod(0o600)
        except OSError as exc:
            logger.warning("Не записать %s: %s", target, exc)

    def _allowed_uapi_keys(self) -> set[str]:
        return {key.uapi for key in ALL_KEYS}

    def _apply_to_interface(self) -> bool:
        """Пересобирает конфиг из БД и заливает в UAPI."""
        try:
            config = self.storage.to_server_config()
            config.ensure_valid()
        except (StorageError, ValidationFailed) as exc:
            err(f"конфигурация не прошла проверку: {exc}")
            return False

        if not self.backend.is_running():
            warn("ИНТЕРФЕЙС НЕ ЗАПУЩЕН — параметры сохранены в базе,")
            warn("но в туннель НЕ применены, и клиенты не подключатся")
            info("подними его пунктом 3 «Запустить интерфейс»")
            return False

        try:
            self.backend.apply_diagnosed(config.to_uapi_pairs(self._allowed_uapi_keys()))
        except (BackendError, UAPIError) as exc:
            err(f"не удалось применить конфигурацию: {exc}")
            return False
        ok(f"конфигурация применена, пиров: {len(config.peers)}")
        return True

    # ── сервер ──────────────────────────────────────────────────────

    def _detect_endpoint(self) -> str:
        """Внешний адрес: определяем сами, оператор только подтверждает."""
        info("определяю внешний адрес сервера...")
        try:
            detected, how = network.detect_endpoint()
        except Exception as exc:
            logger.warning("Детект адреса не сработал: %s", exc)
            detected, how = None, str(exc)

        if detected:
            ok(f"{detected}  {D}({how}){N}")
            value = ask("Enter — принять, либо введи свой адрес", detected)
        else:
            warn(f"определить не удалось: {how}")
            value = ask("Внешний адрес сервера (IP или домен)")

        return value.strip()

    def _choose_mimicry(self) -> "tuple[cps.Profile | None, cps.TagSet]":
        """Профиль мимикрии для I1-I5."""
        print(f"\n  {W}Мимикрия junk-пакетов (I1-I5){N}")
        choices = cps.profile_choices()
        for index, (_, title) in enumerate(choices, start=1):
            print(f"  {G}{index}{N}  {title}")
        print(f"  {G}{len(choices) + 1}{N}  Без мимикрии {D}(только Jc){N}")
        answer = ask("Выбор", "2")
        if answer == str(len(choices) + 1):
            return None, cps.TagSet.EXTENDED
        try:
            profile = choices[int(answer) - 1][0]
        except (ValueError, IndexError):
            warn("непонятный выбор — беру QUIC Initial")
            profile = cps.Profile.QUIC

        print(f"\n  {W}Набор тегов{N}")
        print(f"  {G}1{N}  Полный   {D}<b> <r> <rc> <rd> <t>{N}")
        print(f"  {G}2{N}  Базовый  {D}<b> <r> — для старых клиентов{N}")
        tags = (
            cps.TagSet.BASIC if ask("Выбор", "1") == "2" else cps.TagSet.EXTENDED
        )
        return profile, tags

    def _choose_template(self) -> presets.SetupTemplate | None:
        """Шаблон настроек. None — оператор выбрал подробную настройку."""
        print(f"\n  {W}Шаблон настроек{N}")
        for index, template in enumerate(presets.TEMPLATES, start=1):
            print(f"  {G}{index}{N}  {template.title:<24}{D}{template.description}{N}")
        print(f"  {G}{len(presets.TEMPLATES) + 1}{N}  {'Настроить вручную':<24}"
              f"{D}профиль, DNS, MTU{N}")
        choice = ask("Выбор", "1")

        if choice == str(len(presets.TEMPLATES) + 1):
            return None
        try:
            index = int(choice)
        except ValueError:
            warn(f"нет такого пункта: '{choice}' — беру рекомендуемый")
            return presets.TEMPLATES[0]
        if not 1 <= index <= len(presets.TEMPLATES):
            warn(f"нет такого пункта: '{choice}' — беру рекомендуемый")
            return presets.TEMPLATES[0]
        return presets.TEMPLATES[index - 1]

    def _manual_setup(self) -> tuple[str, bool, str, int] | None:
        """Подробная настройка. None — оператор прервал."""
        print(f"\n  {W}Профиль обфускации{N}")
        for index, profile in enumerate(profiles.profile_choices(), start=1):
            print(f"  {G}{index}{N}  {profile.title:<10}{D}{profile.description}{N}")
        mapping = {"1": "lite", "2": "standard", "3": "pro"}
        profile_name = mapping.get(ask("Профиль", "2"))
        if profile_name is None:
            err("такого профиля нет")
            return None

        use_awg3 = ask("Включить AWG 3.0 (header protection)? [Y/n]", "y").lower() != "n"

        print(f"\n  {W}DNS для клиентов{N}")
        for index, dns in enumerate(presets.DNS_PRESETS, start=1):
            print(f"  {G}{index}{N}  {dns.title:<11}{dns.value:<32}{D}{dns.note}{N}")
        print(f"  {G}{len(presets.DNS_PRESETS) + 1}{N}  Свой")
        dns_choice = ask("Выбор", "1")
        if dns_choice == str(len(presets.DNS_PRESETS) + 1):
            dns_value = ask("DNS через запятую", presets.DEFAULT_DNS.value)
        else:
            try:
                dns_value = presets.DNS_PRESETS[int(dns_choice) - 1].value
            except (ValueError, IndexError):
                warn("непонятный выбор — беру Cloudflare")
                dns_value = presets.DEFAULT_DNS.value

        print(f"\n  {W}MTU{N}")
        for index, mtu in enumerate(presets.MTU_PRESETS, start=1):
            print(f"  {G}{index}{N}  {mtu.title}")
        try:
            mtu_value = presets.MTU_PRESETS[int(ask("Выбор", "1")) - 1].value
        except (ValueError, IndexError):
            warn(f"непонятный выбор — беру {presets.DEFAULT_MTU.value}")
            mtu_value = presets.DEFAULT_MTU.value

        return profile_name, use_awg3, dns_value, mtu_value

    def create_server(self) -> None:
        head("Создание сервера")

        if self.storage.has_server():
            warn("сервер уже создан")
            info("пересоздание сотрёт всех клиентов и выдаст новые ключи")
            if not confirm("Пересоздать сервер? Это необратимо"):
                info("отменено")
                return

        reserved = self._reserved()
        iface = reserved.get("AWG3_IFACE", paths.DEFAULT_IFACE)
        port_default = reserved.get("AWG3_PORT", "51820")

        # Подсеть выбираем заново, а не берём из reserved.env: пересоздание
        # сервера — это новая генерация всего, и оставлять прежнюю сеть
        # означало бы, что она навсегда фиксируется моментом установки.
        try:
            subnet = network.pick_free_subnet()
        except network.NetworkError as exc:
            warn(f"не выбрать подсеть автоматически: {exc}")
            subnet = reserved.get("AWG3_SUBNET", paths.DEFAULT_CLIENT_NET)
        address = f"{subnet.split('/')[0].rsplit('.', 1)[0]}.1/24"

        endpoint = self._detect_endpoint()
        if not endpoint:
            err("без внешнего адреса клиенты не смогут подключиться")
            return

        port_raw = ask("UDP-порт", port_default)
        try:
            port = int(port_raw)
        except ValueError:
            err(f"порт должен быть числом, получено '{port_raw}'")
            return
        if not 1024 <= port <= 65535:
            err(f"порт {port} вне 1024..65535")
            return

        mimicry, tag_set = self._choose_mimicry()

        template = self._choose_template()
        if template is None:
            manual = self._manual_setup()
            if manual is None:
                return
            profile_name, use_awg3, dns, mtu = manual
        else:
            profile_name, use_awg3 = template.profile, template.awg3
            dns, mtu = template.dns, template.mtu

        print(f"\n  {W}Итого{N}")
        print(f"  {D}{'Интерфейс':<16}{N} {iface}")
        print(f"  {D}{'Endpoint':<16}{N} {endpoint}:{port}")
        print(f"  {D}{'Подсеть':<16}{N} {subnet}")
        print(f"  {D}{'Профиль':<16}{N} {profile_name}")
        print(f"  {D}{'AWG 3.0':<16}{N} {'включён' if use_awg3 else 'выключен'}")
        print(f"  {D}{'DNS':<16}{N} {dns}")
        print(f"  {D}{'MTU':<16}{N} {mtu}")
        mimicry_title = (
            cps.PROFILE_TITLES[mimicry] if mimicry else "выключена"
        )
        print(f"  {D}{'Мимикрия':<16}{N} {mimicry_title}")
        if not confirm("Создать сервер с этими параметрами?"):
            info("отменено")
            return

        obf = profiles.generate_obf(
            profile_name, awg3=use_awg3, mimicry=mimicry, mtu=mtu, tags=tag_set
        )
        awg3 = profiles.generate_awg3(enable_header_protection=use_awg3)
        private = wgkeys.generate_private_key()

        row = ServerRow(
            iface=iface,
            private_key=private,
            public_key=wgkeys.public_key(private),
            listen_port=port,
            address=address,
            subnet=subnet,
            mtu=mtu,
            endpoint_host=endpoint,
            dns=dns,
            profile=profile_name,
            obf={
                "jc": obf.jc, "jmin": obf.jmin, "jmax": obf.jmax,
                "s1": obf.s1, "s2": obf.s2, "s3": obf.s3, "s4": obf.s4,
                "h1": obf.h1.render(), "h2": obf.h2.render(),
                "h3": obf.h3.render(), "h4": obf.h4.render(),
                "i": obf.i,
            },
            awg3={
                "header_protection_key": awg3.header_protection_key,
                "content_padding_addition": awg3.content_padding_addition.render(),
                "rekey_after_time": awg3.rekey_after_time.render(),
                "rekey_timeout": awg3.rekey_timeout.render(),
                "reject_after_time": awg3.reject_after_time.render(),
                "keepalive_timeout": awg3.keepalive_timeout.render(),
                "max_handshake_attempts": awg3.max_handshake_attempts.render(),
            },
            created_at="",
        )

        try:
            self.storage.save_server(row)
        except StorageError as exc:
            err(str(exc))
            return

        self._save_reserved(iface, port, subnet, address)
        self.backend = GoBackend(iface=iface)
        ok(f"сервер создан: {iface}, порт {port}, профиль {profile_name}")
        if use_awg3:
            ok("AWG 3.0 включён — header protection активен")
        else:
            warn("AWG 3.0 выключен — работает только обфускация 2.0")

        self._auto_start()
        info("дальше: пункт 7 «Добавить клиента»")

    def show_server(self) -> None:
        head("Конфигурация сервера")
        server = self.storage.get_server()
        if server is None:
            warn("сервер ещё не создан")
            return

        rows = [
            ("Интерфейс", server.iface),
            ("Внешний адрес", f"{server.endpoint_host}:{server.listen_port}"),
            ("Адрес в туннеле", server.address),
            ("Подсеть", server.subnet),
            ("MTU", str(server.mtu)),
            ("DNS", server.dns),
            ("Профиль", server.profile),
            ("Публичный ключ", server.public_key),
            ("Создан", server.created_at),
        ]
        for label, value in rows:
            print(f"  {D}{label:<18}{N} {value}")

        print(f"\n  {W}Обфускация AWG 2.0{N}")
        obf = server.obf
        print(f"  {D}{'Jc / Jmin / Jmax':<18}{N} {obf['jc']} / {obf['jmin']} / {obf['jmax']}")
        print(f"  {D}{'S1-S4':<18}{N} {obf['s1']}, {obf['s2']}, {obf['s3']}, {obf['s4']}")
        for name in ("h1", "h2", "h3", "h4"):
            print(f"  {D}{name.upper():<18}{N} {obf[name]}")

        chains = obf.get("i", [])
        print(f"\n  {W}CPS — мимикрия junk-пакетов{N}")
        if chains:
            for index, chain in enumerate(chains, start=1):
                shown = chain if len(chain) <= 64 else chain[:61] + "..."
                print(f"  {D}{'I' + str(index):<18}{N} {shown}")
            print(f"  {D}{'Размер пакетов':<18}{N} "
                  f"{', '.join(str(cps.estimate_size(c)) for c in chains)} байт")
            all_tags = set().union(*(cps.used_tags(c) for c in chains))
            print(f"  {D}{'Теги':<18}{N} {', '.join(sorted(all_tags))}")
        else:
            warn("мимикрия выключена — junk-пакеты без формы")

        print(f"\n  {W}AWG 3.0{N}")
        awg3 = server.awg3
        if awg3.get("header_protection_key"):
            ok("header protection включён")
            for label, key in (
                ("ContentPadding", "content_padding_addition"),
                ("RekeyAfterTime", "rekey_after_time"),
                ("RekeyTimeout", "rekey_timeout"),
                ("RejectAfterTime", "reject_after_time"),
                ("KeepaliveTimeout", "keepalive_timeout"),
                ("MaxHandshake", "max_handshake_attempts"),
            ):
                print(f"  {D}{label:<18}{N} {awg3.get(key, '—')}")
        else:
            warn("header protection выключен")

    def regenerate_obfuscation(self) -> None:
        """Перевыпускает параметры обфускации, сохраняя клиентов и ключи.

        Нужно, когда параметры оказались невалидными (например, сервер создан
        со старым полом S1-S4) либо когда набор пора обновить. Ключи сервера и
        клиентов не трогаются — меняется только обфускация.
        """
        head("Перегенерация параметров обфускации")
        server = self.storage.get_server()
        if server is None:
            warn("сервер ещё не создан")
            return

        current = server.obf
        print(f"  {D}{'Сейчас S1-S4':<18}{N} {current['s1']}, {current['s2']}, "
              f"{current['s3']}, {current['s4']}")
        low = [f"S{i}={current[f's{i}']}" for i in range(1, 5)
               if current[f"s{i}"] < 12]
        if low and server.awg3.get("header_protection_key"):
            err(f"ниже минимума 12 для header protection: {', '.join(low)}")
            info("именно поэтому UAPI отвергает ключ — перегенерация это чинит")

        print()
        warn("ключи сервера и клиентов сохранятся, но параметры сменятся")
        warn("всем клиентам придётся выдать конфиги заново — старые перестанут работать")
        print()
        if not confirm("Перегенерировать?"):
            info("отменено")
            return

        use_awg3 = bool(server.awg3.get("header_protection_key"))
        keep_hpk = False
        if use_awg3:
            keep_hpk = confirm("Сохранить прежний HeaderProtectionKey?")

        mimicry, tag_set = self._choose_mimicry()
        obf = profiles.generate_obf(
            server.profile, awg3=use_awg3, mimicry=mimicry,
            mtu=server.mtu, tags=tag_set,
        )
        awg3 = profiles.generate_awg3(enable_header_protection=use_awg3)
        if keep_hpk:
            awg3.header_protection_key = server.awg3["header_protection_key"]

        server.obf = {
            "jc": obf.jc, "jmin": obf.jmin, "jmax": obf.jmax,
            "s1": obf.s1, "s2": obf.s2, "s3": obf.s3, "s4": obf.s4,
            "h1": obf.h1.render(), "h2": obf.h2.render(),
            "h3": obf.h3.render(), "h4": obf.h4.render(),
            "i": obf.i,
        }
        server.awg3 = {
            "header_protection_key": awg3.header_protection_key,
            "content_padding_addition": awg3.content_padding_addition.render(),
            "rekey_after_time": awg3.rekey_after_time.render(),
            "rekey_timeout": awg3.rekey_timeout.render(),
            "reject_after_time": awg3.reject_after_time.render(),
            "keepalive_timeout": awg3.keepalive_timeout.render(),
            "max_handshake_attempts": awg3.max_handshake_attempts.render(),
        }

        try:
            self.storage.save_server(server)
        except StorageError as exc:
            err(str(exc))
            return

        ok(f"параметры обновлены: S1-S4 = {obf.s1}, {obf.s2}, {obf.s3}, {obf.s4}")

        if self.backend.is_running():
            self._apply_to_interface()
        else:
            self._auto_start()

        warn("параметры сменились — старые конфиги клиентов больше не подойдут")
        info("выдай каждому новый: пункт 9 «Показать конфиг»")

    # ── интерфейс ───────────────────────────────────────────────────

    def start_interface(self) -> None:
        head("Запуск интерфейса")
        server = self.storage.get_server()
        if server is None:
            warn("сначала создай сервер")
            return

        self.backend = GoBackend(iface=server.iface)
        try:
            for line in actions.bring_up(self.storage):
                ok(line) if "ВНИМАНИЕ" not in line else warn(line)
        except (actions.ActionError, BackendError, network.NetworkError) as exc:
            err(str(exc))
            return

        self._enable_autostart()
        info(f"проверь снаружи: nc -zvu {server.endpoint_host} {server.listen_port}")
        info("если провайдер даёт свой фаервол в панели — порт надо открыть и там")

    def _auto_start(self) -> None:
        """Поднимает интерфейс после генерации параметров.

        Только здесь, а не после любого действия: если оператор сознательно
        остановил туннель пунктом 4, добавление клиента не должно его будить.
        """
        print()
        try:
            for line in actions.bring_up(self.storage):
                ok(line) if "ВНИМАНИЕ" not in line else warn(line)
        except (actions.ActionError, BackendError, network.NetworkError) as exc:
            err(f"автозапуск не удался: {exc}")
            info("подними вручную пунктом 3")
            return
        self._enable_autostart()

    def _enable_autostart(self) -> None:
        """Включает юнит, чтобы туннель поднимался после перезагрузки."""
        import subprocess

        unit = "awg3.service"
        try:
            enabled = subprocess.run(
                ["systemctl", "is-enabled", unit],
                capture_output=True, text=True, timeout=10, check=False,
            )
            if enabled.stdout.strip() == "enabled":
                return
            result = subprocess.run(
                ["systemctl", "enable", unit],
                capture_output=True, text=True, timeout=15, check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            warn(f"автозапуск не включён: {exc}")
            return

        if result.returncode == 0:
            ok("автозапуск включён — туннель поднимется после перезагрузки")
            return

        detail = result.stderr.strip()
        warn(f"автозапуск не включён: {detail}")
        if "does not exist" in detail:
            info("юнит не установлен — обнови установщиком:")
            info("  cd /home/awg3 && sudo bash install.sh --install")
        else:
            info(f"вручную: systemctl enable {unit}")

    def stop_interface(self) -> None:
        head("Остановка интерфейса")
        try:
            for line in actions.bring_down(self.storage):
                ok(line)
        except (actions.ActionError, BackendError) as exc:
            err(str(exc))
        info("правила iptables оставлены — снимаются при полном удалении")

    def show_status(self) -> None:
        head("Состояние")
        server = self.storage.get_server()
        if server is None:
            warn("сервер не создан")
            return

        state = self.backend.state()
        mark = f"{G}работает{N}" if state.running else f"{D}остановлен{N}"
        print(f"  {D}{'Интерфейс':<18}{N} {state.name} — {mark}")
        link_mark = f"{G}UP{N}" if state.link_up else f"{R}DOWN{N}"
        print(f"  {D}{'Линк':<18}{N} {link_mark}")
        if not state.link_up:
            print(f"  {D}{'':<18}{N} {self.backend.link_details()}")
        print(f"  {D}{'Порт':<18}{N} {state.listen_port or server.listen_port}")
        print(f"  {D}{'Пиров в ядре':<18}{N} {state.peer_count}")

        clients = self.storage.list_clients()
        enabled = sum(1 for c in clients if c.enabled)
        print(f"  {D}{'Клиентов в БД':<18}{N} {len(clients)} (включено {enabled})")

        # ── AWG 3.0 ────────────────────────────────────────────────
        print()
        hpk = server.awg3.get("header_protection_key")
        if hpk:
            print(f"  {D}{'Header protection':<18}{N} {G}включён{N}")

            # Проверяем инвариант прямо здесь: параметры могли уехать из БД
            # мимо валидатора, а без S1-S4 >= 12 nonce ChaCha20 берётся
            # не из паддинга, и шифр молча слабеет.
            obf = server.obf
            low = [f"S{i}={obf[f's{i}']}" for i in range(1, 5) if obf[f"s{i}"] < 12]
            if low:
                print(f"  {D}{'':<18}{N} {R}но {', '.join(low)} ниже минимума 12{N}")
                print(f"  {D}{'':<18}{N} {Y}перегенерируй пунктом 6{N}")
            else:
                s_values = ", ".join(str(obf[f"s{i}"]) for i in range(1, 5))
                print(f"  {D}{'S1-S4':<18}{N} {s_values} {D}(минимум 12){N}")

            padding = server.awg3.get("content_padding_addition")
            if padding:
                print(f"  {D}{'Content padding':<18}{N} {padding} {D}байт на пакет{N}")
        else:
            print(f"  {D}{'Header protection':<18}{N} {Y}выключен{N}")
            print(f"  {D}{'':<18}{N} {D}работает только обфускация AWG 2.0{N}")

        chains = server.obf.get("i", [])
        if chains:
            tags = set().union(*(cps.used_tags(c) for c in chains))
            print(f"  {D}{'Мимикрия':<18}{N} {len(chains)} цепочек, теги: "
                  f"{', '.join(sorted(tags))}")
        else:
            print(f"  {D}{'Мимикрия':<18}{N} {D}выключена{N}")

        try:
            net = network.status(server.subnet, server.iface, server.listen_port)
            print(f"  {D}{'WAN':<18}{N} {net['wan']}")
            print(f"  {D}{'ip_forward':<18}{N} {'да' if net['ip_forward'] else 'нет'}")
            print(f"  {D}{'Правил AWG3':<18}{N} {net['rules']}")
            listening = net["port_listening"]
            mark = f"{G}слушается{N}" if listening else f"{R}НЕ слушается{N}"
            print(f"  {D}{'Порт UDP':<18}{N} {server.listen_port} — {mark}")
            print(f"  {D}{'ufw':<18}{N} {'активен' if net['ufw'] else 'выключен'}")
        except network.NetworkError as exc:
            warn(f"сеть недоступна для опроса: {exc}")

        if self.backend.kernel_module_loaded():
            print()
            info("загружен kernel-модуль amneziawg (AWG 2.0) — мы его не трогаем")

    # ── клиенты ─────────────────────────────────────────────────────

    def add_client(self) -> None:
        head("Добавление клиента")
        server = self.storage.get_server()
        if server is None:
            warn("сначала создай сервер")
            return

        name = ask("Имя клиента")
        if not name:
            err("имя не может быть пустым")
            return
        if not all(ch.isalnum() or ch in "-_" for ch in name):
            err("в имени допустимы только буквы, цифры, дефис и подчёркивание")
            return
        if self.storage.get_client(name) is not None:
            err(f"клиент '{name}' уже есть")
            return

        try:
            address = self.storage.next_free_address(server.subnet)
        except StorageError as exc:
            err(str(exc))
            return

        private = wgkeys.generate_private_key()
        try:
            self.storage.add_client(
                name=name,
                private_key=private,
                public_key=wgkeys.public_key(private),
                address=address,
                preshared_key=wgkeys.generate_symmetric_key(),
            )
        except StorageError as exc:
            err(str(exc))
            return

        ok(f"клиент '{name}' создан, адрес {address}")
        self._apply_to_interface()
        self.show_client(name)

    def list_clients(self, detailed: bool = False) -> list:
        """Печатает список и возвращает его же — для выбора номером.

        detailed=True добавляет живые счётчики из UAPI: когда был хендшейк,
        сколько трафика, с какого адреса подключён.
        """
        head("Клиенты")
        clients = self.storage.list_clients()
        if not clients:
            info("клиентов пока нет")
            return []

        if not detailed:
            print(f"  {D}{'№':<4}{'Имя':<20}{'Адрес':<20}{'Статус'}{N}")
            for number, client in enumerate(clients, start=1):
                mark = f"{G}включён{N}" if client.enabled else f"{D}выключен{N}"
                print(f"  {G}{number:<4}{N}{client.name:<20}{client.address:<20}{mark}")
            return clients

        # Сопоставляем по публичному ключу: имена живут в БД, счётчики в ядре.
        stats = {peer.public_key: peer for peer in self.backend.peer_stats()}
        if not stats and self.backend.is_running():
            info("интерфейс работает, но пиров в ядре нет")
        elif not self.backend.is_running():
            warn("интерфейс не запущен — счётчики недоступны")

        print(f"  {D}{'№':<4}{'Имя':<16}{'Адрес':<17}{'Хендшейк':<15}"
              f"{'Принято':<11}{'Отдано':<11}{'Откуда'}{N}")
        online = 0
        for number, client in enumerate(clients, start=1):
            peer = stats.get(client.public_key)
            if peer is None:
                handshake, rx, tx, source = "—", "—", "—", ""
                colour = D
            else:
                handshake = human_age(peer.last_handshake)
                rx = human_bytes(peer.rx_bytes)
                tx = human_bytes(peer.tx_bytes)
                source = peer.endpoint or ""
                colour = G if peer.connected else D
                if peer.connected:
                    online += 1
            name = client.name if client.enabled else f"{client.name}*"
            print(f"  {G}{number:<4}{N}{colour}{name:<16}{N}{client.address:<17}"
                  f"{colour}{handshake:<15}{N}{rx:<11}{tx:<11}{D}{source}{N}")

        print()
        print(f"  {D}Онлайн: {online} из {len(clients)}. "
              f"Клиент считается онлайн, если хендшейк моложе трёх минут.{N}")
        if any(not c.enabled for c in clients):
            print(f"  {D}Звёздочкой помечены выключенные.{N}")
        return clients

    def _pick_client(self, action: str):
        """Выбор клиента по номеру из списка. None — отмена.

        Номером, а не именем: на телефоне ввод имени — это набор текста
        вслепую, а промах даёт «клиент не найден» вместо результата.
        """
        clients = self.list_clients()
        if not clients:
            return None
        print()
        print(f"  {D}0 — назад{N}")
        answer = ask(f"Номер клиента для «{action}»")
        if not answer or answer == "0":
            info("отменено")
            return None
        try:
            index = int(answer)
        except ValueError:
            err(f"нужен номер, а не '{answer}'")
            return None
        if not 1 <= index <= len(clients):
            err(f"номер вне диапазона 1..{len(clients)}")
            return None
        return clients[index - 1]

    def show_client(self, name: str | None = None) -> None:
        if name is None:
            head("Конфиг клиента")
            client = self._pick_client("показать конфиг")
            if client is None:
                return
        else:
            client = self.storage.get_client(name)
            if client is None:
                err(f"клиент '{name}' не найден")
                return

        server = self.storage.get_server()
        if server is None:
            err("сервер не создан")
            return

        config = self.storage.to_server_config(only_enabled=False)
        content = export.render_client_conf(server, client, config)
        target = export.write_client_conf(paths.CLIENTS_DIR, client.name, content)

        awg3_on = bool(server.awg3.get("header_protection_key"))

        print()
        print(content)
        ok(f"conf: {target}")

        if awg3_on:
            print()
            warn("AWG 3.0 включён — основное приложение AmneziaVPN этот конфиг не примет")
            info("его импортёр выбрасывает HeaderProtectionKey, и хендшейк не сходится")
            info("подключайся через AmneziaWG β — там импорт .conf работает")

        info(f"забрать: scp root@{server.endpoint_host}:{target} .")

    def toggle_client(self) -> None:
        head("Включить или выключить клиента")
        client = self._pick_client("включить или выключить")
        if client is None:
            return
        self.storage.set_client_enabled(client.name, not client.enabled)
        ok(f"'{client.name}' теперь {'выключен' if client.enabled else 'включён'}")
        self._apply_to_interface()

    def delete_client(self) -> None:
        head("Удаление клиента")
        client = self._pick_client("удалить")
        if client is None:
            return
        if not confirm(f"Удалить клиента '{client.name}' безвозвратно?"):
            info("отменено")
            return

        self.storage.remove_client(client.name)
        for suffix in (".conf", ".vpn"):
            path = paths.CLIENTS_DIR / f"{client.name}{suffix}"
            try:
                path.unlink(missing_ok=True)
            except OSError as exc:
                warn(f"не удалось удалить {path.name}: {exc}")
        ok(f"клиент '{client.name}' удалён")
        self._apply_to_interface()

    # ── обслуживание ────────────────────────────────────────────────

    def backup_menu(self) -> None:
        head("Бекап конфигурации")
        existing = backup.listing()
        if existing:
            print(f"  {D}{'№':<4}{'Файл':<34}{'Размер':<10}{'Создан'}{N}")
            for number, item in enumerate(existing, start=1):
                print(f"  {G}{number:<4}{N}{item.name:<34}"
                      f"{human_bytes(item.size):<10}"
                      f"{D}{item.created.strftime('%Y-%m-%d %H:%M')} UTC{N}")
        else:
            info("бекапов пока нет")

        print()
        print(f"  {G}1{N}  Создать бекап")
        print(f"  {G}2{N}  Восстановить из бекапа")
        print(f"  {D}0{N}  Назад")
        choice = ask("Выбор", "0")

        if choice == "1":
            try:
                target = backup.create()
            except backup.BackupError as exc:
                err(str(exc))
                return
            ok(f"сохранено: {target}")
            info(f"забрать: scp root@<сервер>:{target} .")
            info(f"хранится последние {backup.KEEP} архивов, старые удаляются")
            return

        if choice != "2":
            return

        if not existing:
            err("восстанавливать нечего")
            return
        answer = ask("Номер бекапа")
        try:
            chosen = existing[int(answer) - 1]
        except (ValueError, IndexError):
            err(f"нет бекапа с номером '{answer}'")
            return

        warn("текущие база и конфиги клиентов будут перезаписаны")
        if not confirm(f"Восстановить из {chosen.name}?"):
            info("отменено")
            return

        try:
            count = backup.restore(chosen.path)
        except backup.BackupError as exc:
            err(str(exc))
            return
        ok(f"восстановлено файлов: {count}")
        self.storage = Storage()
        self.backend = GoBackend(iface=self._iface())
        info("применить: пункт 3 «Запустить интерфейс»")

    def show_logs(self) -> None:
        head("Последние записи журнала")
        for label, path in (
            ("Тулза", paths.LOG_FILE),
            ("Демон", paths.LOG_FILE.with_name("awg3-daemon.log")),
        ):
            lines = backup.tail_log(path, 50)
            print(f"\n  {W}{label}{N} {D}{path}{N}")
            if not lines:
                info("пусто либо файла нет")
                continue
            for line in lines:
                colour = R if ("ERROR" in line or "Traceback" in line) else (
                    Y if "WARNING" in line else D
                )
                print(f"  {colour}{line[:160]}{N}")

    def self_update(self) -> None:
        """Обновляет тулзу из репозитория через сохранённый установщик."""
        head("Обновление с GitHub")
        print(f"  {D}{'Репозиторий':<16}{N} {paths.REPO_URL}")
        print(f"  {D}{'Ветка':<16}{N} {paths.REPO_BRANCH}")
        print(f"  {D}{'Версия сейчас':<16}{N} {__version__}")
        print()
        info("будут обновлены: папка проекта, Python-ядро, бинарь, юнит")
        info(f"{paths.CONF_DIR} не трогается — клиенты и ключи сохранятся")
        print()
        if not confirm("Обновить?"):
            info("отменено")
            return

        import subprocess

        if paths.INSTALLER.is_file():
            command = ["bash", str(paths.INSTALLER), "--update"]
            info(f"запускаю {paths.INSTALLER}")
        else:
            url = paths.installer_raw_url()
            warn(f"локальной копии нет — тяну {url}")
            command = ["bash", "-c", f'bash <(curl -fsSL "{url}") --update']

        print()
        try:
            result = subprocess.run(command, timeout=1800, check=False)
        except FileNotFoundError as exc:
            err(f"не запустить установщик: {exc}")
            return
        except subprocess.TimeoutExpired:
            err("обновление не уложилось в 30 минут — прервано")
            return

        print()
        if result.returncode != 0:
            err(f"установщик завершился с кодом {result.returncode}")
            info("подробности выше; конфигурация не тронута")
            return

        ok("обновление завершено")
        warn("перезапусти меню, чтобы подхватить новый код: выход (0), затем sudo awg3")
        if self.backend.is_running():
            info("интерфейс продолжает работать, клиенты не отвалились")

    # ── полное удаление ─────────────────────────────────────────────

    def purge(self) -> None:
        head("Полное удаление конфигурации")
        warn("будет удалено:")
        print(f"  {R}—{N} база {paths.DB_PATH} со всеми клиентами и ключами")
        print(f"  {R}—{N} конфиги клиентов в {paths.CLIENTS_DIR}")
        print(f"  {R}—{N} правила iptables с тегом {paths.IPTABLES_TAG}")
        print(f"  {R}—{N} интерфейс будет остановлен")
        print(f"  {G}+{N} бинари в {paths.PREFIX} останутся — сносит install.sh --uninstall")
        print(f"  {G}+{N} AWG 2.0 не затрагивается")
        print()

        if not confirm("Удалить всю конфигурацию?"):
            info("отменено")
            return
        if not confirm("Точно? Клиенты и ключи будут потеряны"):
            info("отменено")
            return

        try:
            self.backend.stop()
            ok("интерфейс остановлен")
        except BackendError as exc:
            warn(f"интерфейс не остановлен: {exc}")

        try:
            removed = network.remove_rules()
            ok(f"удалено правил iptables: {removed}")
        except network.NetworkError as exc:
            warn(f"правила не удалены: {exc}")

        removed = 0
        targets = list(paths.CLIENTS_DIR.glob("*.conf"))
        targets += list(paths.CLIENTS_DIR.glob("*.vpn"))
        targets.append(paths.DB_PATH)
        targets += [Path(str(paths.DB_PATH) + s) for s in ("-wal", "-shm")]
        for target in targets:
            if not target.is_file():
                continue
            try:
                target.unlink()
                removed += 1
            except OSError as exc:
                warn(f"не удалось удалить {target.name}: {exc}")
        info(f"удалено файлов: {removed}")

        ok("конфигурация удалена — можно создавать сервер заново")
        self.storage = Storage()

    # ── цикл меню ───────────────────────────────────────────────────

    def _banner(self) -> None:
        server = self.storage.get_server()
        title = f"AWG3 v{__version__} — AmneziaWG 3.0 (amneziawg-go)"
        print(f"\n{W}╔{'═' * 52}╗{N}")
        print(f"{W}║ {title:<50} ║{N}")
        print(f"{W}╚{'═' * 52}╝{N}")
        if server is None:
            print(f"  Сервер    : {D}не создан{N}")
        else:
            running = self.backend.is_running()
            mark = f"{G}работает{N}" if running else f"{Y}остановлен{N}"
            awg3 = "AWG3" if server.awg3.get("header_protection_key") else "AWG2"
            clients = len(self.storage.list_clients())
            print(f"  Сервер    : {mark}  {D}{server.iface}:{server.listen_port} "
                  f"{server.profile}/{awg3}, клиентов {clients}{N}")

    def run(self) -> int:
        while True:
            self._banner()
            print()
            print(f"  {W}Сервер{N}")
            print(f"  {G}1{N}  Создать сервер")
            print(f"  {G}2{N}  Показать конфигурацию")
            print(f"  {G}3{N}  Запустить интерфейс")
            print(f"  {G}4{N}  Остановить интерфейс")
            print(f"  {G}5{N}  Состояние")
            print(f"  {G}6{N}  Перегенерировать обфускацию")
            print()
            print(f"  {W}Клиенты{N}")
            print(f"  {G}7{N}  Добавить клиента")
            print(f"  {G}8{N}  Список клиентов и статистика")
            print(f"  {G}9{N}  Показать конфиг")
            print(f"  {G}10{N} Включить или выключить")
            print(f"  {R}11{N} Удалить клиента")
            print()
            print(f"  {W}Обслуживание{N}")
            print(f"  {G}12{N} Бекап и восстановление")
            print(f"  {G}13{N} Журнал (последние 50)")
            print(f"  {R}14{N} Полное удаление конфигурации")
            print(f"  {G}15{N} Обновление с GitHub")
            print()
            print(f"  {D}0{N}  Выход")
            print()

            try:
                choice = input(f"  Выбор [0-15]: ").strip()
            except (EOFError, KeyboardInterrupt):
                print()
                return 0

            actions = {
                "1": self.create_server,
                "2": self.show_server,
                "3": self.start_interface,
                "4": self.stop_interface,
                "5": self.show_status,
                "6": self.regenerate_obfuscation,
                "7": self.add_client,
                "8": lambda: self.list_clients(detailed=True),
                "9": self.show_client,
                "10": self.toggle_client,
                "11": self.delete_client,
                "12": self.backup_menu,
                "13": self.show_logs,
                "14": self.purge,
                "15": self.self_update,
            }

            if choice == "0":
                print()
                info("выход")
                return 0

            action = actions.get(choice)
            if action is None:
                warn(f"нет такого пункта: '{choice}'")
                continue

            try:
                action()
            except KeyboardInterrupt:
                print()
                warn("прервано пользователем")
            except Exception as exc:  # меню не имеет права падать
                logger.exception("Необработанная ошибка в пункте %s", choice)
                err(f"внутренняя ошибка: {exc}")
                info(f"подробности в {paths.LOG_FILE}")

            # Без паузы вывод пролетает и сразу перерисовывается главное меню.
            pause()


def main(argv: list[str] | None = None) -> int:
    """Точка входа. Без аргументов — меню, с --up/--down — для systemd."""
    import sys as _sys

    args = _sys.argv[1:] if argv is None else argv

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        filename=str(paths.LOG_FILE),
    )
    paths.ensure_dirs()

    if args:
        command = args[0]
        if command == "--up":
            return actions.run_up()
        if command == "--down":
            return actions.run_down()
        if command in ("-h", "--help"):
            print("awg3            интерактивное меню")
            print("awg3 --up       поднять туннель (используется systemd)")
            print("awg3 --down     погасить туннель")
            return 0
        err(f"неизвестный аргумент: {command}")
        return 1

    try:
        return Menu().run()
    except StorageError as exc:
        err(f"хранилище недоступно: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
