"""Backend: жизненный цикл amneziawg-go и настройка сетевого интерфейса.

Сознательно НЕ используем awg-quick. Две причины:

1. Изоляция. awg-quick приходит из системного пакета amneziawg-tools, который
   awg2.sh сносит при своём удалении (`apt-get remove amneziawg-tools`).
2. Выбор backend. При загруженном kernel-модуле amneziawg awg-quick поднимет
   kernel-интерфейс, а не наш userspace-демон — молча и не тем протоколом.

Поэтому интерфейс поднимается сами: запуск демона -> UAPI -> ip addr/link/route.
"""

from __future__ import annotations

import logging
import re
import shutil
import subprocess
import time
import time
from dataclasses import dataclass
from pathlib import Path

from .. import paths
from . import wgkeys
from .uapi import UAPIClient, UAPICommandError, UAPIError, UAPINotRunning

logger = logging.getLogger(__name__)

_SOCKET_WAIT_TIMEOUT = 10.0
_SOCKET_POLL_INTERVAL = 0.1
_IP_COMMAND_TIMEOUT = 10


class BackendError(RuntimeError):
    """Ошибка запуска или настройки интерфейса."""


@dataclass(frozen=True, slots=True)
class PeerStats:
    """Живые счётчики пира из UAPI."""

    public_key: str          # base64, как в конфигах
    endpoint: str | None
    last_handshake: int      # unix-время; 0 — хендшейка не было
    rx_bytes: int            # принято сервером ОТ клиента
    tx_bytes: int            # отправлено сервером клиенту
    allowed_ips: tuple[str, ...]

    @property
    def connected(self) -> bool:
        """Хендшейк был и не протух.

        WireGuard перевыпускает ключи каждые ~120 секунд при активности,
        поэтому свежесть до трёх минут — надёжный признак живого клиента.
        """
        if self.last_handshake == 0:
            return False
        return (time.time() - self.last_handshake) < 180


@dataclass(frozen=True, slots=True)
class InterfaceState:
    name: str
    running: bool
    link_up: bool
    listen_port: int | None
    peer_count: int


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    """Обёртка над subprocess с логированием и внятной ошибкой."""
    logger.debug("exec: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv,
            capture_output=True,
            text=True,
            timeout=_IP_COMMAND_TIMEOUT,
            check=False,
        )
    except FileNotFoundError as exc:
        raise BackendError(f"Команда не найдена: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise BackendError(f"Таймаут выполнения: {' '.join(argv)}") from exc

    if check and proc.returncode != 0:
        raise BackendError(
            f"{' '.join(argv)} -> код {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc


class GoBackend:
    """Управление одним интерфейсом amneziawg-go."""

    def __init__(
        self,
        iface: str = paths.DEFAULT_IFACE,
        binary: Path | None = None,
        log_level: str = "error",
    ) -> None:
        self.iface = iface
        self.binary = binary or paths.GO_BINARY
        self.log_level = log_level
        self.uapi = UAPIClient(paths.socket_path(iface))

    # ── проверки окружения ──────────────────────────────────────────

    def check_binary(self) -> None:
        """Убеждается, что бинарь на месте и исполняем."""
        if not self.binary.is_file():
            raise BackendError(
                f"amneziawg-go не найден: {self.binary}. "
                "Собери его в собственный префикс — системный ставить нельзя, "
                "его удалит деинсталлятор AWG 2.0."
            )
        if not shutil.which(str(self.binary)):
            raise BackendError(f"{self.binary} не исполняем (нужен chmod +x)")

    def kernel_module_loaded(self) -> bool:
        """Загружен ли kernel-модуль AWG 2.0.

        Не ошибка — сосуществование штатно. Но если модуль есть, любой вызов
        awg-quick пойдёт мимо нас, и об этом надо предупредить в doctor.
        """
        return Path("/sys/module/amneziawg").is_dir()

    # ── жизненный цикл ──────────────────────────────────────────────

    def is_running(self) -> bool:
        return self.uapi.is_available()

    def start(self) -> None:
        """Поднимает демон. Идемпотентно."""
        if self.is_running():
            logger.info("%s уже запущен", self.iface)
            return

        self.check_binary()
        paths.RUN_DIR.mkdir(parents=True, exist_ok=True)

        # Осиротевший сокет от умершего демона. is_running() уже сказал «нет»
        # (соединение отвергнуто), но файл остался и займёт адрес: новый демон
        # упадёт с "unable to listen on uapi socket". Частый случай после
        # обновления бинаря, когда старый процесс умер, а файл нет.
        socket_file = self.uapi.socket_path
        if socket_file.exists():
            logger.warning("Убираю осиротевший сокет %s", socket_file)
            try:
                socket_file.unlink()
            except OSError as exc:
                raise BackendError(
                    f"сокет {socket_file} занят и не удаляется: {exc}"
                ) from exc

        # Интерфейс мог остаться от прошлого запуска без своего демона.
        if self._link_exists():
            logger.warning("Убираю осиротевший интерфейс %s", self.iface)
            _run(["ip", "link", "delete", "dev", self.iface], check=False)

        # Демон уходит в фон сам (без -f) и НАСЛЕДУЕТ наши stdout/stderr.
        # Ловушка: с capture_output=True это пайпы, и как только родительский
        # процесс завершится, читающий конец закроется. Первая же строка лога
        # от демона даст EPIPE, и он умрёт — а файл сокета останется. Ровно
        # поэтому интерфейс «поднимался», а через минуту оказывался мёртвым.
        #
        # Поэтому: вывод в файл, отдельная сессия, никаких пайпов.
        daemon_log = paths.LOG_FILE.with_name("awg3-daemon.log")
        try:
            daemon_log.parent.mkdir(parents=True, exist_ok=True)
            log_handle = daemon_log.open("ab")
            # Права выставляем явно: файл создаётся по umask, а он на сервере
            # бывает 022 — тогда лог демона окажется читаемым всем.
            daemon_log.chmod(0o640)
        except OSError as exc:
            raise BackendError(f"не открыть лог демона {daemon_log}: {exc}") from exc

        try:
            proc = subprocess.run(
                [str(self.binary), self.iface],
                stdin=subprocess.DEVNULL,
                stdout=log_handle,
                stderr=log_handle,
                start_new_session=True,
                timeout=_IP_COMMAND_TIMEOUT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as exc:
            raise BackendError(f"не удалось запустить {self.binary}: {exc}") from exc
        finally:
            log_handle.close()

        if proc.returncode != 0:
            tail = ""
            try:
                tail = daemon_log.read_text(errors="replace").splitlines()[-5:]
                tail = "\n  ".join(tail)
            except OSError:
                pass
            raise BackendError(
                f"amneziawg-go не стартовал (код {proc.returncode})\n  {tail}\n"
                f"  подробности: LOG_LEVEL=debug {self.binary} -f {self.iface}"
            )

        self._wait_for_socket()
        logger.info("Интерфейс %s поднят, сокет %s", self.iface, self.uapi.socket_path)

    def stop(self) -> None:
        """Гасит интерфейс. Идемпотентно."""
        if not self._link_exists():
            self._remove_stale_socket()
            logger.info("%s уже остановлен", self.iface)
            return

        _run(["ip", "link", "delete", "dev", self.iface], check=False)
        self._remove_stale_socket()
        logger.info("Интерфейс %s остановлен", self.iface)

    def _wait_for_socket(self, timeout: float = _SOCKET_WAIT_TIMEOUT) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.uapi.is_available():
                return
            time.sleep(_SOCKET_POLL_INTERVAL)
        raise BackendError(
            f"UAPI-сокет {self.uapi.socket_path} не появился за {timeout}s. "
            f"Смотри {paths.LOG_FILE.with_name('awg3-daemon.log')} либо запусти "
            f"вручную: LOG_LEVEL=debug {self.binary} -f {self.iface}"
        )

    def _remove_stale_socket(self) -> None:
        socket_file = self.uapi.socket_path
        if socket_file.exists():
            try:
                socket_file.unlink()
            except OSError as exc:
                logger.warning("Не удалось удалить %s: %s", socket_file, exc)

    def _link_exists(self) -> bool:
        proc = _run(["ip", "link", "show", "dev", self.iface], check=False)
        return proc.returncode == 0

    # ── настройка интерфейса ────────────────────────────────────────

    def configure_link(self, address: str, mtu: int) -> None:
        """Назначает адрес, MTU и поднимает линк.

        address — в формате CIDR, например 10.200.0.1/24.
        """
        if not 1280 <= mtu <= 1500:
            raise BackendError(f"MTU вне допустимого диапазона 1280-1500: {mtu}")

        existing = _run(["ip", "-o", "addr", "show", "dev", self.iface], check=False)
        if address not in existing.stdout:
            _run(["ip", "addr", "add", address, "dev", self.iface])

        _run(["ip", "link", "set", "dev", self.iface, "mtu", str(mtu)])
        _run(["ip", "link", "set", "dev", self.iface, "up"])

        # Проверяем, что линк действительно поднялся: amneziawg-go открывает
        # UDP-сокет только для поднятого интерфейса, и молча опущенный линк
        # выглядит как «всё хорошо, но клиенты не подключаются».
        if not self._link_is_up():
            raise BackendError(
                f"{self.iface} не поднялся после 'ip link set up'. "
                f"Текущее состояние: {self.link_details()}"
            )
        logger.info("%s: адрес %s, MTU %d, линк UP", self.iface, address, mtu)

    def state(self) -> InterfaceState:
        """Сводное состояние — для меню и для doctor."""
        running = self.is_running()
        listen_port: int | None = None
        peer_count = 0

        if running:
            try:
                device = self.uapi.get()
                ports = device.get("listen_port", [])
                listen_port = int(ports[0]) if ports else None
                peer_count = len(device.get("public_key", []))
            except (UAPIError, ValueError) as exc:
                logger.warning("Не удалось прочитать состояние %s: %s", self.iface, exc)

        return InterfaceState(
            name=self.iface,
            running=running,
            link_up=self._link_is_up(),
            listen_port=listen_port,
            peer_count=peer_count,
        )

    def _link_is_up(self) -> bool:
        """Поднят ли интерфейс.

        Проверяем флаг UP в угловых скобках, а НЕ 'state UP': TUN-устройства
        держат operstate UNKNOWN даже будучи полностью рабочими, поэтому
        проверка по state давала вечный DOWN.
        """
        proc = _run(["ip", "-o", "link", "show", "dev", self.iface], check=False)
        if proc.returncode != 0:
            return False
        match = re.search(r"<([^>]*)>", proc.stdout)
        return bool(match) and "UP" in match.group(1).split(",")

    def link_details(self) -> str:
        """Сырой вывод ip link — для диагностики, когда что-то не сходится."""
        proc = _run(["ip", "-o", "link", "show", "dev", self.iface], check=False)
        return proc.stdout.strip() if proc.returncode == 0 else "интерфейс не существует"

    def peer_stats(self) -> list[PeerStats]:
        """Счётчики по каждому пиру. Пустой список, если интерфейс не поднят."""
        if not self.is_running():
            return []

        try:
            pairs = self.uapi.get_ordered()
        except UAPIError as exc:
            logger.warning("Не удалось прочитать статистику: %s", exc)
            return []

        stats: list[PeerStats] = []
        current: dict[str, object] | None = None

        def flush() -> None:
            if current is None:
                return
            stats.append(
                PeerStats(
                    public_key=str(current["public_key"]),
                    endpoint=current.get("endpoint"),  # type: ignore[arg-type]
                    last_handshake=int(current.get("last_handshake", 0)),
                    rx_bytes=int(current.get("rx_bytes", 0)),
                    tx_bytes=int(current.get("tx_bytes", 0)),
                    allowed_ips=tuple(current.get("allowed_ips", [])),  # type: ignore[arg-type]
                )
            )

        for key, value in pairs:
            if key == "public_key":
                flush()
                current = {
                    "public_key": wgkeys.from_uapi_hex(value, "public_key пира"),
                    "allowed_ips": [],
                }
                continue
            if current is None:
                continue
            if key == "endpoint":
                current["endpoint"] = value
            elif key == "last_handshake_time_sec":
                current["last_handshake"] = value
            elif key == "rx_bytes":
                current["rx_bytes"] = value
            elif key == "tx_bytes":
                current["tx_bytes"] = value
            elif key == "allowed_ip":
                current["allowed_ips"].append(value)  # type: ignore[union-attr]
        flush()
        return stats

    # ── применение конфигурации ─────────────────────────────────────

    @staticmethod
    def _split_units(pairs: list[tuple[str, str]]) -> list[list[tuple[str, str]]]:
        """Режет набор на минимальные применимые единицы.

        Ключи устройства применимы по одному, а ключи пира — только вместе
        со своим public_key: allowed_ip без него UAPI не поймёт, и мы бы
        обвинили невиновного.
        """
        units: list[list[tuple[str, str]]] = []
        current: list[tuple[str, str]] | None = None
        for key, value in pairs:
            if key == "public_key":
                current = [(key, value)]
                units.append(current)
            elif current is not None:
                current.append((key, value))
            else:
                units.append([(key, value)])
        return units

    def find_rejected(self, pairs: list[tuple[str, str]]) -> tuple[str, str] | None:
        """Применяет набор по частям и возвращает первую отвергнутую пару.

        Вызывается только после неудачи bulk-применения: UAPI не сообщает,
        какой ключ его не устроил, а без этого сообщение об ошибке бесполезно.
        """
        for unit in self._split_units(pairs):
            try:
                self.uapi.set(unit)
            except UAPICommandError:
                return unit[0]
            except UAPIError:
                return unit[0]
        return None

    def apply_diagnosed(self, pairs: list[tuple[str, str]]) -> None:
        """Применяет набор, а при отказе называет конкретный ключ."""
        try:
            self.apply(pairs)
            return
        except UAPICommandError as exc:
            culprit = self.find_rejected(pairs)
            if culprit is None:
                raise BackendError(
                    f"{exc}; при поштучном применении все ключи прошли — "
                    "похоже, дело в сочетании параметров, а не в одном ключе"
                ) from exc
            key, value = culprit
            raise BackendError(
                f"UAPI отверг ключ '{key}' со значением '{value}' (errno={exc.errno})"
            ) from exc

    def apply(self, pairs: list[tuple[str, str]]) -> None:
        """Применяет набор UAPI key=value к устройству.

        Порядок значим: ключи пира идут после его public_key.
        """
        try:
            self.uapi.set(pairs)
        except UAPINotRunning as exc:
            raise BackendError(
                f"{self.iface} не запущен — сначала start()"
            ) from exc
