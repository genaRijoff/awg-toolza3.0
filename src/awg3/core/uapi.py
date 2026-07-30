"""Клиент UAPI amneziawg-go.

Протокол текстовый, поверх unix stream socket /var/run/amneziawg/<iface>.sock:

    запрос:  "set=1\\n" + "key=value\\n" * N + "\\n"
    ответ:   "errno=0\\n\\n"

    запрос:  "get=1\\n\\n"
    ответ:   "key=value\\n" * N + "errno=0\\n\\n"

Ненулевой errno — ошибка. Значение отдаём как есть, без интерпретации:
разные ветки go-реализации возвращают его с разным знаком, и придумывать
маппинг на strerror мы не будем.
"""

from __future__ import annotations

import logging
import socket
from collections.abc import Iterable, Mapping
from pathlib import Path

logger = logging.getLogger(__name__)

_TERMINATOR = b"\n\n"
_READ_CHUNK = 4096
# Потолок ответа. Реальный get= на сотне пиров укладывается в десятки
# килобайт; без предела повреждённый или враждебный сокет мог бы наливать
# в память бесконечно.
_MAX_RESPONSE = 8 * 1024 * 1024


class UAPIError(RuntimeError):
    """Базовая ошибка UAPI."""


class UAPINotRunning(UAPIError):
    """Сокет отсутствует или соединение отвергнуто — демон не поднят."""


class UAPICommandError(UAPIError):
    """Демон ответил ненулевым errno.

    Важно: UAPI применяет весь набор одной транзакцией и возвращает один
    errno без указания ключа. Поэтому здесь НЕТ поля «отвергнутый ключ» —
    его можно установить только повторным применением по одному
    (см. GoBackend.apply_diagnosed).
    """

    def __init__(self, errno: int, key_count: int) -> None:
        self.errno = errno
        self.key_count = key_count
        super().__init__(
            f"UAPI вернул errno={errno} на наборе из {key_count} ключей "
            f"(какой именно отвергнут — из ответа не видно)"
        )


class UAPIClient:
    """Одно соединение на одну операцию — демон закрывает сокет после ответа."""

    def __init__(self, socket_path: Path, timeout: float = 5.0) -> None:
        self._path = socket_path
        self._timeout = timeout

    @property
    def socket_path(self) -> Path:
        return self._path

    def is_available(self) -> bool:
        """Проверяет, что сокет существует и принимает соединения."""
        if not self._path.exists():
            return False
        try:
            with self._connect():
                return True
        except UAPIError:
            return False

    def get(self) -> dict[str, list[str]]:
        """Возвращает состояние устройства как плоский multimap key -> [values].

        Плоский, а не вложенный: в UAPI-ответе ключи пиров идут потоком после
        public_key, и разбор на объекты — задача уровнем выше (models.py).
        Здесь мы только транспорт.
        """
        raw = self._converse("get=1\n\n")
        result: dict[str, list[str]] = {}
        for line in raw.splitlines():
            if not line or line.startswith("errno="):
                continue
            key, _, value = line.partition("=")
            result.setdefault(key, []).append(value)
        return result

    def get_ordered(self) -> list[tuple[str, str]]:
        """Состояние устройства парами в исходном порядке.

        Порядок значим: ключи пира идут после его public_key, и плоский dict
        эту группировку теряет. Для статистики нужна именно последовательность.
        """
        raw = self._converse("get=1\n\n")
        pairs: list[tuple[str, str]] = []
        for line in raw.splitlines():
            if not line or line.startswith("errno="):
                continue
            key, _, value = line.partition("=")
            pairs.append((key, value))
        return pairs

    def set(self, pairs: Iterable[tuple[str, str]]) -> None:
        """Применяет набор key=value. Порядок сохраняется — он значим.

        В UAPI ключи пира идут после его public_key, поэтому принимаем
        последовательность пар, а не dict.
        """
        lines = [f"{key}={value}" for key, value in pairs]
        if not lines:
            logger.debug("UAPI set вызван с пустым набором — пропускаем")
            return
        payload = "set=1\n" + "\n".join(lines) + "\n\n"
        self._converse(payload)

    def set_mapping(self, mapping: Mapping[str, str]) -> None:
        """Удобная обёртка, когда порядок заведомо не важен (device-уровень)."""
        self.set(list(mapping.items()))

    # ── транспорт ───────────────────────────────────────────────────

    def _connect(self) -> socket.socket:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(self._timeout)
        try:
            sock.connect(str(self._path))
        except (FileNotFoundError, ConnectionRefusedError) as exc:
            sock.close()
            raise UAPINotRunning(f"UAPI-сокет недоступен: {self._path}") from exc
        except OSError as exc:
            sock.close()
            raise UAPIError(f"Ошибка соединения с {self._path}: {exc}") from exc
        return sock

    def _converse(self, payload: str) -> str:
        with self._connect() as sock:
            try:
                sock.sendall(payload.encode("utf-8"))
                raw = self._read_response(sock)
            except socket.timeout as exc:
                raise UAPIError(
                    f"Таймаут {self._timeout}s при обмене с {self._path}"
                ) from exc
            except OSError as exc:
                raise UAPIError(f"Ошибка ввода-вывода UAPI: {exc}") from exc

        text = raw.decode("utf-8", errors="replace")
        errno = self._extract_errno(text)
        if errno != 0:
            key_count = sum(1 for line in payload.splitlines() if "=" in line) - 1
            raise UAPICommandError(errno, max(key_count, 1))
        return text

    @staticmethod
    def _read_response(sock: socket.socket) -> bytes:
        buffer = bytearray()
        while True:
            chunk = sock.recv(_READ_CHUNK)
            if not chunk:
                break
            buffer.extend(chunk)
            if buffer.endswith(_TERMINATOR):
                break
            if len(buffer) > _MAX_RESPONSE:
                raise UAPIError(
                    f"ответ UAPI превысил {_MAX_RESPONSE} байт — "
                    "обрываю, чтобы не съесть память"
                )
        return bytes(buffer)

    @staticmethod
    def _extract_errno(text: str) -> int:
        for line in text.splitlines():
            if line.startswith("errno="):
                try:
                    return int(line.removeprefix("errno="))
                except ValueError as exc:
                    raise UAPIError(f"Не удалось разобрать {line!r}") from exc
        raise UAPIError("В ответе UAPI нет строки errno — протокол не распознан")
