"""Бекап и восстановление.

Внутри архива приватные ключи сервера и всех клиентов, поэтому права 0600
на файл и 0700 на каталог, а распаковка — только в наш префикс с проверкой
каждого пути. Архив из недоверенного источника не должен уметь записать
файл за пределы /etc/awg3.
"""

from __future__ import annotations

import logging
import tarfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import paths

logger = logging.getLogger(__name__)

PREFIX = "awg3-backup-"
SUFFIX = ".tar.gz"
KEEP = 10


class BackupError(RuntimeError):
    """Ошибка бекапа или восстановления."""


@dataclass(frozen=True, slots=True)
class Backup:
    path: Path
    created: datetime
    size: int

    @property
    def name(self) -> str:
        return self.path.name


def _members_to_save() -> list[Path]:
    """Что кладём в архив: база и конфиги клиентов."""
    items: list[Path] = []
    if paths.DB_PATH.is_file():
        items.append(paths.DB_PATH)
    reserved = paths.CONF_DIR / "reserved.env"
    if reserved.is_file():
        items.append(reserved)
    if paths.CLIENTS_DIR.is_dir():
        items.extend(sorted(paths.CLIENTS_DIR.glob("*.conf")))
    return items


def create() -> Path:
    """Создаёт архив. Возвращает путь к нему."""
    items = _members_to_save()
    if not items:
        raise BackupError("нечего сохранять — база не создана")

    paths.BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    paths.BACKUP_DIR.chmod(0o700)

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    target = paths.BACKUP_DIR / f"{PREFIX}{stamp}{SUFFIX}"

    try:
        with tarfile.open(target, "w:gz") as archive:
            for item in items:
                archive.add(item, arcname=item.relative_to(paths.CONF_DIR))
    except OSError as exc:
        target.unlink(missing_ok=True)
        raise BackupError(f"не удалось создать архив: {exc}") from exc

    target.chmod(0o600)
    logger.info("Бекап создан: %s (%d файлов)", target, len(items))
    _rotate()
    return target


def _rotate() -> None:
    """Оставляет последние KEEP архивов, остальные удаляет."""
    archives = sorted(
        paths.BACKUP_DIR.glob(f"{PREFIX}*{SUFFIX}"),
        key=lambda p: p.stat().st_mtime,
        reverse=True,
    )
    for stale in archives[KEEP:]:
        try:
            stale.unlink()
            logger.info("Удалён старый бекап: %s", stale.name)
        except OSError as exc:
            logger.warning("Не удалось удалить %s: %s", stale.name, exc)


def listing() -> list[Backup]:
    """Существующие бекапы, свежие первыми."""
    if not paths.BACKUP_DIR.is_dir():
        return []
    result: list[Backup] = []
    for path in paths.BACKUP_DIR.glob(f"{PREFIX}*{SUFFIX}"):
        try:
            stat = path.stat()
        except OSError:
            continue
        result.append(
            Backup(
                path=path,
                created=datetime.fromtimestamp(stat.st_mtime, timezone.utc),
                size=stat.st_size,
            )
        )
    return sorted(result, key=lambda b: b.created, reverse=True)


def _is_safe_member(member: tarfile.TarInfo, destination: Path) -> bool:
    """Пускаем только обычные файлы, распакованные внутрь назначения.

    Защита от path traversal: архив с именем вида ../../etc/passwd или с
    симлинком наружу не должен ничего записать за пределы CONF_DIR.
    """
    if not (member.isfile() or member.isdir()):
        return False
    if member.name.startswith("/") or ".." in Path(member.name).parts:
        return False
    resolved = (destination / member.name).resolve()
    return resolved == destination.resolve() or destination.resolve() in resolved.parents


def restore(archive: Path) -> int:
    """Распаковывает архив в CONF_DIR. Возвращает число файлов.

    Существующие файлы перезаписываются — вызывающий обязан спросить
    подтверждение до вызова.
    """
    if not archive.is_file():
        raise BackupError(f"архив не найден: {archive}")

    destination = paths.CONF_DIR
    destination.mkdir(parents=True, exist_ok=True)

    try:
        with tarfile.open(archive, "r:gz") as tar:
            members = [m for m in tar.getmembers() if _is_safe_member(m, destination)]
            rejected = len(tar.getmembers()) - len(members)
            if rejected:
                logger.warning("Отклонено небезопасных путей: %d", rejected)
            if not members:
                raise BackupError("в архиве нет пригодных файлов")
            tar.extractall(destination, members=members)
    except (OSError, tarfile.TarError) as exc:
        raise BackupError(f"не удалось распаковать: {exc}") from exc

    # Права восстанавливаем сами: в архиве они могли быть какими угодно.
    destination.chmod(0o700)
    if paths.DB_PATH.is_file():
        paths.DB_PATH.chmod(0o600)
    if paths.CLIENTS_DIR.is_dir():
        paths.CLIENTS_DIR.chmod(0o700)
        for conf in paths.CLIENTS_DIR.glob("*.conf"):
            conf.chmod(0o600)

    logger.info("Восстановлено из %s: %d файлов", archive.name, len(members))
    return len(members)


def tail_log(path: Path, lines: int = 50) -> list[str]:
    """Последние строки лога. Пустой список, если файла нет.

    Читаем хвост, а не файл целиком: лог демона не ротируется и может
    вырасти до размеров, которые незачем тянуть в память.
    """
    if not path.is_file():
        return []
    try:
        size = path.stat().st_size
        window = min(size, 64 * 1024)
        with path.open("rb") as handle:
            handle.seek(size - window)
            chunk = handle.read(window)
    except OSError as exc:
        logger.warning("Не прочитать %s: %s", path, exc)
        return []
    text = chunk.decode("utf-8", errors="replace")
    return text.splitlines()[-lines:]
