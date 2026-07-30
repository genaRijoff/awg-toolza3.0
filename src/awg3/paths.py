"""Пути AWG3. Все — под собственным префиксом.

Правило изоляции: ничего за пределами этих путей не создаётся и не удаляется.
AWG 2.0 (awg2.sh) при удалении делает `rm -rf /etc/amnezia` и
`apt-get remove amneziawg-tools`, поэтому мы не храним ничего в /etc/amnezia
и не зависим от системных бинарей amneziawg.
"""

from __future__ import annotations

import os
from pathlib import Path


def _env_path(name: str, default: str) -> Path:
    return Path(os.environ.get(name, default))


# ── Собственный префикс ─────────────────────────────────────────────
PREFIX = _env_path("AWG3_PREFIX", "/opt/awg3")
BIN_DIR = PREFIX / "bin"
GO_BINARY = BIN_DIR / "amneziawg-go"

# ── Конфигурация и состояние ────────────────────────────────────────
CONF_DIR = _env_path("AWG3_CONF_DIR", "/etc/awg3")
DB_PATH = CONF_DIR / "awg3.db"
CLIENTS_DIR = CONF_DIR / "clients"

# ── Runtime ─────────────────────────────────────────────────────────
# amneziawg-go жёстко использует /var/run/amneziawg/<iface>.sock — этот путь
# задан в самой go-реализации, переопределить его нельзя. Конфликта с AWG 2.0
# нет: kernel-модуль сокетов не создаёт, а имена интерфейсов у нас разные.
RUN_DIR = _env_path("AWG3_RUN_DIR", "/var/run/amneziawg")

# ── Логи и бекапы ───────────────────────────────────────────────────
LOG_FILE = _env_path("AWG3_LOG", "/var/log/awg3.log")
BACKUP_DIR = _env_path("AWG3_BACKUP_DIR", str(Path.home() / "awg3_backup"))

# ── Сетевые дефолты, разведённые с AWG 2.0 ──────────────────────────
# awg2.sh предлагает 10.100/10.101/10.102/10.44.5 либо случайную 10.x.x.0/24,
# поэтому берём диапазон, которого в его списке нет. Реальная проверка на
# пересечение делается в preflight по фактическому awg0.conf.
DEFAULT_CLIENT_NET = "10.200.0.0/24"
DEFAULT_IFACE = "awg1"

# Таблица policy-routing. AWG 2.0 использует 200 и делает по ней
# безусловный `ip route flush table 200` — берём другую.
ROUTE_TABLE = int(os.environ.get("AWG3_ROUTE_TABLE", "210"))

# Тег для правил iptables. Удаление всегда адресное по комментарию,
# никаких -F по цепочкам.
IPTABLES_TAG = "awg3"

# Пути AWG 2.0 — только для чтения в preflight, никогда не для записи.
AWG2_SERVER_CONF = Path("/etc/amnezia/amneziawg/awg0.conf")


def socket_path(iface: str) -> Path:
    """UAPI-сокет интерфейса."""
    return RUN_DIR / f"{iface}.sock"


def ensure_dirs() -> None:
    """Создаёт каталоги AWG3 с безопасными правами."""
    for directory, mode in (
        (CONF_DIR, 0o700),
        (CLIENTS_DIR, 0o700),
        (BACKUP_DIR, 0o700),
        (BIN_DIR, 0o755),
    ):
        directory.mkdir(parents=True, exist_ok=True)
        directory.chmod(mode)
