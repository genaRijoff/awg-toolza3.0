"""Хранилище. SQLite — единственный источник правды.

Конфиги генерируются ИЗ базы, а не парсятся обратно. Это чинит главную
структурную проблему AWG Toolza, где и bash-скрипт, и бот разбирают
awg0.conf регулярками, из-за чего любое изменение формата ломает обоих.

Стандартный sqlite3, без SQLAlchemy: на root-тулзе каждая зависимость —
это лишняя поверхность атаки, а запросов тут два десятка.
"""

from __future__ import annotations

import json
import logging
import sqlite3
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

from .. import paths
from .models import AWG3Params, ObfParams, Peer, Range, ServerConfig

logger = logging.getLogger(__name__)

SCHEMA_VERSION = 1

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS server (
    id            INTEGER PRIMARY KEY CHECK (id = 1),
    iface         TEXT    NOT NULL,
    private_key   TEXT    NOT NULL,
    public_key    TEXT    NOT NULL,
    listen_port   INTEGER NOT NULL,
    address       TEXT    NOT NULL,
    subnet        TEXT    NOT NULL,
    mtu           INTEGER NOT NULL,
    endpoint_host TEXT    NOT NULL,
    dns           TEXT    NOT NULL,
    profile       TEXT    NOT NULL,
    obf_json      TEXT    NOT NULL,
    awg3_json     TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS clients (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT    NOT NULL UNIQUE,
    private_key   TEXT    NOT NULL,
    public_key    TEXT    NOT NULL UNIQUE,
    preshared_key TEXT,
    address       TEXT    NOT NULL UNIQUE,
    enabled       INTEGER NOT NULL DEFAULT 1,
    created_at    TEXT    NOT NULL
);
"""


class StorageError(RuntimeError):
    """Ошибка работы с базой."""


@dataclass(slots=True)
class ClientRow:
    id: int
    name: str
    private_key: str
    public_key: str
    preshared_key: str | None
    address: str
    enabled: bool
    created_at: str


@dataclass(slots=True)
class ServerRow:
    iface: str
    private_key: str
    public_key: str
    listen_port: int
    address: str
    subnet: str
    mtu: int
    endpoint_host: str
    dns: str
    profile: str
    obf: dict
    awg3: dict
    created_at: str


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class Storage:
    """Тонкая обёртка над sqlite3 с явными операциями предметной области."""

    def __init__(self, db_path: Path | None = None) -> None:
        self.path = db_path or paths.DB_PATH
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()
        # Ключи клиентов лежат здесь в открытом виде — иначе нельзя
        # перевыпустить конфиг. Права строго 0600.
        self.path.chmod(0o600)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
            conn.commit()
        except sqlite3.Error as exc:
            conn.rollback()
            raise StorageError(f"Ошибка SQLite: {exc}") from exc
        finally:
            conn.close()

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_SCHEMA)
            conn.execute(
                "INSERT OR IGNORE INTO meta (key, value) VALUES ('schema_version', ?)",
                (str(SCHEMA_VERSION),),
            )

    # ── сервер ──────────────────────────────────────────────────────

    def has_server(self) -> bool:
        with self._connect() as conn:
            row = conn.execute("SELECT 1 FROM server WHERE id = 1").fetchone()
        return row is not None

    def save_server(self, server: ServerRow) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO server (
                    id, iface, private_key, public_key, listen_port, address,
                    subnet, mtu, endpoint_host, dns, profile, obf_json,
                    awg3_json, created_at
                ) VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    server.iface, server.private_key, server.public_key,
                    server.listen_port, server.address, server.subnet,
                    server.mtu, server.endpoint_host, server.dns, server.profile,
                    json.dumps(server.obf), json.dumps(server.awg3),
                    server.created_at or _now(),
                ),
            )
        logger.info("Сервер сохранён: %s:%d", server.iface, server.listen_port)

    def get_server(self) -> ServerRow | None:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM server WHERE id = 1").fetchone()
        if row is None:
            return None
        return ServerRow(
            iface=row["iface"], private_key=row["private_key"],
            public_key=row["public_key"], listen_port=row["listen_port"],
            address=row["address"], subnet=row["subnet"], mtu=row["mtu"],
            endpoint_host=row["endpoint_host"], dns=row["dns"],
            profile=row["profile"], obf=json.loads(row["obf_json"]),
            awg3=json.loads(row["awg3_json"]), created_at=row["created_at"],
        )

    def require_server(self) -> ServerRow:
        server = self.get_server()
        if server is None:
            raise StorageError("Сервер ещё не создан — сначала пункт «Создать сервер»")
        return server

    # ── клиенты ─────────────────────────────────────────────────────

    def add_client(
        self,
        name: str,
        private_key: str,
        public_key: str,
        address: str,
        preshared_key: str | None = None,
    ) -> int:
        with self._connect() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO clients
                        (name, private_key, public_key, preshared_key, address, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (name, private_key, public_key, preshared_key, address, _now()),
                )
            except sqlite3.IntegrityError as exc:
                raise StorageError(
                    f"Клиент '{name}' или адрес {address} уже существует"
                ) from exc
            return int(cur.lastrowid or 0)

    def list_clients(self) -> list[ClientRow]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM clients ORDER BY id").fetchall()
        return [
            ClientRow(
                id=r["id"], name=r["name"], private_key=r["private_key"],
                public_key=r["public_key"], preshared_key=r["preshared_key"],
                address=r["address"], enabled=bool(r["enabled"]),
                created_at=r["created_at"],
            )
            for r in rows
        ]

    def get_client(self, name: str) -> ClientRow | None:
        for client in self.list_clients():
            if client.name == name:
                return client
        return None

    def remove_client(self, name: str) -> bool:
        with self._connect() as conn:
            cur = conn.execute("DELETE FROM clients WHERE name = ?", (name,))
            return cur.rowcount > 0

    def set_client_enabled(self, name: str, enabled: bool) -> bool:
        with self._connect() as conn:
            cur = conn.execute(
                "UPDATE clients SET enabled = ? WHERE name = ?",
                (1 if enabled else 0, name),
            )
            return cur.rowcount > 0

    def used_addresses(self) -> set[str]:
        """Занятые адреса без масок. Адрес сервера тоже занят."""
        taken = {client.address.split("/")[0] for client in self.list_clients()}
        server = self.get_server()
        if server is not None:
            taken.add(server.address.split("/")[0])
        return taken

    def next_free_address(self, subnet: str) -> str:
        """Следующий свободный /32 в подсети. Сервер держит .1."""
        base = subnet.split("/")[0].rsplit(".", 1)[0]
        taken = self.used_addresses()
        for host in range(2, 255):
            candidate = f"{base}.{host}"
            if candidate not in taken:
                return f"{candidate}/32"
        raise StorageError(f"В подсети {subnet} не осталось свободных адресов")

    # ── мост к доменной модели ──────────────────────────────────────

    def to_server_config(self, *, only_enabled: bool = True) -> ServerConfig:
        """Собирает ServerConfig из БД — ровно то, что уходит в UAPI.

        Односторонняя генерация: БД -> модель -> UAPI. Обратного разбора нет
        нигде, поэтому изменение формата конфига не может ничего сломать.
        """
        server = self.require_server()

        raw = server.obf
        obf = ObfParams(
            jc=raw["jc"], jmin=raw["jmin"], jmax=raw["jmax"],
            s1=raw["s1"], s2=raw["s2"], s3=raw["s3"], s4=raw["s4"],
            h1=Range.parse(raw["h1"]), h2=Range.parse(raw["h2"]),
            h3=Range.parse(raw["h3"]), h4=Range.parse(raw["h4"]),
            i=list(raw.get("i", [])),
        )

        def _rng(key: str) -> Range | None:
            value = server.awg3.get(key)
            return Range.parse(value) if value else None

        awg3 = AWG3Params(
            header_protection_key=server.awg3.get("header_protection_key"),
            content_padding_addition=_rng("content_padding_addition"),
            rekey_after_time=_rng("rekey_after_time"),
            rekey_timeout=_rng("rekey_timeout"),
            reject_after_time=_rng("reject_after_time"),
            keepalive_timeout=_rng("keepalive_timeout"),
            max_handshake_attempts=_rng("max_handshake_attempts"),
        )

        peers = [
            Peer(
                name=client.name,
                public_key=client.public_key,
                allowed_ips=[client.address],
                preshared_key=client.preshared_key,
            )
            for client in self.list_clients()
            if client.enabled or not only_enabled
        ]

        return ServerConfig(
            private_key=server.private_key,
            listen_port=server.listen_port,
            address=server.address,
            obf=obf,
            mtu=server.mtu,
            awg3=awg3,
            peers=peers,
        )
