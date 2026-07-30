"""Сетевые правила.

Единственное место, где AWG3 трогает общесистемное состояние, поэтому здесь
доктрина изоляции соблюдается буквально:

  * каждое правило несёт комментарий awg3:<роль>;
  * удаление адресное — ищем свои правила в iptables-save и удаляем по одному;
  * никаких -F и -X: соседние правила AWG 2.0, Warp и каскада не наши;
  * таблица маршрутизации берётся из paths.ROUTE_TABLE (210), потому что по
    таблице 200 AWG 2.0 делает безусловный flush.
"""

from __future__ import annotations

import ipaddress
import logging
import re
import subprocess
import urllib.request
from pathlib import Path

from .. import paths

logger = logging.getLogger(__name__)

_TAG = paths.IPTABLES_TAG
_TIMEOUT = 10


class NetworkError(RuntimeError):
    """Ошибка настройки сети."""


def _run(argv: list[str], *, check: bool = True) -> subprocess.CompletedProcess[str]:
    logger.debug("exec: %s", " ".join(argv))
    try:
        proc = subprocess.run(
            argv, capture_output=True, text=True, timeout=_TIMEOUT, check=False
        )
    except FileNotFoundError as exc:
        raise NetworkError(f"команда не найдена: {argv[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise NetworkError(f"таймаут: {' '.join(argv)}") from exc
    if check and proc.returncode != 0:
        raise NetworkError(
            f"{' '.join(argv)} -> код {proc.returncode}: {proc.stderr.strip()}"
        )
    return proc


def default_wan_interface() -> str:
    """Интерфейс маршрута по умолчанию — через него уходит NAT."""
    proc = _run(["ip", "-4", "route", "show", "default"])
    match = re.search(r"\bdev\s+(\S+)", proc.stdout)
    if not match:
        raise NetworkError("не найден маршрут по умолчанию — некуда делать MASQUERADE")
    return match.group(1)


# Границы второго октета. Те же, что в install.sh: расходимся и с типовыми
# домашними сетями (10.0.x, 10.1.x), и с тем, что предлагает AWG 2.0.
SUBNET_OCTET_MIN = 33
SUBNET_OCTET_MAX = 188


def subnet_in_use(network_addr: str) -> bool:
    """Есть ли на хосте маршрут для этой сети."""
    try:
        proc = _run(["ip", "-4", "route", "show"], check=False)
    except NetworkError:
        return False
    if proc.returncode != 0:
        return False
    return re.search(rf"(^|\s){re.escape(network_addr)}/", proc.stdout, re.M) is not None


def pick_free_subnet(exclude: set[str] | None = None) -> str:
    """Случайная свободная /24 вида 10.X.0.0/24.

    Случайная, а не фиксированная: одинаковая подсеть на всех установках —
    лишняя зацепка и гарантированный конфликт, если поднять два сервера и
    захотеть связать их между собой.
    """
    import secrets

    rand = secrets.SystemRandom()
    blocked = {addr.split("/")[0] for addr in (exclude or set())}
    for _ in range(60):
        candidate = f"10.{rand.randint(SUBNET_OCTET_MIN, SUBNET_OCTET_MAX)}.0.0"
        if candidate in blocked or subnet_in_use(candidate):
            continue
        return f"{candidate}/24"
    raise NetworkError("не нашлось свободной подсети за 60 попыток")


def local_source_ip() -> str | None:
    """Адрес, с которого сервер уходит наружу.

    `ip route get` спрашивает у ядра, какой источник оно выберет для внешнего
    назначения. Пакеты никуда не отправляются — это чистый запрос к таблице
    маршрутизации.
    """
    try:
        proc = _run(["ip", "-4", "route", "get", "1.1.1.1"], check=False)
    except NetworkError as exc:
        # check=False не спасает от отсутствия самой утилиты — ловим отдельно,
        # иначе меню упадёт там, где должно просто спросить адрес руками.
        logger.warning("Определение адреса недоступно: %s", exc)
        return None
    if proc.returncode != 0:
        return None
    match = re.search(r"\bsrc\s+(\d+\.\d+\.\d+\.\d+)", proc.stdout)
    return match.group(1) if match else None


def is_private_ip(address: str) -> bool:
    """RFC1918, loopback, link-local и прочее немаршрутизируемое."""
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    return not parsed.is_global


def external_ip(timeout: float = 5.0) -> str | None:
    """Внешний адрес через сторонний сервис.

    Нужен только когда сервер за NAT: тогда локальный адрес приватный, и
    клиенты по нему не подключатся. Пробуем два независимых сервиса.
    """
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=timeout) as resp:
                candidate = resp.read(64).decode("ascii", errors="ignore").strip()
        except Exception as exc:
            logger.debug("Сервис %s недоступен: %s", url, exc)
            continue
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        return candidate
    return None


def detect_endpoint() -> tuple[str | None, str]:
    """Внешний адрес сервера и способ, которым он определён.

    Возвращает (адрес, пояснение). Адрес None — определить не удалось,
    оператор должен ввести вручную.
    """
    local = local_source_ip()
    if local and not is_private_ip(local):
        return local, "адрес интерфейса"

    if local:
        logger.info("Локальный адрес %s приватный — сервер за NAT", local)
        outside = external_ip()
        if outside:
            return outside, f"через внешний сервис (локальный {local} за NAT)"
        return None, f"локальный {local} приватный, внешний определить не удалось"

    outside = external_ip()
    if outside:
        return outside, "через внешний сервис"
    return None, "маршрут по умолчанию не найден"


def ip_forward_enabled() -> bool:
    try:
        return Path("/proc/sys/net/ipv4/ip_forward").read_text().strip() == "1"
    except OSError:
        return False


def enable_ip_forward(persist: bool = True) -> None:
    """Включает форвардинг. Свой файл в sysctl.d, чужие не трогаем."""
    _run(["sysctl", "-w", "net.ipv4.ip_forward=1"])
    if persist:
        target = Path("/etc/sysctl.d/99-awg3.conf")
        target.write_text("net.ipv4.ip_forward = 1\n", encoding="utf-8")
        logger.info("Форвардинг закреплён в %s", target)


def _rule_specs(
    subnet: str, iface: str, wan: str, port: int | None = None
) -> list[tuple[str, list[str]]]:
    """Правила AWG3. Каждое с комментарием — по нему же и удаляется."""
    specs: list[tuple[str, list[str]]] = []
    if port is not None:
        # Без этого правила при политике INPUT DROP хендшейк не дойдёт вообще:
        # FORWARD и NAT пропускают трафик ЧЕРЕЗ сервер, а пакет клиента
        # приходит НА сервер и упирается в INPUT.
        specs.append(
            ("input", ["INPUT", "-p", "udp", "--dport", str(port),
                       "-m", "comment", "--comment", f"{_TAG}:input", "-j", "ACCEPT"])
        )
    return specs + [
        ("nat", ["-t", "nat", "POSTROUTING", "-s", subnet, "-o", wan,
                 "-m", "comment", "--comment", f"{_TAG}:nat", "-j", "MASQUERADE"]),
        ("fwd-in", ["FORWARD", "-i", iface, "-m", "comment",
                    "--comment", f"{_TAG}:fwd-in", "-j", "ACCEPT"]),
        ("fwd-out", ["FORWARD", "-o", iface, "-m", "comment",
                     "--comment", f"{_TAG}:fwd-out", "-j", "ACCEPT"]),
    ]


def _rule_exists(spec: list[str]) -> bool:
    argv = ["iptables"]
    idx = 0
    if spec[0] == "-t":
        argv += spec[:2]
        idx = 2
    argv += ["-C", spec[idx]] + spec[idx + 1:]
    return _run(argv, check=False).returncode == 0


def apply_rules(
    subnet: str, iface: str, wan: str | None = None, port: int | None = None
) -> list[str]:
    """Ставит правила идемпотентно. Возвращает список добавленных.

    INPUT-правило вставляется первым в цепочку (-I), а не дописывается в конец:
    у ufw и подобных в INPUT уже стоит финальный DROP, и добавленное после него
    правило никогда не сработает.
    """
    wan = wan or default_wan_interface()
    added: list[str] = []
    for role, spec in _rule_specs(subnet, iface, wan, port):
        if _rule_exists(spec):
            logger.debug("Правило %s уже есть", role)
            continue
        argv = ["iptables"]
        idx = 0
        if spec[0] == "-t":
            argv += spec[:2]
            idx = 2
        action = "-I" if role == "input" else "-A"
        argv += [action, spec[idx]] + spec[idx + 1:]
        _run(argv)
        added.append(role)
    if added:
        logger.info("Добавлены правила: %s", ", ".join(added))
    return added


def list_rules() -> list[str]:
    """Наши правила из iptables-save — для показа в меню и для удаления."""
    found: list[str] = []
    for table in ("filter", "nat"):
        proc = _run(["iptables-save", "-t", table], check=False)
        if proc.returncode != 0:
            continue
        for line in proc.stdout.splitlines():
            if f"{_TAG}:" in line and line.startswith("-A"):
                found.append(f"{table}|{line}")
    return found


def remove_rules() -> int:
    """Удаляет только свои правила. Возвращает количество удалённых.

    Разбираем вывод iptables-save и меняем -A на -D. Так удаляется ровно то,
    что мы добавили, включая правила с параметрами, которых мы уже не помним.
    """
    removed = 0
    for entry in list_rules():
        table, _, rule = entry.partition("|")
        # Кавычки вокруг комментария ломают обычный split — разбираем сами.
        argv = ["iptables", "-t", table] + _split_rule(rule.replace("-A", "-D", 1))
        if _run(argv, check=False).returncode == 0:
            removed += 1
        else:
            logger.warning("Не удалось удалить правило: %s", rule)
    logger.info("Удалено правил AWG3: %d", removed)
    return removed


def _split_rule(rule: str) -> list[str]:
    """Разбор строки iptables-save с учётом кавычек вокруг комментария."""
    parts: list[str] = []
    for token in re.findall(r'"[^"]*"|\S+', rule):
        parts.append(token[1:-1] if token.startswith('"') and token.endswith('"') else token)
    return parts


def ufw_active() -> bool:
    """Активен ли ufw. Он ставит свой DROP в INPUT и перетирает наши правила."""
    proc = _run(["ufw", "status"], check=False)
    return proc.returncode == 0 and "Status: active" in proc.stdout


def ufw_allow(port: int) -> bool:
    """Открывает порт в ufw. False — ufw не активен либо команда не прошла.

    Нужно отдельно от iptables: ufw пересобирает свои цепочки при перезагрузке
    и наши правила из INPUT исчезнут, а его собственные — нет.
    """
    try:
        if not ufw_active():
            return False
    except NetworkError:
        return False
    proc = _run(
        ["ufw", "allow", f"{port}/udp", "comment", f"{_TAG} AmneziaWG 3.0"],
        check=False,
    )
    if proc.returncode == 0:
        logger.info("ufw: открыт %d/udp", port)
        return True
    logger.warning("ufw allow не сработал: %s", proc.stderr.strip())
    return False


def port_listening(port: int) -> bool:
    """Слушает ли кто-нибудь UDP-порт.

    Два независимых источника: ss и /proc/net/udp. Первый может отсутствовать
    или отдавать неожиданный формат, второй есть всегда, но требует разбора
    hex. Расхождение между ними само по себе диагностично.
    """
    if _port_listening_ss(port) or _port_listening_proc(port):
        return True
    return False


def _port_listening_ss(port: int) -> bool:
    proc = _run(["ss", "-lunH"], check=False)
    if proc.returncode != 0:
        return False
    needle = f":{port}"
    for line in proc.stdout.splitlines():
        fields = line.split()
        if len(fields) >= 5 and fields[4].endswith(needle):
            return True
    return False


def _port_listening_proc(port: int) -> bool:
    """Разбор /proc/net/udp и udp6: порт лежит в hex после двоеточия."""
    target = f"{port:04X}"
    for path in ("/proc/net/udp", "/proc/net/udp6"):
        try:
            lines = Path(path).read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            fields = line.split()
            if len(fields) >= 2 and fields[1].rsplit(":", 1)[-1].upper() == target:
                return True
    return False


def status(subnet: str, iface: str, port: int | None = None) -> dict[str, object]:
    """Сводка для меню."""
    try:
        wan = default_wan_interface()
    except NetworkError:
        wan = "?"
    try:
        ufw = ufw_active()
    except NetworkError:
        ufw = False
    return {
        "wan": wan,
        "ip_forward": ip_forward_enabled(),
        "rules": len(list_rules()),
        "subnet": subnet,
        "iface": iface,
        "route_table": paths.ROUTE_TABLE,
        "ufw": ufw,
        "port_listening": port_listening(port) if port else None,
    }
