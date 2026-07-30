"""Проверка поддержки AWG 3 в установленном amneziawg-go.

Имена ключей подтверждены (см. keys.py), но собранный бинарь может им не
соответствовать: пользователь мог взять старый коммит или другую ветку.
Поэтому probe остаётся обязательным шагом установки — он проверяет не наши
догадки, а конкретную сборку на конкретной машине.

Поднимаем одноразовый интерфейс, выставляем базовый набор AWG 2.0
(S1-S4 >= 8 — предусловие header protection), пробуем каждый ключ AWG 3.
Отвергнутый ключ надо показать оператору до того, как он раздаст клиентам
конфиги, которые не заработают.

Требует root: создание TUN-интерфейса.
"""

from __future__ import annotations

import base64
import logging
import secrets
from dataclasses import dataclass

from .. import paths
from .backend import BackendError, GoBackend
from .keys import AWG3_KEYS, Confidence, Scope, UAPIKey
from .uapi import UAPICommandError, UAPIError

logger = logging.getLogger(__name__)

PROBE_IFACE = "awg3probe"

# Базовый набор, который выставляется ДО проверки ключей AWG 3.
#
# Без него header protection обязан отвергаться: README amneziawg-go требует
# S1-S4 >= 8, а на голом устройстве они равны нулю. Первая версия probe этого
# не делала и получала errno=-22 — ошибка была в тесте, не в демоне.
_BASELINE: list[tuple[str, str]] = [
    ("jc", "4"),
    ("jmin", "40"),
    ("jmax", "70"),
    ("s1", "64"),
    ("s2", "64"),
    ("s3", "16"),
    ("s4", "16"),
]

# H1-H4 в базовый набор НЕ входят намеренно: именно их форму мы и проверяем
# отдельно. В AWG 2.0 это типы заголовков (замена констант 1/2/3/4), и
# принимает ли демон диапазон вместо одиночного значения — не задокументировано.
_H_FORMATS: list[tuple[str, dict[str, str]]] = [
    ("диапазон a-b", {
        "h1": "5-500000", "h2": "600000000-600500000",
        "h3": "1100000000-1100500000", "h4": "1700000000-1700500000",
    }),
    ("одиночные значения", {
        "h1": "250000", "h2": "600250000",
        "h3": "1100250000", "h4": "1700250000",
    }),
]

_RANGE = "10-20"
_PROBE_VALUES: dict[str, str] = {
    "content_padding_addition": _RANGE,
    "rekey_after_time": "120-150",
    "rekey_timeout": "5-8",
    "reject_after_time": "180-200",
    "keepalive_timeout": _RANGE,
    "max_handshake_attempts": "5-10",
}

# Формат значения header protection в UAPI не задокументирован: в JSON
# sing-box он base64, у остальных ключей WireGuard в UAPI — hex. Перебираем
# кандидатов и запоминаем принятый.
def _hpk_candidates() -> list[tuple[str, str]]:
    raw = secrets.token_bytes(32)
    return [
        ("hex, 32 байта", raw.hex()),
        ("base64, 32 байта", base64.b64encode(raw).decode("ascii")),
        ("hex, 16 байт", secrets.token_bytes(16).hex()),
        ("произвольная строка", "awg3-probe-header-key"),
    ]


@dataclass(frozen=True, slots=True)
class ProbeResult:
    key: UAPIKey
    accepted: bool
    detail: str

    @property
    def symbol(self) -> str:
        return "√" if self.accepted else "×"


@dataclass(frozen=True, slots=True)
class ProbeReport:
    results: tuple[ProbeResult, ...]
    kernel_module_loaded: bool
    baseline_applied: bool = True
    baseline_detail: str = ""
    s_minimum: int | None = None

    @property
    def awg3_supported(self) -> bool:
        """AWG 3 доступен, только если принят ключ header protection.

        Именно он определяет версию протокола: остальные параметры AWG 3
        client-side и без него смысла не имеют.
        """
        return any(
            r.accepted and r.key.uapi == "header_protection_key" for r in self.results
        )

    @property
    def h_format(self) -> str:
        """Как демон принимает H1-H4 — попадает в отчёт отдельной строкой."""
        for result in self.results:
            if result.key.uapi == "h1-h4":
                return result.detail
        return "не проверялось"

    @property
    def rejected(self) -> tuple[ProbeResult, ...]:
        return tuple(r for r in self.results if not r.accepted)


def probe_uapi_keys(binary_log_level: str = "error") -> ProbeReport:
    """Поднимает временный интерфейс и проверяет сомнительные ключи.

    Интерфейс гарантированно убирается — даже при исключении.
    """
    backend = GoBackend(iface=PROBE_IFACE, log_level=binary_log_level)
    backend.check_binary()
    kernel_loaded = backend.kernel_module_loaded()

    results: list[ProbeResult] = []
    baseline_ok = True
    baseline_detail = "Jc/Jmin/Jmax и S1-S4 выставлены"

    try:
        backend.start()

        # Сначала базовый набор AWG 2.0 — иначе header protection отвергнется
        # по причине, не связанной с именем ключа.
        try:
            backend.apply(_BASELINE)
            logger.info("Базовый набор применён: %s", dict(_BASELINE))
        except (BackendError, UAPIError) as exc:
            baseline_ok = False
            baseline_detail = f"базовый набор не применился: {exc}"
            logger.error(baseline_detail)

        s_result, s_minimum = _probe_s_minimum(backend)
        results.append(s_result)

        # Дальше проверяем на заведомо рабочем S, иначе отказ header protection
        # утащит за собой и остальные ключи AWG 3.
        if s_minimum is not None:
            backend.apply([(f"s{n}", str(max(s_minimum, 32))) for n in range(1, 5)])

        results.append(_probe_h_format(backend))

        for key in AWG3_KEYS:
            if key.uapi == "header_protection_key":
                results.append(_probe_header_key(backend, key))
            else:
                results.append(_probe_one(backend, key))
    finally:
        try:
            backend.stop()
        except BackendError as exc:
            logger.warning("Не удалось убрать пробный интерфейс: %s", exc)

    return ProbeReport(
        results=tuple(results),
        kernel_module_loaded=kernel_loaded,
        baseline_applied=baseline_ok,
        baseline_detail=baseline_detail,
        s_minimum=s_minimum,
    )


_S_CANDIDATES = (8, 10, 12, 14, 16, 20, 24, 32, 48, 64)

_S_PSEUDO_KEY = UAPIKey(
    uapi="s-минимум", conf="S1-S4", scope=Scope.DEVICE, confidence=Confidence.ASSUMED,
    awg_version="3.0", note="минимальное S1-S4, при котором принимается header protection",
)


def _probe_s_minimum(backend: GoBackend) -> tuple[ProbeResult, int | None]:
    """Ищет минимальное S1-S4, при котором демон принимает header protection.

    README обещает 8, но это значение не подтверждалось экспериментом: при
    S3=10 ключ отвергается, при S3=16 проходит. Перебираем снизу вверх и
    возвращаем первое сработавшее — оно и станет полом для генератора.
    """
    raw = secrets.token_bytes(32).hex()
    for candidate in _S_CANDIDATES:
        pairs = [(f"s{n}", str(candidate)) for n in range(1, 5)]
        if _try_set(backend, "", "", pairs=pairs) is not None:
            continue
        if _try_set(backend, "header_protection_key", raw) is None:
            return (
                ProbeResult(_S_PSEUDO_KEY, True,
                            f"header protection принят при S1-S4 = {candidate}"),
                candidate,
            )
    return (
        ProbeResult(_S_PSEUDO_KEY, False,
                    f"не принят ни при одном S до {_S_CANDIDATES[-1]}"),
        None,
    )


_H_PSEUDO_KEY = UAPIKey(
    uapi="h1-h4", conf="H1-H4", scope=Scope.DEVICE, confidence=Confidence.ASSUMED,
    awg_version="2.0", note="форма значения: диапазон или одиночное",
)


def _probe_h_format(backend: GoBackend) -> ProbeResult:
    """Выясняет, в какой форме демон принимает H1-H4."""
    attempts: list[str] = []
    for label, values in _H_FORMATS:
        reason = _try_set(backend, "", "", pairs=list(values.items()))
        if reason is None:
            return ProbeResult(_H_PSEUDO_KEY, True, f"принимаются как {label}")
        attempts.append(f"{label}: {reason}")
    return ProbeResult(_H_PSEUDO_KEY, False, "отвергнуты в обеих формах — " + "; ".join(attempts))


def _try_set(
    backend: GoBackend,
    uapi_key: str,
    value: str,
    pairs: list[tuple[str, str]] | None = None,
) -> str | None:
    """Пробует применить пару или набор. None — принято, иначе причина."""
    payload = pairs if pairs is not None else [(uapi_key, value)]
    try:
        backend.apply(payload)
    except UAPICommandError as exc:
        return f"errno={exc.errno}"
    except BackendError as exc:
        return f"backend: {exc}"
    except UAPIError as exc:
        return f"UAPI: {exc}"
    return None


def _probe_one(backend: GoBackend, key: UAPIKey) -> ProbeResult:
    value = _PROBE_VALUES.get(key.uapi)
    if value is None:
        return ProbeResult(key, False, "нет пробного значения — ключ не проверялся")
    reason = _try_set(backend, key.uapi, value)
    return ProbeResult(key, reason is None, "принят" if reason is None else f"отвергнут, {reason}")


def _probe_header_key(backend: GoBackend, key: UAPIKey) -> ProbeResult:
    """Перебирает форматы значения — имя ключа и формат тут неразделимы.

    UAPI на неизвестное ИМЯ и на негодное ЗНАЧЕНИЕ отвечает одинаково (EINVAL),
    поэтому единственный способ их различить — перебрать правдоподобные форматы.
    """
    attempts: list[str] = []
    for label, value in _hpk_candidates():
        reason = _try_set(backend, key.uapi, value)
        if reason is None:
            return ProbeResult(key, True, f"принят как {label}")
        attempts.append(f"{label}: {reason}")
    return ProbeResult(key, False, "отвергнут во всех форматах — " + "; ".join(attempts))


def format_report(report: ProbeReport) -> str:
    """Человекочитаемый отчёт для CLI."""
    lines: list[str] = ["Проверка UAPI-ключей AWG 3:", ""]
    if report.baseline_applied:
        lines.append(f"  базовый набор: {report.baseline_detail}")
    else:
        lines.append(f"  ВНИМАНИЕ: {report.baseline_detail}")
        lines.append("  результаты ниже недостоверны — проверь, что бинарь умеет AWG 2.0")
    lines.append("")
    for result in report.results:
        lines.append(f"  {result.symbol} {result.key.uapi:<26} {result.detail}")

    lines.append("")
    if report.s_minimum is not None:
        lines.append(f"  Минимум S1-S4 для header protection: {report.s_minimum}")
        if report.s_minimum > 8:
            lines.append(f"  {'':2}README обещает 8 — фактическое требование выше.")
        lines.append("")

    if report.awg3_supported:
        lines.append("  AWG 3 поддерживается собранным бинарём.")
    else:
        accepted_others = sum(1 for r in report.results if r.accepted)
        if accepted_others:
            lines.append(
                f"  AWG 3 частично: принято {accepted_others} из "
                f"{len(report.results)}, но не header protection."
            )
            lines.append(
                "  Раз остальные ключи AWG 3 приняты, имя почти наверняка верное — "
                "не подходит формат значения либо не выполнено предусловие."
            )
            lines.append(
                "  Следующий шаг: grep -n 'header_protection' в device/uapi.go "
                "собранных исходников."
            )
        else:
            lines.append(
                "  AWG 3 недоступен: не принят ни один ключ. "
                "Похоже, бинарь собран без поддержки AWG 3."
            )

    if report.kernel_module_loaded:
        lines.append("")
        lines.append(
            f"  Замечание: загружен kernel-модуль amneziawg (AWG 2.0). "
            f"Это штатно, мы его не трогаем. Но awg-quick при нём поднимет "
            f"kernel-интерфейс, поэтому AWG3 им не пользуется."
        )

    lines.append("")
    lines.append(f"  Префикс AWG3: {paths.PREFIX}")
    return "\n".join(lines)
