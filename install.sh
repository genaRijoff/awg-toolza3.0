#!/usr/bin/env bash
#
# AWG3 — установщик менеджера AmneziaWG 3.0 (backend: amneziawg-go).
#
# Ставится РЯДОМ с AWG 2.0 (awg2.sh / AWG Toolza) и не ломает его:
#   * собственный префикс /opt/awg3 — деинсталлятор AWG 2.0 делает
#     `apt-get remove amneziawg-tools`, поэтому системные бинари не трогаем;
#   * собственный /etc/awg3 — AWG 2.0 при удалении делает `rm -rf /etc/amnezia`;
#   * таблица маршрутизации 210 — по 200 AWG 2.0 делает безусловный flush;
#   * правила iptables только с меткой awg3, удаление адресное.
#
#   sudo bash install.sh                 интерактивное меню
#   sudo bash install.sh --install       установка без вопросов
#   sudo bash install.sh --probe         проверить имена UAPI-ключей AWG 3
#   sudo bash install.sh --test          самотест моделей (root не нужен)
#   sudo bash install.sh --update        пересобрать amneziawg-go, конфиги сохранить
#   sudo bash install.sh --uninstall     удалить, конфиги СОХРАНИТЬ
#   sudo bash install.sh --uninstall --purge   удалить вместе с /etc/awg3
#   sudo bash install.sh --dry-run       показать план и выйти
#
# Библиотечный режим для тестов чистых функций без root:
#   AWG3_INSTALL_LIB=1 source install.sh

set -euo pipefail

# ── оформление ──────────────────────────────────────────────────────
if [[ -t 1 ]]; then
	R=$'\033[0;31m'; G=$'\033[0;32m'; Y=$'\033[1;33m'
	C=$'\033[0;36m'; W=$'\033[1;37m'; D=$'\033[0;90m'; N=$'\033[0m'
else
	R=''; G=''; Y=''; C=''; W=''; D=''; N=''
fi

ok()   { echo -e "${G}  √ $*${N}"; }
err()  { echo -e "${R}  × $*${N}" >&2; }
warn() { echo -e "${Y}  ▲ $*${N}"; }
info() { echo -e "${C}  → $*${N}"; }
step() { echo -e "\n${W}$*${N}\n${D}────────────────────────────────────────────────${N}"; }

# ── константы (совпадают с awg3/paths.py) ───────────────────────────
PREFIX="${AWG3_PREFIX:-/opt/awg3}"
BIN_DIR="${PREFIX}/bin"
LIB_DIR="${PREFIX}/lib"
VENV_DIR="${PREFIX}/venv"
CONF_DIR="${AWG3_CONF_DIR:-/etc/awg3}"
LOG_FILE="${AWG3_LOG:-/var/log/awg3.log}"
ROUTE_TABLE="${AWG3_ROUTE_TABLE:-210}"
RESERVED_ENV="${CONF_DIR}/reserved.env"

GO_REPO="https://github.com/amnezia-vpn/amneziawg-go"
# Репозиторий самой тулзы. Нужен для однокомандной установки, когда скрипт
# скачан отдельно и пакета awg3/ рядом нет.
AWG3_REPO="${AWG3_REPO:-https://github.com/pumbaX/awg3}"
AWG3_BRANCH="${AWG3_BRANCH:-main}"
# Папка проекта на сервере. Скачивается один раз и дальше обновляется
# на месте: и установщик, и --update работают с ней, а не с тем, что
# случайно оказалось рядом со скриптом.
SRC_DIR="${PREFIX}/src"
GO_MIN="1.21"      # минимум, при котором Go умеет докачивать toolchain
GO_REQUIRED=""     # заполняется из go.mod в fetch_sources
BUILD_DIR="/tmp/awg3-build"
UNIT_PATH="/etc/systemd/system/awg3.service"
PROBE_WRAPPER="/usr/local/bin/awg3-probe"
CLI_WRAPPER="/usr/local/bin/awg3"

IPTABLES_TAG="awg3"

# Пути AWG 2.0 — ТОЛЬКО ДЛЯ ЧТЕНИЯ.
AWG2_CONF="/etc/amnezia/amneziawg/awg0.conf"

ACTION="menu"
PURGE="false"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ════════════════════════════════════════════════════════════════════
#  Чистые функции — без root, без побочных эффектов, тестируемые
# ════════════════════════════════════════════════════════════════════

# version_ge A B -> 0, если версия A >= B. Сравнение почленное.
version_ge() {
	local a="$1" b="$2"
	[[ "$a" == "$b" ]] && return 0
	local -a pa pb
	IFS='.' read -ra pa <<<"$a"
	IFS='.' read -ra pb <<<"$b"
	local i
	for ((i = 0; i < ${#pb[@]}; i++)); do
		local x="${pa[i]:-0}" y="${pb[i]:-0}"
		((10#${x:-0} > 10#${y:-0})) && return 0
		((10#${x:-0} < 10#${y:-0})) && return 1
	done
	return 0
}

# validate_port PORT -> 0, если пригоден. Отвергает нечисловое, вне диапазона
# и привилегированные порты.
validate_port() {
	local port="${1:-}"
	case "$port" in
		'' | *[!0-9]*) err "порт должен быть числом: '${port}'"; return 1 ;;
	esac
	if ((port < 1024 || port > 65535)); then
		err "порт ${port} вне 1024..65535"
		return 1
	fi
	return 0
}

# awg2_field FILE KEY -> значение из конфига AWG 2.0 (пусто, если нет).
awg2_field() {
	local file="$1" key="$2"
	[[ -r "$file" ]] || return 0
	awk -F'=' -v k="$key" '
		$0 ~ "^[[:space:]]*"k"[[:space:]]*=" {
			gsub(/^[[:space:]]+|[[:space:]]+$/, "", $2); print $2; exit
		}' "$file"
}

# cidr_network CIDR -> сеть /24 в виде a.b.c.0 (пусто при мусоре).
cidr_network() {
	local cidr="${1:-}" ip
	ip="${cidr%%/*}"
	[[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.[0-9]{1,3}$ ]] || return 0
	echo "${BASH_REMATCH[1]}.${BASH_REMATCH[2]}.${BASH_REMATCH[3]}.0"
}

# subnets_conflict A B -> 0, если сети /24 совпадают.
subnets_conflict() {
	[[ -n "${1:-}" && "$1" == "${2:-}" ]]
}

# pick_subnet TAKEN -> свободная /24 из нашего пула.
pick_subnet() {
	local taken="${1:-}" candidate
	for candidate in 10.200.0.0 10.201.0.0 10.202.0.0 10.203.0.0; do
		subnets_conflict "$candidate" "$taken" || { echo "$candidate"; return 0; }
	done
	echo "10.209.0.0"
}

# port_in_use PORT -> 0, если UDP-порт занят (по выводу ss).
port_in_use() {
	local port="$1"
	command -v ss >/dev/null 2>&1 || return 1
	ss -lunH 2>/dev/null | awk '{print $5}' | grep -qE "[:.]${port}$"
}

# pick_port EXCLUDE -> случайный свободный UDP-порт, не равный EXCLUDE.
pick_port() {
	local exclude="${1:-}" port attempt
	for attempt in {1..50}; do
		port=$((RANDOM % 35000 + 30001))
		[[ "$port" == "$exclude" ]] && continue
		port_in_use "$port" && continue
		echo "$port"
		return 0
	done
	err "не нашёл свободный UDP-порт за 50 попыток"
	return 1
}

# gomod_go_version FILE -> минимальная версия Go из директивы `go` в go.mod.
gomod_go_version() {
	local file="${1:-}"
	[[ -r "$file" ]] || return 0
	awk '/^[[:space:]]*go[[:space:]]+[0-9]/ { print $2; exit }' "$file"
}

# check_go_toolchain REQUIRED CURRENT -> 0, если сборка возможна.
# Go >= 1.21 сам докачивает нужный toolchain, но только при GOTOOLCHAIN != local
# и наличии доступа к proxy.golang.org. Молча полагаться на это нельзя.
check_go_toolchain() {
	local required="${1:-}" current="${2:-}"
	[[ -n "$required" ]] || return 0
	if version_ge "$current" "$required"; then
		ok "Go ${current} покрывает требование go.mod (${required})"
		return 0
	fi
	local mode="${GOTOOLCHAIN:-auto}"
	if [[ "$mode" == "local" ]]; then
		err "go.mod требует Go >= ${required}, установлен ${current}, при этом GOTOOLCHAIN=local"
		err "варианты: export GOTOOLCHAIN=auto  либо поставить свежий Go вручную"
		return 1
	fi
	warn "go.mod требует Go >= ${required}, установлен ${current}"
	info "Go докачает toolchain сам (GOTOOLCHAIN=${mode}) — нужен доступ к proxy.golang.org"
	return 0
}

# rule_to_delete LINE -> та же строка с -A заменённым на -D и снятыми кавычками.
# Кавычки вокруг комментария мешают разбить строку на аргументы, а внутри
# комментария пробелов нет, поэтому убрать их безопасно.
rule_to_delete() {
	local line="${1:-}"
	[[ "$line" == -A* ]] || return 1
	local rule="${line/-A/-D}"
	printf '%s' "${rule//\"/}"
}

# safe_rm_tree PATH — удаление каталога с проверками.
# Пути берутся из переменных окружения (AWG3_PREFIX, AWG3_CONF_DIR), и пустое
# или короткое значение превратило бы rm -rf в катастрофу. Отвергаем всё, что
# не является абсолютным путём глубиной >= 2 внутри разрешённых префиксов.
safe_rm_tree() {
	local target="${1:-}"
	if [[ -z "$target" ]]; then
		err "safe_rm_tree: пустой путь"; return 1
	fi
	if [[ "$target" != /* ]]; then
		err "safe_rm_tree: путь не абсолютный: '${target}'"; return 1
	fi
	if [[ "$target" == *..* ]]; then
		err "safe_rm_tree: путь содержит '..': '${target}'"; return 1
	fi
	local clean="${target%/}"
	local depth; depth="$(awk -F/ '{print NF - 1}' <<<"$clean")"
	if ((depth < 2)); then
		err "safe_rm_tree: путь слишком короткий, нужно >= 2 сегментов: '${target}'"
		return 1
	fi
	case "$clean" in
		/opt/awg3 | /opt/awg3/* | /etc/awg3 | /etc/awg3/*) : ;;
		*)
			err "safe_rm_tree: путь вне разрешённых префиксов: '${target}'"
			return 1
			;;
	esac
	rm -rf -- "$clean"
}

# ════════════════════════════════════════════════════════════════════
#  Действия (требуют root)
# ════════════════════════════════════════════════════════════════════

require_root() {
	[[ "$(id -u)" -eq 0 ]] || { err "нужен root: sudo bash install.sh"; exit 1; }
}

detect_os() {
	local id ver
	[[ -r /etc/os-release ]] || { warn "нет /etc/os-release — продолжаю вслепую"; return 0; }
	id="$(. /etc/os-release && echo "${ID:-}")"
	ver="$(. /etc/os-release && echo "${VERSION_ID:-}")"
	case "$id" in
		ubuntu) version_ge "$ver" "22.04" || warn "Ubuntu ${ver}: проверялось на 24.04+" ;;
		debian) version_ge "$ver" "12"    || warn "Debian ${ver}: проверялось на 12+" ;;
		*)      warn "ОС '${id}' не проверялась; ожидается Ubuntu 24.04+ / Debian 12+" ;;
	esac
	ok "ОС: ${id} ${ver}"
}

# Читает конфиг AWG 2.0 и резервирует непересекающиеся порт и подсеть.
preflight() {
	step "Preflight: сосуществование с AWG 2.0"

	# Повторный запуск не должен менять порт: клиенты уже раздали конфиги
	# с прежним значением, и смена порта тихо оборвала бы их всех.
	if [[ -r "$RESERVED_ENV" ]]; then
		local prev_port prev_subnet
		prev_port="$(awk -F= '/^AWG3_PORT=/{print $2}' "$RESERVED_ENV")"
		prev_subnet="$(awk -F= '/^AWG3_SUBNET=/{print $2}' "$RESERVED_ENV")"
		ok "переустановка: сохраняю прежний резерв"
		info "порт ${prev_port}, подсеть ${prev_subnet}"
		info "сбросить резерв: rm ${RESERVED_ENV}"
		return 0
	fi

	local awg2_port="" awg2_addr="" awg2_net=""
	if [[ -r "$AWG2_CONF" ]]; then
		awg2_port="$(awg2_field "$AWG2_CONF" ListenPort)"
		awg2_addr="$(awg2_field "$AWG2_CONF" Address)"
		awg2_net="$(cidr_network "$awg2_addr")"
		ok "AWG 2.0 найден: ${AWG2_CONF}"
		[[ -n "$awg2_port" ]] && info "его порт   : ${awg2_port} (не займём)"
		[[ -n "$awg2_net"  ]] && info "его подсеть: ${awg2_net}/24 (обойдём)"
	else
		info "AWG 2.0 не найден — ставимся на чистый сервер"
	fi

	if [[ -d /sys/module/amneziawg ]]; then
		warn "загружен kernel-модуль amneziawg — это штатно, мы его не трогаем"
		info "именно поэтому AWG3 не пользуется awg-quick: при модуле он поднял бы"
		info "kernel-интерфейс вместо нашего userspace-демона"
	fi

	local our_port our_net
	our_port="$(pick_port "$awg2_port")"
	our_net="$(pick_subnet "$awg2_net")"
	validate_port "$our_port" || exit 1

	mkdir -p "$CONF_DIR"; chmod 700 "$CONF_DIR"
	cat >"$RESERVED_ENV" <<EOF
# Зарезервировано установщиком AWG3 $(date -Is).
# Проверено на непересечение с AWG 2.0 на момент установки.
AWG3_IFACE=awg1
AWG3_PORT=${our_port}
AWG3_SUBNET=${our_net}/24
AWG3_ADDRESS=${our_net%.0}.1/24
AWG3_ROUTE_TABLE=${ROUTE_TABLE}
AWG2_PORT_SEEN=${awg2_port:-none}
AWG2_SUBNET_SEEN=${awg2_net:-none}
EOF
	chmod 600 "$RESERVED_ENV"
	ok "зарезервировано: порт ${our_port}, подсеть ${our_net}/24, таблица ${ROUTE_TABLE}"
	info "записано в ${RESERVED_ENV}"
}

# Список утилит, без которых сборка не поедет. Держим отдельно от apt-пакетов:
# проверяем наличие команд, а не то, что пакет числится установленным.
REQUIRED_TOOLS=(git make curl python3)

# missing_tools -> список отсутствующих команд через пробел.
missing_tools() {
	local tool missing=()
	for tool in "$@"; do
		command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
	done
	printf '%s' "${missing[*]:-}"
}

# Догоняет недостающие утилиты. Вызывается и при установке, и при обновлении:
# на свежем сервере `--update` раньше падал на отсутствующем make уже после
# скачивания Go, оставляя половину установки.
ensure_tools() {
	local missing
	missing="$(missing_tools "${REQUIRED_TOOLS[@]}")"
	if [[ -z "$missing" ]]; then
		return 0
	fi
	warn "не хватает утилит: ${missing}"
	if ! command -v apt-get >/dev/null 2>&1; then
		err "apt-get недоступен — поставь вручную: ${missing}"
		exit 1
	fi
	install_deps
	missing="$(missing_tools "${REQUIRED_TOOLS[@]}")"
	if [[ -n "$missing" ]]; then
		err "после установки пакетов всё ещё нет: ${missing}"
		exit 1
	fi
	ok "недостающие утилиты доставлены"
}

install_deps() {
	step "Зависимости"
	export DEBIAN_FRONTEND=noninteractive
	apt-get update -qq
	# --no-install-recommends: иначе python3-pip тянет build-essential, gcc,
	# g++, binutils, python3-dev — семьдесят пакетов вместо десяти. У
	# cryptography на amd64/arm64 есть готовые wheel, компилятор ей не нужен.
	apt-get install -y -qq --no-install-recommends \
		git make curl ca-certificates iproute2 iptables \
		python3 python3-venv python3-pip golang-go
	ok "базовые пакеты (включая golang-go из репозитория)"
}

# Ставит Go нужной версии: системный, если свежий, иначе официальный тарбол
# с проверкой контрольной суммы (fail-closed — без суммы не ставим).
# Печатает "filename sha256" для свежего стабильного Go под указанную арх.
# Разбор питоном, а не грепом: формат JSON у go.dev может быть как
# отформатированным, так и сжатым, и грep по нему — источник молчаливых сбоев.
fetch_go_release() {
	python3 - "$1" <<'PY' 2>/dev/null
import json, sys, urllib.request

arch = sys.argv[1]
try:
    with urllib.request.urlopen("https://go.dev/dl/?mode=json", timeout=30) as resp:
        releases = json.load(resp)
except Exception as exc:
    print(f"ошибка загрузки списка релизов: {exc}", file=sys.stderr)
    sys.exit(2)

for release in releases:
    if not release.get("stable"):
        continue
    for item in release.get("files", []):
        if (item.get("os") == "linux" and item.get("arch") == arch
                and item.get("kind") == "archive"):
            name, digest = item.get("filename"), item.get("sha256")
            if not name or not digest:
                continue
            print(name, digest)
            sys.exit(0)
sys.exit(1)
PY
}

# Ставит Go нужной версии: системный, если свежий, иначе официальный тарбол
# с обязательной проверкой sha256 (fail-closed).
# Запасной путь: если официальный тарбол недоступен, полагаемся на встроенный
# механизм Go (>= 1.21 сам докачивает toolchain). Работает только при
# GOTOOLCHAIN != local и доступе к proxy.golang.org — оба условия проверяем.
_fallback_toolchain() {
	local required="$1" sys_ver="$2"
	if [[ -z "$sys_ver" ]]; then
		err "Go не установлен и официальный тарбол недоступен"
		err "поставь вручную: apt-get install -y golang-go"
		return 1
	fi
	if ! version_ge "$sys_ver" "$GO_MIN"; then
		err "Go ${sys_ver} не умеет докачивать toolchain (нужен >= ${GO_MIN})"
		return 1
	fi
	if [[ "${GOTOOLCHAIN:-auto}" == "local" ]]; then
		err "GOTOOLCHAIN=local запрещает докачку, а Go ${sys_ver} < ${required}"
		err "сними ограничение: export GOTOOLCHAIN=auto"
		return 1
	fi
	warn "откат: собираю системным Go ${sys_ver} с автодокачкой toolchain"
	info "нужен доступ к proxy.golang.org"
	GO_BIN="$(command -v go)"
	return 0
}

# ensure_go [REQUIRED] — обеспечивает toolchain нужной версии.
# REQUIRED берётся из go.mod исходников, поэтому вызывать после fetch_sources.
ensure_go() {
	local required="${1:-$GO_MIN}"
	step "Go toolchain (нужен >= ${required})"

	local sys_ver=""
	if command -v go >/dev/null 2>&1; then
		sys_ver="$(go version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
		if [[ -n "$sys_ver" ]] && version_ge "$sys_ver" "$required"; then
			ok "системный Go ${sys_ver} подходит"
			GO_BIN="$(command -v go)"
			return 0
		fi
		info "системный Go ${sys_ver} младше ${required} — ставлю официальный"
	else
		warn "Go в системе не найден"
	fi

	# Уже собранный нами Go мог остаться от прошлой установки.
	if [[ -x "${PREFIX}/go/bin/go" ]]; then
		local own_ver
		own_ver="$("${PREFIX}/go/bin/go" version 2>/dev/null | awk '{print $3}' | sed 's/^go//')"
		if [[ -n "$own_ver" ]] && version_ge "$own_ver" "$required"; then
			ok "собственный Go ${own_ver} в ${PREFIX}/go подходит"
			GO_BIN="${PREFIX}/go/bin/go"
			return 0
		fi
	fi

	local arch
	case "$(uname -m)" in
		x86_64)  arch="amd64" ;;
		aarch64) arch="arm64" ;;
		*) err "архитектура $(uname -m) не поддерживается"; exit 1 ;;
	esac

	info "тяну официальный Go для linux-${arch}"
	local release rc=0
	release="$(fetch_go_release "$arch")" || rc=$?
	if ((rc != 0)) || [[ -z "$release" ]]; then
		warn "не удалось получить релиз Go с go.dev (код ${rc})"
		_fallback_toolchain "$required" "$sys_ver"
		return $?
	fi

	local filename digest
	filename="$(awk '{print $1}' <<<"$release")"
	digest="$(awk '{print $2}' <<<"$release")"
	# Fail-closed: без контрольной суммы установка не продолжается.
	if [[ -z "$filename" || -z "$digest" ]]; then
		err "в ответе go.dev нет имени файла или sha256 — отказываюсь ставить непроверенное"
		exit 1
	fi
	info "релиз: ${filename}"

	local tarball="/tmp/${filename}"
	if ! curl -fsSL --retry 3 -o "$tarball" "https://go.dev/dl/${filename}"; then
		warn "не скачался https://go.dev/dl/${filename}"
		_fallback_toolchain "$required" "$sys_ver"
		return $?
	fi

	local actual
	actual="$(sha256sum "$tarball" | awk '{print $1}')"
	if [[ "$actual" != "$digest" ]]; then
		rm -f "$tarball"
		err "sha256 не совпал для ${filename}"
		err "  ожидался: ${digest}"
		err "  получен : ${actual}"
		exit 1
	fi
	ok "sha256 проверен"

	safe_rm_tree "${PREFIX}/go" || true
	mkdir -p "$PREFIX"
	tar -C "$PREFIX" -xzf "$tarball"
	rm -f "$tarball"
	GO_BIN="${PREFIX}/go/bin/go"
	[[ -x "$GO_BIN" ]] || { err "после распаковки нет ${GO_BIN}"; exit 1; }
	ok "Go установлен в ${PREFIX}/go (изолированно, системный не тронут)"
}

# Клонирует исходники и определяет требуемую версию Go.
# Экспортирует GO_REQUIRED для ensure_go.
fetch_sources() {
	step "Исходники amneziawg-go"
	ensure_tools
	if [[ "$BUILD_DIR" == /tmp/* ]]; then rm -rf -- "$BUILD_DIR"; fi
	git clone --depth 1 "$GO_REPO" "$BUILD_DIR" >/dev/null 2>&1 ||
		{ err "git clone не удался: ${GO_REPO}"; exit 1; }

	# Проверяем поддержку AWG 3 до сборки, а не после.
	if grep -rqi "header_protection\|HeaderProtectionKey" "${BUILD_DIR}/device/" 2>/dev/null; then
		ok "в исходниках найдена поддержка AWG 3 (header protection)"
	else
		warn "в device/ нет упоминаний header protection"
		warn "собранный бинарь будет уметь только AWG 2.0 — probe это покажет"
	fi

	GO_REQUIRED="$(gomod_go_version "${BUILD_DIR}/go.mod")"
	if [[ -n "$GO_REQUIRED" ]]; then
		info "go.mod требует Go >= ${GO_REQUIRED}"
	else
		GO_REQUIRED="$GO_MIN"
		warn "версия в go.mod не найдена — беру минимальную ${GO_MIN}"
	fi
}

build_backend() {
	step "Сборка amneziawg-go"
	[[ -d "$BUILD_DIR" ]] || { err "нет исходников — сначала fetch_sources"; exit 1; }
	command -v make >/dev/null 2>&1 || {
		err "make не найден — сборка невозможна"
		err "поставь: apt-get install -y make"
		exit 1
	}

	( cd "$BUILD_DIR" && PATH="$(dirname "$GO_BIN"):$PATH" make >/dev/null ) ||
		{ err "сборка не удалась; повтори вручную: cd ${BUILD_DIR} && make"; exit 1; }

	mkdir -p "$BIN_DIR"
	install -m 0755 "${BUILD_DIR}/amneziawg-go" "${BIN_DIR}/amneziawg-go"
	# BUILD_DIR — константа под /tmp, но проверяем всё равно: правка константы
	# на пустую строку не должна превращать уборку в снос корня.
	if [[ "$BUILD_DIR" == /tmp/* ]]; then rm -rf -- "$BUILD_DIR"; fi
	ok "amneziawg-go -> ${BIN_DIR}/amneziawg-go"
}

# Раскладывает папку проекта в ${PREFIX}/src.
#
# Три источника, по убыванию приоритета:
#   1. src/ рядом со скриптом  — установка из клона репозитория;
#   2. уже скачанная ${SRC_DIR} — обновляем через git pull;
#   3. клонируем репозиторий    — однокомандная установка, когда curl
#      принёс только install.sh.
sync_sources() {
	step "Папка проекта"

	if [[ -d "${SCRIPT_DIR}/src/awg3" ]]; then
		mkdir -p "$PREFIX"
		if [[ "$(cd "${SCRIPT_DIR}/src" && pwd)" == "$SRC_DIR" ]]; then
			ok "работаю прямо в ${SRC_DIR}"
			return 0
		fi
		safe_rm_tree "$SRC_DIR" 2>/dev/null || true
		cp -r "${SCRIPT_DIR}/src" "$SRC_DIR"
		ok "скопировано из ${SCRIPT_DIR}/src -> ${SRC_DIR}"
		return 0
	fi

	if [[ -d "${SRC_DIR}/.git" ]]; then
		info "обновляю ${SRC_DIR}"
		if ( cd "$SRC_DIR" && git fetch --depth 1 origin "$AWG3_BRANCH" >/dev/null 2>&1 &&
			git reset --hard "origin/${AWG3_BRANCH}" >/dev/null 2>&1 ); then
			ok "обновлено до свежего ${AWG3_BRANCH}"
			return 0
		fi
		warn "git pull не удался — склонирую заново"
		safe_rm_tree "$SRC_DIR" 2>/dev/null || true
	fi

	info "тяну ${AWG3_REPO} (${AWG3_BRANCH})"
	local clone="/tmp/awg3-repo"
	if [[ "$clone" == /tmp/* ]]; then rm -rf -- "$clone"; fi
	git clone --depth 1 --branch "$AWG3_BRANCH" "$AWG3_REPO" "$clone" >/dev/null 2>&1 ||
		{ err "не удалось склонировать ${AWG3_REPO}"; exit 1; }
	[[ -d "${clone}/src/awg3" ]] ||
		{ err "в репозитории нет каталога src/awg3/"; exit 1; }

	mkdir -p "$PREFIX"
	safe_rm_tree "$SRC_DIR" 2>/dev/null || true
	cp -r "${clone}/src" "$SRC_DIR"
	cp -r "${clone}/.git" "${SRC_DIR}/.git" 2>/dev/null || true
	if [[ "$clone" == /tmp/* ]]; then rm -rf -- "$clone"; fi
	ok "папка проекта в ${SRC_DIR}"
}

install_python() {
	step "Python-ядро"
	[[ -d "${SRC_DIR}/awg3" ]] ||
		{ err "нет ${SRC_DIR}/awg3 — сначала sync_sources"; exit 1; }

	python3 -m venv "$VENV_DIR"
	"${VENV_DIR}/bin/pip" install --quiet --upgrade pip
	"${VENV_DIR}/bin/pip" install --quiet cryptography

	mkdir -p "$LIB_DIR"
	safe_rm_tree "${LIB_DIR}/awg3" 2>/dev/null || true
	cp -r "${SRC_DIR}/awg3" "${LIB_DIR}/awg3"
	find "${LIB_DIR}/awg3" -name '__pycache__' -type d -exec rm -rf {} + 2>/dev/null || true
	ok "пакет -> ${LIB_DIR}/awg3, venv -> ${VENV_DIR}"

	cat >"$PROBE_WRAPPER" <<EOF
#!/usr/bin/env bash
# Проверка имён UAPI-ключей AWG 3 на установленном бинаре.
exec env PYTHONPATH="${LIB_DIR}" "${VENV_DIR}/bin/python" -c '
from awg3.core.probe import probe_uapi_keys, format_report
print(format_report(probe_uapi_keys()))
' "\$@"
EOF
	chmod 0755 "$PROBE_WRAPPER"
	ok "команда probe -> ${PROBE_WRAPPER}"

	cat >"$CLI_WRAPPER" <<EOF
#!/usr/bin/env bash
# Интерактивное меню управления AWG3.
if [[ "\$(id -u)" -ne 0 ]]; then
	echo "Нужен root: sudo awg3" >&2
	exit 1
fi
exec env PYTHONPATH="${LIB_DIR}" "${VENV_DIR}/bin/python" -m awg3 "\$@"
EOF
	chmod 0755 "$CLI_WRAPPER"
	ok "меню -> ${CLI_WRAPPER}"

	touch "$LOG_FILE"; chmod 640 "$LOG_FILE"
}

install_units() {
	step "systemd"
	# Шаблонный юнит: %i — имя интерфейса. Поднимает ТОЛЬКО демон; применение
	# конфигурации через UAPI появится вместе с CLI. Поэтому enable не делаем.
	#
	# StartLimit* — чтобы демон с кривыми параметрами не уходил в цикл рестартов
	# и не забивал журнал.
	# Не шаблонный юнит и не голый демон: awg3 --up делает полный подъём —
	# демон, адрес, конфигурация через UAPI, правила сети. Иначе после ребута
	# интерфейс встаёт без параметров и клиенты не подключаются.
	cat >"$UNIT_PATH" <<EOF
[Unit]
Description=AWG3 — AmneziaWG 3.0 tunnel
After=network-online.target
Wants=network-online.target
StartLimitIntervalSec=600
StartLimitBurst=5

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=${CLI_WRAPPER} --up
ExecStop=${CLI_WRAPPER} --down
TimeoutStartSec=120
Restart=on-failure
RestartSec=15

[Install]
WantedBy=multi-user.target
EOF
	systemctl daemon-reload
	ok "юнит awg3.service установлен (включится при первом запуске туннеля)"
}

self_test() {
	step "Самотест моделей"
	local runner="python3"
	[[ -x "${VENV_DIR}/bin/python" ]] && runner="${VENV_DIR}/bin/python"
	local tests_dir="$SRC_DIR"
	if [[ -f "${tests_dir}/test_models.py" ]]; then
		( cd "$tests_dir" && "$runner" test_models.py ) ||
			{ err "самотест провален — не ставь это в бой"; return 1; }
	else
		warn "test_models.py не найден — пропускаю"
	fi
}

run_probe() {
	step "Probe: имена UAPI-ключей AWG 3"
	[[ -x "${BIN_DIR}/amneziawg-go" ]] ||
		{ err "amneziawg-go не установлен — сначала --install"; return 1; }
	"$PROBE_WRAPPER"
}

# Снимает ТОЛЬКО правила с нашим тегом. Разбираем iptables-save и удаляем
# по одному — никаких -F, соседние правила AWG 2.0 и Warp не наши.
remove_awg3_iptables() {
	local removed=0 table line rule
	command -v iptables-save >/dev/null 2>&1 || { echo 0; return 0; }
	for table in filter nat; do
		while IFS= read -r line; do
			[[ "$line" == -A*"${IPTABLES_TAG}:"* ]] || continue
			rule="$(rule_to_delete "$line")" || continue
			# Словоделение здесь намеренное: rule — уже готовый набор аргументов.
			# shellcheck disable=SC2086
			if iptables -t "$table" $rule 2>/dev/null; then
				removed=$((removed + 1))
			fi
		done < <(iptables-save -t "$table" 2>/dev/null)
	done
	echo "$removed"
}

# Гасит интерфейсы AWG3, если остались поднятыми.
down_awg3_links() {
	local iface="awg1"
	[[ -r "$RESERVED_ENV" ]] &&
		iface="$(awk -F= '/^AWG3_IFACE=/{print $2}' "$RESERVED_ENV")"
	local link
	for link in "$iface" awg3probe; do
		[[ -n "$link" ]] || continue
		if ip link show dev "$link" >/dev/null 2>&1; then
			ip link delete dev "$link" 2>/dev/null && info "интерфейс ${link} погашен"
		fi
		rm -f "/var/run/amneziawg/${link}.sock"
	done
}

run_cli() {
	[[ -x "$CLI_WRAPPER" ]] || { err "AWG3 не установлен — сначала пункт 1"; return 1; }
	"$CLI_WRAPPER"
}

summary() {
	echo ""
	echo -e "${G}╔══════════════════════════════════════════════╗${N}"
	echo -e "${G}║          AWG3 — установка завершена          ║${N}"
	echo -e "${G}╚══════════════════════════════════════════════╝${N}"
	echo ""
	[[ -r "$RESERVED_ENV" ]] && sed 's/^/  /' "$RESERVED_ENV" | grep -v '^  #'
	echo ""
	echo -e "  ${W}Дальше:${N}"
	echo -e "    ${C}sudo awg3-probe${N}      проверить ключи AWG 3 на этом бинаре"
	echo ""
	echo -e "    ${C}sudo awg3${N}            меню: сервер, клиенты, конфиги"
	echo ""
	echo -e "  ${W}Что НЕ тронуто:${N} /etc/amnezia, awg0, таблица 200, правила AWG 2.0"
}

do_install() {
	require_root
	detect_os
	preflight
	install_deps
	sync_sources
	fetch_sources
	ensure_go "$GO_REQUIRED"
	build_backend
	install_python
	install_units
	self_test || true
	summary
}

do_update() {
	require_root
	step "Обновление"
	ensure_tools
	sync_sources
	fetch_sources
	ensure_go "$GO_REQUIRED"
	build_backend
	install_python
	# Юнит переустанавливаем всегда: его определение меняется между версиями,
	# а пропуск этого шага оставляет систему без автозапуска молча.
	install_units
	ok "бинарь, ядро и юнит обновлены; ${CONF_DIR} не тронут"
}

do_uninstall() {
	require_root
	step "Удаление AWG3"
	echo -e "  ${R}—${N} ${PREFIX} (бинари, venv, Go)"
	echo -e "  ${R}—${N} ${PROBE_WRAPPER}, ${CLI_WRAPPER}"
	echo -e "  ${R}—${N} ${UNIT_PATH}"
	if [[ "$PURGE" == "true" ]]; then
		echo -e "  ${R}—${N} ${CONF_DIR} ${R}(--purge)${N}"
	else
		echo -e "  ${G}+${N} ${CONF_DIR} сохраняется (снести: --uninstall --purge)"
	fi
	echo -e "  ${R}—${N} правила iptables с тегом ${IPTABLES_TAG}"
	echo -e "  ${R}—${N} интерфейсы AWG3 будут погашены"
	echo -e "  ${G}+${N} AWG 2.0 не затрагивается вообще"
	echo -e "  ${G}+${N} ${LOG_FILE} сохраняется — после аварии это единственный след"
	echo ""
	read -rp "  Подтверди удаление [yes/N]: " confirm
	[[ "$confirm" == "yes" ]] || { warn "отменено"; return 0; }

	systemctl list-units 'awg3*' --no-legend 2>/dev/null | awk '{print $1}' |
		while read -r unit; do systemctl disable --now "$unit" 2>/dev/null || true; done

	down_awg3_links
	local rules_removed; rules_removed="$(remove_awg3_iptables)"
	ok "снято правил iptables с тегом ${IPTABLES_TAG}: ${rules_removed}"
	rm -f "$UNIT_PATH"; systemctl daemon-reload 2>/dev/null || true
	safe_rm_tree "$PREFIX" || { err "префикс не удалён — проверь AWG3_PREFIX"; return 1; }
	rm -f "$PROBE_WRAPPER" "$CLI_WRAPPER"
	if [[ "$PURGE" == "true" ]]; then
		safe_rm_tree "$CONF_DIR" || err "конфиги не удалены — проверь AWG3_CONF_DIR"
	fi
	ok "удалено"
	info "правила без тега ${IPTABLES_TAG} не тронуты — они не наши"
}

do_dry_run() {
	step "План установки (ничего не выполняется)"
	cat <<EOF
  1. preflight     прочитать ${AWG2_CONF}, зарезервировать порт и подсеть
  2. deps          git make curl iproute2 python3 python3-venv
  3. src           папка проекта -> ${SRC_DIR}
  4. sources       клон ${GO_REPO}, чтение требуемой версии Go из go.mod
  5. go            системный Go нужной версии либо официальный тарбол с sha256
  6. build         make -> ${BIN_DIR}/amneziawg-go
  7. python        venv ${VENV_DIR} + cryptography, пакет в ${LIB_DIR}
  8. systemd       ${UNIT_PATH} (устанавливается, но не включается)
  9. selftest      test_models.py

  Не создаётся и не удаляется ничего вне: ${PREFIX}, ${CONF_DIR},
  ${UNIT_PATH}, ${PROBE_WRAPPER}, ${LOG_FILE}
EOF
}

usage() {
	cat <<EOF
AWG3 installer

  --install     установить
  --update      пересобрать бинарь и ядро, конфиги сохранить
  --uninstall   удалить (конфиги сохраняются)
  --purge       вместе с --uninstall: снести и ${CONF_DIR}
  --menu        открыть меню управления (то же, что команда awg3)
  --probe       проверить имена UAPI-ключей AWG 3
  --test        самотест моделей
  --dry-run     показать план и выйти
  --help        эта справка

Без аргументов — интерактивное меню.
EOF
}

show_menu() {
	while true; do
		echo ""
		echo -e "${W}╔══════════════════════════════════════════════╗${N}"
		echo -e "${W}║   AWG3 — AmneziaWG 3.0 (amneziawg-go)        ║${N}"
		echo -e "${W}╚══════════════════════════════════════════════╝${N}"
		if [[ -x "${BIN_DIR}/amneziawg-go" ]]; then
			echo -e "  Состояние : ${G}установлен${N}"
		else
			echo -e "  Состояние : ${D}не установлен${N}"
		fi
		[[ -r "$AWG2_CONF" ]] &&
			echo -e "  AWG 2.0   : ${C}обнаружен, не трогаем${N}" ||
			echo -e "  AWG 2.0   : ${D}не найден${N}"
		echo ""
		echo -e "  ${G}1${N}  Установить"
		echo -e "  ${G}2${N}  Управление (сервер, клиенты, конфиги)"
		echo -e "  ${G}3${N}  Probe — проверить ключи AWG 3"
		echo -e "  ${G}4${N}  Самотест"
		echo -e "  ${G}5${N}  Обновить"
		echo -e "  ${G}6${N}  План установки (dry-run)"
		echo -e "  ${R}7${N}  Удалить AWG3 с сервера"
		echo ""
		echo -e "  ${D}0${N}  Выход"
		echo ""
		local choice=""
		read -rp "  Выбор [0-7]: " choice || choice="0"
		case "$choice" in
			1) do_install ;;
			2) run_cli || true ;;
			3) run_probe || true ;;
			4) self_test || true ;;
			5) do_update ;;
			6) do_dry_run ;;
			7) do_uninstall ;;
			0) echo ""; info "выход"; return 0 ;;
			*) warn "нет такого пункта: '${choice}'" ;;
		esac
	done
}

parse_args() {
	while (($# > 0)); do
		case "$1" in
			--install)   ACTION="install" ;;
			--update)    ACTION="update" ;;
			--uninstall) ACTION="uninstall" ;;
			--purge)     PURGE="true" ;;
			--probe)     ACTION="probe" ;;
			--menu)      ACTION="cli" ;;
			--test)      ACTION="test" ;;
			--dry-run)   ACTION="dry-run" ;;
			-h | --help) ACTION="help" ;;
			*) err "неизвестный аргумент: $1"; ACTION="help"; return 0 ;;
		esac
		shift
	done
}

main() {
	parse_args "$@"
	case "$ACTION" in
		help)      usage ;;
		install)   do_install ;;
		update)    do_update ;;
		uninstall) do_uninstall ;;
		probe)     require_root; run_probe ;;
		cli)       require_root; run_cli ;;
		test)      self_test ;;
		dry-run)   do_dry_run ;;
		menu)      show_menu ;;
	esac
}

if [[ "${AWG3_INSTALL_LIB:-0}" != "1" ]]; then
	main "$@"
fi
