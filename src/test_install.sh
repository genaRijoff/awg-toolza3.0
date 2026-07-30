#!/usr/bin/env bash
# Тесты чистых функций install.sh. Без root, без сети, ничего не ставят.
#   bash test_install.sh

set -uo pipefail

AWG3_INSTALL_LIB=1 source "$(dirname "${BASH_SOURCE[0]}")/../install.sh"

PASS=0
FAIL=0

check() {
	local name="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "  OK   ${name}"; PASS=$((PASS + 1))
	else
		echo "  FAIL ${name}"; FAIL=$((FAIL + 1))
	fi
}

check_not() {
	local name="$1"; shift
	if "$@" >/dev/null 2>&1; then
		echo "  FAIL ${name}"; FAIL=$((FAIL + 1))
	else
		echo "  OK   ${name}"; PASS=$((PASS + 1))
	fi
}

check_eq() {
	local name="$1" expected="$2" actual="$3"
	if [[ "$expected" == "$actual" ]]; then
		echo "  OK   ${name}"; PASS=$((PASS + 1))
	else
		echo "  FAIL ${name}: ждали '${expected}', получили '${actual}'"; FAIL=$((FAIL + 1))
	fi
}

echo "── version_ge ──"
check     "1.22 >= 1.21"        version_ge "1.22" "1.21"
check     "1.21 >= 1.21"        version_ge "1.21" "1.21"
check_not "1.19 НЕ >= 1.21"     version_ge "1.19" "1.21"
check     "1.21.5 >= 1.21"      version_ge "1.21.5" "1.21"
check_not "1.9 НЕ >= 1.21 (не строковое сравнение)" version_ge "1.9" "1.21"
check     "24.04 >= 22.04"      version_ge "24.04" "22.04"
check_not "20.04 НЕ >= 22.04"   version_ge "20.04" "22.04"
check     "13 >= 12"            version_ge "13" "12"

echo "── validate_port ──"
check     "51820 годен"         validate_port 51820
check_not "порт 80 отвергнут"      validate_port 80
check_not "нечисловой отвергнут" validate_port "abc"
check_not "пустой отвергнут"    validate_port ""
check_not "99999 отвергнут"     validate_port 99999
check_not "1023 отвергнут"      validate_port 1023
check     "1024 годен"          validate_port 1024

echo "── cidr_network ──"
check_eq  "10.100.0.1/24 -> сеть"  "10.100.0.0" "$(cidr_network '10.100.0.1/24')"
check_eq  "10.44.5.1/24 -> сеть"   "10.44.5.0"  "$(cidr_network '10.44.5.1/24')"
check_eq  "без маски тоже"         "10.8.0.0"   "$(cidr_network '10.8.0.1')"
check_eq  "мусор -> пусто"         ""           "$(cidr_network 'не-адрес')"
check_eq  "пусто -> пусто"         ""           "$(cidr_network '')"

echo "── subnets_conflict ──"
check     "одинаковые конфликтуют"    subnets_conflict "10.200.0.0" "10.200.0.0"
check_not "разные не конфликтуют"     subnets_conflict "10.200.0.0" "10.100.0.0"
check_not "пустая не конфликтует"     subnets_conflict "" "10.100.0.0"

echo "── pick_subnet (случайная, обходит AWG 2.0) ──"
SEEN=""
DUP=0
for _ in $(seq 1 40); do
	NET="$(pick_subnet '10.100.0.0')"
	OCT="$(echo "$NET" | cut -d. -f2)"
	if ((OCT < 33 || OCT > 188)); then echo "  FAIL октет $OCT вне 33..188"; FAIL=$((FAIL+1)); fi
	if [[ "$NET" == "10.100.0.0" ]]; then echo "  FAIL выдана занятая сеть"; FAIL=$((FAIL+1)); fi
	case "$SEEN" in *"$NET"*) DUP=$((DUP+1)) ;; esac
	SEEN="$SEEN $NET"
done
check_eq "40 генераций: третий и четвёртый октет нулевые" "" "$(echo $SEEN | tr ' ' '\n' | grep -v '\.0\.0$' | head -1)"
if ((DUP < 35)); then
	echo "  OK   разнообразие: $((40-DUP)) различных из 40"; PASS=$((PASS+1))
else
	echo "  FAIL почти все одинаковые"; FAIL=$((FAIL+1))
fi
check_eq "занятая сеть не выдаётся" "" "$(echo $SEEN | tr ' ' '\n' | grep -x '10.100.0.0' | head -1)"

echo "── awg2_field (чтение чужого конфига) ──"
TMP="$(mktemp)"
cat >"$TMP" <<'EOF'
# AWG_PROFILE=standard
[Interface]
Address = 10.100.0.1/24
ListenPort = 41300
MTU = 1320
Jc = 6
EOF
check_eq  "ListenPort"            "41300"          "$(awg2_field "$TMP" ListenPort)"
check_eq  "Address"               "10.100.0.1/24"  "$(awg2_field "$TMP" Address)"
check_eq  "MTU"                   "1320"           "$(awg2_field "$TMP" MTU)"
check_eq  "нет такого ключа"      ""               "$(awg2_field "$TMP" НетТакого)"
check_eq  "нет такого файла"      ""               "$(awg2_field /nope/nope.conf ListenPort)"
rm -f "$TMP"

echo "── сквозной сценарий: AWG 2.0 на 10.100.0.0:41300 ──"
NET="$(cidr_network "$(awg2_field <(printf 'Address = 10.100.0.1/24\n') Address)")"
check_eq  "его сеть распознана"   "10.100.0.0" "$NET"
OURS="$(pick_subnet "$NET")"
OCT="$(echo "$OURS" | cut -d. -f2)"
if [[ "$OURS" != "$NET" ]] && ((OCT >= 33 && OCT <= 188)); then
	echo "  OK   наша сеть ${OURS} не пересеклась с ${NET}"; PASS=$((PASS+1))
else
	echo "  FAIL получили ${OURS} при занятой ${NET}"; FAIL=$((FAIL+1))
fi

echo "── gomod_go_version / check_go_toolchain ──"
GOMOD="$(mktemp)"
printf 'module example\n\ngo 1.25\n\ntoolchain go1.25.0\n' >"$GOMOD"
check_eq  "версия из go.mod"        "1.25" "$(gomod_go_version "$GOMOD")"
check_eq  "нет файла -> пусто"      ""     "$(gomod_go_version /nope/go.mod)"
rm -f "$GOMOD"

check     "1.25 покрывает 1.25"     check_go_toolchain "1.25" "1.25"
check     "1.26 покрывает 1.25"     check_go_toolchain "1.25" "1.26"
check     "1.22 + GOTOOLCHAIN=auto: можно (докачает)" env GOTOOLCHAIN=auto bash -c 'AWG3_INSTALL_LIB=1 source ../install.sh; check_go_toolchain 1.25 1.22'
check_not "1.22 + GOTOOLCHAIN=local: нельзя" env GOTOOLCHAIN=local bash -c 'AWG3_INSTALL_LIB=1 source ../install.sh; check_go_toolchain 1.25 1.22'

echo "── missing_tools (проверка утилит перед сборкой) ──"
check_eq "всё на месте -> пусто"        ""              "$(missing_tools bash sh)"
check_eq "одна отсутствует"             "нетакойкоманды" "$(missing_tools bash нетакойкоманды)"
check_eq "несколько отсутствуют"        "нетути1 нетути2" "$(missing_tools нетути1 bash нетути2)"
check_eq "пустой список -> пусто"       ""              "$(missing_tools)"

echo "── версия Go из go.mod (реальные формы) ──"
GOMOD="$(mktemp)"
printf 'module github.com/x/y\n\ngo 1.25.0\n\ntoolchain go1.25.1\n\nrequire (\n\tgolang.org/x/sys v0.36.0\n)\n' >"$GOMOD"
check_eq "патч-версия 1.25.0"      "1.25.0" "$(gomod_go_version "$GOMOD")"
printf 'module x\ngo 1.22\n' >"$GOMOD"
check_eq "минорная 1.22"           "1.22"   "$(gomod_go_version "$GOMOD")"
printf 'module x\n\nrequire y v1\n' >"$GOMOD"
check_eq "нет директивы go -> пусто" ""     "$(gomod_go_version "$GOMOD")"
rm -f "$GOMOD"
check     "1.25.0 >= 1.25"          version_ge "1.25.0" "1.25"
check_not "1.22.2 НЕ >= 1.25.0"     version_ge "1.22.2" "1.25.0"
check     "1.26 >= 1.25.0"          version_ge "1.26" "1.25.0"

echo "── rule_to_delete (снятие правил при удалении) ──"
check_eq "-A -> -D, кавычки сняты" \
  '-D POSTROUTING -s 10.200.0.0/24 -o eth0 -m comment --comment awg3:nat -j MASQUERADE' \
  "$(rule_to_delete '-A POSTROUTING -s 10.200.0.0/24 -o eth0 -m comment --comment "awg3:nat" -j MASQUERADE')"
check_eq "FORWARD тоже" \
  '-D FORWARD -i awg1 -m comment --comment awg3:fwd-in -j ACCEPT' \
  "$(rule_to_delete '-A FORWARD -i awg1 -m comment --comment "awg3:fwd-in" -j ACCEPT')"
check_not "не -A -> отказ" rule_to_delete '-P FORWARD ACCEPT'
check_not "пустая строка -> отказ" rule_to_delete ''

echo "── safe_rm_tree (защита от rm -rf по кривой переменной) ──"
check_not "пустой путь отвергнут"          safe_rm_tree ""
check_not "относительный отвергнут"        safe_rm_tree "opt/awg3"
check_not "корень отвергнут"               safe_rm_tree "/"
check_not "/opt отвергнут (мало сегментов)" safe_rm_tree "/opt"
check_not "/etc отвергнут"                 safe_rm_tree "/etc"
check_not "/usr/local отвергнут"           safe_rm_tree "/usr/local"
check_not "чужой префикс отвергнут"        safe_rm_tree "/etc/amnezia"
check_not "чужой глубокий путь отвергнут"  safe_rm_tree "/var/lib/postgresql"
check_not "обход через .. отвергнут"       safe_rm_tree "/opt/awg3/../../etc"

TMPD="$(mktemp -d)"
mkdir -p "${TMPD}/nested"
check_not "путь вне белого списка не удалён" safe_rm_tree "$TMPD"
check     "каталог уцелел"                 test -d "$TMPD"
rm -rf "$TMPD"

echo ""
if ((FAIL == 0)); then
	echo "ИТОГО: ВСЕ ПРОШЛИ (${PASS})"
	exit 0
fi
echo "ИТОГО: провалено ${FAIL} из $((PASS + FAIL))"
exit 1
