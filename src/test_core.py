"""Тесты хранилища, профилей и экспорта. Без root, без сети."""
import os, sys, tempfile, pathlib
_TD = tempfile.mkdtemp()
os.environ.update(AWG3_CONF_DIR=_TD+"/etc", AWG3_LOG=_TD+"/awg3.log",
                  AWG3_PREFIX=_TD+"/opt", AWG3_BACKUP_DIR=_TD+"/bak")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from awg3.core import export, profiles, wgkeys
from awg3.core.storage import ServerRow, Storage, StorageError

fails = []
def check(name, cond):
    print(("  OK   " if cond else "  FAIL ") + name)
    if not cond: fails.append(name)

def _server_row(**kw):
    obf = kw.pop("obf"); a3 = kw.pop("awg3"); priv = kw.pop("priv")
    return ServerRow(iface="awg1", private_key=priv, public_key=wgkeys.public_key(priv),
        listen_port=50004, address="10.200.0.1/24", subnet="10.200.0.0/24", mtu=1420,
        endpoint_host="203.0.113.10", dns="1.1.1.1", profile="standard",
        obf={"jc":obf.jc,"jmin":obf.jmin,"jmax":obf.jmax,"s1":obf.s1,"s2":obf.s2,
             "s3":obf.s3,"s4":obf.s4,"h1":obf.h1.render(),"h2":obf.h2.render(),
             "h3":obf.h3.render(),"h4":obf.h4.render()},
        awg3={"header_protection_key":a3.header_protection_key,
              "content_padding_addition":a3.content_padding_addition.render(),
              "rekey_after_time":a3.rekey_after_time.render(),
              "rekey_timeout":a3.rekey_timeout.render(),
              "reject_after_time":a3.reject_after_time.render(),
              "keepalive_timeout":a3.keepalive_timeout.render(),
              "max_handshake_attempts":a3.max_handshake_attempts.render()},
        created_at="")

print("── profiles: генерация всегда валидна ──")
for pname in ("lite", "standard", "pro"):
    bad = []
    for _ in range(500):
        obf = profiles.generate_obf(pname, awg3=True)
        a3 = profiles.generate_awg3(enable_header_protection=True)
        errs = obf.errors(1420) + a3.errors(obf.s_values)
        if errs: bad.append(errs[0])
    check(f"{pname}: 500 наборов, ноль ошибок валидации", not bad)
    if bad: print("      пример:", bad[0])

try:
    profiles.generate_obf("нетакого"); check("неизвестный профиль отвергнут", False)
except ValueError: check("неизвестный профиль отвергнут", True)
check("три профиля в меню", len(profiles.profile_choices()) == 3)

print("── storage ──")
with tempfile.TemporaryDirectory() as td:
    db = pathlib.Path(td) / "t.db"
    st = Storage(db)
    check("схема создана", db.is_file())
    check("права 0600", oct(db.stat().st_mode)[-3:] == "600")
    check("сервера нет", not st.has_server())

    obf = profiles.generate_obf("standard"); a3 = profiles.generate_awg3()
    priv = wgkeys.generate_private_key()
    st.save_server(_server_row(obf=obf, awg3=a3, priv=priv))
    check("сервер сохранён", st.has_server())

    check("первый адрес .2 (сервер держит .1)",
          st.next_free_address("10.200.0.0/24") == "10.200.0.2/32")
    cp = wgkeys.generate_private_key()
    st.add_client("phone", cp, wgkeys.public_key(cp), "10.200.0.2/32",
                  wgkeys.generate_symmetric_key())
    check("клиент добавлен", len(st.list_clients()) == 1)
    check("следующий адрес .3", st.next_free_address("10.200.0.0/24") == "10.200.0.3/32")

    try:
        st.add_client("phone", cp, wgkeys.public_key(cp), "10.200.0.9/32")
        check("дубликат имени отвергнут", False)
    except StorageError: check("дубликат имени отвергнут", True)

    cfg = st.to_server_config()
    check("ServerConfig валиден", cfg.errors() == [])
    check("пир доехал", cfg.peers[0].name == "phone")
    check("HPK доехал", cfg.awg3.header_protection_key == a3.header_protection_key)
    check("UAPI-пары формируются",
          len(cfg.to_uapi_pairs({k for k, _ in
              [(x, 1) for x in ("private_key","listen_port","replace_peers","jc","s1",
                                "header_protection_key","public_key","allowed_ip",
                                "replace_allowed_ips","preshared_key")]})) > 5)

    st.set_client_enabled("phone", False)
    check("выключенный пир не уходит в UAPI", st.to_server_config().peers == [])
    check("но виден в полном списке", len(st.to_server_config(only_enabled=False).peers) == 1)
    check("удаление клиента", st.remove_client("phone") and not st.list_clients())
    check("удаление несуществующего = False", st.remove_client("нет") is False)

print("── export ──")
with tempfile.TemporaryDirectory() as td:
    st = Storage(pathlib.Path(td) / "e.db")
    obf = profiles.generate_obf("pro"); a3 = profiles.generate_awg3()
    priv = wgkeys.generate_private_key()
    st.save_server(_server_row(obf=obf, awg3=a3, priv=priv))
    cp = wgkeys.generate_private_key()
    st.add_client("laptop", cp, wgkeys.public_key(cp), "10.200.0.2/32",
                  wgkeys.generate_symmetric_key())
    conf = export.render_client_conf(st.get_server(), st.get_client("laptop"),
                                     st.to_server_config())
    need = ["[Interface]","PrivateKey","Address = 10.200.0.2/32","MTU = 1420",
            "Jc =","S1 =","S4 =","H1 =","H4 =","HeaderProtectionKey",
            "ContentPaddingAddition","RekeyAfterTime","RejectAfterTime","[Peer]",
            "PublicKey","PresharedKey","Endpoint = 203.0.113.10:50004",
            "AllowedIPs","PersistentKeepalive"]
    missing = [n for n in need if n not in conf]
    check(f"конфиг содержит все {len(need)} обязательных полей", not missing)
    if missing: print("      нет:", missing)
    check("серверный приватный ключ НЕ попал в клиентский конфиг",
          st.get_server().private_key not in conf)
    check("клиентский приватный ключ на месте", st.get_client("laptop").private_key in conf)

    out = export.write_client_conf(pathlib.Path(td) / "clients", "laptop", conf)
    check("файл записан", out.is_file())
    check("права 0600", oct(out.stat().st_mode)[-3:] == "600")

    a3_off = profiles.generate_awg3(enable_header_protection=False)
    st2 = Storage(pathlib.Path(td) / "f.db")
    st2.save_server(_server_row(obf=profiles.generate_obf("lite", awg3=False),
                                awg3=a3_off, priv=wgkeys.generate_private_key()))
    cp2 = wgkeys.generate_private_key()
    st2.add_client("c2", cp2, wgkeys.public_key(cp2), "10.200.0.2/32", None)
    conf2 = export.render_client_conf(st2.get_server(), st2.get_client("c2"),
                                      st2.to_server_config())
    check("без AWG3 секция HeaderProtectionKey отсутствует",
          "HeaderProtectionKey" not in conf2)
    check("без PSK строка PresharedKey отсутствует", "PresharedKey" not in conf2)
    check("IPv6 не маршрутизируется в туннель без IPv6-адреса",
          "::/0" not in conf and "::/0" not in conf2)
    check("с AWG 3 keepalive диапазоном",
          "PersistentKeepalive = 22-30" in conf)
    check("без AWG 3 keepalive одиночным (совместимость со старыми клиентами)",
          "PersistentKeepalive = 25" in conf2)

print("── presets ──")
from awg3.core import presets
check("три шаблона", len(presets.TEMPLATES) == 3)
check("рекомендуемый = standard + AWG3",
      presets.TEMPLATES[0].profile == "standard" and presets.TEMPLATES[0].awg3)
check("все шаблоны с AWG 3", all(t.awg3 for t in presets.TEMPLATES))
check("поиск по несуществующему ключу = None", presets.template_by_key("нет") is None)
check("все шаблоны ссылаются на реальные профили",
      all(t.profile in profiles.PROFILES for t in presets.TEMPLATES))
check("MTU всех шаблонов в допустимых границах",
      all(1280 <= t.mtu <= 1500 for t in presets.TEMPLATES))
check("у каждого шаблона непустой DNS", all(t.dns.strip() for t in presets.TEMPLATES))
check("ключи шаблонов уникальны",
      len({t.key for t in presets.TEMPLATES}) == len(presets.TEMPLATES))

print("── детект внешнего адреса ──")
import types
from awg3.core import network
_real = network._run
def _fake(out):
    return lambda argv, check=True: types.SimpleNamespace(returncode=0, stdout=out, stderr="")

network._run = _fake("1.1.1.1 via 10.0.0.1 dev enp0s3 src 79.137.199.29 uid 0")
check("публичный src извлечён", network.local_source_ip() == "79.137.199.29")
check("детект отдаёт адрес интерфейса", network.detect_endpoint()[0] == "79.137.199.29")

network._run = _fake("1.1.1.1 via 172.31.0.1 dev eth0 src 172.31.24.9 uid 0")
check("за NAT src тоже извлечён", network.local_source_ip() == "172.31.24.9")
check("приватный распознан", network.is_private_ip("172.31.24.9"))

network._run = _fake("мусор без src")
check("нет src -> None", network.local_source_ip() is None)
network._run = _real

for addr, private in (("10.0.0.5", True), ("192.168.1.1", True), ("127.0.0.1", True),
                      ("100.64.0.1", True), ("79.137.199.29", False), ("8.8.8.8", False)):
    check(f"{addr} приватный={private}", network.is_private_ip(addr) is private)
check("мусор не считается приватным", network.is_private_ip("не-адрес") is False)

print("── диагностика отвергнутого ключа ──")
from awg3.core.backend import GoBackend
pairs = [("private_key","aa"),("listen_port","1"),("h1","5-9"),
         ("public_key","bb"),("preshared_key","cc"),
         ("replace_allowed_ips","true"),("allowed_ip","10.0.0.2/32"),
         ("public_key","dd"),("allowed_ip","10.0.0.3/32")]
units = GoBackend._split_units(pairs)
check("набор разбит на 5 единиц", len(units) == 5)
check("ключи устройства по одному", units[0] == [("private_key","aa")])
check("первый пир собран целиком", len(units[3]) == 4 and units[3][0][0] == "public_key")
check("второй пир отделён", units[4][0] == ("public_key","dd"))
check("allowed_ip не оторван от своего public_key",
      all(u[0][0] == "public_key" for u in units if any(k == "allowed_ip" for k, _ in u)))
check("пустой набор -> пусто", GoBackend._split_units([]) == [])

print("── детект поднятого линка (TUN отдаёт state UNKNOWN) ──")
import re as _re
def _link_up(out):
    m = _re.search(r"<([^>]*)>", out)
    return bool(m) and "UP" in m.group(1).split(",")
check("TUN с UP во флагах, но state UNKNOWN -> поднят",
      _link_up("5: awg1: <POINTOPOINT,MULTICAST,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN"))
check("TUN без UP -> опущен",
      not _link_up("5: awg1: <POINTOPOINT,MULTICAST,NOARP> mtu 1420 state DOWN"))
check("ethernet UP -> поднят",
      _link_up("2: enp0s3: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500 state UP"))
check("старая проверка 'state UP' провалилась бы на TUN",
      "state UP" not in "5: awg1: <POINTOPOINT,NOARP,UP,LOWER_UP> mtu 1420 state UNKNOWN")

print("── проверка порта через /proc/net/udp ──")
check("несуществующий порт не найден", network._port_listening_proc(59926) is False)
check("hex-формат порта", f"{59926:04X}" == "EA16")

print("── подтверждения меню ──")
import builtins
from awg3.cli.menu import confirm
_real_input = builtins.input
for ans, want in (("y", True), ("Y", True), ("yes", True), ("да", True), ("Да", True),
                  ("n", False), ("no", False), ("", False), ("мусор", False)):
    builtins.input = lambda p, a=ans: a
    check(f"ответ {ans!r} -> {want}", confirm("тест") is want)
def _raise(p): raise EOFError
builtins.input = _raise
check("EOF считается отказом, не падением", confirm("тест") is False)
builtins.input = _real_input

print("── выбор подсети ──")
import types as _t
_real_run = network._run
network._run = lambda a, check=True: _t.SimpleNamespace(
    returncode=0, stdout="default via 10.0.0.1 dev eth0\n10.77.0.0/24 dev docker0\n", stderr="")
_nets = {network.pick_free_subnet() for _ in range(60)}
_octets = {int(n.split(".")[1]) for n in _nets}
check("октеты в диапазоне 33-188", all(33 <= o <= 188 for o in _octets))
check("третий и четвёртый октет нулевые", all(n.endswith(".0.0/24") for n in _nets))
check("занятая маршрутом сеть не выдаётся", "10.77.0.0/24" not in _nets)
check("разнообразие: больше 30 различных из 60", len(_nets) > 30)
check("исключение через exclude работает",
      network.pick_free_subnet(exclude={"10.50.0.0/24"}) != "10.50.0.0/24")
network._run = _real_run

print("── network: разбор правил ──")
from awg3.core import network
r = network._split_rule('-D POSTROUTING -s 10.200.0.0/24 -o eth0 -m comment '
                        '--comment "awg3:nat" -j MASQUERADE')
check("кавычки вокруг комментария сняты", "awg3:nat" in r and '"' not in "".join(r))
check("токены не склеились", len(r) == 12)

print()
print("ИТОГО:", "ВСЕ ПРОШЛИ" if not fails else f"ПРОВАЛЕНО {len(fails)}")
sys.exit(1 if fails else 0)
