"""Проверка инвариантов — без сети и без root."""
import sys; sys.path.insert(0, '.')
from awg3.core import wgkeys, models as m
from awg3.core.models import Range, ObfParams, AWG3Params, Peer, ServerConfig

fails = []
def check(name, cond):
    print(("  OK   " if cond else "  FAIL ") + name)
    if not cond: fails.append(name)

# ── ключи ────────────────────────────────────────────────────────────
priv = wgkeys.generate_private_key()
pub  = wgkeys.public_key(priv)
check("генерация приватного ключа (32 байта base64)", wgkeys.is_valid_b64_key(priv))
check("вывод публичного ключа", wgkeys.is_valid_b64_key(pub) and pub != priv)
check("детерминизм pubkey", wgkeys.public_key(priv) == pub)
check("b64 -> hex -> b64 round-trip", wgkeys.from_uapi_hex(wgkeys.to_uapi_hex(priv)) == priv)
check("hex длиной 64 символа", len(wgkeys.to_uapi_hex(priv)) == 64)
try:
    wgkeys.to_uapi_hex("короткий"); check("отказ на мусорном ключе", False)
except wgkeys.KeyError_: check("отказ на мусорном ключе", True)

# ── Range ────────────────────────────────────────────────────────────
check("Range 'a-b'", Range.parse("10-20") == Range(10, 20))
check("Range одиночное", Range.parse("5") == Range(5, 5))
check("Range (off) -> None", Range.parse("(off)") is None)
check("Range render одиночного", Range(7, 7).render() == "7")
check("Range render диапазона", Range(7, 9).render() == "7-9")
check("пересечение диапазонов", Range(1, 10).overlaps(Range(10, 20)))
check("непересечение", not Range(1, 9).overlaps(Range(10, 20)))
try:
    Range(20, 10); check("отказ на вывернутом диапазоне", False)
except ValueError: check("отказ на вывернутом диапазоне", True)

# ── ObfParams ────────────────────────────────────────────────────────
good_h = (Range(5, 500_000), Range(600_000_000, 700_000_000),
          Range(1_100_000_000, 1_200_000_000), Range(1_700_000_000, 1_800_000_000))
ok_obf = ObfParams(jc=6, jmin=50, jmax=500, s1=20, s2=100, s3=16, s4=12, *[], **dict(zip("h1 h2 h3 h4".split(), good_h)))
check("валидный набор AWG2 без ошибок", ok_obf.errors(1420) == [])

bad = ObfParams(jc=6, jmin=50, jmax=500, s1=20, s2=76, s3=16, s4=12, **dict(zip("h1 h2 h3 h4".split(), good_h)))
check("ловит S1+56 == S2", any("S1+56" in e for e in bad.errors()))

overlap_h = (Range(5, 500), Range(400, 900), Range(1_100_000_000, 1_200_000_000), Range(1_700_000_000, 1_800_000_000))
bad2 = ObfParams(jc=6, jmin=50, jmax=500, s1=20, s2=100, s3=16, s4=12, **dict(zip("h1 h2 h3 h4".split(), overlap_h)))
check("ловит пересечение H1/H2", any("пересекаются" in e for e in bad2.errors()))

bad3 = ObfParams(jc=6, jmin=50, jmax=1500, s1=20, s2=100, s3=16, s4=12, **dict(zip("h1 h2 h3 h4".split(), good_h)))
check("ловит Jmax >= MTU", any("Jmax" in e for e in bad3.errors(1420)))

bad4 = ObfParams(jc=6, jmin=600, jmax=500, s1=20, s2=100, s3=16, s4=12, **dict(zip("h1 h2 h3 h4".split(), good_h)))
check("ловит Jmin >= Jmax", any("Jmin" in e for e in bad4.errors()))

# ── AWG3Params ───────────────────────────────────────────────────────
hpk = wgkeys.generate_symmetric_key()
a3 = AWG3Params(header_protection_key=hpk, rekey_after_time=Range(120, 150),
                reject_after_time=Range(180, 210))
check("AWG3 включён по наличию HPK", a3.enabled)
check("валидный AWG3 при S>=8", a3.errors((20, 100, 16, 12)) == [])
check("ловит S<8 при header protection", any("S1-S4" in e for e in a3.errors((4, 100, 16, 12))))

a3bad = AWG3Params(header_protection_key=hpk, rekey_after_time=Range(120, 200),
                   reject_after_time=Range(180, 210))
check("ловит rekey_after >= reject_after", any("сменить ключи" in e for e in a3bad.errors((20, 100, 16, 12))))
check("без HPK параметры AWG3 не требуют S>=8", AWG3Params(rekey_timeout=Range(5,5)).errors((1,1,1,1)) == [])

# ── ServerConfig и рендер UAPI ───────────────────────────────────────
peer = Peer(name="phone", public_key=wgkeys.public_key(wgkeys.generate_private_key()),
            allowed_ips=["10.200.0.2/32"], preshared_key=wgkeys.generate_symmetric_key())
cfg = ServerConfig(private_key=priv, listen_port=51820, address="10.200.0.1/24",
                   obf=ok_obf, awg3=a3, peers=[peer])
check("валидный ServerConfig", cfg.errors() == [])

ALL = {"jc","jmin","jmax","s1","s2","s3","s4","h1","h2","h3","h4",
       "header_protection_key","content_padding_addition","rekey_after_time",
       "rekey_timeout","reject_after_time","keepalive_timeout","max_handshake_attempts"}
pairs = cfg.to_uapi_pairs(ALL)
keys_out = [k for k, _ in pairs]
check("private_key отдан в hex", dict(pairs)["private_key"] == wgkeys.to_uapi_hex(priv))
check("HPK отдан в hex", dict(pairs)["header_protection_key"] == wgkeys.to_uapi_hex(hpk))
check("порядок: public_key перед allowed_ip",
      keys_out.index("public_key") < keys_out.index("allowed_ip"))
check("replace_peers присутствует", "replace_peers" in keys_out)
check("пустые параметры AWG3 не пишутся", "content_padding_addition" not in keys_out)

# главное: деградация при неподтверждённых ключах
degraded = cfg.to_uapi_pairs(ALL - {"header_protection_key", "rekey_after_time"})
dk = [k for k, _ in degraded]
check("неподтверждённый ключ выкинут, остальное осталось",
      "header_protection_key" not in dk and "jc" in dk and "public_key" in dk)

# дубликат пира
cfg2 = ServerConfig(private_key=priv, listen_port=51820, address="10.200.0.1/24",
                    obf=ok_obf, peers=[peer, peer])
check("ловит дубликат PublicKey", any("дубликат" in e for e in cfg2.errors()))

cfg3 = ServerConfig(private_key=priv, listen_port=99999, address="10.200.0.1",
                    obf=ok_obf)
errs = cfg3.errors()
check("ловит порт вне диапазона и адрес без CIDR", len(errs) >= 2)

print()
print(f"ИТОГО: {'ВСЕ ПРОШЛИ' if not fails else 'ПРОВАЛЕНО ' + str(len(fails))}")
sys.exit(1 if fails else 0)
