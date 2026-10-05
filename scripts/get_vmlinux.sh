#!/usr/bin/env bash
# get_vmlinux.sh - stiahne vmlinuz z hosta a rozbali ho na vmlinux (A3).
#
# vmlinux (linkovany obraz jadra) sluzi ako referencny obsah textu pre
# baseline A3: boot patchy (static keys, static calls, relokacie) sa
# maskuju podla tabuliek, takze kontrola textu je boot-independent a
# nepotrebuje "cistu snimku z kazdeho bootu".
#
# Vystup (MIMO gitu): data/raw/profile-assets/vmlinux-<uname -r>
set -uo pipefail

HERE=$(cd "$(dirname "$0")" && pwd)
OUTDIR="$HERE/../data/raw/profile-assets"
mkdir -p "$OUTDIR"

KVER=$("$HERE/guest_exec.sh" -- 'uname -r' 2>/dev/null | tail -1)
[ -n "$KVER" ] || { echo "get_vmlinux: host neodpoveda (guest_exec.sh)" >&2; exit 2; }

VMLINUZ="$OUTDIR/vmlinuz-$KVER"
VMLINUX="$OUTDIR/vmlinux-$KVER"
if [ -f "$VMLINUX" ]; then
    echo "get_vmlinux: $VMLINUX uz existuje"
    exit 0
fi

"$HERE/guest_exec.sh" -- "cat /boot/vmlinuz-$KVER | base64 -w0" \
    > "$VMLINUZ.b64" 2>/dev/null
SIZE=$(wc -c < "$VMLINUZ.b64")
[ "$SIZE" -gt 1000000 ] || { echo "get_vmlinux: stiahnute je prilis male ($SIZE B)" >&2; exit 2; }
base64 -d "$VMLINUZ.b64" > "$VMLINUZ"
rm -f "$VMLINUZ.b64"

python3 - "$VMLINUZ" "$VMLINUX" <<'PYEOF'
import sys

src, dst = sys.argv[1], sys.argv[2]
data = open(src, "rb").read()

def lz4_raw(d, max_out=512 * 1024 * 1024):
    """Legacy LZ4 blok (format, ktory pouziva jadro), bez frame hlavicky."""
    out = bytearray()
    i, n = 0, len(d)
    while i < n:
        token = d[i]; i += 1
        lit = token >> 4
        if lit == 15:
            while True:
                b = d[i]; i += 1
                lit += b
                if b != 255:
                    break
        out += d[i:i + lit]; i += lit
        if i >= n:
            break
        if i + 1 >= n:
            raise ValueError("lz4: useknuty zaznam")
        off = d[i] | (d[i + 1] << 8); i += 2
        if off == 0 or off > len(out):
            raise ValueError("lz4: nespravny offset")
        mlen = (token & 0xF) + 4
        if token & 0xF == 15:
            while True:
                b = d[i]; i += 1
                mlen += b
                if b != 255:
                    break
        src = len(out) - off
        for k in range(mlen):
            out.append(out[src + k])
        if len(out) > max_out:
            raise ValueError("lz4: vystup prilis velky")
    return bytes(out)


def hdr_off(d):
    # podpis 0x1f8b (gzip), 28 b5 2f fd (zstd), 'MZ'? nie - ELF rovno
    if d[:2] == b"\x1f\x8b":
        return "gzip"
    if d[:4] == b"\x28\xb5\x2f\xfd":
        return "zstd"
    if d[:4] == b"\x7fELF":
        return "elf"
    return None

kind = hdr_off(data)
print("get_vmlinux: hlavicka %s, %d B" % (kind, len(data)))
if kind == "elf":
    out = data
else:
    # Debian vmlinuz = boot stub (MZ/hlavicka) + payload podla boot
    # hlavicky: protocol 2.15, payload_len na 0x248, payload_offset 0x1F1.
    # Kompresia payloadu je v hlavicke ('LZ4 compressed' podla file).
    import gzip, lzma
    # Boot hlavicka je pri PE-wrapperoch nespolahliva, preto sa
    # kompresia SKUSA na kazdom offsеte do 4 KiB (prvy je 0x2cc - tam
    # 'file' nasiel LZ4 stream). Berie sa ta, ktora da ELF.
    out = None
    tried = []
    for pay_off in sorted(set([0x2CC] + list(range(0x200, 0x1000, 4)))):
        pay = data[pay_off:pay_off + 0xD5CA81]
        for meno, fn in (("lz4", lz4_raw),
                         ("gzip", gzip.decompress),
                         ("xz", lambda p: lzma.decompress(
                             p, format=lzma.FORMAT_XZ))):
            try:
                o = fn(pay)
                tried.append((pay_off, meno))
                if hdr_off(o) == "elf":
                    out = o
                    print("get_vmlinux: offsеt %d, %s -> ELF"
                          % (pay_off, meno))
                    break
            except Exception:
                continue
        if out is not None:
            break
    if out is None:
        raise SystemExit("get_vmlinux: ziadny format nedal ELF "
                         "(skusanych %d kombinacii)" % len(tried))

# gzip/zstd moze byt vnoreny (pe_load: gzip(xz(elf))?) - skus este raz
kind2 = hdr_off(out)
if kind2 == "gzip":
    import gzip
    out = gzip.decompress(out)
elif kind2 == "zstd":
    import zstd
    out = zstd.ZstdDecompressor().decompress(out)
assert hdr_off(out) == "elf", "po rozbaleni nie je ELF (%s)" % hdr_off(out)
open(dst, "wb").write(out)
print("get_vmlinux: vmlinux -> %s (%d B)" % (dst, len(out)))
PYEOF
file "$VMLINUX" 2>/dev/null | head -1
