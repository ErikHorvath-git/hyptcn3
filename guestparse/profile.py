"""
Profil jadra hosta: symboly (kallsyms) a offsety poli struktur (BTF).

Profil je jednorazova vstupna zavislost ziskana z hosta mimo behu zberu -
rovnako, ako profil pouziva LibVMI alebo Volatility. Nie je to "bez akejkolvek
znalosti hosta"; je to znalost, ktora sa ziskala raz a mimo meraneho okna.

PRECO sa offsety citaju z BTF a nie z hlavickovych suborov: rozlozenie
struktur zavisi od konfiguracie jadra (CONFIG_*), nie iba od verzie. Cislo
opisane zo zdrojakov by pri inom .config ticho ukazovalo na ine pole.
"""

import json
import os
import re

# Struktury, ktorych offsety balik potrebuje. Ostatne sa z BTF neberu,
# aby sa vypis nemusel drzat cely v pamati.
WANTED = (
    "task_struct",
    "module",
    "file",
    "files_struct",
    "fdtable",
    "socket",
    "sock_common",
)

# Strojovo citatelne udaje o tom, z KTOREHO startu hosta je profil.
# Zapisuje ho scripts/get_profile.sh; profil odobraty skor ho nema.
META = "boot.json"

_BTF_CACHE = {}


def load_meta(directory):
    """
    Udaje o bootu z <profil>/boot.json: boot_id hosta, datum odberu, verzia
    jadra. Chybajuci alebo pokazeny subor nie je chyba profilu - starsie
    profily ho nemaju - ale vtedy sa o bootu nic netvrdi.
    """
    try:
        with open(os.path.join(directory, META)) as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


class ProfileError(Exception):
    pass


def _pick(directory, *patterns):
    """Najde v adresari prvy subor, ktory sedi na niektory zo vzorov."""
    names = sorted(os.listdir(directory))
    for pat in patterns:
        rx = re.compile(pat)
        for n in names:
            if rx.match(n):
                return os.path.join(directory, n)
    return None


class Profile:
    """Symboly z kallsyms + offsety poli z BTF vypisu."""

    def __init__(self, kallsyms_path, btf_path, wanted=WANTED):
        self.kallsyms_path = kallsyms_path
        self.btf_path = btf_path
        self.dir = os.path.dirname(os.path.abspath(kallsyms_path))
        self.meta = load_meta(self.dir)
        self.sym = {}
        with open(kallsyms_path) as fh:
            for ln in fh:
                p = ln.split()
                # format: <adresa> <typ> <meno> [modul]; prve vyskyty vyhravaju,
                # duplicitne staticke symboly z modulov sa ignoruju
                if len(p) >= 3:
                    try:
                        addr = int(p[0], 16)
                    except ValueError:
                        continue
                    self.sym.setdefault(p[2], addr)
        if not self.sym:
            raise ProfileError("%s: ziadne symboly" % kallsyms_path)
        if not any(v for v in self.sym.values()):
            raise ProfileError(
                "%s: vsetky adresy su nulove (kallsyms citany bez roota)"
                % kallsyms_path)
        self.off = btf_offsets(btf_path, set(wanted))

    @classmethod
    def from_dir(cls, directory, wanted=WANTED):
        """
        Nacita profil z adresara. Kanonicke mena su kallsyms.txt a btf.txt;
        prijimaju sa aj mena s verziou jadra, aby sa profil nemusel
        premenovavat pri prenose z hosta.
        """
        if not os.path.isdir(directory):
            raise ProfileError("%s: nie je adresar" % directory)
        ks = _pick(directory, r"^kallsyms\.txt$", r"^kallsyms.*\.txt$",
                   r".*kallsyms.*")
        btf = _pick(directory, r"^btf\.txt$", r".*btf.*\.txt$")
        if ks is None:
            raise ProfileError("%s: chyba kallsyms.txt" % directory)
        if btf is None:
            raise ProfileError(
                "%s: chyba btf.txt (vypis 'bpftool btf dump file <vmlinux> "
                "format raw')" % directory)
        return cls(ks, btf, wanted)

    def describe(self):
        """
        Jedna veta o povode profilu do hlasok. Ked boot.json chyba, povie sa
        to - "neznamy boot" je informacia, dohadovat sa nic nebude.
        """
        boot = self.meta.get("boot_id")
        kedy = self.meta.get("captured")
        if boot:
            return ("profil %s je z bootu %s (odobraty %s)"
                    % (self.dir, boot, kedy or "bez datumu"))
        return ("profil %s nema boot.json - z ktoreho startu hosta je, "
                "zistit neviem" % self.dir)

    def addr(self, name):
        return self.sym.get(name)

    def member(self, struct_name, field):
        """Offset pola v bajtoch, alebo None ked struktura/pole chyba."""
        s = self.off.get(struct_name)
        if not s:
            return None
        return s["members"].get(field)

    def require(self, struct_name, *fields):
        """Offsety poli; chybajuce pole je chyba profilu, nie prazdny vysledok."""
        s = self.off.get(struct_name)
        if not s:
            raise ProfileError("profil nema strukturu %s" % struct_name)
        out = []
        for f in fields:
            v = s["members"].get(f)
            if v is None:
                raise ProfileError("profil nema %s.%s" % (struct_name, f))
            out.append(v)
        return out


def _btf_index(btf_dump_path):
    """Nacita vypis BTF do tabulky typov: id -> {kind, name, size, members}."""
    cached = _BTF_CACHE.get(btf_dump_path)
    if cached is not None:
        return cached
    head = re.compile(r"\[(\d+)\] (\w+) '([^']*)'(.*)")
    memb = re.compile(r"\s+'([^']*)' type_id=(\d+) bits_offset=(\d+)")
    types = {}
    cur = None
    with open(btf_dump_path, errors="replace") as fh:
        for ln in fh:
            ln = ln.rstrip("\n")
            if ln.startswith("["):
                m = head.match(ln)
                if not m:
                    cur = None
                    continue
                tid, kind, name, rest = (int(m.group(1)), m.group(2),
                                         m.group(3), m.group(4))
                sz = re.search(r"size=(\d+)", rest)
                ref = re.search(r"type_id=(\d+)", rest)
                cur = {
                    "kind": kind,
                    "name": name,
                    "size": int(sz.group(1)) if sz else 0,
                    "ref": int(ref.group(1)) if ref else None,
                    "members": [],
                }
                types[tid] = cur
                continue
            if cur is not None and cur["kind"] in ("STRUCT", "UNION"):
                # anonymne cleny vypisuje bpftool ako '(anon)' - musia sa
                # chytit, inak by chybali polia vnorene v anonymnych unionoch
                mm = memb.match(ln)
                if mm:
                    nm = "" if mm.group(1) == "(anon)" else mm.group(1)
                    cur["members"].append((nm, int(mm.group(2)), int(mm.group(3))))
    _BTF_CACHE[btf_dump_path] = types
    return types


def _flatten(types, tid, base_bits=0, out=None, depth=0):
    """
    Zoznam poli struktury v bajtoch. Zostupuje do anonymnych unionov a
    struktur - v jadrach 6.x su prave v nich ulozene napr. adresy a porty
    v `sock_common`, takze bez tohto zostupu by chybali uplne.
    """
    if out is None:
        out = {}
    t = types.get(tid)
    if not t or depth > 6:
        return out
    if t["kind"] in ("TYPEDEF", "VOLATILE", "CONST", "RESTRICT") and t["ref"]:
        return _flatten(types, t["ref"], base_bits, out, depth + 1)
    if t["kind"] not in ("STRUCT", "UNION"):
        return out
    for name, mtid, bits in t["members"]:
        if name:
            out.setdefault(name, (base_bits + bits) // 8)
        else:
            _flatten(types, mtid, base_bits + bits, out, depth + 1)
    return out


def btf_offsets(btf_dump_path, wanted):
    """
    Vytiahne offsety clenov struktur z vypisu BTF
    ('bpftool btf dump file <vmlinux> format raw').

    Ked sa to iste meno vyskytne viackrat (napr. typ z modulu), vyhrava
    zaznam s najviac clenmi - prazdna forward deklaracia by inak prebila
    skutocnu strukturu.
    """
    types = _btf_index(btf_dump_path)
    out = {}
    for tid, t in types.items():
        if t["kind"] != "STRUCT" or t["name"] not in wanted:
            continue
        members = _flatten(types, tid)
        prev = out.get(t["name"])
        if prev is None or len(members) > len(prev["members"]):
            out[t["name"]] = {"size": t["size"], "members": members}
    return out
