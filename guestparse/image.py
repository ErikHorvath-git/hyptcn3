"""
Citanie pamatovych snimok zberaca.

Snimka sa NEROZBALUJE do raw obrazu: retazec .vmicd sa cita na mieste, lebo
rozbalenie 2 GiB VM stoji 4 GiB miesta a niekolko sekund na kazdy jeden dotaz.
Index stranok drzi iba dvojicu (subor, offset), samotny obsah sa cita az pri
citani adresy.

RETAZEC SA PRI OTVORENI OVERUJE. Delta obsahuje iba stranky, ktore sa od
predchadzajucej snimky zmenili, takze sa aplikuje NA PREDCHADZAJUCI STAV.
Ked v retazci chyba delta uprostred, stranky, ktore mala priniest, ostanu v
stave spred nej - vysledkom je pamat, ktora v hostovi nikdy naraz neexistovala,
a nic na to neupozorni. Preto sa taky retazec odmietne (ChainError), rovnako
ako to robi vmic_delta_restore() vo vmicollect/src/writer_delta.c.

Povodny prototyp: jednosuborovy vmi_parse.py (2026-09-18), tu rozdeleny do balika.

Povod: modul vznikol 2026-09-18 rozdelenim prototypu vmi_parse.py z pripravnej
fazy do modulov. Prototyp bol overeny nad realnou snimkou domeny hyptcn-guest;
co presne sa prevzalo a co pribudlo, je v docs/ARCHITEKTURA.md.
"""

import os
import struct
import sys

PAGE = 4096

# hlavicka .vmicd, viz vmicollect/src/writer_delta.c
VMICD_MAGIC = b"VMICDLT1"
VMICD_HDR = 64
VMICD_VERSION = 1
VMICD_FLAG_FULL = 1


class ChainError(ValueError):
    """
    Retazec .vmicd sa neda precitat tak, aby sa vysledku dalo verit.

    Dedi z ValueError zamerne: volajuci uz chybu formatu chytaju ako
    ValueError a nova kontrola im nesmie prepadnut inou vetvou.
    """


class RawImage:
    """Raw snimka: offset v subore == fyzicka adresa."""

    kind = "raw"

    def __init__(self, path):
        self.path = path
        self.paths = [path]
        self.f = open(path, "rb")
        self.size = os.path.getsize(path)
        self.page_size = PAGE
        self.memsize = self.size

    def read(self, pa, n):
        if pa is None or pa < 0 or n <= 0 or pa + n > self.size:
            return None
        self.f.seek(pa)
        b = self.f.read(n)
        return b if len(b) == n else None

    def page_present(self, pa):
        """Raw obraz nema zaznamovu strukturu - stranka v rozsahu suboru sa
        povazuje za pritomnu (riedke nuly su na nerozoznanie od obsahu)."""
        return pa is not None and 0 <= pa < self.size

    def pages(self):
        """Iteruje (index_stranky, obsah) - pre skenovanie; nulove preskakuje."""
        for idx in range(self.size // self.page_size):
            self.f.seek(idx * self.page_size)
            b = self.f.read(self.page_size)
            if b and b.strip(b"\0"):
                yield idx, b

    def page_count(self):
        return self.size // self.page_size

    def close(self):
        self.f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


class VmicdImage:
    """
    Snimka v nativnom formate zberaca (.vmicd), citana bez rozbalovania.

    Retazec je plna snimka + delty v poradi seq. Neskorsi zaznam prepisuje
    starsi, takze vysledok je stav pamate v case poslednej delty. Stranky,
    ktore v retazci nie su, su nulove - presne tak, ako ich zberac nenasiel
    (diera vo fyzickom priestore alebo nedotknuta pamat).

    Retazec sa pri otvoreni overuje (validate_chain). Kontrolu sa da vypnut
    iba vyslovne, parametrom validate=False - sluzi na skumanie rozbitych
    snimok v testoch, nie na bezne citanie.
    """

    kind = "vmicd"

    def __init__(self, paths, validate=True):
        if isinstance(paths, str):
            paths = [paths]
        self.index = {}          # index stranky -> (subor, offset)
        self.files = {}
        self.paths = list(paths)
        self.memsize = 0
        self.page_size = PAGE
        self.headers = [self.header(p) for p in self.paths]
        self.validated = bool(validate)
        if validate:
            validate_chain(self.headers)
        h0 = self.headers[0] if self.headers else None
        self.chain_id = h0["chain_id"] if h0 else None
        self.seq_from = h0["seq"] if h0 else None
        self.seq_to = self.headers[-1]["seq"] if self.headers else None
        self.full_baseline = bool(h0 and h0["full"])
        try:
            for h in self.headers:
                self._load(h)
        except Exception:
            # ked sa niektora cast odmietne, uz otvorene subory sa musia
            # zavriet - volajuci dostane vynimku, nie polootvoreny objekt
            self.close()
            raise

    @staticmethod
    def header(path):
        """Precita hlavicku bez otvarania celeho retazca (pouziva open_image)."""
        with open(path, "rb") as f:
            hdr = f.read(VMICD_HDR)
        if len(hdr) != VMICD_HDR or hdr[:8] != VMICD_MAGIC:
            raise ValueError("%s: nie je .vmicd" % path)
        magic, ver, psz, chain, seq, memsize, nrec, flags, sig = struct.unpack(
            "<8sIIQQQQQQ", hdr
        )
        if ver != VMICD_VERSION:
            # C strana (read_header) taky subor odmietne; ticho precitat
            # neznamu verziu by znamenalo hadat rozlozenie zaznamov
            raise ValueError("%s: nepodporovana verzia formatu %d "
                             "(tento balik cita verziu %d)"
                             % (path, ver, VMICD_VERSION))
        return {
            "path": path,
            "version": ver,
            "page_size": psz,
            "chain_id": chain,
            "seq": seq,
            "memsize": memsize,
            "records": nrec,
            "full": bool(flags & VMICD_FLAG_FULL),
            "region_sig": sig,
        }

    def _load(self, h):
        path = h["path"]
        if h["page_size"] <= 0 or h["page_size"] % 4096:
            raise ChainError("%s: nepodporovana velkost stranky %d"
                             % (path, h["page_size"]))
        psz = h["page_size"]
        size = os.path.getsize(path)
        need = VMICD_HDR + h["records"] * (8 + psz)
        if size < need:
            # C strana to hlasi ako "'%s' je skrateny (zaznam i/n)"; ticho
            # precitat prvu polovicu zaznamov by dalo neuplnu snimku
            raise ChainError(
                "%s: subor je skrateny - hlavicka slubuje %d zaznamov "
                "(%d B), subor ma %d B" % (path, h["records"], need, size))
        f = open(path, "rb")
        self.files[path] = f
        self.page_size = psz
        self.memsize = max(self.memsize, h["memsize"])
        # Zaznamy su pevne dlhe (8 B index + stranka), takze sa index da
        # postavit citanim samotnych indexov - obsah sa nikdy nekopiruje.
        off = VMICD_HDR
        for _ in range(h["records"]):
            f.seek(off)
            raw = f.read(8)
            if len(raw) != 8:
                break
            idx = struct.unpack("<Q", raw)[0]
            self.index[idx] = (path, off + 8)   # neskorsi subor prepise starsi
            off += 8 + psz

    def _page(self, idx):
        loc = self.index.get(idx)
        if loc is None:
            return b"\0" * self.page_size
        path, off = loc
        f = self.files[path]
        f.seek(off)
        return f.read(self.page_size)

    def read(self, pa, n):
        if pa is None or pa < 0 or n <= 0:
            return None
        out = bytearray()
        while n > 0:
            idx, off = divmod(pa, self.page_size)
            take = min(self.page_size - off, n)
            pg = self._page(idx)
            if len(pg) < self.page_size:
                return None
            out += pg[off:off + take]
            pa += take
            n -= take
        return bytes(out)

    def page_present(self, pa):
        """True, ked je stranka naozaj v retazci. Citanie (read) vracia za
        chybajucu stranku nuly - diera vo fyzickom priestore - takze bez
        tejto metody sa chybajuca a nulova stranka neda rozlisit."""
        if pa is None or pa < 0:
            return False
        return (pa // self.page_size) in self.index

    def pages(self):
        for idx in sorted(self.index):
            pg = self._page(idx)
            if pg.strip(b"\0"):
                yield idx, pg

    def page_count(self):
        return len(self.index)

    def chain_info(self):
        """Zhrnutie retazca pre vypis `info` - co sa vlastne otvorilo."""
        return {
            "chain_id": self.chain_id,
            "parts": len(self.paths),
            "seq_from": self.seq_from,
            "seq_to": self.seq_to,
            "full_baseline": self.full_baseline,
            "validated": self.validated,
        }

    def close(self):
        for f in self.files.values():
            f.close()

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()


# --------------------------------------------------------- overenie retazca


def validate_chain(headers):
    """
    Overi, ze hlavicky tvoria retazec, ktory sa da bez tichej chyby precitat.

    Semantika je zhodna s vmic_delta_restore() (vmicollect/src/writer_delta.c,
    cast "OVERENIE SUVISLOSTI RETAZCA"):

      1. retazec nie je prazdny;
      2. vsetky casti maju rovnaky chain_id;
      3. subory su v poradi rastuceho seq a ziadne seq sa neopakuje;
      4. prva cast je PLNA snimka (baseline), inak sa delty aplikuju na nic;
      5. seq su suvisle - ziadna cast nesmie chybat;
      6. page_size je v celom retazci rovnaka;
      7. region_sig je v celom retazci rovnaky (rovnaka konfiguracia oblasti).

    Vyhodi ChainError s presnym popisom toho, co chyba. Nevracia nic.
    """
    if not headers:
        raise ChainError("retazec je prazdny: ziadny subor .vmicd")

    chains = sorted({h["chain_id"] for h in headers})
    if len(chains) != 1:
        raise ChainError(
            "retazec miesa %d rozne chain_id (%s) - stranky z roznych "
            "retazcov spolu nedavaju jeden stav pamate; subory: %s"
            % (len(chains), ", ".join(str(c) for c in chains),
               ", ".join(os.path.basename(h["path"]) for h in headers)))

    first = headers[0]
    chain = first["chain_id"]

    if not first["full"]:
        raise ChainError(
            "retazec %d nezacina plnou snimkou: prva cast je delta "
            "(seq=%d, %s). Delta nesie iba zmenene stranky, takze bez "
            "baseline by sa citala pamat, ktora v hostovi nikdy "
            "neexistovala. Baseline chyba - bud sa nezozbierala, alebo ju "
            "zmazala retencia."
            % (chain, first["seq"], os.path.basename(first["path"])))

    for i, h in enumerate(headers):
        if h["page_size"] != first["page_size"]:
            raise ChainError(
                "nekonzistentna velkost stranky v retazci %d: %s ma %d B, "
                "%s ma %d B"
                % (chain, os.path.basename(first["path"]), first["page_size"],
                   os.path.basename(h["path"]), h["page_size"]))
        if h["region_sig"] != first["region_sig"]:
            raise ChainError(
                "cast seq=%d (%s) bola zozbierana s inou konfiguraciou "
                "oblasti pamate (region_sig 0x%x vs 0x%x) - indexy stranok "
                "z nej ukazuju inam nez v baseline"
                % (h["seq"], os.path.basename(h["path"]), h["region_sig"],
                   first["region_sig"]))
        if i == 0:
            continue
        prev = headers[i - 1]
        if h["seq"] == prev["seq"]:
            raise ChainError(
                "dve casti s rovnakym seq=%d ('%s' a '%s') - neda sa urcit, "
                "ktora je novsia"
                % (h["seq"], os.path.basename(prev["path"]),
                   os.path.basename(h["path"])))
        if h["seq"] < prev["seq"]:
            raise ChainError(
                "casti nie su zoradene podla seq (%d po %d): neskorsi zaznam "
                "prepisuje starsi, takze na poradi zalezi"
                % (h["seq"], prev["seq"]))
        if h["seq"] != prev["seq"] + 1:
            missing = list(range(prev["seq"] + 1, h["seq"]))
            raise ChainError(
                "v retazci %d chyba snimka seq=%s (mam %d, potom rovno %d) - "
                "stranky, ktore mala priniest, by ostali v stave spred nej a "
                "citala by sa TICHO nekonzistentna pamat. Ak staci stav po "
                "poslednej suvislej casti, pouzi --chain-until %d."
                % (chain, ", ".join(str(s) for s in missing),
                   prev["seq"], h["seq"], prev["seq"]))


def chain_headers(directory, chain_id=None, until_seq=None, warn=True):
    """
    Precita hlavicky .vmicd v adresari a vyberie z nich jeden retazec.

    V adresari moze lezat viac retazcov (kazda plna snimka zacina novy).
    Miesanie dvoch retazcov by dalo nekonzistentnu pamat, preto sa berie
    ten s najvyssim chain_id, ak sa nepovie inak. `until_seq` odreze
    retazec po danom seq - rovnako ako `vmicollect restore --until`.

    Subor, ktory sa neda precitat ako .vmicd, sa preskoci a NAHLASI sa
    (C strana to robi rovnako, LOGW "nie je platny .vmicd subor").
    """
    parts, skipped = [], []
    for name in sorted(os.listdir(directory)):
        if not name.endswith(".vmicd"):
            continue
        p = os.path.join(directory, name)
        try:
            parts.append(VmicdImage.header(p))
        except (ValueError, OSError) as exc:
            skipped.append(str(exc))
            continue
    if warn and skipped:
        for msg in skipped:
            sys.stderr.write("upozornenie: preskakujem subor - %s\n" % msg)
    if not parts:
        raise ChainError(
            "%s: ziadny citatelny subor .vmicd%s"
            % (directory,
               " (%d suborov sa nedalo precitat)" % len(skipped)
               if skipped else ""))

    if chain_id is None:
        pritomne = sorted({h["chain_id"] for h in parts})
        chain_id = max(pritomne)
        # Viac retazcov v jednom adresari znamena, ze sa tu zbieralo viackrat.
        # Vybrat ten najnovsi je rozumne vychodisko, ale ticho to spravit nie je:
        # kto ziadal starsi beh, by dostal cudzie cisla a nedozvedel sa o tom.
        if warn and len(pritomne) > 1:
            print("guestparse: v '%s' je %d retazcov (%s); beriem najnovsi %d, "
                  "iny sa vybera cez chain_id"
                  % (directory, len(pritomne),
                     ", ".join(str(c) for c in pritomne), chain_id),
                  file=sys.stderr)
    sel = [h for h in parts if h["chain_id"] == chain_id]
    if not sel:
        raise ChainError("%s: retazec %d sa nenasiel (su tu: %s)"
                         % (directory, chain_id,
                            ", ".join(str(c) for c in
                                      sorted({h["chain_id"] for h in parts}))))
    sel.sort(key=lambda h: h["seq"])
    if until_seq is not None:
        sel = [h for h in sel if h["seq"] <= until_seq]
        if not sel:
            raise ChainError(
                "%s: v retazci %d nie je ziadna cast so seq <= %d"
                % (directory, chain_id, until_seq))
    validate_chain(sel)
    return sel


def chain_files(directory, chain_id=None, until_seq=None, warn=True):
    """Cesty jedneho overeneho retazca, v poradi seq (viz chain_headers)."""
    return [h["path"] for h in
            chain_headers(directory, chain_id, until_seq, warn)]


def open_image(path, chain_id=None, until_seq=None, validate=True):
    """
    Otvori snimku: adresar s retazcom .vmicd, jeden .vmicd, alebo raw obraz.

    Rozbity retazec sa NEOTVORI - vyhodi sa ChainError. Jeden samostatny
    .vmicd musi byt plna snimka; samotna delta je bez baseline necitatelna
    a odmietne sa z toho isteho dovodu.
    """
    if os.path.isdir(path):
        parts = chain_files(path, chain_id, until_seq) if validate else [
            os.path.join(path, n) for n in sorted(os.listdir(path))
            if n.endswith(".vmicd")]
        return VmicdImage(parts, validate=validate)
    if path.endswith(".vmicd"):
        return VmicdImage(path, validate=validate)
    return RawImage(path)
