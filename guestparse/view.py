"""
Pohlad na hosta nad jednou snimkou: preklad adries a rekonstrukcia objektov.

Snimka je ziva - VM sa pri zbere nezastavuje, takze stranky pochadzaju z
roznych okamihov a spajany zoznam sa moze roztrhnut. Preto ma kazdy prechod
zoznamu strop, detekciu cyklu a kontrolu rozumnosti hodnot, a ked sa prerusi,
vysledok to hlasi polom 'truncated' - tichy polovicny zoznam by sa nedal
odlisit od skutocneho stavu hosta.
"""

import ipaddress
import struct
from uuid import UUID

from .context import boot_uuid, capture_boot_id
from .image import PAGE
from .profile import ProfileError

START_KERNEL_MAP = 0xFFFFFFFF80000000
MODULES_VADDR = 0xFFFFFFFFC0000000      # koniec linearne mapovaneho obrazu jadra
KERNEL_VA_MIN = 0xFFFF800000000000      # najnizsia kanonicka adresa jadra
LIST_POISON2 = 0xDEAD000000000122       # list_del_rcu: prev odstraneneho uzla (x86_64)
PTE_P, PTE_RW, PTE_US, PTE_PS = 1, 2, 4, 1 << 7
PTE_NX = 1 << 63
PTE_ADDR = 0x000FFFFFFFFFF000
DIRECT_MAP_MAX = 1 << 46                # 64 TiB okno priameho mappingu

AF_INET = 2
AF_INET6 = 10

PID_MAX = 4 * 1024 * 1024


class GuestView:
    """
    Preklad adries ma tri cesty, presne ako jadro x86_64:
      - obraz jadra:    PA = VA - __START_KERNEL_map + posun   (linearne)
      - priamy mapping: PA = VA - page_offset_base             (linearne)
      - oblast modulov a vmalloc: prechod tabuliek stranok z init_top_pgt

    Posun sa nehada: kandidati sa najdu skenovanim banneru a vyberie sa ten,
    pri ktorom init_task.comm naozaj obsahuje "swapper/0".
    """

    TCP_STATES = {
        1: "ESTABLISHED", 2: "SYN_SENT", 3: "SYN_RECV", 4: "FIN_WAIT1",
        5: "FIN_WAIT2", 6: "TIME_WAIT", 7: "CLOSE", 8: "CLOSE_WAIT",
        9: "LAST_ACK", 10: "LISTEN", 11: "CLOSING", 12: "NEW_SYN_RECV",
    }

    # Protokol sa neuhadne z cisla portu ani z rodiny: porovnava sa ukazovatel
    # skc_prot so symbolmi hosta. IPv6 ma vlastne `proto` struktury, preto sa
    # bez v6 symbolov socket reportoval ako "?".
    PROTO_SYMS = (
        ("tcp_prot", "TCP"), ("udp_prot", "UDP"), ("raw_prot", "RAW"),
        ("tcpv6_prot", "TCP"), ("udpv6_prot", "UDP"), ("rawv6_prot", "RAW"),
    )

    PTE_PRESENT = 1 << 0
    PTE_PSE = 1 << 7

    # Mena urovni tabuliek stranok x86_64 - kvoli hlaske, ktora povie, KDE
    # prechod skoncil. "zlyhalo to" bez urovne sa nedalo odlisit od chybajucej
    # stranky v snimke.
    PGT_LEVELS = ("PGD", "PUD", "PMD", "PTE")

    def __init__(self, img, prof, expected_boot_id=None):
        self.img = img
        self.p = prof
        self.ktext_shift = None
        self.page_offset_base = None
        self.banner = None
        self.banner_pa = None
        self.banner_candidates = 0
        self.expected_boot_id = boot_uuid(expected_boot_id) if expected_boot_id is not None else None
        self.snapshot_boot_id = None
        self.kernel_candidates = []
        self._resolve_error = None
        # Posun, o ktory sa profil preukotvil na boot snimky (A2);
        # 0 = profil a snimka su z toho isteho bootu.
        self.reanchored = 0
        # Nad hranicou uz nie je RAM snimky; ukazovatel, ktory sem trafi,
        # je roztrhnuty zoznam, nie platny objekt.
        self.max_pa = max(getattr(img, "memsize", 0) or 0,
                          getattr(img, "size", 0) or 0)

    # ------------------------------------------------------------- posun

    def resolve(self, banner_text=None):
        """
        Najde posun obrazu jadra (KASLR) a bazu priameho mappingu.

        Skenuje sa banner: kazdy jeho vyskyt je kandidat na fyzicku adresu
        symbolu linux_banner. Kandidat plati az vtedy, ked pri jeho posune
        sedi init_task.comm == "swapper/0". Po reboote moze RAM obsahovat
        aj stare jadro s rovnakou dvojicou kotiev. Pri native zbere musi
        sysctl_bootid sediet s identitou ulozenou pred zberom; bez nej sa
        viac kandidatov odmietne. Pocet procesov ani verdikt integrity
        nerozhoduju o tom, ktoru kopiu jadra vybrat.
        """
        self.ktext_shift = self.page_offset_base = None
        self.banner = self.banner_pa = self.snapshot_boot_id = None
        self.kernel_candidates = []
        self._resolve_error = None
        needle = (banner_text or "Linux version ").encode()
        comm_off = self.p.member("task_struct", "comm")
        banner_va = self.p.addr("linux_banner")
        init_va = self.p.addr("init_task")
        if comm_off is None or banner_va is None or init_va is None:
            return False
        boot_va = self.p.addr("sysctl_bootid")
        if self.expected_boot_id is not None and boot_va is None:
            self._resolve_error = "profil nema sysctl_bootid; boot snimky sa neda overit"
            return False

        seen = 0
        matches = []
        for pa in self._find(needle):
            seen += 1
            shift = pa - (banner_va - START_KERNEL_MAP)
            ipa = init_va - START_KERNEL_MAP + shift
            if ipa < 0 or (self.max_pa and ipa + comm_off + 16 > self.max_pa):
                continue
            comm = self.img.read(ipa + comm_off, 16)
            if comm and comm.split(b"\0")[0] == b"swapper/0":
                boot_pa = boot_va - START_KERNEL_MAP + shift if boot_va is not None else None
                raw_boot = self.img.read(boot_pa, 16) if self._ok(boot_pa, 16) else None
                boot_id = str(UUID(bytes=raw_boot)) if raw_boot and len(raw_boot) == 16 and any(raw_boot) else None
                candidate = {"banner_pa": pa, "init_task_pa": ipa, "boot_id": boot_id}
                self.kernel_candidates.append(candidate)
                if self.expected_boot_id is None or boot_id == self.expected_boot_id:
                    matches.append((shift, candidate))
        self.banner_candidates = seen
        if not matches:
            if self.expected_boot_id is not None:
                self._resolve_error = "ziadna kotva jadra nema zaznamenany boot_id " + self.expected_boot_id
            return False
        if len(matches) != 1:
            self._resolve_error = ("nejednoznacne kotvy jadra: %d kandidatov; "
                                   "treba jednoznacny boot_id zo zberu" % len(matches))
            return False
        self.ktext_shift, selected = matches[0]
        self.banner_pa = selected["banner_pa"]
        self.snapshot_boot_id = selected["boot_id"]
        raw = self.img.read(self.banner_pa, 256) or b""
        self.banner = raw.split(b"\n")[0].split(b"\0")[0].decode("utf8", "replace")
        pob_sym = self.p.addr("page_offset_base")
        if pob_sym is not None:
            self.page_offset_base = self.u64(self.ktext_pa(pob_sym))
        return True

    def resolve_problem(self):
        """
        Preco sa posun jadra nenasiel - pomenovany podla skutocnej priciny.

        Rozlisuju sa tri rozne veci, ktore sa pred tym hlasili jednou vetou
        ("Sedi profil s jadrom v snimke?"), hoci profil za dve z nich nemoze:
          - v profile chybaju symboly, bez ktorych sa hladat neda;
          - banner sa v snimke vobec nenasiel: snimke chybaju stranky s
            textom jadra (typicky delta bez plnej snimky alebo orezany obraz);
          - banner sa nasiel, ale init_task.comm pri nom nesedi: vtedy je na
            rade naozaj profil z ineho jadra.
        """
        if self.ktext_shift is not None:
            return None
        if self._resolve_error:
            return self._resolve_error
        chyba = [n for n in ("linux_banner", "init_task")
                 if self.p.addr(n) is None]
        if self.p.member("task_struct", "comm") is None:
            chyba.append("task_struct.comm")
        if chyba:
            return ("profil je neuplny: chyba %s - bez toho sa posun jadra "
                    "hladat neda" % ", ".join(chyba))
        if self.banner_candidates == 0:
            return ("banner jadra sa v snimke nenasiel (0 kandidatov): snimka "
                    "neobsahuje stranky s textom jadra. Otvoril si cely "
                    "retazec aj s plnou snimkou, alebo iba vyrez/deltu?")
        return ("nasiel som %d kandidatov banneru, ale pri ziadnom nesedi "
                "init_task.comm == 'swapper/0': profil (kallsyms/BTF) je "
                "zrejme z ineho jadra, nez bezi v snimke"
                % self.banner_candidates)

    def _find(self, needle):
        """Najde vsetky vyskyty retazca vo fyzickej pamati snimky."""
        prev_idx, tail = None, b""
        keep = max(len(needle) - 1, 0)
        for idx, pg in self.img.pages():
            base = idx * PAGE
            if prev_idx is not None and idx == prev_idx + 1 and tail:
                blob, origin = tail + pg, base - len(tail)
            else:
                blob, origin = pg, base
            start = 0
            while True:
                k = blob.find(needle, start)
                if k < 0:
                    break
                yield origin + k
                start = k + 1
            prev_idx, tail = idx, pg[-keep:] if keep else b""

    # ------------------------------------------------------- preklad adries

    def ktext_pa(self, va):
        if self.ktext_shift is None:
            return None
        return va - START_KERNEL_MAP + self.ktext_shift

    def direct_pa(self, va):
        if self.page_offset_base is None:
            return None
        pa = va - self.page_offset_base
        return pa if 0 <= pa < DIRECT_MAP_MAX else None

    def _pgt_root(self):
        """Fyzicka adresa vrcholovej tabulky stranok jadra hosta."""
        sym = self.p.addr("init_top_pgt")
        return self.ktext_pa(sym) if sym is not None else None

    def _page_present(self, pa):
        """
        Je stranka s touto fyzickou adresou naozaj v snimke?

        Retazec .vmicd cita nezozbieranu stranku ako nulovu (tak ju zberac
        nasiel). Bez tejto otazky sa "polozka tabuliek je prazdna" neda
        odlisit od "tu stranku sme nezbierali" - a prave na tomto rozdiele
        stoji diagnoza profilu z ineho bootu.
        """
        if pa is None or pa < 0:
            return False
        idx = getattr(self.img, "index", None)
        if idx is not None:                      # .vmicd: mapa zozbieranych stranok
            return (pa // self.img.page_size) in idx
        size = (getattr(self.img, "size", 0)
                or getattr(self.img, "memsize", 0) or 0)
        if size:                                 # raw obraz: vsetko do velkosti
            return pa < size
        # Obal, ktory sa na pritomnost spytat neda (napr. Recorder v
        # tests/data/make_mini.py): nepredstieraj, ze stranka chyba - z
        # "neviem" by inak vznikla diagnoza.
        return True

    def walk_pa_detail(self, va, root_pa=None):
        """
        Preklad virtualnej adresy hosta prechodom tabuliek stranok
        (4 urovne, x86_64). Pokryva aj oblasti, ktore linearne mapovane nie su -
        moduly a vmalloc.

        `root_pa` = fyzicka adresa vrcholovej tabulky. Default je
        init_top_pgt (jadro); pre uzivatelsky priestor procesu sa podava
        jeho mm->pgd (preklad cez to_pa), pozri guestparse/procmap.py.

        Vracia {'pa', 'level', 'index', 'reason', 'reason_code'}; 'pa' je None,
        ked sa prechod nedokoncil. Velke stranky (1 GiB, 2 MiB) sa rozpoznaju
        podla bitu PSE.

        Kody dovodov (na nich stoji diagnoza, nie na samotnom None):
          bez_korena     - nepozname posun jadra alebo init_top_pgt
          chyba_tabulka  - tabulku na tej urovni snimka neobsahuje (nic to
                           nehovori o profile, iba o tom, co sa zozbieralo)
          chyba_polozka  - tabulka V SNIMKE JE, ale polozka pre tuto adresu
                           v nej nie je pritomna, teda jadro tuto virtualnu
                           adresu nemapuje
        """
        out = {"pa": None, "level": None, "index": None,
               "reason": None, "reason_code": None}
        table = self._pgt_root() if root_pa is None else root_pa
        if table is None:
            out["reason_code"] = "bez_korena"
            out["reason"] = ("neznamy posun jadra alebo profil nema "
                             "init_top_pgt")
            return out
        # bity 47:39 / 38:30 / 29:21 / 20:12
        for level, shift in enumerate((39, 30, 21, 12)):
            idx = (va >> shift) & 0x1FF
            name = self.PGT_LEVELS[level]
            ent = self.u64(table + idx * 8) if self._page_present(table) else None
            if ent is None:
                out.update(level=name, index=idx, reason_code="chyba_tabulka",
                           reason="tabulka %s na 0x%x nie je v snimke"
                                  % (name, table))
                return out
            if not (ent & self.PTE_PRESENT):
                out.update(level=name, index=idx, reason_code="chyba_polozka",
                           reason="polozka %s[%d] nie je pritomna"
                                  % (name, idx))
                return out
            phys = ent & 0x000FFFFFFFFFF000
            if level in (1, 2) and (ent & self.PTE_PSE):
                size = 1 << shift
                out["pa"] = phys + (va & (size - 1))
                return out
            table = phys
        out["pa"] = table + (va & 0xFFF)
        return out

    def walk_pa(self, va):
        """Prechod tabuliek stranok; iba fyzicka adresa, bez dovodu."""
        return self.walk_pa_detail(va)["pa"]

    def to_pa(self, va):
        """
        Preklad, ktory najprv skusi lacne linearne vetvy a az potom tabulky
        stranok. Horna hranica obrazu jadra je MODULES_VADDR: nad nou uz
        linearny vztah neplati a vypocet by ticho vratil cudziu stranku.
        """
        if va is None:
            return None
        if (self.ktext_shift is not None
                and START_KERNEL_MAP <= va < MODULES_VADDR):
            pa = self.ktext_pa(va)
            if pa is not None and pa >= 0:
                return pa
        if self.page_offset_base is not None and va >= self.page_offset_base:
            pa = self.direct_pa(va)
            if pa is not None:
                return pa
        return self.walk_pa(va)

    # ------------------------------------------------------------- citanie

    def _ok(self, pa, n):
        return pa is not None and pa >= 0 and (
            not self.max_pa or pa + n <= self.max_pa)

    def u64(self, pa):
        if not self._ok(pa, 8):
            return None
        b = self.img.read(pa, 8)
        return struct.unpack("<Q", b)[0] if b else None

    def i32(self, pa):
        if not self._ok(pa, 4):
            return None
        b = self.img.read(pa, 4)
        return struct.unpack("<i", b)[0] if b else None

    def u16(self, pa, big=False):
        if not self._ok(pa, 2):
            return None
        b = self.img.read(pa, 2)
        return struct.unpack(">H" if big else "<H", b)[0] if b else None

    def u8(self, pa):
        if not self._ok(pa, 1):
            return None
        b = self.img.read(pa, 1)
        return b[0] if b else None

    def cstr(self, pa, n):
        if not self._ok(pa, n):
            return ""
        b = self.img.read(pa, n)
        return b.split(b"\0")[0].decode("utf8", "replace") if b else ""

    @staticmethod
    def _plausible_va(va):
        """Kanonicka adresa jadra, zarovnana na 8 B - inak je to smetie."""
        return bool(va) and va >= KERNEL_VA_MIN and (va & 7) == 0

    # ----------------------------------------------------------- procesy

    def processes(self, limit=8192):
        """
        Prejde zoznam init_task.tasks. Kazdy uzol ukazuje na pole `tasks`
        dalsieho task_struct, takze zaciatok struktury je uzol minus offset.
        Prechod konci navratom do init_task alebo na uz videnom uzle.

        Ziva snimka cita stranky v roznych okamihoch, takze spojenie moze
        pochadzat z ineho okamihu nez uzol, na ktory ukazuje (session
        benign-v3-20261022_03_train_bursty, snimka 505: `next` posledneho
        vlakna ukazoval na uz ukonceny proces so starymi ukazovatelmi a
        prechod sa zacyklil). Ked sa zoznam dopredu neuzavrie, prejde sa
        dozadu cez `prev`. Zoznam potom tvoria uzly, ktore prechod dopredu
        presiel pred prvym spojenim nezhodnym s opacnym smerom (uzol.prev
        neukazuje tam, odkial sa k nemu prislo), ale iba ak sa prechod dozadu
        uzavrel cez presne tie iste uzly. Samotne uzavretie nestaci: v tej
        istej session sa prechod dozadu v snimke 529 uzavrel cez 78 procesov
        namiesto 110.

        Opacny pripad je vlozenie na koniec (session
        benign-v5-20261025_18_train_quiet, snimka 613): kthreadd vlozil nove
        vlakno do recyklovaneho task_struct, ktoreho stranka sa precitala
        pred jeho inicializaciou - drzala ukonceny thread so spojeniami
        skopirovanymi od vodcu skupiny. `next` posledneho uzla aj `prev`
        init_task, precitane neskor, uz ukazovali na novy uzol, takze prechod
        dopredu z neho skocil doprostred zoznamu a zacyklil sa a prechod
        dozadu presiel iba 79 zo 110 uzlov. Ked init_task.prev ukazuje prave
        na prvy nezhodny uzol, je to posledny uzol zoznamu podla oboch
        spojeni, ktore nanho vedu. To samo nestaci (rovnaky obraz da aj
        uzol, pred ktorym sa medzi citaniami odstranili ine), preto musi byt
        jeho obsah vlakno (tgid != pid), ktoreho vodca je medzi zhodnymi
        uzlmi pred nim. copy_process vklada do init_task.tasks iba vodcov
        skupin; de_thread pri exec z vedlajsieho vlakna dava to vlakno na
        miesto vodcu, takze vtedy vodca v zozname nie je. Taka stranka je
        teda z ineho okamihu nez spojenia, ktore na uzol vedu. Zoznam potom
        tvoria uzly pred nim, ktorych spojenia sa zhoduju v oboch smeroch;
        novy proces pribudne v dalsej snimke. Zvyskove riziko (exec vedlajsieho
        vlakna procesu na konci zoznamu) je v L1 v docs/LIMITACIE.md.

        Pravidlo 'tail' moze predchadzat aj nezhodne spojenie, ktore vysvetli
        odstranenie procesu v tom istom obraze (session
        events-v3-20261108_46_test_events_write_heavy, snimka 270: proces
        sluzby worker a jeho postgres zanikli pocas citania). Uzol X dosiahnuty
        z uzla A ma `prev` na uzol D namiesto A, ale stranka D ukazuje D
        odstraneny cez list_del_rcu (D.prev == LIST_POISON2) a D.next == X.
        Stranka X je teda z casu pred odstranenim D a A.next uz D obchadza.
        Take spojenie nie je roztrhnutie, ktore by skrylo uzol: D v zozname
        po odstraneni nie je. Pravidlo 'prev' sa tym nemeni (prechod dozadu
        cez X skonci na LIST_POISON2 a neuzavrie sa).

        Vracia {'processes', 'count', 'truncated', 'stop_reason', 'walk'}.
        'walk' je 'next', 'prev', ked zoznam potvrdil prechod dozadu, alebo
        'tail', ked prvy nezhodny uzol je podla init_task.prev posledny a
        jeho obsah je vlakno procesu zo zoznamu;
        pri 'prev' a 'tail' je dovod zastavenia dopredu vo
        'forward_stop_reason'. 'truncated' znamena, ze zoznam sa neuzavrel -
        vysledok je dolna hranica z prechodu dopredu a 'backward_stop_reason'
        hovori, preco ho nepotvrdil prechod dozadu.
        """
        need = ("tasks", "comm", "pid", "tgid", "mm")
        m = {}
        for f in need:
            m[f] = self.p.member("task_struct", f)
            if m[f] is None:
                return self._result("processes", [], True,
                                    "profil nema task_struct.%s" % f)
        init_va = self.p.addr("init_task")
        init_pa = self.ktext_pa(init_va) if init_va is not None else None
        if init_pa is None:
            return self._result("processes", [], True, "neznamy posun jadra")

        out, stop, zhodne, vysvetlene = self._prechod_tasks(init_pa, init_va, m, 0, limit)
        if stop is None:
            return dict(self._result("processes", out, False, None), walk="next")
        spat, stop_spat, _, _ = self._prechod_tasks(init_pa, init_va, m, 8, limit)
        if stop_spat is None and zhodne and ({pr["task_va"] for pr in spat}
                                             == {pr["task_va"] for pr in out[:zhodne]}):
            return dict(self._result("processes", out[:zhodne], False, None),
                        walk="prev", forward_stop_reason=stop)
        koniec = vysvetlene["zhodne"]
        posledny = out[koniec] if 0 < koniec < len(out) else None
        if (posledny is not None and posledny["tgid"] != posledny["pid"]
                and posledny["tgid"] in {pr["pid"] for pr in out[:koniec]}
                and self.u64(init_pa + m["tasks"] + 8) == posledny["task_va"] + m["tasks"]):
            res = dict(self._result("processes", out[:koniec], False, None),
                       walk="tail", forward_stop_reason=stop)
            if vysvetlene["odstranene"]:
                res["deleted_links"] = vysvetlene["odstranene"]
            return res
        return dict(self._result("processes", out, True, stop), walk="next",
                    backward_stop_reason=stop_spat
                    or "prechod dozadu presiel ine uzly ako zhodne spojenia dopredu")

    def _prechod_tasks(self, init_pa, init_va, m, smer, limit):
        """
        Jeden smer zoznamu init_task.tasks: `smer` 0 ide cez `next`, 8 cez
        `prev`. Vracia (procesy v poradi prechodu, dovod zastavenia alebo
        None, pocet uzlov pred prvym uzlom, ktoreho opacne spojenie
        neukazuje tam, odkial sa k nemu prislo, a pre smer 0 slovnik
        {'zhodne': to iste bez spojeni vysvetlenych odstranenim uzla v tom
        istom obraze, 'odstranene': pocet takych spojeni}).
        """
        head_va = init_va + m["tasks"]
        out, seen = [], set()
        stop = None
        odkial, zhodne = head_va, None
        vysvetlene = {"zhodne": None, "odstranene": 0}
        nxt = self.u64(init_pa + m["tasks"] + smer)
        while True:
            if nxt == head_va:
                break                                  # zoznam sa uzavrel
            if not self._plausible_va(nxt):
                stop = "nerozumny ukazovatel 0x%x" % (nxt or 0)
                break
            if nxt in seen:
                stop = "cyklus v zozname"
                break
            if len(out) >= limit:
                stop = "strop %d poloziek" % limit
                break
            seen.add(nxt)
            tpa = self.to_pa(nxt - m["tasks"])
            if tpa is None:
                stop = "task_struct sa neda prelozit"
                break
            comm = self.cstr(tpa + m["comm"], 16)
            pid = self.i32(tpa + m["pid"])
            tgid = self.i32(tpa + m["tgid"])
            mm = self.u64(tpa + m["mm"])
            if pid is None or pid < 0 or pid > PID_MAX:
                stop = "nerozumny pid %r" % pid
                break
            if not comm:
                stop = "prazdne comm pri pid %d" % pid
                break
            opacne = self.u64(tpa + m["tasks"] + 8 - smer)
            if opacne != odkial:
                if zhodne is None:
                    zhodne = len(out)
                if vysvetlene["zhodne"] is None:
                    if smer == 0 and self._odstraneny_pred(opacne, nxt, m, seen):
                        vysvetlene["odstranene"] += 1
                    else:
                        vysvetlene["zhodne"] = len(out)
            out.append({
                "pid": pid,
                "tgid": tgid,
                "comm": comm,
                "kernel_thread": mm == 0,
                "task_va": nxt - m["tasks"],
            })
            odkial = nxt
            nxt = self.u64(tpa + m["tasks"] + smer)
        if vysvetlene["zhodne"] is None:
            vysvetlene["zhodne"] = len(out)
        return out, stop, len(out) if zhodne is None else zhodne, vysvetlene

    def _odstraneny_pred(self, uzol, nasledovnik, m, seen):
        """
        Je `uzol` (spojenie tasks) proces odstraneny cez list_del_rcu, ktory
        v zozname stal tesne pred `nasledovnik`? Jeho stranka ma prev ==
        LIST_POISON2 a next == nasledovnik; prechod dopredu ho nepresiel.
        """
        if not self._plausible_va(uzol) or uzol in seen:
            return False
        upa = self.to_pa(uzol - m["tasks"])
        if upa is None:
            return False
        return (self.u64(upa + m["tasks"] + 8) == LIST_POISON2
                and self.u64(upa + m["tasks"]) == nasledovnik)

    # ------------------------------------------------------------- moduly

    def modules(self, limit=1024):
        """
        Prejde zoznam `modules`. Hlavicka je premenna v obraze jadra, clanky
        su struct module v oblasti modulov (0xffffffffc0000000+), ktora
        linearne mapovana NIE JE - preto prechod tabuliek stranok.
        """
        o_list = self.p.member("module", "list")
        o_name = self.p.member("module", "name")
        if o_list is None or o_name is None:
            return self._result("modules", [], True, "profil nema struct module")
        head_va = self.p.addr("modules")
        head_pa = self.ktext_pa(head_va) if head_va is not None else None
        if head_pa is None:
            return self._result("modules", [], True, "neznamy posun jadra")

        out, seen = [], set()
        stop = None
        nxt = self.u64(head_pa)
        while True:
            if nxt == head_va:
                break
            if not self._plausible_va(nxt):
                stop = "nerozumny ukazovatel 0x%x" % (nxt or 0)
                break
            if nxt in seen:
                stop = "cyklus v zozname"
                break
            if len(out) >= limit:
                stop = "strop %d poloziek" % limit
                break
            seen.add(nxt)
            mpa = self.walk_pa(nxt - o_list)
            if mpa is None:
                stop = "struct module sa neda prelozit"
                break
            name = self.cstr(mpa + o_name, 56)
            if not name or not name.isascii() or not name.isprintable():
                stop = "nerozumne meno modulu %r" % name
                break
            out.append({"name": name, "module_va": nxt - o_list})
            nxt = self.u64(mpa + o_list)
        return self._result("modules", out, stop is not None, stop)

    # ------------------------------------------------------------- sokety

    def sockets(self, procs=None, max_fds=4096):
        """
        Sietove spojenia hosta: pre kazdy proces sa prejde tabulka deskriptorov
        a vyberu sa tie, ktorych `file->f_op` je `socket_file_ops` (symbol
        hosta, nie heuristika). Z `struct socket` sa vezme `sk` a z jeho
        `sock_common` adresy, porty a stav.

        Protokol sa urci porovnanim `skc_prot` so symbolmi hosta (PROTO_SYMS).
        IPv6 sokety maju vlastne `proto` struktury (tcpv6_prot, udpv6_prot,
        rawv6_prot) aj vlastne polia adries (skc_v6_daddr, skc_v6_rcv_saddr,
        16 B); bez oboch by mal IPv6 socket protokol "?" a adresu precitanu
        zo styroch bajtov pola urceneho pre IPv4.
        """
        try:
            o_files, = self.p.require("task_struct", "files")
            o_fdt, = self.p.require("files_struct", "fdt")
            o_maxfds, o_fd = self.p.require("fdtable", "max_fds", "fd")
            o_fop, o_priv = self.p.require("file", "f_op", "private_data")
            o_sk, = self.p.require("socket", "sk")
            sc = {}
            for f in ("skc_family", "skc_state", "skc_dport", "skc_num",
                      "skc_rcv_saddr", "skc_daddr", "skc_prot",
                      "skc_v6_daddr", "skc_v6_rcv_saddr"):
                sc[f], = self.p.require("sock_common", f)
        except ProfileError as exc:                 # chybajuce pole v profile
            return self._result("sockets", [], True, str(exc))

        sock_fops = self.p.addr("socket_file_ops")
        if sock_fops is None:
            return self._result("sockets", [], True, "profil nema socket_file_ops")
        protos = {}
        for sym, name in self.PROTO_SYMS:
            a = self.p.addr(sym)
            if a is not None:
                protos[a] = name
        missing_syms = [s for s, _ in self.PROTO_SYMS if self.p.addr(s) is None]

        if procs is None:
            pres = self.processes()
            procs = pres["processes"]
            proc_trunc = pres["truncated"]
        else:
            proc_trunc = False

        out = []
        skipped = 0
        for pr in procs:
            if pr.get("kernel_thread"):
                continue
            tpa = self.to_pa(pr["task_va"])
            if tpa is None:
                skipped += 1
                continue
            files = self.u64(tpa + o_files)
            fpa = self.to_pa(files) if self._plausible_va(files) else None
            if fpa is None:
                skipped += 1
                continue
            fdt_va = self.u64(fpa + o_fdt)
            fdtpa = self.to_pa(fdt_va) if self._plausible_va(fdt_va) else None
            if fdtpa is None:
                skipped += 1
                continue
            nmax = self.i32(fdtpa + o_maxfds)
            arr = self.u64(fdtpa + o_fd)
            apa = self.to_pa(arr) if self._plausible_va(arr) else None
            if apa is None or nmax is None or nmax < 0:
                skipped += 1
                continue

            for i in range(min(nmax, max_fds)):
                fva = self.u64(apa + i * 8)
                if not self._plausible_va(fva):
                    continue
                fpa2 = self.to_pa(fva)
                if fpa2 is None:
                    continue
                if self.u64(fpa2 + o_fop) != sock_fops:
                    continue
                priv = self.u64(fpa2 + o_priv)
                spa = self.to_pa(priv) if self._plausible_va(priv) else None
                if spa is None:
                    continue
                sk = self.u64(spa + o_sk)
                skpa = self.to_pa(sk) if self._plausible_va(sk) else None
                if skpa is None:
                    continue
                row = self._socket_row(skpa, sc, protos)
                if row is None:
                    continue
                row["pid"] = pr["pid"]
                row["comm"] = pr["comm"]
                row["fd"] = i
                row["sk_va"] = sk
                out.append(row)

        res = self._result("sockets", out, proc_trunc,
                           "zoznam procesov je neuplny" if proc_trunc else None)
        res["skipped_tasks"] = skipped
        if missing_syms:
            res["missing_symbols"] = missing_syms
        return res

    # ------------------------------------------------ podozrive vzory pamate

    MEMFD_PREFIX = "memfd:"

    def memory_patterns(self, procs=None, max_fds=4096, max_tables=65536):
        """
        Dva vzory, ktore beznemu serveru nepatria a pouziva ich kod vlozeny
        do pamate: stranky zapisovatelne a zaroven spustitelne (W+X) a subory
        `memfd:` (anonymny subor v RAM, typicky pre spustenie bez suboru na
        disku, memfd_create + fexecve).

        W+X sa cita z uzivatelskych tabuliek stranok procesu (mm->pgd), nie zo
        stromu VMA: rozhoduje, co hardver naozaj dovoli. Stranka sa pocita,
        ked je pritomna, pouzivatelska, zapisovatelna na kazdej urovni a bez
        NX na urovniach PUD, PMD a PTE. NX na urovni PGD sa ignoruje: jadro
        s PTI ma v kopii PGD pre rezim jadra pouzivatelske polozky s NX
        (pti_set_user_pgtbl) a mm->pgd ukazuje na tuto kopiu; pouzivatelska
        kopia je bez neho. Pristupove prava na zapis bez skutocne zapisanej
        stranky (copy-on-write) sa neratia, lebo PTE ma vtedy RW = 0.

        memfd sa hlada v tabulke deskriptorov procesu (meno dentry zacina
        `memfd:`) a v mm->exe_file (proces spusteny z memfd). Mapovany memfd
        bez otvoreneho deskriptora tento prechod nevidi (L1 v
        docs/LIMITACIE.md).

        Vracia {'patterns', 'count', 'truncated', 'stop_reason',
        'wx_processes', 'memfd_processes', 'wx_pages', 'tables',
        'skipped_tasks'}; procesy zdielajuce mm (vfork) sa ratia raz.
        """
        try:
            o_mm, o_files = self.p.require("task_struct", "mm", "files")
            o_pgd, o_exe = self.p.require("mm_struct", "pgd", "exe_file")
            o_fdt, = self.p.require("files_struct", "fdt")
            o_maxfds, o_fd = self.p.require("fdtable", "max_fds", "fd")
            o_path, = self.p.require("file", "f_path")
            o_dentry, = self.p.require("path", "dentry")
            o_dname, = self.p.require("dentry", "d_name")
            o_qname, = self.p.require("qstr", "name")
        except ProfileError as exc:
            return dict(self._result("patterns", [], True, str(exc)), wx_processes=0,
                        memfd_processes=0, wx_pages=0, tables=0, skipped_tasks=0)
        if procs is None:
            pres = self.processes()
            procs, proc_trunc = pres["processes"], pres["truncated"]
        else:
            proc_trunc = False

        def file_name(fva):
            fpa = self.to_pa(fva) if self._plausible_va(fva) else None
            if fpa is None:
                return None
            d = self.u64(fpa + o_path + o_dentry)
            dpa = self.to_pa(d) if self._plausible_va(d) else None
            if dpa is None:
                return None
            name = self.u64(dpa + o_dname + o_qname)
            npa = self.to_pa(name) if self._plausible_va(name) else None
            return self.cstr(npa, len(self.MEMFD_PREFIX)) if npa is not None else None

        out, mms, skipped, tables, pages = [], set(), 0, 0, 0
        stop = None
        wx_pids, memfd_pids = set(), set()
        for pr in procs:
            if pr.get("kernel_thread"):
                continue
            tpa = self.to_pa(pr["task_va"])
            if tpa is None:
                skipped += 1
                continue
            mm = self.u64(tpa + o_mm)
            mpa = self.to_pa(mm) if self._plausible_va(mm) else None
            if mpa is not None and mm not in mms:
                mms.add(mm)
                pgd = self.u64(mpa + o_pgd)
                root = self.to_pa(pgd) if self._plausible_va(pgd) else None
                if root is None:
                    skipped += 1
                else:
                    n, t, capped = self._wx_pages(root, max_tables - tables)
                    tables += t
                    if capped:
                        stop = "strop %d tabuliek stranok" % max_tables
                    if n:
                        pages += n
                        wx_pids.add(pr["pid"])
                        out.append({"pid": pr["pid"], "comm": pr["comm"], "kind": "wx", "pages": n})
                exe = self.u64(mpa + o_exe)
                if exe and file_name(exe) == self.MEMFD_PREFIX:
                    memfd_pids.add(pr["pid"])
                    out.append({"pid": pr["pid"], "comm": pr["comm"], "kind": "memfd_exe"})
            if stop:
                break
            files = self.u64(tpa + o_files)
            fpa = self.to_pa(files) if self._plausible_va(files) else None
            fdt = self.u64(fpa + o_fdt) if fpa is not None else None
            fdtpa = self.to_pa(fdt) if self._plausible_va(fdt) else None
            nmax = self.i32(fdtpa + o_maxfds) if fdtpa is not None else None
            arr = self.u64(fdtpa + o_fd) if fdtpa is not None else None
            apa = self.to_pa(arr) if self._plausible_va(arr) else None
            if apa is None or nmax is None or nmax < 0:
                skipped += 1
                continue
            for i in range(min(nmax, max_fds)):
                fva = self.u64(apa + i * 8)
                if fva and file_name(fva) == self.MEMFD_PREFIX:
                    memfd_pids.add(pr["pid"])
                    out.append({"pid": pr["pid"], "comm": pr["comm"], "kind": "memfd_fd", "fd": i})
        truncated = proc_trunc or stop is not None
        res = self._result("patterns", out, truncated,
                           stop or ("zoznam procesov je neuplny" if proc_trunc else None))
        res.update(wx_processes=len(wx_pids), memfd_processes=len(memfd_pids),
                   wx_pages=pages, tables=tables, skipped_tasks=skipped)
        return res

    def _wx_pages(self, root_pa, max_tables):
        """
        Pocet 4 KiB stranok (velka stranka sa rata po 4 KiB) zapisovatelnych
        a spustitelnych z pouzivatelskeho rezimu pod korenom root_pa. Do
        nizsej urovne sa zostupuje iba cez polozky, ktore zapis a spustenie
        este dovoluju. Vracia (stranky, precitane tabulky, dosiahnuty strop).
        """
        need = PTE_P | PTE_RW | PTE_US
        need_nx = need | PTE_NX
        stack = [(root_pa, 0)]
        pages = tables = 0
        while stack:
            if tables >= max_tables:
                return pages, tables, True
            pa, lvl = stack.pop()
            raw = self.img.read(pa, PAGE)
            if not raw or len(raw) < PAGE:
                continue
            tables += 1
            entries = struct.unpack("<512Q", raw)
            if lvl == 0:                           # iba pouzivatelska polovica
                stack.extend(((e & PTE_ADDR, 1) for e in entries[:256] if e & need == need))
                continue
            if lvl == 3:
                pages += sum(1 for e in entries if e & need_nx == need)
                continue
            for e in entries:
                if e & need_nx != need:
                    continue
                if e & PTE_PS:
                    pages += 512 if lvl == 2 else 512 * 512
                else:
                    stack.append((e & PTE_ADDR, lvl + 1))
        return pages, tables, False

    def _socket_row(self, skpa, sc, protos):
        """Jeden riadok z sock_common; None ked to nie je IPv4/IPv6 socket."""
        fam = self.u16(skpa + sc["skc_family"])
        state = self.u8(skpa + sc["skc_state"])
        if fam is None or state is None or fam not in (AF_INET, AF_INET6):
            return None
        prot = self.u64(skpa + sc["skc_prot"])
        # skc_dport je v sietovom poradi, skc_num v poradi hostitela
        dport = self.u16(skpa + sc["skc_dport"], big=True)
        sport = self.u16(skpa + sc["skc_num"])
        if dport is None or sport is None:
            return None
        if fam == AF_INET6:
            saddr = self._ip6(skpa + sc["skc_v6_rcv_saddr"])
            daddr = self._ip6(skpa + sc["skc_v6_daddr"])
        else:
            saddr = self._ip4(skpa + sc["skc_rcv_saddr"])
            daddr = self._ip4(skpa + sc["skc_daddr"])
        if saddr is None or daddr is None:
            return None
        pname = protos.get(prot, "?")
        # skc_state je spolocne pole: pri datagramovych soketoch znamena
        # TCP_CLOSE "nepripojeny", nie zatvoreny - `ss` to tlaci ako UNCONN
        # a bez tohto prekladu by sa vystupy nedali porovnat.
        sname = self.TCP_STATES.get(state, str(state))
        if pname in ("UDP", "RAW") and state == 7:
            sname = "UNCONN"
        row = {
            "proto": pname,
            "family": "IPv4" if fam == AF_INET else "IPv6",
            "state": sname,
            "saddr": saddr,
            "sport": sport,
            "daddr": daddr,
            "dport": dport,
            "skc_prot": prot,
        }
        if pname == "RAW":
            # raw socket nema port: skc_num drzi cislo IP protokolu (58 = ICMPv6)
            row["sport_is_ip_protocol"] = True
        return row

    def _ip4(self, pa):
        b = self.img.read(pa, 4) if self._ok(pa, 4) else None
        return str(ipaddress.IPv4Address(b)) if b else None

    def _ip6(self, pa):
        # RFC 5952 (skratene nuly, male pismena) da ipaddress zo standardnej
        # kniznice; ::ffff:a.b.c.d ostane citatelne ako IPv4-mapped
        b = self.img.read(pa, 16) if self._ok(pa, 16) else None
        return str(ipaddress.IPv6Address(b)) if b else None

    # --------------------------------------------------------------- info

    def info(self):
        """Zhrnutie snimky a profilu vratane krizovej kontroly prekladu adries."""
        img = self.img
        out = {
            "image": {
                "kind": getattr(img, "kind", "?"),
                "files": [str(p) for p in getattr(img, "paths", [])],
                "page_size": img.page_size,
                "pages_present": img.page_count(),
                "memsize": getattr(img, "memsize", 0),
                # retazec .vmicd: co sa otvorilo a ci to preslo overenim
                "chain": (img.chain_info()
                          if hasattr(img, "chain_info") else None),
            },
            "profile": {
                "kallsyms": self.p.kallsyms_path,
                "btf": self.p.btf_path,
                "symbols": len(self.p.sym),
                "structs": sorted(self.p.off),
                # z boot.json (zapisuje scripts/get_profile.sh); starsi profil
                # ho nema a vtedy su hodnoty None - nedopisuju sa odhadom
                "boot_id": getattr(self.p, "meta", {}).get("boot_id"),
                "captured": getattr(self.p, "meta", {}).get("captured"),
                "guest_kernel": getattr(self.p, "meta", {}).get("guest_kernel"),
            },
            "resolved": self.ktext_shift is not None,
            "resolve_problem": self.resolve_problem(),
            "banner": self.banner,
            "banner_pa": self.banner_pa,
            "banner_candidates": self.banner_candidates,
            "expected_boot_id": self.expected_boot_id,
            "snapshot_boot_id": self.snapshot_boot_id,
            "kernel_candidates": self.kernel_candidates,
            "ktext_shift": self.ktext_shift,
            # 0 = profil a snimka su z toho isteho bootu; inak posun, o ktory
            # sa profil preukotvil (A2)
            "reanchored": self.reanchored,
            "page_offset_base": self.page_offset_base,
            "translation_check": self.translation_check(),
            # None alebo text diagnozy; nesulad profilu je chyba vstupu,
            # nie neuzavreta kontrola (viz navratove kody v cli.py)
            "profile_mismatch": self.profile_boot_mismatch(),
        }
        return out

    def translation_check(self, symbols=("linux_banner", "init_task")):
        """
        Krizova kontrola: linearny vypocet vs. prechod tabuliek stranok.
        Zhoda je jediny dokaz, ze posun nie je nahoda.

        Kazdy riadok nesie aj to, PRECO prechod zlyhal (uroven, index, kod
        dovodu) a ci je stranka linearneho vysledku vobec v snimke - z toho
        sa sklada diagnoza v profile_boot_mismatch().
        """
        rows = []
        for name in symbols:
            va = self.p.addr(name)
            if va is None:
                continue
            lin = self.ktext_pa(va)
            d = self.walk_pa_detail(va)
            rows.append({
                "symbol": name,
                "va": va,
                "linear_pa": lin,
                "linear_page_present": self._page_present(lin),
                "walk_pa": d["pa"],
                "walk_level": d["level"],
                "walk_index": d["index"],
                "walk_reason": d["reason"],
                "walk_reason_code": d["reason_code"],
                "match": lin is not None and lin == d["pa"],
            })
        return rows

    # ------------------------------------------------- diagnoza: iny boot

    def _linear_confirmed(self, name, lin):
        """
        Da sa symbol na linearne vypocitanej adrese naozaj precitat a je tam
        to, co tam byt ma? Diagnoza nizsie smie stat iba na symbole, o ktorom
        to vieme - inak by "adresa sa neprelozila" mohol byt hocijaky
        nemapovany kus pamate.
        """
        if lin is None:
            return False
        if name == "linux_banner":
            return (self.banner_pa is not None and lin == self.banner_pa
                    and self._page_present(lin))
        if name == "init_task":
            # comm lezi az hlboko v strukture - pytame sa na stranku, z ktorej
            # sa NAOZAJ cita, nie na tu so zaciatkom init_task (v malom vyreze
            # snimky to nemusi byt ta ista stranka)
            off = self.p.member("task_struct", "comm")
            if off is None or not self._page_present(lin + off):
                return False
            comm = self.img.read(lin + off, 16) if self._ok(lin + off, 16) else None
            return bool(comm) and comm.split(b"\0")[0] == b"swapper/0"
        return False

    def profile_boot_mismatch(self, symbols=("init_task", "linux_banner")):
        """
        Diagnoza: kallsyms v profile je z INEHO STARTU jadra, nez je snimka.

        Ako sa to pozna. Adresy symbolov randomizuje KASLR pri kazdom starte,
        ale posuva ich vsetky rovnako - preto sken banneru posun dopocita a
        linearny vypocet (PA = VA - __START_KERNEL_map + posun) sedi aj so
        starym profilom. Tabulky stranok su vsak indexovane SKUTOCNYMI
        virtualnymi adresami tohto startu, takze stara VA v nich nie je.

        Podmienka je preto: symbol sa na linearne vypocitanej adrese precitat
        DA a obsah sedi (init_task.comm == "swapper/0", resp. banner na
        najdenej adrese), ale prechod tabuliek stranok pre jeho virtualnu
        adresu skoncil na NEPRITOMNEJ polozke v tabulke, ktora v snimke je,
        alebo mapoval na inu fyzicku stranku. Prekryv KASLR rozsahov medzi
        bootmi nezarucuje zhodu len tym, ze sa stara VA da prelozit.
        S profilom z toho isteho bootu tato dvojica nastat nemoze.

        Vracia None (nic tomu nenasvedcuje) alebo text diagnozy.
        """
        if self.ktext_shift is None:
            return None                       # inu pricinu hlasi resolve_problem
        for name in symbols:
            va = self.p.addr(name)
            if va is None:
                continue
            lin = self.ktext_pa(va)
            d = self.walk_pa_detail(va)
            if d["pa"] is not None:
                if d["pa"] != lin and self._linear_confirmed(name, lin):
                    return self._mismatch_text(name, va, lin, d)
                continue                      # verify the other anchor too
            if d["reason_code"] != "chyba_polozka":
                continue                      # tabulku nemame: nedokazuje nic
            if not self._linear_confirmed(name, lin):
                continue
            return self._mismatch_text(name, va, lin, d)
        return None

    def _mismatch_text(self, name, va, lin, d):
        """Hlaska diagnozy: co sa stalo, preco to tak je a co s tym."""
        outcome = ("mapuje na inu fyzicku adresu 0x%x." % d["pa"]
                   if d["pa"] is not None else
                   "skoncil na urovni %s, %s." % (d["level"], d["reason"]))
        riadky = [
            "NESULAD PROFILU: kallsyms je z ineho startu jadra (KASLR), nez je "
            "snimka.",
            "  symbol %s: linearne sa cita z 0x%x (obsah sedi), ale prechod "
            "tabuliek stranok" % (name, lin),
            "  pre VA 0x%x %s" % (va, outcome),
            "  Tabulky stranok su indexovane virtualnymi adresami TOHTO startu; "
            "adresy v kallsyms.txt",
            "  su z ineho. Offsety poli z BTF reboot prezivaju, adresy symbolov "
            "nie.",
        ]
        popis = self.p.describe() if hasattr(self.p, "describe") else None
        if popis:
            riadky.append("  %s" % popis)
        riadky.append(
            "  Obnov profil: scripts/get_profile.sh -f root@<host-hosta> "
            "(alebo -t agent <domena>).")
        riadky.append(
            "  Snimka z ineho bootu potrebuje profil z TOHO bootu, alebo "
            "preukotvenie (A2) - toto zlyhalo, pozri dovod vyssie.")
        return "\n".join(riadky)

    def reanchor(self):
        """
        Preukotvenie profilu na boot snimky (blok A2): namiesto padu s kodom 5
        sa profil posunie o KASLR rozdiel a pokracuje sa.

        Ako to funguje. KASLR posuva obraz jadra pri kazdom starte, ale
        VZDY rovnako pre vsetky symboly - preto staci najst posun `delta`
        medzi bootom profilu a bootom snimky. Neberie sa zo samotneho
        banneru (ten ukotvi fyzicke adresy, nie aktualne virtualne adresy), ale
        MERIA sa z tabuliek stranok: pre znamu fyzicku adresu init_task
        (overenu obsahom comm == "swapper/0" v resolve()) sa najde virtualna
        adresa, ktora ju mapuje; delta = VA_v_snimke - VA_v_profile.
        Druha kotva (linux_banner) musi s tym istym delta sediet, inak sa
        posun NEAKCEPTUJE - nesediaci walk znamena FGKASLR alebo chybajuce
        stranky a plati doterajsie spravanie.

        Vrati (True, info) alebo (False, dovod). Na uspech mutuje profil
        (Profile.shift) a upravi ktext_shift tak, aby preklad VA->PA zostal
        presne taky isty ako pred preukotvenim.
        """
        if self.ktext_shift is None:
            return False, "posun jadra sa nenasiel - nie je z coho preukotvit"
        init_va = self.p.addr("init_task")
        banner_va = self.p.addr("linux_banner")
        if init_va is None or banner_va is None:
            return False, "profil nema kotvy init_task/linux_banner"
        init_pa = self.ktext_pa(init_va)     # banner-anchored, obsahovo overeny
        if init_pa is None:
            return False, "PA init_task sa neda vypocitat"

        va_init_b = self._va_for_pa(init_pa)
        if va_init_b is None:
            return False, ("PA init_task 0x%x sa v tabulkach stranok obrazu "
                           "jadra nenasla - snimke chybaju stranky alebo ide "
                           "o FGKASLR" % init_pa)
        delta = va_init_b - init_va
        if delta == 0:
            return False, "posun vysiel nulovy - profil a snimka sedia"
        va_banner_b = banner_va + delta
        if not (START_KERNEL_MAP <= va_banner_b < MODULES_VADDR):
            return False, ("posun %+d vyvedie banner mimo rozsah obrazu "
                           "jadra" % delta)
        d = self.walk_pa_detail(va_banner_b)
        if d["pa"] != self.banner_pa:
            return False, ("druha kotva nesedi: walk(banner) dal 0x%x, banner "
                           "je na 0x%x - posun by bol hadanie"
                           % (d["pa"] or 0, self.banner_pa or 0))

        self.p.shift(delta, START_KERNEL_MAP, MODULES_VADDR)
        # preklad VA->PA musi ostat rovnaky: pa = va_po - START + ktext_shift
        self.ktext_shift = self.ktext_shift - delta
        self.reanchored = delta
        return True, {"delta": delta, "init_task_va": va_init_b,
                      "init_task_pa": init_pa}

    def _va_for_pa(self, pa, step=2 * 1024 * 1024):
        """
        Spatne hladanie: ktora virtualna adresa obrazu jadra mapuje danu
        fyzicku adresu? Skenuje sa okno [__START_KERNEL_map,
        MODULES_VADDR) po 2 MiB blokoch a kandidat sa overi presnym
        prechodom tabuliek - vracia iba POTVRDENE adresy.
        """
        for s in range(0, 1 << 30, step):
            va = START_KERNEL_MAP + s
            d = self.walk_pa_detail(va)
            if d["pa"] is None:
                continue
            base = d["pa"] & ~(step - 1)
            if not (0 <= pa - base < step):
                continue
            cand = va + (pa - base)
            dd = self.walk_pa_detail(cand)
            if dd["pa"] == pa:
                return cand
        return None

    # -------------------------------------------------------------- utility

    @staticmethod
    def _result(key, items, truncated, stop_reason):
        return {
            key: items,
            "count": len(items),
            "truncated": bool(truncated),
            "stop_reason": stop_reason,
        }


def build_view(image_path, profile_dir, banner_text=None, until_seq=None, *, expected_boot_id=None,
               image=None):
    """
    Otvori snimku, nacita profil a najde posun. Vracia (view, image).

    `until_seq` odreze retazec .vmicd po danom seq - rovnako ako
    `vmicollect restore --until`. Rozbity retazec sa neotvori: open_image
    vyhodi ChainError.
    """
    from .image import open_image
    from .profile import Profile

    expected_boot_id = capture_boot_id(image_path, expected_boot_id)
    # `image` = obraz z ChainCursor (rovnaky stav ako open_image); patri kurzoru.
    img = open_image(image_path, until_seq=until_seq) if image is None else image
    try:
        prof = Profile.from_dir(profile_dir)
        view = GuestView(img, prof, expected_boot_id)
        view.resolve(banner_text)
    except BaseException:
        if image is None:
            img.close()
        raise
    return view, img
