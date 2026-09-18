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

from .image import PAGE
from .profile import ProfileError

START_KERNEL_MAP = 0xFFFFFFFF80000000
MODULES_VADDR = 0xFFFFFFFFC0000000      # koniec linearne mapovaneho obrazu jadra
KERNEL_VA_MIN = 0xFFFF800000000000      # najnizsia kanonicka adresa jadra
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

    def __init__(self, img, prof):
        self.img = img
        self.p = prof
        self.ktext_shift = None
        self.page_offset_base = None
        self.banner = None
        self.banner_pa = None
        self.banner_candidates = 0
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
        sedi init_task.comm == "swapper/0" - jeden retazec v pamati sa najde
        aj v inych kontextoch (log jadra, /proc data), samotny nalez nestaci.
        """
        needle = (banner_text or "Linux version ").encode()
        comm_off = self.p.member("task_struct", "comm")
        banner_va = self.p.addr("linux_banner")
        init_va = self.p.addr("init_task")
        if comm_off is None or banner_va is None or init_va is None:
            return False

        seen = 0
        for pa in self._find(needle):
            seen += 1
            shift = pa - (banner_va - START_KERNEL_MAP)
            ipa = init_va - START_KERNEL_MAP + shift
            if ipa < 0 or (self.max_pa and ipa + comm_off + 16 > self.max_pa):
                continue
            comm = self.img.read(ipa + comm_off, 16)
            if comm and comm.split(b"\0")[0] == b"swapper/0":
                self.ktext_shift = shift
                self.banner_pa = pa
                self.banner_candidates = seen
                raw = self.img.read(pa, 256) or b""
                self.banner = raw.split(b"\n")[0].split(b"\0")[0].decode(
                    "utf8", "replace")
                pob_sym = self.p.addr("page_offset_base")
                if pob_sym is not None:
                    self.page_offset_base = self.u64(self.ktext_pa(pob_sym))
                return True
        self.banner_candidates = seen
        return False

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

    def walk_pa(self, va):
        """
        Preklad virtualnej adresy hosta prechodom tabuliek stranok
        (4 urovne, x86_64). Pokryva aj oblasti, ktore linearne mapovane nie su -
        moduly a vmalloc.

        Vracia None, ked stranka nie je pritomna. Velke stranky (1 GiB, 2 MiB)
        sa rozpoznaju podla bitu PSE.
        """
        table = self._pgt_root()
        if table is None:
            return None
        # bity 47:39 / 38:30 / 29:21 / 20:12
        for level, shift in enumerate((39, 30, 21, 12)):
            idx = (va >> shift) & 0x1FF
            ent = self.u64(table + idx * 8)
            if ent is None or not (ent & self.PTE_PRESENT):
                return None
            phys = ent & 0x000FFFFFFFFFF000
            if level in (1, 2) and (ent & self.PTE_PSE):
                size = 1 << shift
                return phys + (va & (size - 1))
            table = phys
        return table + (va & 0xFFF)

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

        Vracia {'processes', 'count', 'truncated', 'stop_reason'}. 'truncated'
        znamena, ze zoznam sa neuzavrel - vysledok je teda dolna hranica.
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

        head_va = init_va + m["tasks"]
        out, seen = [], set()
        stop = None
        nxt = self.u64(init_pa + m["tasks"])
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
            out.append({
                "pid": pid,
                "tgid": tgid,
                "comm": comm,
                "kernel_thread": mm == 0,
                "task_va": nxt - m["tasks"],
            })
            nxt = self.u64(tpa + m["tasks"])
        return self._result("processes", out, stop is not None, stop)

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
            },
            "resolved": self.ktext_shift is not None,
            "resolve_problem": self.resolve_problem(),
            "banner": self.banner,
            "banner_pa": self.banner_pa,
            "banner_candidates": self.banner_candidates,
            "ktext_shift": self.ktext_shift,
            "page_offset_base": self.page_offset_base,
            "translation_check": self.translation_check(),
        }
        return out

    def translation_check(self, symbols=("linux_banner", "init_task")):
        """
        Krizova kontrola: linearny vypocet vs. prechod tabuliek stranok.
        Zhoda je jediny dokaz, ze posun nie je nahoda.
        """
        rows = []
        for name in symbols:
            va = self.p.addr(name)
            if va is None:
                continue
            lin = self.ktext_pa(va)
            walk = self.walk_pa(va)
            rows.append({
                "symbol": name,
                "va": va,
                "linear_pa": lin,
                "walk_pa": walk,
                "match": lin is not None and lin == walk,
            })
        return rows

    # -------------------------------------------------------------- utility

    @staticmethod
    def _result(key, items, truncated, stop_reason):
        return {
            key: items,
            "count": len(items),
            "truncated": bool(truncated),
            "stop_reason": stop_reason,
        }


def build_view(image_path, profile_dir, banner_text=None, until_seq=None):
    """
    Otvori snimku, nacita profil a najde posun. Vracia (view, image).

    `until_seq` odreze retazec .vmicd po danom seq - rovnako ako
    `vmicollect restore --until`. Rozbity retazec sa neotvori: open_image
    vyhodi ChainError.
    """
    from .image import open_image
    from .profile import Profile

    img = open_image(image_path, until_seq=until_seq)
    prof = Profile.from_dir(profile_dir)
    view = GuestView(img, prof)
    view.resolve(banner_text)
    return view, img
