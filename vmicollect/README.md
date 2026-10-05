# vmicollect

Hypervisor modul pre **periodicky zber pamatovych snimok virtualnych strojov**
nad **QEMU/KVM**, postaveny na **eBPF**.

Ziadne patchnute QEMU, ziadny KVMi socket, ziadny libvirt, ziadna LibVMI -
staci neupraveny QEMU/KVM, jadro s BTF a root. Zberac si mapu pamate pyta
priamo od modulu `kvm` v jadre.

Napisany v C, zavislosti: `libbpf`, `zlib`, `libdl`. BPF cast preklada `clang`.
Vsetky komentare v zdrojakoch su po slovensky a vysvetluju *preco*, nie *co*.

---

## Rychly start

```sh
make            # -> build/vmicollect  (+ build/vmic_kvm.bpf.o vlozeny v nom)
make test       # cela cesta zberu nad synteticky obrazom - bez VM a bez roota
```

Nad ostrou VM (vzdy cez `sudo` - citanie cudzej pamate je privilegovana operacia):

```sh
# 1. Kto tu vlastne bezi a co z neho vidime
sudo ./build/vmicollect probe                     # jedina VM sa najde sama
sudo ./build/vmicollect probe -o vm.domain=win10  # alebo menom / pid:1234

# 2. Jedna snimka
sudo ./build/vmicollect once -o vm.domain=win10 -o output.dir=/var/tmp/snap

# 3. Periodicky zber, kazde 2 s, inkrementalne
sudo ./build/vmicollect run -o vm.domain=win10 \
    -o output.dir=/var/tmp/snap \
    -o output.writer=delta \
    -o schedule.interval_s=2

# 4. Obnova plneho obrazu z delta retazca
./build/vmicollect restore --dir /var/tmp/snap --out /var/tmp/mem.raw

# 5. Kontrola kontrolnych suctov
./build/vmicollect verify /var/tmp/snap
```

Alebo cez konfiguracny subor:

```sh
cp vmicollect.example.conf my.conf
$EDITOR my.conf
sudo ./build/vmicollect run -c my.conf
```

`-o sekcia.kluc=hodnota` sa da opakovat a prebija subor - je to najrychlejsi
sposob ako nieco vyskusat bez editovania.

### Vyskusanie bez toho, aby si mal ostru VM

Na zber staci VM, ktora ma pamat - nemusi mat ani disk, ani operacny system:

```sh
qemu-system-x86_64 -enable-kvm -m 512 -name guest=test-vm -display none &
sudo ./build/vmicollect probe -o vm.domain=test-vm
sudo ./build/vmicollect once  -o vm.domain=test-vm -o output.dir=/var/tmp/snap
```

---

## Architektura

Modul ma **styri vrstvy**, ktore sa vidia iba cez tabulky ukazovatelov na
funkcie. Ked nieco menis, takmer vzdy sa dotknes iba jednej z nich.

```
                    ┌──────────────────────────────┐
                    │   sched.c   KEDY sa zbiera   │
                    │   bezdriftove terminy,       │
                    │   jitter, overrun politika   │
                    └──────────────┬───────────────┘
                                   │ work(seq)
                    ┌──────────────▼───────────────┐
                    │  collector.c   jeden cyklus  │
                    │  begin - refresh slotov -    │
                    │  capture - finish            │
                    └───┬───────────────────────┬──┘
                        │                       │
     ODKIAL berieme bajty                    KAM ich ukladame
    ┌───────────────────▼──────┐   ┌────────────▼─────────────┐
    │ backend_ebpf.c   KVM/eBPF│   │ writer_raw.c    cely obraz│
    │ backend_file.c   subor   │   │ writer_delta.c  iba zmeny │
    └──────────┬───────────────┘   └───────────────────────────┘
               │ bpf_prog_test_run()
    ┌──────────▼───────────────┐
    │ bpf/vmic_kvm.bpf.c       │   BEZI V JADRE
    │  vmic_probe  memsloty    │   struct kvm -> GPA/HVA mapa
    │  vmic_read   stranky     │   copy_from_user_task -> mmap mapa
    └──────────────────────────┘
               │
    ┌──────────▼───────────────────┐
    │  hooks.c   CO sa stane potom │
    │  dlopen() plugin - tvoj kod  │
    └──────────────────────────────┘
```

| subor | co riesi |
|---|---|
| `include/vmic.h` | verejne API a vsetky datove typy - **zacni tu** |
| `bpf/vmic_bpf_abi.h` | rozhranie medzi jadrom a zberacom (offsety, kontexty) |
| `bpf/vmic_kvm.bpf.c` | BPF programy: memsloty a citanie stranok |
| `src/backend_ebpf.c` | najdenie domeny, nacitanie BPF programu, `read_pa` |
| `src/backend_file.c` | raw obraz na disku (vyvoj, testy) |
| `src/collector.c` | jeden cyklus zberu |
| `src/sched.c` | periodicke terminy bez driftu |
| `src/backend.c` | register backendov + spolocna citacia slucka |
| `src/writer_raw.c` | raw vystup: riedky zapis, gzip, SHA-256 |
| `src/writer_delta.c` | inkrementalny zber + obnova retazca |
| `src/hooks.c` | nacitanie a volanie pluginov |
| `src/retention.c` | mazanie starych snimok po retazcoch |
| `src/config.c` | INI parser riadeny tabulkou `FIELDS` |
| `src/meta.c` | `.json` metadata vedla kazdej snimky |
| `src/util.c` `src/sha256.c` `src/log.c` | cas, I/O, hashe, logovanie |

### Backendy

| backend | pristup | pouzitie |
|---|---|---|
| `ebpf` | lubovolny rozsah | ostry zber z bezicej KVM domeny; potrebuje roota |
| `file` | lubovolny rozsah | vyvoj a testy bez VM, prehravanie uz zozbieraneho dumpu |

### Writery

| writer | vystup | poznamka |
|---|---|---|
| `raw` | `.raw` / `.raw.gz` | **offset v subore == fyzicka adresa**, riedky zapis |
| `delta` | `.vmicd` | iba stranky zmenene od minulej snimky |

---

## Preco je to napisane tak, ako je

### Preco eBPF, ked pamat hosta je "len" pamat procesu QEMU

Pamat hosta naozaj zije v adresnom priestore procesu QEMU a bajty by sa dali
citat aj `process_vm_readv()`. Lenze zvonka sa neda zistit to podstatne:
**ktora cast toho procesu je ktora fyzicka adresa hosta**. Tuto tabulku
(GPA -> HVA) drzi modul `kvm` vo svojich *memslotoch* a von ju neposkytuje
ziadnym rozhranim.

Ostatne cesty k nej vedu iba cez zmeny v prostredi:

| cesta | co si pyta |
|---|---|
| LibVMI + KVM legacy | patchnute QEMU |
| LibVMI + KVMi | jadro s KVMi a socket |
| `virsh dump` | libvirt, a vzdy cely obraz naraz |
| **eBPF** | **nic - iba root na tom istom stroji** |

BPF program preto robi dve veci, ktore userspace spravit nevie:

* `vmic_probe` najde v procese VMM deskriptor anonymneho inode `kvm-vm`
  (to je zaroven najspolahlivejsi test "toto je hypervizor"), z jeho
  `private_data` vytiahne `struct kvm` a prejde hash tabulku memslotov -
  vysledkom je presna mapa GPA -> HVA aj s dierami,
* `vmic_read` prelozi ziadanu fyzicku adresu na HVA a skopiruje stranky
  cez `bpf_copy_from_user_task()`.

Oba su `SEC("syscall")`, teda ich zberac **sam zavola** cez
`bpf_prog_test_run()` vtedy, ked ma naplanovany termin. Na horuce cesty KVM
(`kvm_entry`, `kvm_exit`, milion udalosti za sekundu) sa nevesa nic - bezica
VM o zberaci nevie.

### Offsety jadrovych struktur sa neprekladaju, citaju sa z BTF

BPF program nepozna ani jednu jadrovu strukturu. Vsetky offsety (`kvm.memslots`,
`kvm_memory_slot.userspace_addr`, `file.private_data`, ...) mu zberac posle v
mape `koff`; berie ich z BTF, ktore ma jadro samo o sebe
(`/sys/kernel/btf/vmlinux`, pripadne `/sys/kernel/btf/kvm`). Dosledky:

* nepotrebujeme `bpftool` ani `vmlinux.h`,
* modul nie je prelozeny natvrdo proti jednej verzii jadra,
* ked sa pole presunie, nic sa nedeje; ked zmizne, zberac to **povie menom**
  pri starte namiesto ticheho citania smeti.

Vyhladavanie clenov musi vediet zostupit aj do **anonymnych unionov** - v
jadrach 7.x su `file->f_path` aj `dentry->d_name` vnorene prave v nich.

### Ziadny jadrovy ukazovatel neprezije jedno volanie

`struct kvm *` sa nikde neuklada. Kazdy beh `vmic_probe` si ho znovu najde cez
tabulku deskriptorov procesu, a to pod `bpf_rcu_read_lock()` - `fdtable` aj
`struct file` sa uvolnuju cez RCU, takze pod tymto zamkom nezmiznu. Citanie
pamate uz ziadny jadrovy ukazovatel nepouziva: bezi nad **kopiou** tabulky
slotov v BPF mape.

Memsloty sa navyse citaju s kontrolou `generation` pred aj po prechode. Ked sa
mapa pamate medzitym zmenila (hotplug, presun BAR), cyklus sa radsej preskoci,
nez by sa citalo podla neplatnych HVA.

### Diery vo fyzickom priestore sa vobec nenavstivia

Fyzicky priestor x86 nie je suvisly: VGA diera na `0xA0000`, PCI hole pod 4 GiB,
MMIO. Pri 4 GiB VM su to bezne 2 GiB adries, kde nie je nic.

Kedze memsloty presne hovoria, ktore useky namapovane su, `probe` ich posle
zberacu (`vmic_vminfo_t.ram`) a ten **zbiera iba ich**. Diera sa teda necita
ani nehashuje - a co je dolezitejsie, neobjavi sa ani v statistikach: pri
zdravej VM je `read_errors` naozaj pocet chyb a `changed_ratio` v delta
snimke sa pocita zo skutocnej RAM, nie z adresneho priestoru.

Ked si oblasti zadas rucne (`capture.regions`) a nejaka z nich dieru
pretina, plati zaloha: `vmic_read` vrati `KIND_HOLE` **aj s dlzkou diery az
po najblizsi dalsi slot**, zberac ju vyplni nulami a cita dalej - preskocit,
nie sa zastavit. Naivne "co nedoslo, vynuluj zvysok" by pri diere na
`0xA0000` zahodilo aj shadow BIOS na `0xC0000`, co je normalna RAM. Strazi to
regresny test `tests/hole_test.c` (`make test-holes`).

### Snimka je "ziva" - VM sa nezastavuje

eBPF je pozorovacie, nie riadiace rozhranie: nema ako povedat "zastav vCPU".
Preto `ops->pause` neexistuje a `capture.pause` je vychodzie `false`.

Co to znamena v praxi: **kazda stranka je precitana jednym volanim, takze je
konzistentna sama v sebe, ale dve stranky mozu byt z rozneho okamihu.** Pre
periodicky zber priznakov (a pre casovy rad, ktory z neho vznika) je to
prijatelne - a je to zaroven jediny rezim, pri ktorom VM nezavaha.

Ked potrebujes naozaj atomicku snimku, zastav VM zvonka a az potom zbieraj:

```sh
virsh suspend win10 && sudo ./build/vmicollect once -o vm.domain=win10; virsh resume win10
```

### Cim je pamat hosta podlozena - to rozhoduje o vplyve na VM

Citanie ide cez `access_process_vm()`, cize sa sprava ako obycajny pristup do
pamate procesu:

| podlozenie | citanie stranky, ktorej sa host nikdy nedotkol |
|---|---|
| anonymne (vychodzie QEMU) | zadarmo - jadro namapuje spolocnu nulovu stranku |
| memfd, `/dev/shm`, hugetlbfs | stranku **naozaj vytvori** |

Pri druhom pripade by dlhy zber postupne "nafukol" VM na plnu velkost RAM, co
je presny opak minimalizacie vplyvu. Zberac preto pri starte pozrie do
`/proc/<pid>/maps`, ci HVA memslotov nepadaju do pomenovaneho mapovania, a ked
ano, **varuje**. Riesenie je zbierat konkretne oblasti (`capture.regions`).

### Perioda nesmie driftovat

Naivne "spracuj a `sleep(interval)`" predlzi periodu o cas spracovania. Po
hodine casova rada nesedi. `sched.c` preto pocita **absolutne terminy na
`CLOCK_MONOTONIC`** a spi cez `clock_nanosleep(TIMER_ABSTIME)`. Chyba sa
nekumuluje a signal spanok okamzite prerusi (`Ctrl-C` zabera hned, nie az po
dospani periody).

Ked cyklus periodu presiahne, rozhoduje `schedule.overrun`:
`skip` (drz mriezku, zahod sloty), `catch_up` (dobehni), `stretch` (posun mriezku).

### Delta zber

Snimky kazdych 5 s zo 4 GiB VM = **2,8 TB za hodinu**. Medzi dvoma snimkami sa
ale typicky zmeni len 0,5-5 % stranok. `writer_delta.c` preto pre kazdu stranku
pocita rychly 64-bitovy hash a zapise len tie zmenene.

Format `.vmicd` je zamerne trivialny (prilozitelny do prace, citatelny aj
z Pythonu). Hlavicka 64 B, little-endian:

| offset | typ | vyznam |
|---|---|---|
| 0 | `char[8]` | `VMICDLT1` |
| 8 | `u32` | verzia formatu |
| 12 | `u32` | velkost stranky |
| 16 | `u64` | id retazca |
| 24 | `u64` | poradove cislo snimky |
| 32 | `u64` | logicka velkost pamate |
| 40 | `u64` | pocet zaznamov v subore |
| 48 | `u64` | priznaky (bit 0 = plna snimka) |
| 56 | `u64` | podpis konfiguracie oblasti |

Za hlavickou nasleduje `pocet zaznamov` krat: `u64` index stranky
+ `velkost stranky` bajtov obsahu.

Obnova zacina od nuloveho obrazu, aplikuje plnu snimku a potom delty v poradi
(`vmicollect restore`). Preto sa **retencia maze po celych retazcoch** - bez
plnej snimky su delty nepouzitelne.

### Marker HOLD (flight recorder)

Retencia respektuje subor `HOLD` vo vystupnom adresari: retazce v nom uvedene
sa **nikdy nemazu**, ani ked prekrocia `retention.max_snapshots` / `max_bytes` /
`max_age_s`. Marker sa cita z disku pri kazdom upratovani, takze prezije
restart zberaca. Jeden zaznam na riadok (`#` = komentar, prazdne riadky sa
preskakuju); zaznam je `chain_id` retazca (delta zber) alebo meno suboru
snimky - vtedy sa drzi cely retazec, v ktorom ten subor je.

```sh
vmicollect hold /var/tmp/snap 1789746463651   # drz retazec spred alarmu
```

Pouzitie: po alarme (blok A6) sa oznac retazec z obdobia PRED alarmom, aby
forenzny material prezil upratovanie.

### Prenos stranok cez jednu mmap mapu

BPF mapa `pages` je `BPF_F_MMAPABLE` a zberac si ju namapuje do svojho
adresneho priestoru. Stranky hosta tak prekrocia hranicu jadro/userspace presne
raz (`copy_from_user` v kontexte VMM -> mapa). Ziadny ringbuf, ziadne
kopirovanie navyse.

Bezny pripad je **jedno** volanie helpera na cely 2 MiB usek. Ked zlyha (helper
je "vsetko alebo nic"), program to zopakuje po strankach, takze jedna
necitatelna stranka nezhodi cely blok - a v metadatach je vidiet, kolko ich
bolo.

---

## Ako to rozsiris

### 1. Vlastny hook (bez prekladania zberaca)

Sem patri parsovanie struktur a extrakcia priznakov. Vzor:
[`hooks/example_hook.c`](hooks/example_hook.c).

```c
int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st);
int  vmic_hook_snapshot(void *st, const vmic_snapshot_t *snap);
void vmic_hook_fini(void *st);
```

```sh
make hooks
sudo ./build/vmicollect run -c my.conf -o hooks.load=./build/example_hook.so:/tmp/index.csv
```

Hook bezi **synchronne** v hlavnej slucke. Ked bude trvat dlhsie ako perioda,
zberac zacne zmeskavat sloty - nieco narocne daj do fronty a spracuj mimo.

### 2. Vlastny backend alebo writer

1. skopiruj `src/backend_file.c` (najkratsi vzor)
2. vypln `vmic_backend_ops_t` - staci `open/close/probe/read_pa`
3. pridaj dva riadky do `src/internal.h` a jeden do `REGISTRY` v `src/backend.c`

Writer analogicky: `src/writer_raw.c` -> `vmic_writer_ops_t` -> `src/writer.c`.

### 3. Vlastny parameter konfiguracie

Pridaj pole do `vmic_config_t` (`include/vmic.h`) a **jeden riadok** do tabulky
`FIELDS` v `src/config.c`. Tym sa automaticky da nastavit z `.conf`, z `-o`,
vypise sa v `config` aj v `config --keys` a zvaliduje sa.

### 4. Zmena BPF casti

```sh
make bpf                     # prelozi iba bpf/vmic_kvm.bpf.o
sudo ./build/vmicollect probe -v -o vm.bpf_object=build/vmic_kvm.bpf.o
```

`-v` pusti do logu aj vypisy libbpf vratane celej hlasky verifikatora - to je
pri uprave BPF programu jedina vec, ktoru naozaj potrebujes vidiet.
`vm.bpf_object` prebije program vlozeny v binarke, takze sa da skusat nova
verzia bez preinstalovania.

---

## Vystup

Vedla kazdej snimky vznika `.json` s metadatami - to je rozhranie pre vsetko,
co pride po zbere:

```json
{
  "seq": 12,
  "timestamp": "2026-08-26T10:07:26.902Z",
  "vm":      { "domain": "win10", "backend": "ebpf/kvm", "memsize": 4294967296, ... },
  "capture": { "pause_ms": 0.0, "capture_ms": 39.5, "write_ms": 190.8, "total_ms": 230.3 },
  "stats":   { "bytes_read": 4294967296, "read_errors": 3, "read_mib_s": 1043.2 },
  "output":  { "writer": "delta", "chain_id": 1787695646902, "full": false,
               "pages_changed": 812, "pages_total": 1048576, "changed_ratio": 0.000774,
               "sha256": "..." }
}
```

`paused` je to, co sa naozaj stalo, nie co si ziadal config: backend `ebpf`
VM zastavit nevie, takze tam bude vzdy `false` a `pause_ms` 0.

`read_errors` su naozaj chyby - stranky, ktore sa v namapovanom useku
precitat nepodarilo. Diery medzi memslotmi sa nezbieraju, takze sa v tomto
cisle neobjavia.

---

## Ciele `make`

| ciel | co robi |
|---|---|
| `make` | prelozi BPF program aj zberac -> `build/vmicollect` |
| `make bpf` | prelozi iba BPF cast (rychla kontrola po uprave) |
| `make hooks` | prelozi vzorovy plugin |
| `make test` | selftest + regresne testy - cela cesta bez VM a bez roota |
| `make test-holes` | regresny test preskakovania dier vo fyzickom priestore |
| `make check` | preklad s kontrolou UB a pretecenia + selftest |
| `make debug` | ASan/UBSan (`sudo dnf install libasan libubsan`) |
| `make install` | do `$(PREFIX)/bin`, vychodzie `/usr/local` |

---

## Poznamky k prostrediu

**Co musi mat jadro.** `CONFIG_BPF_SYSCALL`, `CONFIG_DEBUG_INFO_BTF` (kvoli
offsetom z BTF) a nacitany modul `kvm`. Overenie:

```sh
ls /sys/kernel/btf/vmlinux    # musi existovat
lsmod | grep kvm
```

**Prava.** Nacitanie BPF programu a citanie cudzej pamate su privilegovane
operacie: potrebujes roota, alebo `CAP_BPF` + `CAP_PERFMON` (+ pristup k
`/proc/<pid>/fd` cudzieho procesu). Bez nich zberac skonci hlaskou
"nacitanie BPF programu vyzaduje roota".

**Preklad BPF casti.** Potrebuje `clang` (gcc cielovu architekturu `bpf` nema)
a `libbpf-devel`. Ked chybaju, `make` prejde, ale backend `ebpf` v takom builde
nie je - zostane `file` a testy. Instalacia na Fedore:

```sh
sudo dnf install clang libbpf-devel elfutils-libelf-devel zlib-devel
```

**Jeden adresar = jeden zberac.** Retencia pracuje nad celym `output.dir` a
nerozlisuje domeny. Ked do jedneho adresara zbieraju dva zberace, mazu si
navzajom snimky. Kazdej domene daj vlastny `output.dir`.

**Confidential VM (SEV-SNP, TDX).** Pamat takej VM je v `guest_memfd` a cez
adresny priestor VMM sa precitat neda. Zberac take sloty preskoci, napise, kolko
ich bolo, a v snimke budu nulove.
