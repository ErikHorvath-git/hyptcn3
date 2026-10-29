# vmicollect

Hypervisor modul pre **periodicky zber pamatovych snimok virtualnych strojov**
nad **QEMU/KVM**, postaveny na **eBPF**. Pri delta zbere modul pocita aj
per-bin priznakovy vektor kazdej snimky a zapisuje ho do jej metadat
(cast "Blok `features`" nizsie).

Ziadne patchnute QEMU, ziadny KVMi socket, ziadny libvirt, ziadna LibVMI -
staci neupraveny QEMU/KVM, jadro s BTF a root. Zberac si mapu pamate pyta
priamo od modulu `kvm` v jadre.

Napisany v C, zavislosti: `libbpf`, `zlib`, `libdl`, `libm`, `pthread`. BPF
cast preklada `clang`.
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

### Prikazy a prepinace

Podla `./build/vmicollect --help` (verzia 1.1.0):

| prikaz | co robi |
|---|---|
| `run` | periodicky zber (Ctrl-C korektne ukonci) |
| `once` | jedna snimka a koniec |
| `probe` | pripoj sa a vypis parametre VM (nic nezapisuje) |
| `restore --dir D --out F [--chain ID] [--until SEQ]` | poskladaj plny obraz z delta retazca (bez `--chain` z najnovsieho) |
| `hold <dir> <id>...` | oznac retazce markerom `HOLD`; `<id>` = `chain_id` alebo meno suboru snimky |
| `verify [adresar]` | over kontrolne sucty snimok podla `.json` (bez argumentu v `output.dir`) |
| `config` | vypis efektivnu konfiguraciu (aj s `-c` a `-o`) |
| `config --keys` | vypis vsetky nastavitelne parametre s napovedou |
| `backends` | zoznam dostupnych backendov |
| `selftest [adresar]` | over celu cestu bez VM (vychodzi adresar `/tmp/vmicollect-selftest`) |

Prepinace: `-c subor.conf`, `-o sekcia.kluc=hodnota`, `-v` (log DEBUG),
`-q` (iba ERROR), `-V` (verzia), `-h` (napoveda); `-V` a `-h` platia iba
namiesto prikazu (`vmicollect -h`).

Vychodzie hodnoty vypise `./build/vmicollect config` bez `-c` a `-o`.
`vmicollect.example.conf` neuvadza sekciu `[features]` ani novsie parametre
`[output]` (`fsync`, `queue_mib`, `mlock`, `drain_s`); uplny zoznam je
v `config --keys`. Pri zbere su podstatne: `output.writer` je vychodzie `raw`
(delta zber treba zapnut), `schedule.interval_s` 5, `output.fsync` `true`
(snimka sa pred premenovanim zapise na disk; `false` = zapis cez page cache),
`output.queue_mib` 0, `output.mlock` `false`, `output.drain_s` 240 (vyznam
poslednych troch je v casti "Zapis mimo cyklu" nizsie) a `[features]`
(cast "Blok `features`" nizsie).

Navratovy kod `run` a `once`: 0 = vsetko prebehlo, 4 = aspon jeden cyklus
zlyhal, snimka sa nezverejnila cela alebo sa stratil riadok logu, 1 = ziadna
zverejnena snimka, 2 = chybna konfiguracia alebo argumenty, 3 = chyba pri
starte alebo fatalna chyba pocas zberu (aj zlyhany hook pri
`hooks.strict=true`).

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
                    ┌──────────────▼───────────────┐   PO ZAPISE SNIMKY:
                    │  collector.c   jeden cyklus  ├─> meta.c      sidecar .json
                    │  begin - refresh slotov -    │   hooks.c     dlopen() plugin
                    │  capture - finish - publish  │   retention.c mazanie, HOLD
                    └───┬───────────────────────┬──┘
                        │                       │
     ODKIAL berieme bajty                    KAM ich ukladame
    ┌───────────────────▼──────┐   ┌────────────▼───────────────────┐
    │ backend_ebpf.c   KVM/eBPF│   │ writer_raw.c    cely obraz     │
    │ backend_file.c   subor   │   │ writer_delta.c  iba zmeny      │
    └──────────┬───────────────┘   │ perbin.c        per-bin vektor │
               │                   │ output.c        zapis z fronty │
               │                   └────────────────────────────────┘
               │ bpf_prog_test_run()
    ┌──────────▼───────────────┐
    │ bpf/vmic_kvm.bpf.c       │   BEZI V JADRE
    │  vmic_probe  memsloty    │   struct kvm -> GPA/HVA mapa
    │  vmic_read   stranky     │   copy_from_user_task -> mmap mapa
    └──────────────────────────┘
```

Kroky po zapise snimky idu vzdy v poradi subor, sidecar (`meta.c`), pluginy
(`hooks.c`), retencia (`retention.c`). Pri writeri `raw` ich robi sam
`vmic_collector_cycle()` (`src/collector.c`) synchronne po `finish`; pri
writeri `delta` cyklus snimku iba odovzda (`publish`) a subor, `fsync`,
SHA-256 aj tieto kroky robi vlakno `vmic-writer` (`src/output.c`, nizsie).
Per-bin vektor pocita `perbin.c` pocas porovnavania stranok v delta writeri.

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
| `src/writer.c` | register writerov |
| `src/internal.h` | vnutorne prepojenie registrov backendov a writerov |
| `src/writer_raw.c` | raw vystup: riedky zapis, gzip, SHA-256 |
| `src/writer_delta.c` | inkrementalny zber + obnova retazca |
| `src/perbin.c` `src/perbin.h` | per-bin priznakovy vektor pocitany v delta writeri |
| `src/output.c` `src/output.h` | zapis 'delta' mimo cyklu: fronta v pamati, vlakno `vmic-writer` |
| `src/hooks.c` | nacitanie a volanie pluginov, alarmy |
| `src/retention.c` | mazanie starych snimok po retazcoch, marker `HOLD` |
| `src/config.c` | INI parser riadeny tabulkou `FIELDS` |
| `src/meta.c` | `.json` metadata vedla kazdej snimky, `alarm.json` |
| `src/main.c` | prikazovy riadok (`run`, `once`, `probe`, `restore`, `hold`, `verify`, `config`, `backends`, `selftest`) |
| `src/util.c` `src/sha256.c` `src/log.c` | cas, I/O, hashe, logovanie (`run`: vlakno `vmic-log`) |
| `hooks/*.c` | vzorove pluginy `example_hook`, `alarm_hook`, `react_hook` |
| `tests/*.c` | regresne testy: diery, per-bin vektor, retencia, alarm |
| `vmicollect.example.conf` | vzor konfiguracneho suboru |

Komentare v kode (`Makefile`, `include/vmic.h`, `src/meta.c`, `src/hooks.c`,
`hooks/*.c`, `tests/*.c`) pouzivaju oznacenia blokov A5 az A8 z planu
z 2026-10-05; ich legenda je v [`docs/STAV.sk.md`](../docs/STAV.sk.md).

**Zapis mimo cyklu (od verzie 1.1).** Pri writeri `delta` cyklus na disk
nesiaha: zmenene stranky kopiruje do fronty v pamati (`src/output.c`) a subor,
`fsync`, SHA-256, sidecar, hooky aj retenciu robi vlakno `vmic-writer` v poradi
snimok; riadky logu zapisuje vlakno `vmic-log`. Snimka sa zverejni cela, alebo
vobec: data aj sidecar pod bodkovymi docasnymi menami, potom dve premenovania
s `RENAME_NOREPLACE`. Planovac totiz zapocita do slotu vsetko, co sa v cykle
stane - ked zapis suboru cakal na disk (SSD pocas zapisu na pozadi), cyklus
presiahol periodu a slot sa zahodil. Velkost fronty je `output.queue_mib`
(0 = najvacsia mozna plna snimka + 512 MiB), `output.mlock` uzamkne pamat
procesu (`mlockall`; citanie pamate VM moze vyswapovane stranky QEMU nacitat
aj tak) a `output.drain_s` obmedzi dobehnutie fronty na konci (po signale
najviac 40 s).

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
(`kvm_entry`, `kvm_exit`) sa nevesa nic a VM sa nepozastavuje. Bez vplyvu na
hosta zber napriek tomu nie je - pozri "Snimka je ziva" nizsie.

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
zdravej VM hlasia `read_errors` a `filled_zero` iba skutocne chyby citania a
`changed_ratio` v delta snimke sa pocita zo skutocnej RAM, nie z adresneho
priestoru.

Ked si oblasti zadas rucne (`capture.regions`) a nejaka z nich dieru
pretina, plati zaloha: `vmic_read` vrati `KIND_HOLE` **aj s dlzkou diery az
po najblizsi dalsi slot**, zberac ju vyplni nulami a cita dalej - preskocit,
nie sa zastavit. Naivne "co nedoslo, vynuluj zvysok" by pri diere na
`0xA0000` zahodilo aj shadow BIOS na `0xC0000`, co je normalna RAM. Kontrakt
`read_pa()` (dieru preskocit, nie sa na nej zastavit) strazi regresny test
`tests/hole_test.c` (`make test-holes`) s falosnym backendom. Samotnu BPF
vetvu `KIND_HOLE` tento test nepokryva (HONESTY P5).

### Snimka je "ziva" - VM sa nezastavuje

eBPF je pozorovacie, nie riadiace rozhranie: nema ako povedat "zastav vCPU".
Preto `ops->pause` neexistuje a `capture.pause` je vychodzie `false`.

Co to znamena v praxi: **VM pocas citania bezi, takze dve stranky (a pri
sucasnom zapise aj casti jednej stranky) mozu byt z rozneho okamihu.** Pre
periodicky zber priznakov (a pre casovy rad, ktory z neho vznika) je to
prijatelne. VM sa pritom nepozastavuje (`capture.paused` je `false`,
`pause_ms` 0), zber vsak nie je bez vplyvu na hosta: plna snimka cita celu
RAM procesu QEMU (vyswapovanu pamat nacita spat) a ked je disk VM na tom
istom suborovom systeme ako snimky, spatny zapis snimky moze zdrzat zapisy
hosta. Doklad je v `data/results/collection_io_interference_20261021.json`
a v `docs/MERANIA.md` (zaznam z 2026-10-21 o zamietnutom pilote).

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

Obe cisla v predchadzajucom odseku su ilustracny radovy odhad zo starsej
vetvy, nie meranie (HONESTY kap. 3). Namerane velkosti plnej a delta snimky
su v sidecaroch `data/results/2026-09-18_prvy_beh/sidecars/vmic-delta/`.

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

Pouzitie: po alarme sa oznaci retazec z obdobia PRED alarmom, aby forenzny
material prezil upratovanie. Robi to alarmove rozhranie pluginov (nizsie)
aj detektor `safeguard/`, ktory pri alarme vola `vmicollect hold`.

### Prenos stranok cez jednu mmap mapu

BPF mapa `pages` je `BPF_F_MMAPABLE` a zberac si ju namapuje do svojho
adresneho priestoru. Stranky hosta tak prekrocia hranicu jadro/userspace raz
(`bpf_copy_from_user_task()` v kontexte VMM -> mapa `pages`). V userspace
nasleduje jeden `memcpy` z namapovaneho okna do bufferu zberaca (`eb_read_pa`
v `src/backend_ebpf.c`). Ziadny ringbuf; nulove kopirovanie to nie je
(HONESTY P5).

Bezny pripad je **jedno** volanie helpera na cely blok `capture.chunk_size`
(vychodzie 1 MiB). Jedno volanie pokryje najviac 2 MiB (velkost mapy `pages`)
a skonci aj na hranici memslotu; blok nad 2 MiB alebo cez hranicu slotu
rozdeli `eb_read_pa` na viac volani. Ked volanie zlyha (helper je "vsetko
alebo nic"), program to zopakuje po strankach, takze jedna necitatelna
stranka nezhodi cely blok - a v metadatach je vidiet, ze blok nebol
precitany cely (`read_errors`, `filled_zero`).

---

## Ako to rozsiris

### 1. Vlastny hook (bez prekladania zberaca)

Hook je notifikacny: po kazdej snimke dostane `vmic_snapshot_t` (cesty
k suborom, casy, statistiky, per-bin vektor `features`), ale nema `read_pa` -
pamat VM sam necita (HONESTY P5). Per-bin priznaky pocita modul
(`src/perbin.c`), parsovanie struktur jadra robi `guestparse/` nad ulozenou
snimkou. Vzor: [`hooks/example_hook.c`](hooks/example_hook.c).

```c
int  vmic_hook_init(const vmic_hook_api_t *api, const char *args, void **st);
int  vmic_hook_snapshot(void *st, const vmic_snapshot_t *snap);
void vmic_hook_fini(void *st);
int  vmic_hook_alarm(void *st, const vmic_alarm_t *alarm);
```

Plugin musi exportovat aspon `vmic_hook_snapshot()` alebo `vmic_hook_alarm()`;
`vmic_hook_init()` a `vmic_hook_fini()` su volitelne (`vmic_hooks_load()`
v `src/hooks.c`; komentar v `include/vmic.h` uvadza prve tri ako povinne,
plati kod). Rozhranie zberaca `vmic_hook_api_t` (`abi`, `cfg`, `log`,
`alarm`) dostane plugin vo `vmic_hook_init()` a verziu `VMIC_HOOK_ABI`
(dnes 2, `include/vmic.h`) ma v nom overit, tak ako `example_hook.c`.

```sh
make hooks
sudo ./build/vmicollect run -c my.conf -o hooks.load=./build/example_hook.so:/tmp/index.csv
```

Pri writeri `delta` bezi hook vo vlakne `vmic-writer` az po zverejneni snimky,
nad jej kopiou: dlhy hook nezdrzi cyklus, ale oneskori zverejnenie dalsich
snimok. Pri writeri `raw` bezi **synchronne** v hlavnej slucke a hook dlhsi
ako perioda sposobi zmeskane sloty - nieco narocne daj do fronty a spracuj mimo.
Ukazovatele v snimke platia iba pocas volania. Vlakno `vmic-writer` ma
zablokovane signaly SIGINT, SIGTERM a SIGHUP a dieta spustene z hooku ich
zdedi zablokovane; deti treba spustat s prazdnou maskou
(`posix_spawnattr_setsigmask`). Nenulova navratova hodnota plugin vypne, pri
`hooks.strict=true` ukonci zber.

### 2. Alarm (rozhranie pluginov)

Plugin moze vyhlasit alarm cez `api->alarm()`. Zberac ho spracuje hned
(`vmic_alarm_raise()` v `src/hooks.c`):

1. ked alarm nesie `chain_id` (writer `delta`; writer `raw` ma `chain_id` 0),
   oznaci jeho retazec markerom `HOLD` (flight recorder - forenzny material
   prezije retenciu),
2. prepise `alarm.json` (posledny alarm: cas, `seq`, `chain_id`, zdroj,
   skore, top biny, stav invariantov) a dopise riadok do `alarms.jsonl`
   (historia); schemu `hyptcn3/alarm/1` drzi `src/meta.c` (`vmic_alarm_write`),
3. posle alarm kazdemu pluginu, ktory exportuje `vmic_hook_alarm()`.

Vzory: [`hooks/alarm_hook.c`](hooks/alarm_hook.c) vyhlasi alarm nad prahom
poctu zmenenych stranok a prijima alarmy (NIE JE to detekcia anomalie, je to
priklad kontraktu); [`hooks/react_hook.c`](hooks/react_hook.c) je volitelna
reakcia cez libvirt (`suspend`, `netoff` alebo `snapshot`, rezim `dry` bez
volania `virsh`), vychodzie vypnuta - nacita sa iba cez `hooks.load` - a
latenciu alarm -> reakcia zapisuje do `alarm_reakcia.jsonl`. Obe preklada
`make hooks`, kontrakt strazi `make test-alarm`.

```sh
make hooks
sudo ./build/vmicollect run -o output.writer=delta \
     -o hooks.load=./build/alarm_hook.so:/tmp/alarms.csv,100
```

Detektor prace pluginom nie je: `safeguard/` (`python3 -m safeguard`,
[`docs/SAFEGUARD.sk.md`](../docs/SAFEGUARD.sk.md)) bezi mimo zberaca, cita
snimky a ich sidecary a pri alarme vola `vmicollect hold`. Alarmove
rozhranie pluginov ani `react_hook` nepouziva. Schemu `hyptcn3/alarm/1`
dnes v repozitari necita ziadny Python skript; diagnosticky
`scripts/detektor.py` zapisuje do suboru s rovnakym menom `alarm.json` iny
format (bez kluca `schema`).

### 3. Vlastny backend alebo writer

1. skopiruj `src/backend_file.c` (najkratsi vzor)
2. vypln `vmic_backend_ops_t` - staci `open/close/probe/read_pa`
3. pridaj dva riadky do `src/internal.h`, jeden do `REGISTRY` v `src/backend.c`
   a meno backendu do `CH_BACKEND` v `src/config.c` (inak `vm.backend` nove
   meno odmietne); ked backend vie nahodny pristup, dopln ho aj do
   `backend_is_random_access()` v `src/config.c` (bez toho sa writer `delta`
   a `capture.regions` odmietnu)

Writer analogicky: `src/writer_raw.c` -> `vmic_writer_ops_t` -> `REGISTRY`
v `src/writer.c` + `CH_WRITER` v `src/config.c`.

### 4. Vlastny parameter konfiguracie

Pridaj pole do `vmic_config_t` (`include/vmic.h`) a **jeden riadok** do tabulky
`FIELDS` v `src/config.c`. Parameter sa potom da nastavit z `.conf` aj z `-o`,
vypise sa v `config` aj v `config --keys` a skontroluje sa jeho typ. Nenulovu
vychodziu hodnotu treba doplnit do `vmic_config_defaults()`, rozsah alebo
kombinacie s inymi parametrami do `vmic_config_validate()`. Nove pole patri
na koniec `vmic_config_t`, inak sa posunu polia, ktore cita plugin
(`api->cfg`), a s nimi ABI pluginu.

### 5. Zmena BPF casti

```sh
make bpf                     # prelozi iba bpf/vmic_kvm.bpf.c -> build/vmic_kvm.bpf.o
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

Priklad je ilustracny (vymyslene hodnoty a domena `win10` zo starsej vetvy,
HONESTY kap. 3), nie meranie, a je skrateny. Sidecar ma
`"schema": "vmicollect/1"`, `version` a navyse kluce `id`, `path`, `timestamp_unix`,
`vm.vmid`, `vm.max_paddr`, `vm.num_vcpus`, `vm.address_width`,
`vm.page_mode`, `capture.regions`, `capture.chunk_size`, `capture.paused`,
`capture.pause_exceeded`, `stats.bytes_requested`, `stats.chunks`,
`stats.filled_zero`, blok `sched` (`lateness_s`, `skipped_before`),
`output.fsync`, `output.async`, `output.mlock`, `output.bytes_logical`,
`output.bytes_on_disk`, `output.page_size`, `output.sha256_covers_file`,
`output.hash_deferred`, kluce verzie 1.1 (nizsie) a pri writeri `delta` blok
`features` (nizsie). Uplny zoznam je v `src/meta.c`. Skutocne sidecary su
napr. v `data/results/perbin_c_20260918/sidecars/`; su z 2026-09-18 (verzia
1.0.0), takze `sched`, `output.fsync`, `output.hash_deferred`,
`features.regions` ani kluce verzie 1.1 este nemaju.

`paused` je to, co sa naozaj stalo, nie co si ziadal config: backend `ebpf`
VM zastavit nevie, takze tam bude vzdy `false` a `pause_ms` 0.

Od verzie 1.1 (`"version": "1.1.0"`, `output.async: true`) je `capture_ms`
citanie, porovnanie, priznaky, kopia do fronty a cakanie na pamat fronty
(bez zapisu na disk), `write_ms` zapis suboru vo vlakne `vmic-writer` a
pribudli `output.async`, `output.mlock`, `capture.backend_read_ms`,
`capture.begin_ms`, `capture.queue_wait_ms`, `capture.rusage`,
`output.data_closed_ms`, `output.sha_ms` a stav fronty
(`queue_jobs`, `queue_bytes`, `queue_pool_bytes`). Pri writeri `raw`
(`output.async: false`) obsahuje `capture_ms` aj vo verzii 1.1 zapis blokov
(`pwrite()` vo `feed()`). Presne definicie su v `docs/ARCHITEKTURA.md`,
cast 6.

`read_errors` je pocet blokov (`capture.chunk_size`), z ktorych backend
neprecital vsetko; kolko bajtov nahradili nuly, hovori `stats.filled_zero`.
Diery medzi memslotmi sa nezbieraju, takze sa v tychto cislach neobjavia.

### Blok `features` - per-bin priznakovy vektor

Pri writeri `delta` pocita `src/perbin.c` pocas porovnavania stranok pre
kazdy bin velkosti `features.bin_bytes` (vychodzie 16 MiB, mocnina 2, aspon
`output.delta_page_size`) pocet podlozenych, zmenenych a nulovych stranok a
priemernu Shannonovu entropiu zmenenych stranok (`features.entropy`,
vychodzie zapnuta). Biny vznikaju iba nad podlozenymi oblastami (memslotmi),
index binu = GPA >> log2(bin_bytes). Vypina sa `features.enable=false`; pri
writeri `raw` vektor nevznika.

Do sidecaru ide blok `features` so schemou `hyptcn3/perbin/1`: `bin_bytes`,
`page_size`, `entropy`, `compute_ms`, `bins_total`, `regions` (oblasti, nad
ktorymi biny vznikli) a pole `bins` s polami `bin`, `gpa`, `pages_total`,
`pages_changed`, `changed_ratio`, `zero_ratio`, `entropy_mean` (iba pri
zapnutej entropii) a `has_changed`. Blok sa zapise iba vtedy, ked vektor
prejde kontrolou invariantu (sucty `pages_total` a `pages_changed` cez biny
sedia so snimkou); inak v sidecari chyba. Kontrakt a nezavisla Pythonova
referencia: [`features/PERBIN.md`](../features/PERBIN.md); test
`make test-perbin`.

---

## Ciele `make`

| ciel | co robi |
|---|---|
| `make` | prelozi BPF program aj zberac -> `build/vmicollect` |
| `make bpf` | prelozi iba BPF cast (rychla kontrola po uprave) |
| `make hooks` | prelozi vzorove pluginy `example_hook`, `alarm_hook`, `react_hook` -> `build/*.so` |
| `make test` | selftest + regresne testy (`test-holes`, `test-perbin`, `test-retention`, `test-alarm`) - cela cesta bez VM a bez roota |
| `make test-holes` | regresny test preskakovania dier (kontrakt `read_pa` s falosnym backendom) |
| `make test-perbin` | regresny test per-bin vektora (biny, invariant suctov, entropia) |
| `make test-retention` | regresny test markera `HOLD` v retencii |
| `make test-alarm` | regresny test alarmoveho rozhrania (`alarm_hook`, `react_hook` v rezime `dry`) |
| `make check` | `make clean`, potom preklad s kontrolou UB a pretecenia + selftest, `test-holes`, `test-perbin` |
| `make debug` | `make clean`, potom ASan/UBSan (`sudo dnf install libasan libubsan`) |
| `make install` | do `$(PREFIX)/bin`, vychodzie `/usr/local` |
| `make uninstall` | zmaze nainstalovanu binarku |
| `make clean` | zmaze `build/` |
| `make help` | vypise hlavicku `Makefile` |

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

**Profil jadra hosta zberac nepotrebuje.** Cita fyzicku pamat podla memslotov,
takze ho KASLR hosta neovplyvnuje. Snimku interpretuje az `guestparse/`
(procesy, moduly, sokety) a ten potrebuje profil jadra hosta z `profiles/` -
priznanu vstupnu zavislost (HONESTY P6).
