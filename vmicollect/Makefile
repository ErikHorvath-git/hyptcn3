# ---------------------------------------------------------------------
# vmicollect - periodicky zber pamatovych snimok KVM domen cez eBPF
#
#   make            prelozi BPF program aj zberac do build/vmicollect
#   make bpf        prelozi iba bpf/vmic_kvm.bpf.c (rychla kontrola)
#   make hooks      prelozi vzorovy plugin do build/example_hook.so
#   make test       selftest + regresne testy (nepotrebuje VM ani roota)
#   make check      preklad s kontrolami UB/pretecenia + selftest
#   make debug      preklad s ASan/UBSan (dnf install libasan libubsan)
#   make install    nainstaluje do $(PREFIX)/bin  (vychodzie /usr/local)
#   make clean
#
# Zavislosti: clang (preklad BPF casti), libbpf, zlib, libdl, libm
#   dnf install clang libbpf-devel elfutils-libelf-devel zlib-devel
#
# Ked clang alebo libbpf chybaju, zberac sa PRELOZI aj tak - iba bez
# backendu 'ebpf' (backend 'file', selftest a testy funguju dalej).
# ---------------------------------------------------------------------

CC      ?= gcc
CLANG   ?= clang
LD      ?= ld
PREFIX  ?= /usr/local
BUILD   ?= build

# ---- eBPF cast ------------------------------------------------------
# Prelozit ju vieme iba s clangom (gcc cielovu architekturu bpf nema)
# a nacitat iba s libbpf.
HAVE_LIBBPF := $(shell pkg-config --exists libbpf 2>/dev/null && echo 1)
HAVE_CLANG  := $(shell command -v $(CLANG) >/dev/null 2>&1 && echo 1)
EBPF        := $(if $(HAVE_LIBBPF),$(HAVE_CLANG),)

BPF_SRC   := bpf/vmic_kvm.bpf.c
BPF_OBJ   := $(BUILD)/vmic_kvm.bpf.o
BPF_EMBED := $(BUILD)/vmic_kvm.bpf.embed.o

# -g je POVINNE: bez neho clang nevygeneruje BTF a program sa nenacita.
# -mcpu=v3 kvoli 32-bitovym skokom v cykloch nad memslotmi.
# Priradenie je ZAMERNE rekurzivne (=, nie :=): $(BPF_INC) sa plni az
# nizsie a bez toho by sa sem rozvinulo prazdno. Program vklada
# <bpf/bpf_helpers.h>, cize ked libbpf nie je v /usr/include (vlastny
# build, cross sysroot), bez tejto cesty by preklad spadol.
BPF_CFLAGS = -g -O2 -target bpf -mcpu=v3 -D__TARGET_ARCH_x86 \
             -Wall -Wextra -Ibpf $(BPF_INC)

ifeq ($(EBPF),1)
BPF_DEFS  := -DVMIC_HAVE_EBPF
BPF_LIBS  := $(shell pkg-config --libs libbpf)
BPF_INC   := $(shell pkg-config --cflags libbpf)
EMBED_OBJ := $(BPF_EMBED)
else
BPF_DEFS  :=
BPF_LIBS  :=
BPF_INC   :=
EMBED_OBJ :=
endif

Z_CFLAGS   := $(shell pkg-config --cflags zlib 2>/dev/null)
Z_LIBS     := $(shell pkg-config --libs   zlib 2>/dev/null || echo -lz)

# -Wno-format-truncation: snprintf() pouzivame zamerne ako bezpecne
# orezavajuce kopirovanie do poli pevnej velkosti.
WARN := -Wall -Wextra -Wshadow -Wpointer-arith -Wcast-align \
        -Wstrict-prototypes -Wmissing-prototypes -Wno-format-truncation

# OPT a SAN sa daju prebit zvonka (pouziva to ciel `debug`), zvysok
# flagov sa vzdy pripoji - inak by sa stratili -I cesty a pkg-config.
OPT     ?= -O2 -g
SAN     ?=

# -MMD -MP: prekladac si sam vyrobi zoznam hlaviciek, ktore .c subor
# pouziva (build/*.d). Bez toho by zmena bpf/vmic_bpf_abi.h prelozila iba
# BPF cast a userspace by zostal s NEZHODNYM rozlozenim struktur - cize
# by posielal offsety do inych poli a cital by z inych adries. Taka chyba
# sa hlada velmi tazko, lebo sa nijako neprejavi pri preklade.
# `override`, lebo priradenie z prikazoveho riadku (`make CFLAGS=-O2`,
# co robi RPM aj vacsina CI obalov) by inak zahodilo aj -Iinclude a
# preklad by spadol hned na prvom subore.
override CFLAGS  += $(OPT) $(SAN) -std=c11 $(WARN) -MMD -MP \
                    -Iinclude -Isrc -Ibpf \
                    $(BPF_DEFS) $(BPF_INC) $(Z_CFLAGS)
override LDFLAGS += $(SAN)
override LDLIBS  += $(BPF_LIBS) $(Z_LIBS) -ldl -lm

SRC := $(wildcard src/*.c)
OBJ := $(patsubst src/%.c,$(BUILD)/%.o,$(SRC))
DEP := $(OBJ:.o=.d)
BIN := $(BUILD)/vmicollect

# Odtlacok konfiguracie. Bez neho by po `dnf install clang` (co radi aj
# README aj chybova hlaska za behu) zostali .o subory prelozene BEZ
# -DVMIC_HAVE_EBPF, prelozil by sa iba BPF program a vysledna binarka by
# sa tvarila, ze backend 'ebpf' v nej nie je. Recept bezi vzdy, ale subor
# prepise iba ked sa obsah zmenil - takze zbytocny preklad nesposobuje.
CONFIG_STAMP := $(BUILD)/.config

.PHONY: all bpf hooks test test-holes test-perbin test-retention test-alarm check debug install uninstall clean help FORCE

all: $(BIN)
ifneq ($(EBPF),1)
	@echo "POZOR: clang alebo libbpf chyba -> backend 'ebpf' nebude fungovat."
	@echo "       dnf install clang libbpf-devel"
endif

$(BIN): $(OBJ) $(EMBED_OBJ) | $(BUILD)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(EMBED_OBJ) $(LDLIBS)
	@echo "hotovo -> $@"

$(BUILD)/%.o: src/%.c $(CONFIG_STAMP) | $(BUILD)
	$(CC) $(CFLAGS) -c -o $@ $<

$(CONFIG_STAMP): FORCE | $(BUILD)
	@printf 'EBPF=%s DEFS=%s LIBS=%s CC=%s\n' \
		'$(EBPF)' '$(BPF_DEFS)' '$(BPF_LIBS)' '$(CC)' > $@.new; \
	 cmp -s $@.new $@ || { mv -f $@.new $@; }; rm -f $@.new

FORCE:

$(BUILD):
	@mkdir -p $(BUILD)

# ---- BPF program ----------------------------------------------------
bpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) bpf/vmic_bpf_abi.h | $(BUILD)
	$(CLANG) $(BPF_CFLAGS) -c -o $@ $<
	@echo "hotovo -> $@"

# Prelozeny program prilepime priamo do binarky, nech je zberac jeden
# subor. `cd` je dolezity: `ld -r -b binary` odvodzuje meno symbolu z
# CESTY k suboru, takze bez neho by symbol niesol aj adresar `build`.
$(BPF_EMBED): $(BPF_OBJ)
	cd $(BUILD) && $(LD) -r -b binary -o $(notdir $@) $(notdir $<)

# Plugin sa linkuje ako zdielana kniznica; nepotrebuje nic zo zberaca,
# staci mu hlavicka include/vmic.h.
hooks: $(BUILD)/example_hook.so $(BUILD)/alarm_hook.so $(BUILD)/react_hook.so

$(BUILD)/example_hook.so: hooks/example_hook.c include/vmic.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<
	@echo "hotovo -> $@"

# Priklad detektora pre alarmove rozhranie (blok A6): prah na pocet
# zmenenych stranok -> api->alarm(), prijima aj alarmy inych pluginov.
$(BUILD)/alarm_hook.so: hooks/alarm_hook.c include/vmic.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<
	@echo "hotovo -> $@"

# VOLITELNA reakcia na urovni hypervizora cez libvirt (blok A7), DEFAULT
# VYPNUTA (nahra sa len ked je v hooks.load); latencia alarm->reakcia sa
# meria do alarm_reakcia.jsonl.
$(BUILD)/react_hook.so: hooks/react_hook.c include/vmic.h | $(BUILD)
	$(CC) $(CFLAGS) -fPIC -shared -o $@ $<
	@echo "hotovo -> $@"

test: $(BIN) test-holes test-perbin test-retention test-alarm
	$(BIN) selftest $(BUILD)/selftest

# Regresny test na spravne preskakovanie dier vo fyzickom priestore.
# Linkuje sa proti skutocnym .o suborom modulu, iba backend je fake.
TEST_OBJ := $(filter-out $(BUILD)/main.o,$(OBJ))

test-holes: $(BUILD)/hole_test
	$(BUILD)/hole_test

$(BUILD)/hole_test: tests/hole_test.c $(TEST_OBJ) $(EMBED_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_OBJ) $(EMBED_OBJ) $(LDFLAGS) $(LDLIBS)

# Regresny test per-bin priznakoveho vektora (biny iba nad podlozenymi
# rozsahmi, invariant suctov, entropia, determinizmus). Rovnako ako
# hole_test sa linkuje proti skutocnym .o suborom modulu.
test-perbin: $(BUILD)/perbin_test
	$(BUILD)/perbin_test $(BUILD)/perbintest

$(BUILD)/perbin_test: tests/perbin_test.c $(TEST_OBJ) $(EMBED_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_OBJ) $(EMBED_OBJ) $(LDFLAGS) $(LDLIBS)

# Regresny test markera HOLD v retencii (blok A5): oznaceny retazec
# prezije retencne limity, cez chain_id aj cez meno suboru, raw aj delta.
test-retention: $(BUILD)/retention_test
	$(BUILD)/retention_test

$(BUILD)/retention_test: tests/retention_test.c $(TEST_OBJ) $(EMBED_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_OBJ) $(EMBED_OBJ) $(LDFLAGS) $(LDLIBS)

# Regresny test alarmoveho rozhrania (blok A6): alarm.json + alarms.jsonl
# + HOLD + notifikacia vmic_hook_alarm, end-to-end cez hooks.c/meta.c.
test-alarm: $(BUILD)/alarm_test $(BUILD)/alarm_hook.so $(BUILD)/react_hook.so
	$(BUILD)/alarm_test $(BUILD)/alarm_hook.so $(BUILD)/react_hook.so

$(BUILD)/alarm_test: tests/alarm_test.c $(TEST_OBJ) $(EMBED_OBJ) | $(BUILD)
	$(CC) $(CFLAGS) -o $@ $< $(TEST_OBJ) $(EMBED_OBJ) $(LDFLAGS) $(LDLIBS)

# Kontrolny preklad, ktory NEPOTREBUJE ziadne extra balicky:
#   -fsanitize=undefined + trap-on-error  -> UB skonci SIGILL, nie ticho
#   -D_FORTIFY_SOURCE=3                   -> kontrola dlzok v str*/mem*
#   -fstack-protector-all                 -> detekcia pretecenia na zasobniku
# Presne to chces spustit, ked si nieco upravil a chces vediet, ci to nerozbil.
check:
	$(MAKE) clean
	$(MAKE) OPT="-O1 -g3 -D_FORTIFY_SOURCE=3 -fstack-protector-all" \
	        SAN="-fsanitize=undefined -fsanitize-undefined-trap-on-error"
	$(BIN) selftest $(BUILD)/checktest
	$(MAKE) OPT="-O1 -g3 -D_FORTIFY_SOURCE=3 -fstack-protector-all" \
	        SAN="-fsanitize=undefined -fsanitize-undefined-trap-on-error" test-holes
	$(MAKE) OPT="-O1 -g3 -D_FORTIFY_SOURCE=3 -fstack-protector-all" \
	        SAN="-fsanitize=undefined -fsanitize-undefined-trap-on-error" test-perbin
	@echo "check: PRESLO"

# Plna diagnostika. Vyzaduje:  sudo dnf install libasan libubsan
debug:
	$(MAKE) clean
	$(MAKE) OPT="-O1 -g3 -fno-omit-frame-pointer" \
	        SAN="-fsanitize=address,undefined"

install: $(BIN)
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 $(BIN) $(DESTDIR)$(PREFIX)/bin/vmicollect

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/vmicollect

clean:
	rm -rf $(BUILD)

help:
	@sed -n '2,18p' $(firstword $(MAKEFILE_LIST))

-include $(DEP)
