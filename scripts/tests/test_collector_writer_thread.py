"""The collector's sampling thread does no file I/O; a stalled disk delays publication, never a cycle.

Campaign benign-v4-20261022 lost a slot when one cycle waited 5 s on SSD writeback while it created,
wrote and renamed snapshot files on the sampling thread. tmpfs cannot stall, so an LD_PRELOAD shim
counts and delays the libc calls that write to files instead.
"""
import fcntl
import json
import os
from pathlib import Path
import re
import subprocess
import time

import pytest

REPO = Path(__file__).resolve().parents[2]
BIN = Path(os.environ.get("VMIC_TEST_BIN", REPO / "vmicollect/build/vmicollect"))  # override: compare builds
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="vmicollect is not built (make -C vmicollect)")

SHIM = r"""
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

/* File-system calls and heap allocations of the main (sampling) thread, per interval between its
   clock_nanosleep calls: interval k holds everything the main thread did after its k-th sleep. */
static int sleeps, counts[8192], allocs[8192];
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static int stalled, failed, part_writes;

static int is_main(void) { return syscall(SYS_gettid) == getpid(); }
static int env(const char *name) { const char *v = getenv(name); return v ? atoi(v) : 0; }

static void note(void)
{
    if (is_main() && sleeps > 0 && sleeps < 8192) counts[sleeps]++;
}

static void note_alloc(void)
{
    if (is_main() && sleeps > 0 && sleeps < 8192) allocs[sleeps]++;
}

extern void *__libc_malloc(size_t);
extern void *__libc_calloc(size_t, size_t);
extern void *__libc_realloc(void *, size_t);
void *malloc(size_t n) { note_alloc(); return __libc_malloc(n); }
void *calloc(size_t n, size_t m) { note_alloc(); return __libc_calloc(n, m); }
void *realloc(void *p, size_t n) { note_alloc(); return __libc_realloc(p, n); }

/* SHIM_STALL_MS / SHIM_STALL_COUNT: once sampling has started (and SHIM_STALL_AFTER_MS later), the first
   COUNT write-type calls of any thread sleep that long - a disk stuck in writeback. */
static struct timespec first_sleep;

static void stall(void)
{
    int ms = env("SHIM_STALL_MS"), limit = env("SHIM_STALL_COUNT"), after = env("SHIM_STALL_AFTER_MS");
    if (!ms || sleeps == 0) return;
    if (after) {
        struct timespec now;
        clock_gettime(CLOCK_MONOTONIC, &now);
        long elapsed = (now.tv_sec - first_sleep.tv_sec) * 1000L + (now.tv_nsec - first_sleep.tv_nsec) / 1000000L;
        if (elapsed < after) return;
    }
    pthread_mutex_lock(&mu);
    int go = stalled < limit;
    if (go) stalled++;
    pthread_mutex_unlock(&mu);
    if (go) { struct timespec t = { ms / 1000, (ms % 1000) * 1000000L }; nanosleep(&t, NULL); }
}

#define REAL(ret, name, ...) static ret (*real)(__VA_ARGS__); if (!real) real = dlsym(RTLD_NEXT, #name)

int clock_nanosleep(clockid_t c, int flags, const struct timespec *req, struct timespec *rem)
{
    REAL(int, clock_nanosleep, clockid_t, int, const struct timespec *, struct timespec *);
    if (is_main() && sleeps++ == 0) clock_gettime(CLOCK_MONOTONIC, &first_sleep);
    return real(c, flags, req, rem);
}

static int part_fd = -1;

/* SHIM_FAIL_PART_WRITE=N: the N-th write() into a .part file fails with ENOSPC. */
ssize_t write(int fd, const void *buf, size_t n)
{
    REAL(ssize_t, write, int, const void *, size_t);
    note(); stall();
    int fail = env("SHIM_FAIL_PART_WRITE");
    if (fail && fd == part_fd) {
        pthread_mutex_lock(&mu);
        int now = ++part_writes == fail;
        if (now) failed++;
        pthread_mutex_unlock(&mu);
        if (now) { errno = ENOSPC; return -1; }
    }
    return real(fd, buf, n);
}
ssize_t pwrite(int fd, const void *b, size_t n, off_t o) { REAL(ssize_t, pwrite, int, const void *, size_t, off_t); note(); stall(); return real(fd, b, n, o); }
ssize_t pwrite64(int fd, const void *b, size_t n, off_t o) { REAL(ssize_t, pwrite64, int, const void *, size_t, off_t); note(); stall(); return real(fd, b, n, o); }
ssize_t writev(int fd, const struct iovec *v, int c) { REAL(ssize_t, writev, int, const struct iovec *, int); note(); stall(); return real(fd, v, c); }

static int opened(const char *path, int fd)
{
    if (fd >= 0 && path && strstr(path, ".part")) part_fd = fd;
    return fd;
}
#define OPEN_BODY(name) \
    mode_t mode = 0; \
    if (flags & (O_CREAT | O_TMPFILE)) { va_list ap; va_start(ap, flags); mode = va_arg(ap, mode_t); va_end(ap); } \
    note(); \
    if (flags & (O_WRONLY | O_RDWR | O_CREAT | O_TRUNC)) stall();
int open(const char *p, int flags, ...) { REAL(int, open, const char *, int, ...); OPEN_BODY(open) return opened(p, real(p, flags, mode)); }
int open64(const char *p, int flags, ...) { REAL(int, open64, const char *, int, ...); OPEN_BODY(open64) return opened(p, real(p, flags, mode)); }
int openat(int d, const char *p, int flags, ...) { REAL(int, openat, int, const char *, int, ...); OPEN_BODY(openat) return opened(p, real(d, p, flags, mode)); }
int openat64(int d, const char *p, int flags, ...) { REAL(int, openat64, int, const char *, int, ...); OPEN_BODY(openat64) return opened(p, real(d, p, flags, mode)); }
int rename(const char *a, const char *b) { REAL(int, rename, const char *, const char *); note(); stall(); return real(a, b); }
int renameat(int x, const char *a, int y, const char *b) { REAL(int, renameat, int, const char *, int, const char *); note(); stall(); return real(x, a, y, b); }
int renameat2(int x, const char *a, int y, const char *b, unsigned f) { REAL(int, renameat2, int, const char *, int, const char *, unsigned); note(); stall(); return real(x, a, y, b, f); }
int fstat(int fd, struct stat *b) { REAL(int, fstat, int, struct stat *); note(); return real(fd, b); }
int statx(int d, const char *p, int f, unsigned m, struct statx *b) { REAL(int, statx, int, const char *, int, unsigned, struct statx *); note(); return real(d, p, f, m, b); }
int close(int fd) { REAL(int, close, int); note(); return real(fd); }
int unlink(const char *p) { REAL(int, unlink, const char *); note(); return real(p); }
ssize_t read(int fd, void *b, size_t n) { REAL(ssize_t, read, int, void *, size_t); note(); return real(fd, b, n); }
int unlinkat(int d, const char *p, int f) { REAL(int, unlinkat, int, const char *, int); note(); return real(d, p, f); }
int fsync(int fd) { REAL(int, fsync, int); note(); stall(); return real(fd); }
int fdatasync(int fd) { REAL(int, fdatasync, int); note(); stall(); return real(fd); }
int mkdir(const char *p, mode_t m) { REAL(int, mkdir, const char *, mode_t); note(); return real(p, m); }
int stat(const char *p, struct stat *b) { REAL(int, stat, const char *, struct stat *); note(); return real(p, b); }
int lstat(const char *p, struct stat *b) { REAL(int, lstat, const char *, struct stat *); note(); return real(p, b); }
int fstatat(int d, const char *p, struct stat *b, int f) { REAL(int, fstatat, int, const char *, struct stat *, int); if (p && *p) note(); return real(d, p, b, f); }
int access(const char *p, int m) { REAL(int, access, const char *, int); note(); return real(p, m); }
void *opendir(const char *p) { REAL(void *, opendir, const char *); note(); return real(p); }
FILE *fopen(const char *p, const char *m) { REAL(FILE *, fopen, const char *, const char *); note(); if (strpbrk(m, "wa+")) stall(); return real(p, m); }
FILE *fopen64(const char *p, const char *m) { REAL(FILE *, fopen64, const char *, const char *); note(); if (strpbrk(m, "wa+")) stall(); return real(p, m); }
size_t fwrite(const void *b, size_t s, size_t n, FILE *f) { REAL(size_t, fwrite, const void *, size_t, size_t, FILE *); note(); return real(b, s, n, f); }
int fputs(const char *s, FILE *f) { REAL(int, fputs, const char *, FILE *); note(); return real(s, f); }
int fputc(int c, FILE *f) { REAL(int, fputc, int, FILE *); note(); return real(c, f); }
int fflush(FILE *f) { REAL(int, fflush, FILE *); if (f) note(); return real(f); }
int vfprintf(FILE *f, const char *fmt, va_list ap) { REAL(int, vfprintf, FILE *, const char *, va_list); note(); return real(f, fmt, ap); }
int fprintf(FILE *f, const char *fmt, ...) { va_list ap; va_start(ap, fmt); int r = vfprintf(f, fmt, ap); va_end(ap); return r; }
int __vfprintf_chk(FILE *f, int flag, const char *fmt, va_list ap) { (void)flag; return vfprintf(f, fmt, ap); }
int __fprintf_chk(FILE *f, int flag, const char *fmt, ...) { (void)flag; va_list ap; va_start(ap, fmt); int r = vfprintf(f, fmt, ap); va_end(ap); return r; }

__attribute__((destructor)) static void report(void)
{
    const char *path = getenv("SHIM_REPORT");
    if (!path) return;
    FILE *(*real_fopen)(const char *, const char *) = (FILE *(*)(const char *, const char *))dlsym(RTLD_NEXT, "fopen");
    FILE *f = real_fopen(path, "w");
    if (!f) return;
    int total = sleeps < 8192 ? sleeps : 8191;
    fprintf(f, "sleeps %d stalled %d failed %d\n", total, stalled, failed);
    for (int k = 1; k <= total; k++) fprintf(f, "%d %d %d\n", k, counts[k], allocs[k]);
    fclose(f);
}
"""


@pytest.fixture(scope="module")
def shim(tmp_path_factory):
    work = tmp_path_factory.mktemp("shim")
    source, library = work / "shim.c", work / "libfsshim.so"
    source.write_text(SHIM)
    try:
        subprocess.run(["cc", "-shared", "-fPIC", "-O1", "-o", library, source, "-ldl", "-lpthread"],
                       check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError) as exc:
        pytest.skip(f"C compiler unavailable for the file I/O shim: {exc}")
    return library


def image(tmp_path):
    path = tmp_path / "img.raw"
    path.write_bytes(bytes(range(256)) * (2 * 16 * 4096))  # 32 MiB, two 16 MiB bins
    return path


def run(tmp_path, *options, env=None, timeout=120, **kwargs):
    out = tmp_path / "out"
    command = [BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image(tmp_path)}",
               "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
               "-o", "features.bin_bytes=16777216", *[a for o in options for a in ("-o", o)]]
    result = subprocess.run(command, capture_output=True, text=True, timeout=timeout,
                            env={"PATH": "/usr/bin:/bin", **(env or {})}, **kwargs)
    return result, out


def sidecars(out):
    return sorted((json.loads(p.read_text()) for p in out.glob("*.json")), key=lambda d: d["seq"])


def koniec(log):
    m = re.search(r"koniec: (\d+) snimok, (\d+) chyb, (\d+) zmeskanych slotov", log)
    assert m, log
    return tuple(map(int, m.groups()))


def shim_report(path):
    lines = path.read_text().split("\n")
    sleeps = int(lines[0].split()[1])
    rows = [tuple(map(int, l.split())) for l in lines[1:] if l]
    return sleeps, {k: fs for k, fs, _ in rows}, {k: a for k, _, a in rows}


def test_sampling_thread_makes_no_file_calls_and_no_allocations(tmp_path, shim):
    """No cycle opens, stats, writes, renames or syncs a file on the sampling thread; after the first
    cycle (hash table, change map) it allocates nothing either."""
    report = tmp_path / "report.txt"
    # align=true: the scheduler also sleeps before cycle 0, so the first full snapshot is covered.
    result, out = run(tmp_path, "schedule.interval_s=0.3", "schedule.align=true", "schedule.max_cycles=8",
                      "output.delta_full_every=3", env={"LD_PRELOAD": str(shim), "SHIM_REPORT": str(report)})
    assert result.returncode == 0, result.stderr
    assert koniec(result.stderr) == (8, 0, 0)
    sleeps, counts, allocs = shim_report(report)
    assert sleeps == 8  # one sleep before every cycle
    # Interval k = cycle k-1 up to the next sleep; the last interval also holds the shutdown.
    assert {k: counts[k] for k in range(1, sleeps)} == {k: 0 for k in range(1, sleeps)}
    assert {k: allocs[k] for k in range(2, sleeps)} == {k: 0 for k in range(2, sleeps)}
    assert [s["seq"] for s in sidecars(out)] == list(range(8))
    subprocess.run([BIN, "verify", out], check=True, capture_output=True, timeout=60)


def test_stalled_disk_delays_publication_not_cycles(tmp_path, shim):
    """Each of the first 6 write-type calls blocks 1.2 s; at a 0.4 s period no slot may be lost."""
    report = tmp_path / "report.txt"
    result, out = run(tmp_path, "schedule.interval_s=0.4", "schedule.max_cycles=12", "output.delta_full_every=4",
                      env={"LD_PRELOAD": str(shim), "SHIM_REPORT": str(report),
                           "SHIM_STALL_MS": "1200", "SHIM_STALL_COUNT": "6"})
    assert result.returncode == 0, result.stderr
    assert "stalled 6" in report.read_text()
    assert koniec(result.stderr) == (12, 0, 0)
    docs = sidecars(out)
    assert [d["seq"] for d in docs] == list(range(12))
    assert [d["output"]["full"] for d in docs] == [i % 4 == 0 for i in range(12)]
    assert all(d["sched"]["skipped_before"] == 0 for d in docs)
    # Timing fields are real and nested: read_pa time <= capture <= cycle < period.
    assert all(0 < d["capture"]["backend_read_ms"] <= d["capture"]["capture_ms"] <= d["capture"]["total_ms"] < 400
               for d in docs)
    assert all(d["output"]["async"] and len(d["output"]["sha256"]) == 64 for d in docs)
    # The stall is visible where it belongs: queued bytes and the time to written data, not in the cycle.
    assert max(d["output"]["queue_bytes"] for d in docs) > 0
    assert max(d["output"]["data_closed_ms"] for d in docs) > 1200
    assert not [p.name for p in out.iterdir() if p.name.startswith(".") or p.name.endswith(".tmp")]
    subprocess.run([BIN, "verify", out], check=True, capture_output=True, timeout=60)


def test_blocked_log_reader_does_not_skip_slots(tmp_path):
    """collect.log is written by the log thread: a full stderr pipe must not hold up sampling."""
    read_end, write_end = os.pipe()
    fcntl.fcntl(write_end, 1031, 4096)  # F_SETPIPE_SZ: one page, so the log fills it quickly
    out = tmp_path / "out"
    process = subprocess.Popen([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image(tmp_path)}",
                                "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
                                "-o", "features.bin_bytes=16777216", "-o", "schedule.interval_s=0.1",
                                "-o", "schedule.max_cycles=40", "-o", "output.delta_full_every=10"],
                               stdout=write_end, stderr=write_end, env={"PATH": "/usr/bin:/bin"})
    os.close(write_end)
    time.sleep(5.5)  # nobody reads: about 40 cycle lines cannot fit into one page
    chunks = []
    while chunk := os.read(read_end, 65536):
        chunks.append(chunk)
    os.close(read_end)
    assert process.wait(timeout=60) == 0
    log = b"".join(chunks).decode()
    assert koniec(log) == (40, 0, 0)
    assert len(re.findall(r" INFO  #\d+ ", log)) == 40 and log.endswith("\n")
    assert all(d["sched"]["skipped_before"] == 0 for d in sidecars(out))


def test_failed_snapshot_write_breaks_the_chain_and_fails_the_run(tmp_path, shim):
    """A late write error is an error of that snapshot: nothing partial stays, the chain restarts full."""
    result, out = run(tmp_path, "schedule.interval_s=0.5", "schedule.max_cycles=4", "output.delta_full_every=100",
                      env={"LD_PRELOAD": str(shim), "SHIM_FAIL_PART_WRITE": "2"})
    assert result.returncode == 4, result.stderr
    assert " ERROR " in result.stderr and "zapis dat" in result.stderr
    published, errors, missed = koniec(result.stderr)
    docs = sidecars(out)
    assert published == len(docs) and errors == 4 - published and missed == 0
    # Seq 0 (full) fails while writing its records; later deltas of that chain are never published,
    # and the sampler starts a new full chain once it sees the failure (seq = order of capture, so the
    # failed and dropped snapshots leave a gap).
    assert docs and all(d["seq"] > 0 for d in docs) and docs[0]["output"]["full"]
    assert all(d["output"]["chain_id"] == docs[0]["output"]["chain_id"] for d in docs)
    assert not [p.name for p in out.iterdir() if p.name.startswith(".") or p.name.endswith(".tmp")]
    subprocess.run([BIN, "verify", out], check=True, capture_output=True, timeout=60)


def test_queue_smaller_than_a_full_snapshot_is_rejected_at_start(tmp_path):
    """An explicit queue that cannot hold a full snapshot of the collected regions never starts sampling."""
    result, out = run(tmp_path, "schedule.interval_s=0.3", "schedule.max_cycles=2", "output.queue_mib=4",
                      timeout=60)
    assert result.returncode == 3, result.stderr
    assert "output.queue_mib" in result.stderr and "nestaci" in result.stderr
    assert not out.exists() or not sidecars(out)


def test_hash_async_option_no_longer_exists(tmp_path):
    result = subprocess.run([BIN, "config", "-o", "output.hash_async=true"], capture_output=True, text=True,
                            timeout=30)
    assert result.returncode != 0 and "hash_async" in result.stderr


def test_mlock_and_queue_size_are_configurable(tmp_path):
    result = subprocess.run([BIN, "config", "-o", "output.mlock=true", "-o", "output.queue_mib=64"],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    assert re.search(r"^mlock\s+= true$", result.stdout, re.M)
    assert re.search(r"^queue_mib\s+= 64$", result.stdout, re.M)


def test_sigterm_during_a_stalled_writer_ends_within_the_drain_budget(tmp_path, shim):
    """After a signal the collector waits at most min(drain_s, 40 s), counts what is left and leaves no temp files."""
    out = tmp_path / "out"
    env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(shim), "SHIM_STALL_MS": "2000", "SHIM_STALL_COUNT": "40"}
    process = subprocess.Popen([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image(tmp_path)}",
                                "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
                                "-o", "features.bin_bytes=16777216", "-o", "schedule.interval_s=0.3",
                                "-o", "schedule.max_cycles=100", "-o", "output.drain_s=3"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    time.sleep(2.0)
    t0 = time.monotonic()
    process.terminate()
    stdout, stderr = process.communicate(timeout=30)
    assert time.monotonic() - t0 < 12, stderr
    assert process.returncode in (1, 4), stderr  # 1 when nothing at all could be published
    assert "dobehnutie fronty prekrocilo" in stderr and " ERROR " in stderr
    published, errors, missed = koniec(stderr)
    assert errors > 0 and missed == 0 and published == len(sidecars(out))
    assert not [p.name for p in out.iterdir() if p.name.startswith(".")]


def test_sigterm_while_waiting_for_queue_memory_stops_promptly(tmp_path, shim):
    """A sampler blocked on a full queue still reacts to SIGTERM (timed waits check the stop flag)."""
    out = tmp_path / "out"
    env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(shim), "SHIM_STALL_MS": "2000", "SHIM_STALL_COUNT": "40"}
    # 48 MiB holds one 32 MiB full; the next full has to wait while the writer is stalled.
    process = subprocess.Popen([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image(tmp_path)}",
                                "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
                                "-o", "features.bin_bytes=16777216", "-o", "schedule.interval_s=0.2",
                                "-o", "schedule.max_cycles=100", "-o", "output.delta_full_every=2",
                                "-o", "output.queue_mib=48", "-o", "output.drain_s=2"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    time.sleep(2.5)
    t0 = time.monotonic()
    process.terminate()
    stdout, stderr = process.communicate(timeout=30)
    assert time.monotonic() - t0 < 10, stderr
    assert process.returncode in (1, 4), stderr
    assert "koniec:" in stderr
    assert not [p.name for p in out.iterdir() if p.name.startswith(".")]


def test_sigterm_during_the_final_drain_caps_it_at_40_s(tmp_path, shim):
    """A signal that arrives after the last cycle shortens a long drain (output.drain_s=100) to 40 s."""
    out = tmp_path / "out"
    env = {"PATH": "/usr/bin:/bin", "LD_PRELOAD": str(shim), "SHIM_STALL_MS": "2000", "SHIM_STALL_COUNT": "200"}
    process = subprocess.Popen([BIN, "run", "-o", "vm.backend=file", "-o", f"vm.image_path={image(tmp_path)}",
                                "-o", f"output.dir={out}", "-o", "output.writer=delta", "-o", "output.fsync=false",
                                "-o", "features.bin_bytes=16777216", "-o", "schedule.interval_s=0.2",
                                "-o", "schedule.max_cycles=3", "-o", "output.drain_s=100"],
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, env=env)
    time.sleep(3.0)  # all three cycles are done; the writer is stalled on the first full snapshot
    t0 = time.monotonic()
    process.terminate()
    stdout, stderr = process.communicate(timeout=90)
    assert time.monotonic() - t0 < 52, stderr  # 40 s budget + 3 s grace + log stop
    assert "dobehnutie fronty prekrocilo" in stderr and "koniec:" in stderr
    published, errors, missed = koniec(stderr)
    assert published + errors == 3 and errors > 0 and missed == 0
    assert process.returncode in (1, 4)


def test_slow_log_write_at_the_end_is_not_reported_as_loss(tmp_path, shim):
    """One collect.log write that takes 6 s near the end is slow, not lost: exit 0, no ERROR line."""
    result, out = run(tmp_path, "schedule.interval_s=0.3", "schedule.max_cycles=6",
                      env={"LD_PRELOAD": str(shim), "SHIM_STALL_MS": "6000", "SHIM_STALL_COUNT": "1",
                           "SHIM_STALL_AFTER_MS": "1300"}, timeout=120)
    assert result.returncode == 0, result.stderr
    assert koniec(result.stderr) == (6, 0, 0) and " ERROR " not in result.stderr
    assert [d["seq"] for d in sidecars(out)] == list(range(6))

