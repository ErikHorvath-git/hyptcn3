/* Which page faults of a read through access_remote_vm (/proc/PID/mem, the path of access_process_vm and so of
 * bpf_copy_from_user_task) are counted in the reading thread's getrusage(RUSAGE_THREAD)?
 *
 * usage: gup_fault_check DISK_FILE
 * file: a child maps DISK_FILE without touching it and its page cache is dropped, so the read needs the disk.
 * swap: a child writes anonymous memory and swaps it out with MADV_PAGEOUT; the read swaps it back in.
 * Build: gcc -O1 -Wall -o gup_fault_check gup_fault_check.c
 */
#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/wait.h>
#include <unistd.h>
#ifndef MADV_PAGEOUT
#define MADV_PAGEOUT 21
#endif
#define N (256 * 4096)

static long swap_kb(pid_t pid)
{
    char path[64], line[256];
    long kb = -1;
    snprintf(path, sizeof path, "/proc/%d/status", pid);
    FILE *f = fopen(path, "r");
    while (f && fgets(line, sizeof line, f))
        if (!strncmp(line, "VmSwap:", 7)) kb = atol(line + 7);
    if (f) fclose(f);
    return kb;
}

static void remote_read(const char *what, pid_t child, char *addr, const char *expect)
{
    char path[64];
    snprintf(path, sizeof path, "/proc/%d/mem", child);
    int fd = open(path, O_RDONLY);
    char *buf = calloc(1, N);
    long swap0 = swap_kb(child);
    struct rusage r0, r1;
    getrusage(RUSAGE_THREAD, &r0);
    ssize_t got = pread(fd, buf, N, (off_t)(unsigned long)addr);
    getrusage(RUSAGE_THREAD, &r1);
    printf("%s: read %zd B, content %s, child VmSwap %ld -> %ld kB, reader thread majflt +%ld minflt +%ld\n",
           what, got, memcmp(buf, expect, N) ? "BAD" : "ok", swap0, swap_kb(child),
           r1.ru_majflt - r0.ru_majflt, r1.ru_minflt - r0.ru_minflt);
    close(fd);
    free(buf);
}

int main(int argc, char **argv)
{
    if (argc != 2) return 2;
    char *data = malloc(N);
    for (size_t i = 0; i < N; i++) data[i] = (char)(i * 13 + 3);
    for (int mode = 0; mode < 2; mode++) {
        int fd = -1, up[2], down[2];
        if (mode == 0) {
            fd = open(argv[1], O_RDWR | O_CREAT | O_TRUNC, 0600);
            if (fd < 0 || write(fd, data, N) != N) return 1;
            fsync(fd);
        }
        if (pipe(up) || pipe(down)) return 1;
        pid_t child = fork();
        if (child == 0) {
            char *m;
            if (mode == 0) {
                m = mmap(NULL, N, PROT_READ, MAP_PRIVATE, fd, 0);
            } else {
                m = mmap(NULL, N, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
                memcpy(m, data, N);
                madvise(m, N, MADV_PAGEOUT);
            }
            if (write(up[1], &m, sizeof m) != sizeof m) _exit(1);
            char c;
            if (read(down[0], &c, 1) < 0) _exit(1);
            _exit(0);
        }
        char *addr;
        if (read(up[0], &addr, sizeof addr) != sizeof addr) return 1;
        if (mode == 0) {
            posix_fadvise(fd, 0, N, POSIX_FADV_DONTNEED);
            unsigned char vec[N / 4096];
            void *probe = mmap(NULL, N, PROT_READ, MAP_SHARED, fd, 0);
            int cached = 0;
            mincore(probe, N, vec);
            for (int i = 0; i < N / 4096; i++) cached += vec[i] & 1;
            munmap(probe, N);
            printf("file: %d of %d pages in the page cache before the read\n", cached, N / 4096);
            remote_read("file", child, addr, data);
        } else {
            usleep(300000);
            remote_read("swap", child, addr, data);
        }
        if (write(down[1], "x", 1) != 1) return 1;
        waitpid(child, NULL, 0);
        if (fd >= 0) { close(fd); unlink(argv[1]); }
    }
    return 0;
}
