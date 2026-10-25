#!/bin/bash
# Induced SSD write load for the writer-thread diagnostic (not part of any session; data only in
# /mnt/ssd/hyptcn3-work/diagnostics, deleted afterwards). Waits until the diagnostic has published the
# sidecar of seq START_SEQ (just after the second full snapshot at seq 360), then writes SIZE of random data
# through the page cache with one fdatasync at the end, which saturates the DRAM-less SSD for a while.
# usage: ballast.sh RAW_DIR LOG [START_SEQ] [SIZE]
RAW=$1
LOG=$2
SEQ=${3:-365}
SIZE=${4:-6G}
[ -n "$RAW" ] && [ -n "$LOG" ] || { echo "usage: $0 RAW_DIR LOG [START_SEQ] [SIZE]"; exit 2; }
F=/mnt/ssd/hyptcn3-work/diagnostics/ballast-$$.bin
until compgen -G "$RAW/*_$(printf %06d "$SEQ")_*.json" > /dev/null; do sleep 2; done
FREE=$(df --output=avail -B1G /mnt/ssd | tail -1)
echo "free_gib_before $FREE" >> "$LOG"
if [ "$FREE" -lt 45 ]; then echo "abort: not enough free space for the reserve plus ballast" >> "$LOG"; exit 1; fi
echo "start $(date -u +%FT%T.%3NZ)" >> "$LOG"
head -c "$SIZE" /dev/urandom | dd of="$F" bs=4M iflag=fullblock conv=fdatasync status=none
echo "written $(date -u +%FT%T.%3NZ)" >> "$LOG"
rm -f "$F"
echo "end $(date -u +%FT%T.%3NZ)" >> "$LOG"
