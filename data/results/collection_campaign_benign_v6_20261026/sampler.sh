#!/bin/bash
# Passive, read-only /proc sampler for campaign benign-v6 (diagnoses slow audits, e.g. s40 77.7 min vs ~20).
# One line per 30 s; stops when the runner exits or after 22 h. Reads only /proc and the campaign status.json.
OUT=/tmp/claude-1000/-home-eh-projects-hyptcn3/07093d58-41fa-4430-9394-40392329f312/scratchpad/v6/sampler.log
STATUS=/home/eh/projects/hyptcn3/data/campaigns/benign-v6-20261026/status.json
RUNNER=3145866
QEMU=3129887
end=$(( $(date +%s) + 22*3600 ))
while [ "$(date +%s)" -lt "$end" ] && [ -d /proc/$RUNNER ]; do
  ts=$(date -u +%FT%TZ)
  stage=$(grep -o '"stage": "[^"]*"' $STATUS 2>/dev/null | cut -d'"' -f4)
  sess=$(grep -o '"session": "[^"]*"' $STATUS 2>/dev/null | cut -d'"' -f4 | sed 's/benign-v6-20261026_//' | cut -c1-2)
  psi=$(for r in cpu memory io; do awk -v r=$r '{split($2,a,"="); split($5,t,"="); printf "%s_%s=%s/%d ", r, $1, a[2], t[2]/1000000}' /proc/pressure/$r; done)
  vm=$(awk '$1~/^(pswpin|pswpout|pgmajfault|pgsteal_kswapd|pgsteal_direct|pgscan_kswapd)$/{printf "%s=%s ", $1, $2}' /proc/vmstat)
  mem=$(awk '$1~/^(MemFree|MemAvailable|Cached|SwapFree|Dirty|Writeback):$/{sub(":","",$1); printf "%s=%d ", $1, $2/1024}' /proc/meminfo)
  q=$(awk '/^(VmRSS|VmSwap):/{printf "qemu_%s=%d ", $1, $2/1024}' /proc/$QEMU/status 2>/dev/null)
  procs=""
  for p in $(pgrep -f "scripts/collection(_archive)?\.py"); do
    sub=$(tr '\0' ' ' < /proc/$p/cmdline 2>/dev/null | grep -o -w -E "audit|archive|verify|run" | head -1)
    st=$(sed 's/^.*) //' /proc/$p/stat 2>/dev/null | awk '{print $1, $10, $12+$13}')   # state majflt utime+stime
    mm=$(awk '/^(VmRSS|VmSwap):/{printf "%d/", $2/1024}' /proc/$p/status 2>/dev/null)
    procs="$procs[$p $sub st/majflt/ticks=${st// /,} rss/swapMiB=${mm%/}] "
  done
  echo "$ts stage=$stage s=$sess load=$(cut -d' ' -f1 /proc/loadavg) $psi$vm$mem$q$procs" >> $OUT
  sleep 30
done
echo "$(date -u +%FT%TZ) sampler stopped" >> $OUT
