#!/bin/bash
# Passive, read-only per-disk IO sampler for campaign benign-v6 (attributes slow-audit reads to sda/sdb).
# One line per 30 s from /proc/diskstats: reads, sectors read, ms reading, writes, sectors written, ms writing, io_ticks.
OUT=/tmp/claude-1000/-home-eh-projects-hyptcn3/07093d58-41fa-4430-9394-40392329f312/scratchpad/v6/sampler2.log
STATUS=/home/eh/projects/hyptcn3/data/campaigns/benign-v6-20261026/status.json
RUNNER=3145866
end=$(( $(date +%s) + 8*3600 ))
while [ "$(date +%s)" -lt "$end" ] && [ -d /proc/$RUNNER ]; do
  ts=$(date -u +%FT%TZ)
  stage=$(grep -o '"stage": "[^"]*"' $STATUS 2>/dev/null | cut -d'"' -f4)
  d=$(awk '$3=="sda"||$3=="sdb"{printf "%s r=%s rs=%s rms=%s w=%s ws=%s wms=%s ticks=%s ", $3, $4, $6, $7, $8, $10, $11, $13}' /proc/diskstats)
  echo "$ts stage=$stage $d" >> $OUT
  sleep 30
done
echo "$(date -u +%FT%TZ) sampler2 stopped" >> $OUT
