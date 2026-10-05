#!/usr/bin/env bash
#
# net_isolated.sh - B3: definuje/spúšťa/zastavuje izolovanú sieť hyptcn-iso.
#
#   net_isolated.sh up      definuj (ak treba) a spusti sieť
#   net_isolated.sh down    zastav sieť
#   net_isolated.sh state   vypíš stav
#
# Sieť je izolovaná (bez NAT): hosť vidí len hostiteľa. Definícia je
# v harness/net_isolated.xml; libvirt si ju drží pod qemu:///session.
#
set -uo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
URI="${VMIC_LIBVIRT_URI:-qemu:///session}"
XML="$REPO/harness/net_isolated.xml"
NET="hyptcn-iso"

state()
{
    virsh --connect "$URI" net-info "$NET" 2>/dev/null | head -3 || true
}

case "${1:-state}" in
    up)
        if ! virsh --connect "$URI" net-info "$NET" >/dev/null 2>&1; then
            echo "net_isolated: definujem sieť $NET z $XML"
            virsh --connect "$URI" net-define "$XML"
        fi
        if ! virsh --connect "$URI" net-info "$NET" 2>/dev/null | grep -q "Active:.*yes"; then
            virsh --connect "$URI" net-start "$NET"
        fi
        state
        ;;
    down)
        virsh --connect "$URI" net-destroy "$NET" 2>/dev/null || true
        ;;
    state|*)
        state
        ;;
esac
