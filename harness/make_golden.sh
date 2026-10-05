#!/usr/bin/env bash
#
# make_golden.sh - B1: zlatý obraz Debianu 12 pre hyptcn3.
#
# Stiahne PRIPNUTÚ verziu cloud obrazu (reprodukovateľnosť: najnovšia by sa
# menila pod rukami), vyrobí seed ISO z harness/cloud-init/ a base qcow2.
# Výsledok: vms/debian-12-base.qcow2 (mimo gitu) + golden.manifest.json
# (SHA-256 obrazu a seedu, dátum, commit).
#
# Vyžaduje: curl, qemu-img, genisoimage (dnf install genisoimage).
# Spustenie: bash harness/make_golden.sh [--fresh]
#
set -euo pipefail

REPO=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
HARNESS="$REPO/harness"
VMS="$REPO/vms"
mkdir -p "$VMS"

# Pripnutá verzia: Debian 12 (bookworm) genericcloud amd64.
IMAGE_URL="${GOLDEN_URL:-https://cloud.debian.org/images/cloud/bookworm/20241004-1890/debian-12-genericcloud-amd64-20241004-1890.qcow2}"
IMAGE_NAME="debian-12-genericcloud-amd64-20241004-1890.qcow2"
BASE="$VMS/debian-12-base.qcow2"
SEED="$VMS/cloud-init.iso"
MANIFEST="$HARNESS/golden.manifest.json"
SIZE_G=3

for tool in curl qemu-img genisoimage sha256sum; do
    command -v "$tool" >/dev/null || { echo "make_golden: chyba $tool" >&2; exit 1; }
done

if [ -e "$BASE" ] && [ "${1:-}" != "--fresh" ]; then
    echo "make_golden: $BASE uz existuje (--fresh prepise)" >&2
    exit 1
fi

TMP=$(mktemp -d /tmp/make_golden.XXXXXX)
trap 'rm -rf "$TMP"' EXIT

echo "make_golden: stahujem $IMAGE_URL"
curl -fL -o "$TMP/$IMAGE_NAME" "$IMAGE_URL"

echo "make_golden: seed ISO z harness/cloud-init/"
( cd "$HARNESS/cloud-init" && \
  genisoimage -quiet -output "$SEED" -volid cidata \
      -joliet -rock user-data meta-data )

echo "make_golden: base qcow2 (${SIZE_G} GiB)"
qemu-img create -f qcow2 -F qcow2 -b "$TMP/$IMAGE_NAME" "$BASE.tmp" >/dev/null
qemu-img resize "$BASE.tmp" "${SIZE_G}G" >/dev/null
# po resize sa backing odpoji a obraz sa "skutocne" zmeni az pri zapise;
# nechame preto overlay ako je - backing ukazuje na subor v /tmp, takze
# backing musime skopirovat vedla (gitignored vms/)
cp "$TMP/$IMAGE_NAME" "$VMS/$IMAGE_NAME"
qemu-img create -f qcow2 -F qcow2 -b "$VMS/$IMAGE_NAME" "$BASE" >/dev/null
qemu-img resize "$BASE" "${SIZE_G}G" >/dev/null
rm -f "$BASE.tmp"

SHA_IMG=$(sha256sum "$VMS/$IMAGE_NAME" | cut -d' ' -f1)
SHA_SEED=$(sha256sum "$SEED" | cut -d' ' -f1)
cat > "$MANIFEST" <<EOF
{
  "schema": "hyptcn3/golden/1",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "commit": "$(git -C "$REPO" rev-parse HEAD)",
  "image_url": "$IMAGE_URL",
  "image_sha256": "$SHA_IMG",
  "seed_sha256": "$SHA_SEED",
  "base_path": "$BASE",
  "virtual_size_gib": $SIZE_G
}
EOF

echo "make_golden: hotovo"
echo "  base:  $BASE"
echo "  seed:  $SEED"
echo "  image: $VMS/$IMAGE_NAME ($SHA_IMG)"
echo "  manifest: $MANIFEST"
