#!/bin/sh
# SPDX-FileCopyrightText: © 2026 Phala Network <dstack@phala.network>
# SPDX-License-Identifier: Apache-2.0

# Reproduce the cryptsetup behaviour DiskMigration.tla assumes, on file images
# (no root needed): which keys open a disk when luksHeaderRestore of a
# re-keyed header reaches the disk only in part.
set -eu
dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
cd "$dir"
kdf="--pbkdf pbkdf2 --pbkdf-force-iterations 1000"

truncate -s 32M before.img
printf old >old.key
printf new >new.key
cryptsetup luksFormat -q --type luks2 $kdf --key-file old.key before.img
cryptsetup luksHeaderBackup --header-backup-file hdr before.img
chmod 600 hdr
cryptsetup luksChangeKey --batch-mode $kdf --key-slot 0 --key-file old.key hdr new.key
echo '{"type":"dstack-kms","keyslots":["0"],"root_epoch":1,"app_epoch":0}' |
    cryptsetup token import --token-id 0 --token-replace hdr
cp before.img after.img
cryptsetup luksHeaderRestore --batch-mode --header-backup-file=hdr after.img

# Keyslot areas before and after the change, from the JSON metadata.
area() { cryptsetup luksDump --dump-json-metadata "$1" | python3 -c 'import json,sys; a=json.load(sys.stdin)["keyslots"]["0"]["area"]; print(a["offset"], a["size"])'; }
set -- $(area before.img) $(area after.img)
echo "keyslot 0 area: $1 before, $3 after"

# Torn images: the old image with some regions of the new one.
splice() {
    out=$1; shift
    cp before.img "$out"
    for region in "$@"; do
        off=${region%:*} len=${region#*:}
        dd if=after.img of="$out" bs=4096 skip=$((off / 4096)) seek=$((off / 4096)) \
            count=$((len / 4096)) conv=notrunc status=none
    done
}
splice primary.img 0:16384
splice secondary.img 16384:16384
splice headers.img 0:32768
splice area.img "$3:$4"

opens() { cryptsetup open --test-passphrase --key-file "$2" "$1" 2>/dev/null && echo yes || echo no; }
printf '%-14s %-8s %-8s\n' image old-key new-key
for img in before after primary secondary headers area; do
    printf '%-14s %-8s %-8s\n' "$img" "$(opens $img.img old.key)" "$(opens $img.img new.key)"
done
