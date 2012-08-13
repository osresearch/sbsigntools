#!/bin/bash -e

invsig="test.invsig"
dd if=/dev/zero of="$invsig" bs=1 count=1k
tmp_image=test.pecoff
cp "$image" "$tmp_image"

set +e
"$sbattach" --attach "$invsig" "$tmp_image"
rc=$?
set -e

test $rc -eq 1
