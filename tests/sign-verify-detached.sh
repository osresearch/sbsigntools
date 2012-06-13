#!/bin/bash -e

. "$srcdir/common.sh"

sig=test.sig

trap 'rm -f "$sig"' EXIT

"$sbsign" --cert "$cert" --key "$key" --detached --output $sig "$image"
"$sbverify" --cert "$cert" --detached $sig "$image"
