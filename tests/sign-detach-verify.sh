#!/bin/bash -e

. "$srcdir/common.sh"

signed="test.signed"
sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbattach" --detach "$sig" "$signed"
"$sbverify" --cert "$cert" --detached $sig "$image"
