#!/bin/bash -e

. "$srcdir/common.sh"

sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --detached --output $sig "$image"
"$sbverify" --cert "$cert" --detached $sig "$image"
