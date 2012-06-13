#!/bin/bash -e

. "$srcdir/common.sh"

"$sbsign" --cert "$cert" --key "$key" --output test.signed "$image"
"$sbverify" --cert "$cert" test.signed
