#!/bin/bash -e

. "$srcdir/common.sh"

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbverify" --cert "$cert" "$signed"
