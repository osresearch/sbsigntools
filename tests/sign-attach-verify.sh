#!/bin/bash -e

. "$srcdir/common.sh"

sig=test.sig
signed=test.signed

trap 'rm -f "$sig" "$signed"' EXIT

"$sbsign" --cert "$cert" --key "$key" --detached --output $sig "$image"
"$sbattach" --attach $sig $signed
"$sbverify" --cert "$cert" "$signed"
