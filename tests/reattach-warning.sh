#!/bin/bash -e
##
# The original warning is gone because we now do multiple signatures
# instead check that the second signature is added
##

signed="test.signed"
sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --detached --output "$sig" "$image"
cp "$image" "$signed"
"$sbattach" --attach "$sig" "$signed"
"$sbattach" --attach "$sig" "$signed" 2>&1 |
	grep '^Image was already signed; adding additional signature'
