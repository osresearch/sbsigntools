#!/bin/bash -e
##
# The original warning is gone because we now do multiple signatures
# instead check that the second signature is added
##

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$signed" 2>&1 |
	grep '^Image was already signed; adding additional signature'
