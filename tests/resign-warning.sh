#!/bin/bash -e

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$signed" 2>&1 |
	grep '^warning: overwriting'
