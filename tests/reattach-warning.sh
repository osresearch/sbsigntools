#!/bin/bash -e

signed="test.signed"
sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --detached --output "$sig" "$image"
cp "$image" "$signed"
"$sbattach" --attach "$sig" "$signed"
"$sbattach" --attach "$sig" "$signed" 2>&1 |
	grep '^warning: overwriting'
