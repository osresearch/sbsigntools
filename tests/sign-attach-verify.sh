#!/bin/bash -e

sig="test.sig"
signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --detached --output "$sig" "$image"
cp "$image" "$signed"
"$sbattach" --attach "$sig" "$signed"
"$sbverify" --cert "$cert" "$signed"
