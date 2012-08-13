#!/bin/bash -e

signed="test.signed"
sig="test.sig"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbattach" --detach "$sig" "$signed"
"$sbverify" --cert "$cert" --detached $sig "$image"
