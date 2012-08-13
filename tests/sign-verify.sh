#!/bin/bash -e

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
"$sbverify" --cert "$cert" "$signed"
