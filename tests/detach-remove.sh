#!/bin/bash -ex

signed="test.signed"
unsigned="test.unsigned"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
cp "$signed" "$unsigned"
"$sbattach" --remove "$unsigned"

# ensure that there is no security directory
objdump -p $unsigned | grep -q '0\+ 0\+ Security Directory'

# ensure that the unsigned file is the same size as our original binary
[ $(stat --format=%s "$image") -eq $(stat --format=%s "$unsigned") ]

