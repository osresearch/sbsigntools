#!/bin/bash -ex

signed="test.signed"
unsigned="test.unsigned"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"
cp "$signed" "$unsigned"
"$sbattach" --remove "$unsigned"

# ensure that there is no security directory
objdump -p $unsigned | grep -q '0\+ 0\+ Security Directory'

##
# somewhat tricky: i386 pecoff binaries can be too short, so we add padding
# when signing, so make sure the sizes match modulo the padding
##
# ensure that the unsigned file is the same size as our original binary
[ $(( ($(stat --format=%s "$image")+7)&~7)) -eq $(( ($(stat --format=%s "$unsigned")+7)&~7)) ]

