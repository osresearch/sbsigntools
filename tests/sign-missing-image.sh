#!/bin/bash -e

. "$srcdir/common.sh"

signed="test.signed"

set +e
"$sbsign" --cert "$cert" --key "$key" --output "$signed" "missing-image"
rc=$?
set -e

test $rc -eq 1
