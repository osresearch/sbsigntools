#!/bin/bash -e

signed="test.signed"

set +e
"$sbsign" --cert "$cert" --key "missing-key" --output "$signed" "$image"
rc=$?
set -e

test $rc -eq 1
