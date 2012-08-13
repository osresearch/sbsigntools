#!/bin/bash -e

signed="test.signed"

"$sbsign" --cert "$cert" --key "$key" --output "$signed" "$image"

set +e
"$sbverify" --cert "missing-cert" "$signed"
rc=$?
set -e

test $rc -eq 1
