#!/bin/bash -e

signed="test.signed"

set +e
"$sbsign" --cert "missing-cert" --key "$key" --output "$signed" "$image"
rc=$?
set -e

test $rc -eq 1
