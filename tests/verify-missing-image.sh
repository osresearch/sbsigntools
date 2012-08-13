#!/bin/bash -e

signed="test.signed"

set +e
"$sbverify" "missing-image"
rc=$?
set -e

test $rc -eq 1
