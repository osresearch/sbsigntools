
basedir=..
testdir="$basedir/tests"
bindir="$basedir"

sbsign=$bindir/sbsign
sbverify=$bindir/sbverify
sbattach=$bindir/sbattach

key="$testdir/private-key.rsa"
cert="$testdir/public-cert.pem"
image="$testdir/test.pecoff"
