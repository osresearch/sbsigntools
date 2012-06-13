
basedir=$(cd $srcdir && pwd)
datadir=$(pwd)
bindir="$datadir/.."

sbsign=$bindir/sbsign
sbverify=$bindir/sbverify
sbattach=$bindir/sbattach

key="$datadir/private-key.rsa"
cert="$datadir/public-cert.pem"
image="$datadir/test.pecoff"

tempdir=$(mktemp --directory)
exit_trap='rm -rf $tempdir'
trap "$exit_trap" EXIT

cd "$tempdir"
