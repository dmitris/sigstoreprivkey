#!/bin/bash

# script creates key pair, imports it with cosign, and then
# decrypts the private key to the "normal" PEM format.
# If it works as expected, there should be "OK" printed at the end.

# check if sigstoreprivkey binary can be found in the PATH
SIGSTOREPRIVKEY=$(command -v sigstoreprivkey)
if [[ -z "$SIGSTOREPRIVKEY" ]]; then
    go build -o /tmp/sigstoreprivkey . && SIGSTOREPRIVKEY=/tmp/sigstoreprivkey
fi
GOBIN=/tmp GOPROXY=https://proxy.golang.org,direct go install -v github.com/dmitris/gencert@latest

rm -f ca-key.pem key.pem
# use gencert to generate CA, keys and certificates
# echo "generate keys and certificates with gencert"

passwd=$(uuidgen | head -c 32 | tr 'A-Z' 'a-z')
# redirect to /dev/null avoids printing 'Private key written to import-cosign.key'
# and 'Public key written to import-cosign.pub'.
rm -f import-cosign.* && /tmp/gencert && COSIGN_PASSWORD="$passwd" cosign import-key-pair --key key.pem >& /dev/null
# echo "passwd: $passwd"

# verify decryption of sigstore password
$SIGSTOREPRIVKEY import-cosign.key $passwd > key2.pem

# check that there is no difference between the two keys
diff_output=$(diff key.pem key2.pem)
if [[ -z "$diff_output" ]]; then
    echo "OK"
else
    echo "ERROR - the keys are different (not removing temporary files):"
    echo "$diff_output"
    exit 1
fi

# cleanup 
rm -f /tmp/gencert /tmp/sigstoreprivkey ca-key.pem cert.pem cacert.pem import-cosign.key import-cosign.pub key.pem key2.pem passwd