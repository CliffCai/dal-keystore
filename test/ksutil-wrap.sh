#!/bin/sh

WORK=${PWD}

KSUTIL=/usr/sbin/ksutil

# The persistency service!
mkdir -p /tmp/keystore/
PERSISTENCY=/tmp/keystore/

# Stop on error
set -e

echo
echo Create a 256-bit key:
echo
dd if=/dev/urandom of=unwrapped_key_1.bin bs=1 count=32
hexdump unwrapped_key_1.bin
echo

# Wrap the key
echo Wrapping key for client 1
echo
${KSUTIL} reg device ticket_1.ks
${KSUTIL} wrap ticket_1.ks aes256 unwrapped_key_1.bin wrapped_key_1.ks
${KSUTIL} unreg ticket_1.ks
rm ticket_1.ks
echo
echo "Here is the wrapped key:"
echo
hexdump wrapped_key_1.ks
echo
cp wrapped_key_1.ks ${PERSISTENCY}



