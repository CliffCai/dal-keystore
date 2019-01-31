#!/bin/sh

WORK=${PWD}

KSUTIL=/usr/sbin/ksutil
KSUTIL2=${WORK}/ksutil_2

# The persistency service!
PERSISTENCY=/tmp/keystore/

# Create two separate clients
cp ${KSUTIL} ${KSUTIL2}

# Load the key from the persistency service
cp ${PERSISTENCY}/wrapped_key_1.ks $WORK
cp ${PERSISTENCY}/cyphertext1.txt $WORK

# Regsiter the second application (this should fail if manifest checking is enabled)
echo Attempting to register client which has no manifest
${KSUTIL2} reg device ticket_2.ks

# Load the wrapped key into a slot
echo
echo Attempting to load a key into the wrong client:
echo
${KSUTIL2} load ticket_2.ks aes256 wrapped_key_1.ks slot_file_2.ks

# Clean up
${KSUTIL2} unload ticket_2.ks slot_file_2.ks
${KSUTIL2} unreg ticket_2.ks

rm ticket_2.ks
rm slot_file_2.ks







