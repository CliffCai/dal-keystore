#!/bin/sh

WORK=${PWD}

KSUTIL=/usr/sbin/ksutil

# The persistency service!
PERSISTENCY=/tmp/keystore/

# Stop on error
set -e

# Load the key from the persistency service
cp ${PERSISTENCY}/wrapped_key_1.ks $WORK

# Create some plain text
echo "Keystore does not store keys!" > plaintext.txt
echo "Plaintext message: "
cat plaintext.txt
echo

# Regsiter the device
${KSUTIL} reg device ticket_1.ks
# Load the wrapped key into a slot
${KSUTIL} load ticket_1.ks aes256 wrapped_key_1.ks slot_file_1.ks
# Create an init vector
${KSUTIL} initvec aes_gcm aes_init_vector.ks
# Do the encryption
${KSUTIL} encrypt ticket_1.ks slot_file_1.ks aes_gcm aes_init_vector.ks \
    plaintext.txt cyphertext1.txt

echo "Encrypted message:"
hexdump cyphertext1.txt
echo

# And decrypt
${KSUTIL} decrypt ticket_1.ks slot_file_1.ks aes_gcm \
    cyphertext1.txt recovered_plaintext1.txt

echo "Recovered plaintext:"
cat recovered_plaintext1.txt
echo

# Persistify the encrypted message
cp cyphertext1.txt ${PERSISTENCY}

# Clean up
${KSUTIL} unload ticket_1.ks slot_file_1.ks
${KSUTIL} unreg ticket_1.ks

rm ticket_1.ks
rm slot_file_1.ks




