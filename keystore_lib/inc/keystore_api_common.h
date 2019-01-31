/*
   Copyright 2018 Intel Corporation

   This software is licensed to you in accordance
   with the agreement between you and Intel Corporation.

   Alternatively, you can use this file in compliance
   with the Apache license, Version 2.


   Apache License, Version 2.0

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/
#ifndef _KEYSTORE_API_COMMON_H_
#define _KEYSTORE_API_COMMON_H_

/**
 * DOC: Introduction
 *
 * Common constants and structures common to both user- and kernel-space
 * clients are listed here.
 *
 */

/* Version numbers of the Keystore API
 * Follows the Apache versioning scheme
 *
 * Major versions represent large scale changes in the API.
 * Minor changes return API compatibility with older minor versions.
 * Patch changes are forwards and backwards compatible.
 *
 * Ensure that version numbers are updated if changes are made to
 * the API!
 */
#define KEYSTORE_VERSION_MAJOR 2
#define KEYSTORE_VERSION_MINOR 0
#define KEYSTORE_VERSION_PATCH 0

/**
 * KEYSTORE_MAJOR - "/dev/keystore" char device major number
 */
#define KEYSTORE_MAJOR               40

/**
 * KEYSTORE_CLIENT_TICKET_SIZE - client_ticket size in bytes
 */
#define KEYSTORE_CLIENT_TICKET_SIZE   8

/**
 * KEYSTORE_MAX_IV_SIZE - Maximum size of the Initialization Vector
 */
#define KEYSTORE_MAX_IV_SIZE         16

/**
 * KEYSTORE_ECC_DIGITS - Number of ECC digits used to calculate ECC key sizes
 */
#define KEYSTORE_ECC_DIGITS          17

/**
 * struct keystore_ecc_public_key_t - ECC Public Key Holder
 * @x: The x co-ordinate of the ECC key
 * @y: The y co-ordinate of the ECC key
 *
 * Represents an ECC public key
 */
struct keystore_ecc_public_key {
	uint32_t x[KEYSTORE_ECC_DIGITS];
	uint32_t y[KEYSTORE_ECC_DIGITS];
};

/**
 * struct ias_keystore_ecc_keypair - Public / private ECC key pair
 * @private_key: The ECC private key.
 * @public_key:  The ECC public key.
 */
struct ias_keystore_ecc_keypair {
	uint32_t private_key[KEYSTORE_ECC_DIGITS];
	struct keystore_ecc_public_key public_key;
};

/**
 * struct keystore_ecc_signature - ECDSA signature
 * @r: r component of the signature
 * @s: s component of the signature
 *
 * Holds and Eliptic Curve Digital Signature Algorithm signature.
 * The meaning of the (@r, @s) components can be found in FIPS-186-4.
 */
struct keystore_ecc_signature {
	uint32_t r[KEYSTORE_ECC_DIGITS];
	uint32_t s[KEYSTORE_ECC_DIGITS];
};

/**
 * enum keystore_seed_type - User/device seed type
 * @SEED_TYPE_DEVICE: The keys should be associated to the device.
 *                    SEED will only change if the device SEED is
 *                    compromised.
 * @SEED_TYPE_USER:   The keys should be associated to the user. The
 *                    SEED can be changed by the user if requested.
 */
enum keystore_seed_type {
	SEED_TYPE_DEVICE = 0,
	SEED_TYPE_USER   = 1
};

/**
 * enum keystore_key_spec - The key specification
 * @KEYSPEC_INVALID: Invalid keyspec
 * @KEYSPEC_LENGTH_128: 128-bit raw key (for AES)
 * @KEYSPEC_LENGTH_256: 256-bit raw key (for AES)
 * @KEYSPEC_LENGTH_ECC_PAIR: 1664-bit raw key pair (for ECC)
 */
enum keystore_key_spec {
	KEYSPEC_INVALID = 0,
	KEYSPEC_LENGTH_128 = 1,
	KEYSPEC_LENGTH_256 = 2,
	KEYSPEC_LENGTH_ECC_PAIR = 128,
};

/**
 * enum keystore_algo_spec - The encryption algorithm specification
 * @ALGOSPEC_INVALID: Invalid Algospec
 * @ALGOSPEC_AES_CCM: AES_CCM Algorithm (128/256 bit depending on key length)
 * @ALGOSPEC_AES_GCM: AES_GCM Algorithm (128/256 bit depending on key length)
 * @ALGOSPEC_ECIES: ECC/ECIES Encryption Algorithm (using secp521r1)
 * @ALGOSPEC_ECDSA: ECC/ECDSA Signature Algorithm (using secp521r1)
 */
enum keystore_algo_spec {
	ALGOSPEC_INVALID = 0,
	ALGOSPEC_AES_CCM = 1,
	ALGOSPEC_AES_GCM = 2,
	ALGOSPEC_ECIES = 128,
	ALGOSPEC_ECDSA = 129
};

#endif /* _KEYSTORE_API_COMMON_H_ */
