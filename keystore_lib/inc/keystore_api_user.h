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

#ifndef _KEYSTORE_API_USER_H_
#define _KEYSTORE_API_USER_H_

#include "keystore_api_common.h"

/**
 * DOC: Introduction
 *
 * Keystore is a key-wrapping service running inside the kernel. It allows a
 * client to wrap (encrypt) secret keys for local storage on a filesystem or
 * other medium. Keystore also provides interfaces to perfrom cryptographic
 * operations with the wrapped keys using the kernel crypto API.
 *
 * Key-wrapping is performed using a set of client keys, which are themselves
 * derived from a single SEED value. It is assumed that this SEED value is
 * provisioned by the bootloader, the address of which is passed to the
 * kernel command line.
 *
 */

/**
 * DOC: Key Wrapping
 *
 * The main function of keystore is to wrap keys (encrypt) from an application.
 * The application can safely store these wrapped keys on a filesystem.
 * Cryptographic operations on these keys are also performed within keystore
 * so that the bare keys are not exposed outside of the kernel.
 *
 * An application must first register with keystore by calling:
 *
 * keystore_register()
 *
 * The application can then either import or generate keys using the functions:
 *
 * keystore_generate_key() and keystore_wrap_key()
 *
 * The wrapped keys can be stored in non-volatile memory for future use.
 * Once a key has been wrapped, it can be loaded into a client "slot" where it
 * is internally wrapped:
 *
 * keystore_load_key()
 *
 * Following loading, data can be encrypted or decrypted using the key:
 *
 * keystore_encrypt() and keystore_decrypt()
 *
 * Finally, the slot can be freed and session ended using:
 *
 * keystore_unload_key() and keystore_unregister()
 *
 * For more details see the descriptions of the relevant functions.
 */

/**
 * DOC: Backup and Migration
 *
 * A secondary keystore functionality is where wrapped keys need to be
 * backed up and migrated from one device to another (or two clients on the
 * same device). The device which is providing the backup is denoted device
 * 1, and the new device is denoted device 2. Migration itself is performed on
 * a secure host machine separate from the two keystore devices.
 *
 * A mechanism to backup and rewrap keys is provided using a hybrid key
 * transport scheme. The authenticity of backup keys is provided using
 * a combination of RSA and ECC signatures. This allows backup and
 * migration to take place even with an untrusted third-party.
 *
 * The public ECC key of each device must be extracted and recorded on the host:
 *
 * keystore_get_ksm_key()
 *
 * On device 1, the backup API needs to be called first:
 *
 * keystore_backup()
 *
 * On device 2, a migration key must be generated:
 *
 * keystore_generate_mkey()
 *
 * The host must decrypt the backup data from device 1 and the migration key
 * from device 2, and then re-encrypt the backup data using the migration key.
 * This should take place on the host. For testing purposes a keystore API
 * is provided to do this, made available by defining the
 * %KEYSTORE_TEST_MIGRATION config option:
 *
 * keystore_migrate()
 *
 * The output of keystore_migrate(), together with any wrapped keys from device
 * 1, should then be copied to device 2 and re-wrapped using the function:
 *
 * keystore_rewrap_key()
 *
 */

/**
 * DOC: Keystore Device
 *
 * Keystore is controlled from user-space via ioctl commands to the
 * /dev/keystore device.
 *
 */

/**
 * DOC: Keystore ioctl structs
 *
 * The keystore ioctls pass the following structs from user- to kernel-space.
 *
 */

/**
 * struct ias_keystore_version - The keystore version
 * @major: Major version number
 * @minor: Minor version number
 * @patch: Patch version number
 *
 * The keystore API version, following the Apache versioning system.
 *
 * Major versions represent large scale changes in the API.
 * Minor changes return API compatibility with older minor versions.
 * Patch changes are forwards and backwards compatible.
 */
struct ias_keystore_version {
	/* output */
	uint32_t major;
	uint32_t minor;
	uint32_t patch;
};

/**
 * struct ias_keystore_register - Register a keystore client.
 * @seed_type:       Type of SEED to use for client key generation.
 * @client_ticket:   Ticket used to identify this client session.
 *
 * Register a keystore client. The client will be registered under an
 * internal client ID which is computed by taking the SHA-256 hash of
 * the absolute path name.
 *
 * On registration a client key is computed by combining the client ID
 * with either the device or user SEED using HMAC.
 *
 * The @seed_type determines whether the keys are wrapped using the
 * keystore device or user SEED. The choice depends on the type of
 * data being encrypted. Device keys will be used to encrypt data
 * associated with the device, whereas user keys are associated
 * to user data. The device SEED value can only be updated by the
 * device manufacturer, whereas the user SEED can be reset by a
 * system user.
 *
 * As the client ID is computed from the application path and name,
 * it is important to maintain the same path across releases.
 */
struct ias_keystore_register {
	/* input */
	enum keystore_seed_type seed_type;

	/* output */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
};

/**
 * struct ias_keystore_unregister - Unregister a keystore client..
 * @client_ticket:   Ticket used to identify this client session.
 */
struct ias_keystore_unregister {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
};

/**
 * struct ias_keystore_wrapped_key_size - Gets size of a wrapped key in bytes.
 * @key_spec:       The key type to get the size for.
 * @key_size:       The size of the wrapped key in bytes.
 * @unwrapped_key_size: Size of the unwrapped key.
 *
 * Returns the size of a wrapped key for a given key spec. This
 * should be called before a wrapped key is generated or imported
 * in order to allocate memory for the wrapped key buffer.
 *
 * The unwrapped key size will also be returned to be used when
 * importing exisiting keys or retrieving public keys.
 */
struct ias_keystore_wrapped_key_size {
	/* input */
	uint32_t key_spec;

	/* output */
	uint32_t key_size;
	uint32_t unwrapped_key_size;
};

/**
 * struct ias_keystore_generate_key - Generate a keystore key
 * @client_ticket:   Ticket used to identify this client session
 * @key_spec:        Key type to be generated (enum keystore_key_spec)
 * @wrapped_key:     The generated key wrapped by keystore
 *
 * Keystore will generate a random key according to the given
 * key-spec and wrap it before returning.
 * The caller must ensure that wrapped_key points to a buffer with the
 * correct size for the given key_spec. This size can be calculated
 * by first calling the ias_wrapped_key_size.
 */
struct ias_keystore_generate_key {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
	uint32_t key_spec;

	/* output */
	uint8_t *wrapped_key;
};

/**
 * struct ias_keystore_wrap_key - Wrap an existing key
 * @client_ticket:   Ticket used to identify this client session
 * @key_spec:        Key type to be generated
 * @app_key:         The bare application key to be wrapped
 * @app_key_size:    Size of the bare key.
 * @wrapped_key:     The generated key wrapped by keystore
 *
 * Keystore checks the key spec and size before wrapping it.
 * The caller must ensure that wrapped_key points to a buffer with the
 * correct size for the given key_spec. This size can be calculated
 * by first calling the %KEYSTORE_IOC_WRAPPED_KEYSIZE ioctl.
 *
 * Keys are wrapped using the AES-SIV algorithm. AES-SIV was chosen
 * as it does not require an Initialisation Vector.
 */
struct ias_keystore_wrap_key {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
	uint32_t key_spec;
	const uint8_t *app_key;
	uint32_t app_key_size;

	/* output */
	uint8_t *wrapped_key;
};

/**
 * struct ias_keystore_load_key - Load a key into a slot
 * @client_ticket:    Ticket used to identify this client session
 * @wrapped_key:      The wrapped key
 * @wrapped_key_size: Size of the wrapped key
 * @slot_id:          The assigned slot
 *
 * Loads a wrapped key into the next available slot for
 * this client ticket.
 */
struct ias_keystore_load_key {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
	uint8_t *wrapped_key;
	uint32_t wrapped_key_size;

	/* output */
	uint32_t slot_id;
};

/**
 * struct ias_keystore_unload_key - Unload a key from a slot
 * @client_ticket:    Ticket used to identify this client session
 * @slot_id:          The assigned slot
 *
 * Unloads a key from the given slot.
 */
struct ias_keystore_unload_key {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
	uint32_t slot_id;
};

/**
 * struct ias_keystore_crypto_size - Get the size of output buffer.
 * @algospec:    The encryption algorithm to use.
 * @input_size:  Size of the input buffer.
 * @output_size: Size of the output buffer.
 *
 * This struct is used by the client to calculate the required size of
 * an output buffer passed to the Keystore encrypt and decrypt operations.
 */
struct ias_keystore_crypto_size {
	/* input */
	uint32_t algospec;
	uint32_t input_size;

	/* output */
	uint32_t output_size;
};

/**
 * struct ias_keystore_encrypt_decrypt - Encrypt or Decrypt using a loaded key
 * @client_ticket:    Ticket used to identify this client session
 * @slot_id:          The assigned slot
 * @algospec:         The encryption algorithm to use
 * @iv:               The initialisation vector (IV)
 * @iv_size:          Size of the IV.
 * @input:            Pointer to the cleartext input
 * @input_size:       Size of the input data
 * @output:           Pointer to an output buffer
 *
 * Encrypt a block of data using the key stored in the given slot.
 * The caller must assure that the output points to a buffer with
 * at enough space. The correct size can be calculated by calling
 * ias_keystore_crypto_size.
 */
struct ias_keystore_encrypt_decrypt {
	/* input */
	uint8_t client_ticket[KEYSTORE_CLIENT_TICKET_SIZE];
	uint32_t slot_id;
	uint32_t algospec;
	const uint8_t *iv;
	uint32_t iv_size;
	const uint8_t *input;
	uint32_t input_size;

	/* output */
	uint8_t *output;  /* notice: pointer */
};

/**
 * DOC: Keystore IOCTLs
 *
 * A list of the keystore ioctls can be found here. Each ioctl
 * is more or less mapped to a corresponding function in
 * keystore_api_kernel.h.
 *
 * Although documented as functions, the ioctls are preprocessor
 * defines to be used in the ioctl() function.
 *
 */

#define KEYSTORE_IOC_MAGIC  '7'

/**
 * KEYSTORE_IOC_VERSION - Keystore version
 *
 * Returns the keystore version in a &struct ias_keystore_version
 */
#define KEYSTORE_IOC_VERSION\
	_IOR(KEYSTORE_IOC_MAGIC,   0, struct ias_keystore_version)

/**
 * KEYSTORE_IOC_REGISTER - Register a client with keystore
 *
 * Calls the keystore_register() function with &struct ias_keystore_register.
 */
#define KEYSTORE_IOC_REGISTER\
	_IOWR(KEYSTORE_IOC_MAGIC,  1, struct ias_keystore_register)

/**
 * KEYSTORE_IOC_REGISTER - Register a client with keystore
 *
 * Calls the keystore_unregister() function with
 * &struct ias_keystore_unregister.
 */
#define KEYSTORE_IOC_UNREGISTER\
	_IOW(KEYSTORE_IOC_MAGIC,   2, struct ias_keystore_unregister)

/**
 * KEYSTORE_IOC_WRAPPED_KEYSIZE - Gets the wrapped keysize for a given key.
 *
 * Calls the keystore_wrapped_key_size() function with
 * &struct ias_keystore_wrapped_key_size.
 */
#define KEYSTORE_IOC_WRAPPED_KEYSIZE\
	_IOWR(KEYSTORE_IOC_MAGIC,  3, struct ias_keystore_wrapped_key_size)

/**
 * KEYSTORE_IOC_GENERATE_KEY - Generate a random key and wrap it.
 *
 * Calls the keystore_generate_key() function with
 * &struct ias_keystore_generate_key.
 */
#define KEYSTORE_IOC_GENERATE_KEY\
	_IOW(KEYSTORE_IOC_MAGIC,  4, struct ias_keystore_generate_key)

/**
 * KEYSTORE_IOC_WRAP_KEY - Wrap the application key.
 *
 * Calls the keystore_wrap_key() function with
 * &struct ias_keystore_wrap_key.
 */
#define KEYSTORE_IOC_WRAP_KEY\
	_IOW(KEYSTORE_IOC_MAGIC,  5, struct ias_keystore_wrap_key)

/**
 * KEYSTORE_IOC_LOAD_KEY - Unwrap the application key and store in a slot.
 *
 * Calls the keystore_load_key() function with
 * &struct ias_keystore_load_key.
 */
#define KEYSTORE_IOC_LOAD_KEY\
	_IOWR(KEYSTORE_IOC_MAGIC,   6, struct ias_keystore_load_key)

/**
 * KEYSTORE_IOC_UNLOAD_KEY - Remove a key from a slot
 *
 * Calls the keystore_unload_key() function with
 * &struct ias_keystore_unload_key.
 */
#define KEYSTORE_IOC_UNLOAD_KEY\
	_IOW(KEYSTORE_IOC_MAGIC,   7, struct ias_keystore_unload_key)

/**
 * KEYSTORE_IOC_ENCRYPT_SIZE - Get the required size of an encrypted buffer.
 *
 * Calls the keystore_encrypt_size() function with
 * &struct ias_keystore_crypto_size.
 */
#define KEYSTORE_IOC_ENCRYPT_SIZE\
	_IOWR(KEYSTORE_IOC_MAGIC,   8, struct ias_keystore_crypto_size)

/**
 * KEYSTORE_IOC_ENCRYPT - Encrypt plaintext using AppKey/IV according to
 *                        AlgoSpec.
 *
 * Calls the keystore_encrypt() function with
 * &struct ias_keystore_encrypt_decrypt.
 */
#define KEYSTORE_IOC_ENCRYPT\
	_IOW(KEYSTORE_IOC_MAGIC,   9, struct ias_keystore_encrypt_decrypt)

/**
 * KEYSTORE_IOC_DECRYPT_SIZE - Get the required size of an decrypted buffer.
 *
 * Calls the keystore_decrypt_size() function with
 * &struct ias_keystore_crypto_size.
 */
#define KEYSTORE_IOC_DECRYPT_SIZE\
	_IOWR(KEYSTORE_IOC_MAGIC,  10, struct ias_keystore_crypto_size)

/**
 * KEYSTORE_IOC_DECRYPT - Decrypt cyphertext using AppKey/IV according to
 *                        AlgoSpec.
 *
 * Calls the keystore_decrypt() function with
 * &struct ias_keystore_encrypt_decrypt.
 */
#define KEYSTORE_IOC_DECRYPT\
	_IOW(KEYSTORE_IOC_MAGIC,  11, struct ias_keystore_encrypt_decrypt)

#endif /* _KEYSTORE_API_USER_H_ */
