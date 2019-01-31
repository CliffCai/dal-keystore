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

#ifndef IAS_SECURITY_KEYSTORE_LIB_HPP
#define IAS_SECURITY_KEYSTORE_LIB_HPP

#include "keystore_api_common.h"

typedef enum keystore_seed_type keystore_seed_type_t;
typedef enum keystore_key_spec keystore_key_spec_t;
typedef enum keystore_algo_spec keystore_algo_spec_t;
typedef struct keystore_ecc_public_key EccPoint;

#define KEYSTORE_WRAPPED_KEY_EXTRA 17
#define KEYSTORE_MAX_APPKEY_SIZE 32
#define KEYSTORE_MAX_WRAPPED_KEY_SIZE (KEYSTORE_WRAPPED_KEY_EXTRA + KEYSTORE_MAX_APPKEY_SIZE)
#define ECC_SIGNATURE_SIZE sizeof(struct keystore_ecc_signature)
#define SIGNED_MKEY_SIZE ECC_SIGNATURE_SIZE
#define KEYSTORE_ECC_PUB_KEY_SIZE sizeof(struct keystore_ecc_public_key)
#define KEYSTORE_ECC_PRIV_KEY_SIZE (sizeof(uint32_t) * KEYSTORE_ECC_DIGITS)

/**
 * @brief Ias
 */
namespace Ias {

  /**
   * @brief keystore user space library
   */
  namespace IasKeystoreLib
  {
    /**
     * @brief Get library version.
     *
     * @param[out] buffer Pointer to the buffer for the library version.
     * @param[in] length The buffer length in bytes.
     */
    void getLibraryVersion(char *buffer, unsigned int length);

    /**
     * Perform integrity/authorization checks on client, validating
     * the authenticity of the claimed ClientID.
     *
     * @param seed_type The type of seed to be used by the client (SEED_TYPE_DEVICE or SEED_TYPE_USER)
     * @param client_ticket Output buffer for the client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     *
     * @deprecated This function will be replaced by the C function ias_keystore_register_client().
     *
     * @return 0 if OK or negative error code (see errno).
     */
    int registerClientType(keystore_seed_type_t seed_type, void *client_ticket);

    /**
     * Remove all state associated with ClientTicket.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     *
     * @deprecated This function will be replaced by the C function ias_keystore_unregister_client().
     *
     * @return 0 if OK or negative error code (see errno).
     */
    int unregisterClient(const void *client_ticket);

    /**
     * Generate new random NewKey and format it according to KeySpec.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param keyspec The key specification.
     * @param wrapped_key Output buffer for the wrapped key (key size + KEYSTORE_WRAPPED_KEY_EXTRA bytes).
     *
     * @deprecated This function will be replaced by the C function ias_keystore_generate_key().
     *
     * @return Wrapped key size in bytes if OK or negative error code (see errno).
     */
    int generateKey(const void *client_ticket, keystore_key_spec_t keyspec, void *wrapped_key);

    /**
     * Encrypt the application key and wrap according to KeySpec.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param app_key The application key.
     * @param app_key_size The application key size in bytes.
     * @param keyspec The key specification.
     * @param wrapped_key Output buffer for the wrapped key (app_key_size + KEYSTORE_WRAPPED_KEY_EXTRA bytes).
     *
     * @deprecated This function will be replaced by the C function ias_keystore_wrap_key().
     *
     * @return Wrapped key size in bytes if OK or negative error code (see errno).
     */
    int wrapKey(const void *client_ticket, const void *app_key, unsigned int app_key_size,
        keystore_key_spec_t keyspec, void *wrapped_key);

    /**
     * Decrypt the application key and store in a slot.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param wrapped_key The wrapped key.
     * @param wrapped_key_size The wrapped key size in bytes.
     *
     * @deprecated This function will be replaced by the C function ias_keystore_load_key().
     *
     * @return Used slot ID if OK or negative error code (see errno).
     */
    int loadKey(const void *client_ticket, const void *wrapped_key, unsigned int wrapped_key_size);

    /**
     * Lookup key by slotID/ClientTicket and purge it from KSM memory.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param slot_id The slot ID.
     *
     * @deprecated This function will be replaced by the C function ias_keystore_unload_key().
     *
     * @return 0 if OK or negative error code (see errno).
     */
    int unloadKey(const void *client_ticket, int slot_id);

    /**
     * Encrypt plaintext using AppKey/IV according to AlgoSpec.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param slot_id The slot ID.
     * @param algo_spec The algorithm specification.
     * @param iv Encryption initialization vector.
     * @param iv_size Initialization vector size in bytes.
     * @param input Input block of data to encrypt.
     * @param input_size Input block size in bytes.
     * @param output Pointer to the block for encrypted data.
     * @param output_size Output block size in bytes (at least iv_size + input_size + 9 bytes).
     *
     * @deprecated This function will be replaced by the C function ias_keystore_encrypt().
     *
     * @return Encrypted data size in bytes if OK or negative error code (see errno).
     */
    int encrypt(const void *client_ticket, int slot_id, keystore_algo_spec_t algo_spec,
        const void *iv, unsigned int iv_size, const void *input, unsigned int input_size,
        void *output, unsigned int output_size);

    /**
     * Decrypt cipher using AppKey and AlgoSpec/IV.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param slot_id The slot ID.
     * @param input Input block of data to decrypt.
     * @param input_size Input block size in bytes.
     * @param output Pointer to the block for decrypted data.
     * @param output_size Output block size in bytes.
     *
     * @deprecated This function will be replaced by the C function ias_keystore_decrypt().
     *
     * @return Decrypted data size in bytes if OK or negative error code (see errno).
     */
    int decrypt(const void *client_ticket, int slot_id, const void *input, unsigned int input_size,
        void *output, unsigned int output_size);

  } // namespace IasKeystoreLib

} // namespace Ias

#endif  // IAS_SECURITY_KEYSTORE_LIB_HPP
