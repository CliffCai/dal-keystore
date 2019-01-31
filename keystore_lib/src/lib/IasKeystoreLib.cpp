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

#include <stdio.h>
#include <errno.h>

#include "ias_keystore.h"
#include "IasKeystoreLib.hpp"

/**
 * @brief Ias
 */
namespace Ias
{

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
    void getLibraryVersion(char *buffer, unsigned int length)
    {
      snprintf(buffer, length, "%u.%u.%u", BASE_VERSION_MAJOR, BASE_VERSION_MINOR, BASE_VERSION_REVISION);
    }

    /**
     * Perform integrity/authorization checks on client, validating
     * the authenticity of the claimed ClientID.
     *
     * @param seed_type The type of seed to be used by the client (SEED_TYPE_DEVICE or SEED_TYPE_USER)
     * @param client_ticket Output buffer for the client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     *
     * @return 0 if OK or negative error code (see errno.h).
     */
    int registerClientType(keystore_seed_type_t seed_type, void *client_ticket)
    {
      return ias_keystore_register_client(seed_type, (uint8_t *)client_ticket);
    }

    /**
     * Remove all state associated with ClientTicket.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     *
     * @return 0 if OK or negative error code (see errno.h).
     */
    int unregisterClient(const void *client_ticket)
    {
      return ias_keystore_unregister_client((uint8_t *)client_ticket);
    }

    /**
     * Generate new random NewKey and format it according to KeySpec.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param keyspec The key specification.
     * @param wrapped_key Output buffer for the wrapped key (key size + KEYSTORE_WRAPPED_KEY_EXTRA bytes).
     *
     * @return Wrapped key size in bytes if OK or negative error code (see errno.h).
     */
    int generateKey(const void *client_ticket, keystore_key_spec_t keyspec, void *wrapped_key)
    {
      int res;
      size_t wrapped_size;

      res = ias_keystore_wrapped_key_size(keyspec, &wrapped_size, NULL);
      if (res)
        return res;

      res = ias_keystore_generate_key((uint8_t *)client_ticket, keyspec, (uint8_t *)wrapped_key);
      if (res)
        return res;

      return (int)wrapped_size;
    }

    /**
     * Encrypt the application key and wrap according to KeySpec.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param app_key The application key.
     * @param app_key_size The application key size in bytes.
     * @param keyspec The key specification.
     * @param wrapped_key Output buffer for the wrapped key (app_key_size + KEYSTORE_WRAPPED_KEY_EXTRA bytes).
     *
     * @return Wrapped key size in bytes if OK or negative error code (see errno.h).
     */
    int wrapKey(const void *client_ticket, const void *app_key, unsigned int app_key_size,
        keystore_key_spec_t keyspec, void *wrapped_key)
    {
      int res;
      size_t wrapped_size;

      res = ias_keystore_wrapped_key_size(keyspec, &wrapped_size, NULL);
      if (res)
        return res;

      res = ias_keystore_wrap_key((uint8_t *)client_ticket, (uint8_t *)app_key, app_key_size,
                                  keyspec, (uint8_t *)wrapped_key);
      if (res)
        return res;

      return (int)wrapped_size;
    }

    /**
     * Decrypt the application key and store in a slot.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param wrapped_key The wrapped key.
     * @param wrapped_key_size The wrapped key size in bytes.
     *
     * @return Used slot ID if OK or negative error code (see errno.h).
     */
    int loadKey(const void *client_ticket, const void *wrapped_key, unsigned int wrapped_key_size)
    {
      int res = 0;
      uint32_t slot = 0;

      res = ias_keystore_load_key((uint8_t *)client_ticket, (uint8_t *)wrapped_key, wrapped_key_size, &slot);
      if (res)
        return res;

      return slot;
    }

    /**
     * Lookup key by slotID/ClientTicket and purge it from KSM memory.
     *
     * @param client_ticket The client ticket (KEYSTORE_CLIENT_TICKET_SIZE bytes).
     * @param slot_id The slot ID.
     *
     * @return 0 if OK or negative error code (see errno.h).
     */
    int unloadKey(const void *client_ticket, int slot_id)
    {
      if (slot_id < 0)
        return -EINVAL;

      return ias_keystore_unload_key((uint8_t *)client_ticket, slot_id);
    }

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
     * @return Encrypted data size in bytes if OK or negative error code (see errno.h).
     */
    int encrypt(const void *client_ticket, int slot_id, keystore_algo_spec_t algo_spec,
        const void *iv, unsigned int iv_size, const void *input, unsigned int input_size,
        void *output, unsigned int output_size)
    {
      int res = 0;
      size_t required_output_size = 0;
      uint8_t *output_start = (uint8_t *)output;
      uint8_t *encrypted_output_start;
      unsigned int copy_len = iv_size;

      if (!output || !iv)
        return -EFAULT;

      if (iv_size != KEYSTORE_MAX_IV_SIZE || slot_id < 0)
        return -EINVAL;

      res = ias_keystore_encrypt_size(algo_spec, input_size, &required_output_size);
      if (res)
        return res;

      /* Check total output size: */
      if (output_size < required_output_size + iv_size + 1)
        return -EINVAL;

      /* For backwards compatibility: pack the algo spec and iv into the output */
      output_start[0] = (uint8_t) algo_spec;

      if (output_size - 1 < iv_size)
        copy_len = output_size -1;

      if (0 != keystore_memcpy(&output_start[1], iv, copy_len))
      {
        return -EFAULT;
      }
      encrypted_output_start = output_start + iv_size + 1;

      res =  ias_keystore_encrypt((uint8_t *)client_ticket, slot_id, algo_spec, (uint8_t *)iv, iv_size,
                                  (uint8_t *)input, input_size, (uint8_t *)encrypted_output_start);
      if (res)
        return res;

      return (int)(required_output_size + iv_size + 1);
    }

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
     * @return Decrypted data size in bytes if OK or negative error code (see errno.h).
     */
    int decrypt(const void *client_ticket, int slot_id, const void *input, unsigned int input_size,
        void *output, unsigned int output_size)
    {
      int res = 0;
      size_t actual_input_size = 0;
      size_t required_output_size = 0;
      uint8_t *encrypted_input_start;
      uint8_t *input_start = (uint8_t *)input;
      uint8_t *iv;
      keystore_algo_spec_t algo_spec;

      if (!input)
        return -EFAULT;

      if (input_size < 1 + KEYSTORE_MAX_IV_SIZE || slot_id < 0)
        return -EINVAL;

      actual_input_size = input_size - 1 - KEYSTORE_MAX_IV_SIZE;

      /* Extract the algo_spec */
      algo_spec = (keystore_algo_spec_t)(*input_start);
      iv = &input_start[1];
      encrypted_input_start = input_start + 1 + KEYSTORE_MAX_IV_SIZE;

      res = ias_keystore_decrypt_size(algo_spec, actual_input_size, &required_output_size);
      if (res)
        return res;

      /* Check total output size: */
      if (output_size < required_output_size)
        return -EINVAL;

      res = ias_keystore_decrypt((uint8_t *)client_ticket, slot_id, algo_spec, (uint8_t *)iv, KEYSTORE_MAX_IV_SIZE,
                                 (uint8_t *)encrypted_input_start, actual_input_size, (uint8_t *)output);
      if (res)
        return res;

      return (int)required_output_size;
    }
  } // namespace KeystoreLib

} // namespace Ias

/* end of file */
