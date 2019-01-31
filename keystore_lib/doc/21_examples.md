# Code Examples


## Encryption and Decryption

The function below shows how to use the keystore interface to encrypt and decrypt some data:

    #include "security/keystore_lib/ias_keystore.h"
    #include <string.h>
    
    int ks_encrypt(enum keystore_seed_type seed_type,
                   enum  keystore_key_spec key_spec,
                   enum keystore_algo_spec algo_spec)
    {
      int res = 0;
      uint8_t ticket[KEYSTORE_CLIENT_TICKET_SIZE];
      size_t wrapped_key_size = 0;
      char message[] = "This is a very secret message!";
      size_t message_size = sizeof(message);
      uint8_t iv[KEYSTORE_MAX_IV_SIZE] = { 0x01, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                                           0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f };
      size_t encrypted_message_size = 0;
      size_t decrypted_message_size = 0;
      uint32_t slot = 0;
    
      /* Register */
      res = ias_keystore_register_client(seed_type, ticket);
      if (res)
        return res;
    
      /* Generate new key */
      res = ias_keystore_wrapped_key_size(key_spec, &wrapped_key_size, NULL);
      if (res)
        return res;
    
      uint8_t wrapped_key[wrapped_key_size];
      res = ias_keystore_generate_key(ticket, key_spec, wrapped_key);
      if (res)
        return res;
    
      /* Load Key */
      res = ias_keystore_load_key(ticket, wrapped_key, wrapped_key_size, &slot);
      if (res)
        return res;
    
      /* Encrypt */
      res = ias_keystore_encrypt_size(algo_spec, message_size, &encrypted_message_size);
      if (res)
        return res;
    
      uint8_t cypher[encrypted_message_size];
      if (algo_spec == ALGOSPEC_ECIES) {
        res = ias_keystore_encrypt(ticket, slot, algo_spec, NULL, 0,
                                   (uint8_t *)message, message_size, cypher);
      } else {
        res = ias_keystore_encrypt(ticket, slot, algo_spec, iv, sizeof(iv),
                                   (uint8_t *)message, message_size, cypher);
      }
    
      if (res)
        return res;
    
      /* Decrypt */
      res = ias_keystore_decrypt_size(algo_spec, encrypted_message_size, &decrypted_message_size);
      if (res)
        return res;
    
      char clear[decrypted_message_size];
      if (algo_spec == ALGOSPEC_ECIES) {
        res = ias_keystore_decrypt(ticket, slot, algo_spec, NULL, 0,
                                   cypher, encrypted_message_size, (uint8_t *)clear);
      } else {
        res = ias_keystore_decrypt(ticket, slot, algo_spec, iv, sizeof(iv),
                                   cypher, encrypted_message_size, (uint8_t *)clear);
      }
    
      if (res)
        return res;
    
      /* Unload Key */
      res = ias_keystore_unload_key(ticket, slot);
      if (res)
        return res;
    
      /* Unload Ticket */
      res = ias_keystore_unregister_client(ticket);
      if (res)
        return res;
    
      /* Check message */
      res = strncmp(message, clear, message_size);
    
      return res;
    }
