# C Interface: ias_keystore

## Introduction

This section describes how to use the Keystore ias_keystore.h interface. The functionality
can be divided into three broad categories.

  * [Basic functionality](#KeyWrapping): Key wrapping and usage
  * [Backup functionality](#BackupFunctions): Key backup and re-wrapping
    * [Supported Algorithms and Keys](#SupportedAlgos): Currently supported algorithms
  * [Utility Functions](#Utilities): Reference functions for migration

For detailed documentation, see the ias_keystore.h header file.

## <a name="KeyWrapping"></a> Basic Functionality ##

This section describes how to use the basic functionality of Keystore to wrap keys and
use them to encrypt/decrypt data.

### Key Wrapping

A Keystore client has two options for producing wrapped keys:

  1. Import bare keys from outside of Keystore with ias_keystore_wrap_key().
  2. Let Keystore generate and wrap keys using ias_keystore_generate_key().

Key generation or import will typically be a one time operation performed during
the device configuration before it enters the field.

The diagram below shows an example of how to generate keys using Keystore:

![Message sequence chart for key generation.](KeystoreGenerateKey.png)

In the above diagram, a client must call the following Keystore functions:

  1. Register with Keystore using ias_keystore_register_client().
     1. This will return a client_ticket which can be used in all future Keystore calls.
  2. The size of the wrapped key can be obtained by calling ias_keystore_wrapped_key_size().
     1. The size can be used to allocate a buffer for the wrapped key appropriate for the client.
  3. Wrapped keys can then be produced using:
     1. ias_keystore_wrap_key() to wrap an existing key.
     2. ias_keystore_generate_key() to generate a random key within Keystore.
  4. The client can unregister using ias_keystore_unregister_client().
  5. The wrapped key returned by Keystore is saved via a persistency service.
     The nature of the persistency service is outside of the scope of the Keystore library.
     It is up to the application to choose a persistency service appropriate to the exact use-case.

Once keys have been wrapped they can be retrieved and used to perfrom cryptographic operations
as described in the following section.

### Encryption and Decryption

A key can be used to encrypt or decrypt data inside Keystore using the following sequence
of calls:

![Message sequence chart for encryption.](KeystoreEncryptDecrypt.png)

The sequence uses the following calls, and is similiar for both encryption and decryption operations.

  1. Retreive the wrapped key from the Persistency service.
  2. Register with Keystore using ias_keystore_register_client() if not done previously.
     1. This will return a client_ticket which can be used in all future Keystore calls.
  3. Load the wrapped key into a slot in Keystore using ias_keystore_load_key(). Keystore will internally unwrap
     the key and store it locally in kernel memory.
     1. This will return a slot_id which can be using for encryption and decryption calls.
  4. Get the size of the output buffer using:
     1. ias_keystore_encrypt_size() for encryption.
     2. ias_keystore_decrypt_size() for decryption.
  5. Perform encryption or decryption using ias_keystore_encrypt() or ias_keystore_decrypt().
  6. Unload the key from the slot using ias_keystore_unload_key().
  7. Unregister the client with ias_keystore_unregister_client().

It should be noted that the multiple operations can be performed after ias_keystore_register_client() has been
called. In the same way, multiple encrypt/decrypt operations can be performed once a key has been loaded
into a slot with ias_keystore_load_key().

### Asymmetric Key Support

For asymmetric key support, the ias_keystore_generate_key() function will generate a
public/private key pair. Similarly, ias_keystore_wrap_key() expects a key pair to be
imported. A asymmetric key pairs will usually be structured objects which need to be
cast as a byte pointer before importing.

The following diagram illustrates how a public key can be extracted and used in a second keystore
instance on another client:

![Message sequence chart for public key extraction.](KeystorePublicKey.png)

The public key of a wrapped key pair can be obtained unwrapped using the ias_keystore_get_public_key()
function. This will return an array which contains an unwrapped key pair with an invalid private key.
The public key can be extracted and used in a third-party application (outside of keystore) or
which can be reimported using the ias_keystore_wrap_key() function.
In this case only the ias_keystore_encrypt() and ias_keystore_verify() functions will succeed as
only the public key is valid.

### <a name="SupportedAlgos"></a> Key and Algorithm Compatibility

The following tables shows which key types and algorithms are supported, and their
interoperability:

| Key Spec   | Type                            | Encrypt | Decrypt | Verify | Sign  |
|------------|---------------------------------|---------|---------|--------|-------|
| LENGTH_128 | uint8_t[16]                     | AES_GCM | AES_GCM |        |       |
| LENGTH_256 | uint8_t[32]                     | AES_GCM | AES_GCM |        |       |

The "Key Spec" column lists the enum ias_keystore_keyspec value (with KEYSPEC_ removed) of the
key specification. The "Type" indicates the type of input expected for the ias_keystore_wrap_key()
operation. The "Encrypt", "Decrypt"  columns list the enum keystore_algo_spec
values (with ALGOSPEC_ removed) supported for each key type.

