# C++ Interface: IasKeystoreLib (deprecated)

This section describes the use of the IasKeystoreLib.hpp interface to the Keystore device.
This interface has been deprecated and replaced with the ias_keystore.h interface.
Backwards compatibility has been maintained, although it is recommended to move the
ias_keystore.h interface.

## Using the library in the application

To use the library, include the header file "security/keystore_lib/IasKeystoreLib.hpp"
in the source code and add this macro into CMakeLists.txt file:

	IasUseEntity(security keystore_lib STATIC)

Notice: All library function are reentrant and thread-safe.

Detailed documentation for each function can be found in IasKeystoreLib.hpp.

## The flow of the example application that uses the keystore user-space library and AES encryption

### 1. The application registers itself as a keystore client, with seed type SEED_TYPE_DEVICE (alternatively it could be SEED_TYPE_USER).

The client ticket (constant size of KEYSTORE_CLIENT_TICKET_SIZE bytes) block is filled after the call.

The error code (0 if OK or negative errno-based error code) is returned.

	unsigned char clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
	int res;

	res = registerClient(SEED_TYPE_DEVICE, clientTicket);
	if (res < 0)
	  ERROR;

### 2. The application generates the random 256-bit key.

The wrapped (encrypted) key block is filled after the call.

The wrapped key size in bytes or negative errno-based error code is returned.

	unsigned char wrappedKey[256 / 8 + KEYSTORE_WRAPPED_KEY_EXTRA];
	int wrappedKeySize;

	wrappedKeySize = generateKey(clientTicket, KEYSPEC_LENGTH_256, wrappedKey);
	if (wrappedKeySize < 0)
	  ERROR;

#### Alternatively the application can provide its own 256-bit key to be used:

The wrapped (encrypted) key block is filled after the call.

The wrapped key size in bytes or negative errno-based error code is returned.

	unsigned char myKey[256 / 8];
	// ... fill in myKey contents ...

	unsigned char wrappedKey[256 / 8 + KEYSTORE_WRAPPED_KEY_EXTRA];
	int wrappedKeySize;

	wrappedKeySize = wrapKey(clientTicket, myKey, sizeof(myKey), KEYSPEC_LENGTH_256, wrappedKey);
	if (wrappedKeySize < 0)
	  ERROR;

### 3. Application loads the wrapped key to be used for encryption.

The slot identifier is returned.

	int slotId;

	slotId = loadKey(clientTicket, wrappedKey, wrappedKeySize);
	if (slotId < 0)
	  ERROR;

### 4. The application encrypts a block of data using the key loaded into slot *slotId*.

The encrypted data block is filled after the call.

The size of encrypted data in bytes or negative errno-based error code is returned.

The IV size is 16 bytes for 256-bit AES encryption. The output block size must be at least IV size + input size + 9 bytes.

	unsigned char plain[99];
	unsigned char iv[16];
	// ... fill in plain data block and iv contents ...

	unsigned char encrypted[sizeof(iv) + sizeof(plain) + 9];
	int encryptedSize;

	encryptedSize = encrypt(clientTicket, slotId, ALGOSPEC_AES, iv, sizeof(iv), plain, sizeof(plain), encrypted, sizeof(encrypted));
	if (encryptedSize < 0)
	  ERROR;

### 5. The application could decrypt the encrypted data block using the opposite operation.

The decrypted data block is filled after the call.

The size of decrypted data in bytes or negative errno-based error code is returned.

The output block size must be at least input size - 16 - 9 bytes (for AES-256 decryption).

	unsigned char decrypted[encryptedSize - 16 - 9];
	int plainSize;

	plainSize = decrypt(clientTicket, slotId, encrypted, encryptedSize, decrypted, sizeof(decrypted));
	if (plainSize < 0)
	  ERROR;

### 6. After using the key application has to unload it from the keystore.

The slotId value is not valid after this call.

The error code (0 if OK or negative errno-based error code) is returned.

	int res;

	res = unloadKey(clientTicket, slotId);
	if (res < 0)
	  ERROR;

### 7. The application can also unregister itself, freeing keystore internal contexts when no needed.

The clientTicket contents are not valid after this call.

The error code (0 if OK or negative errno-based error code) is returned.

	int res;

	res = unregisterClient(clientTicket);
	if (res < 0)
	  ERROR;
