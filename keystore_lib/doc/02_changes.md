# Changes {#changes}

## release/KC3.0:

Version 2.3.0
  * Move the implementation to TEE only.

Version 2.2.0
  * Updating API to support SEED migration.
    See ias_keystore_load_key() for more details.

Version 2.1.6
  * Documentation update.

Version 2.1.5
  * Documentation update.

Version 2.1.4
  * Documentation update.

Version 2.1.3
  * Fixing C++ interface bug which was using ias_keystore_encrypt in the decrypt function.
  * Correcting a return code description in the API documentation.
  * Adding details of the ECIES algorithm
  * Adding line stating that the client ID can be replaced during migration.
  * key_spec is an output paramter to the get_public_key API, so does not need to be copied into the struct.

Version 2.1.2
  * Moving OEM attestation keys to a separate repo to allow keystore_lib to be built and delivered separately.

Version 2.1.1
  * Adding NONCE provisioning information in the configuration section.
  * Adding public key provisioning information in the configuration section.

Version 2.1.0

  * Adding support for signing and verification
  * Adding ECC support using ECIES and ECDSA
  * Adding AES GCM support

Version 2.0.0

  * Updating to latest version of keystore interface
  * Adding more intuitive ias_keystore.h C interface
  * Deprecating IasKeystoreLib.hpp interface (remains backward compatible)

Version 1.1.10

  * ICD update

## release/KC2.2_R2:

Version 1.1.9

  * OBS build fix

Version 1.1.8

  * Disambiguation: references to errno changed to errno.h in comments and documentation

Version 1.1.7

  * Sync-up with KC2.2 (getKSMkey added)

Version 1.1.3

  * Workaround to build under yocto without kernel headers

Version 1.1.2

  * Sync up with kernel headers, removing old stuff, x86_64 build

Version 1.1.0

  * Adding interface for user and device SEED

Version 1.0.9

  * Migrating from keystore_kmod
