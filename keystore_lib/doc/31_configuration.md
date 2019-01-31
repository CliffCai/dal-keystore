# Configuration {#config}

This section contains information on manifest based chain of trust,
app authentication, how to configure the SEED values used by keystore,
and how to provide RSA keys for app authentication manifests.

## Seed Provisioning

Keystore uses two 64-byte seed values to derive all internal client keys.
There are two types of seed:

 * The device seed (dSEED) is used to derive keys for clients
   calling ias_keystore_register_client() with SEED_TYPE_DEVICE.
   Device seed clients should be used when the data the client
   is encrypting is associated with the device, and is not
   expected to contain personal information associated with a user.
 * The user seed (uSEED) is used to derive keys for clients
   calling ias_keystore_register_client() with SEED_TYPE_USER.
   User seed clients should be used when client data is
   expected to contain personal information which will change
   with each user of the device.

> Note: A client can register separate keystore sessions using both seed types.

The seeds are derived in TEE using a single,
device-specific constant value known as the platform seed (pSEED).
An SHA512-HMAC operations are performed on the pSEED, using a 64-byte
value (NONCE) for the key. The user-NONCE (uNONCE) is used to derive
uSEED, while the device-NONCE is used to derive dSEED.

The device NONCE and user NONCE are created in TEE.

The NONCE values should be initially set to a random number,
which can be the same across devices (as pSEED is device-unique).
The NONCEs should be updated if:

 * One of the SEED values is compromised.
 * If the device owner changes, the user SEED should be updated.

## App authentication

Keystore, by default, identifies clients based on the path of the binary
accessing the keystore device. There exists an additional integrity
mechanism based on signed application manifest files. This optional
feature can be enabled/disabled by using the kernel config option,
CONFIG_APPLICATION_AUTH. When enabled, each keystore client needs
to provide a manifest file. The manifest file contain the application
file names and digests. It is also signed using a dedicated private
RSA key. Application is authenticated by kernel when it registers
with keystore by verifying the signed manifest file attached to the
application.

The RSA key pair used to sign application manifests must be a part of
the Manifest Based Chain of Trust to ensure it is genuine. The master
public key (the public counterpart of the private key used to sign the
app authentication RSA public key) must be present in .manifest_keyring
during app authentication operations.

## Manifest Based Chain of Trust

The master OEM RSA key pair is the root of the trust for the RSA keys used
by keystore for backup and migration and app authentication.
The hash of the master public key is stored in the Key Manifest structure
of the IFWI image in the SPI flash. The Key Manifest itself is signed
and then verified during secure boot. If secure boot is enabled, the ABL
will pass the address of the Key Manifest to the kernel command line:

    ABL.oemkm=size@addr

Kernel will parse and keep the Key Manifest data.

Manifest Based Chain of Trust is built upon the Key Manifest and the
trusted kernel keyring named .manifest_keyring. The keyring accepts
public keys packed in a form of X509 DER certificates which fulfill
the following criteria:

For primary (master) certificates:

 * The certificate must be self-signed.
 * Its public key hash must be present in the Key Manifest (so in practice it must be the master OEM public key).
 * All the usage bits declared for the key in the certificate must be also set for this key in the Key Manifest.

For secondary certificates:

 * The public key pointed by the certificate Authority ID field (the signing key public counterpart) must be present in the keyring.
 * All the usage bits declared for the key in the certificate must be also present in the master key description.

## Master OEM Key Provisioning

The Diagram below gives an overview of master OEM key provisioning:

![Overview of OEM key provisioning.](KeystoreArchDiagrams.png)

> Note: these steps are only needed if keystore backup and migration
> functionality is a required feature. The encrypt and decrypt
> feature will work without an OEM key present.

The steps are described in more detail below:

### Manufacturing

During manufacturing, the RSA key pair must be created, for example
using the openssl command:

    openssl genrsa -out oem_attestation_rsa_private.pem 2048

The hash of the corresponding public key must be added to the key manifest,
which can be done using the MEU stitching tool and the ifwi-apl
scripts. The public key can be provided by via the oemattestationkey
argument to the IFWIStitch.py script. This is by default set to a
private key, but a public key can also be provided. As the
attestation key is not used to sign any of the IFWI image section,
only the public key is required.

The key hash must have the correct usage bits set in the manifest.
Kestore will check for the presence of the bit given by
CONFIG_KEYSTORE_OEM_KEY_USAGE_BIT flag (bit 47) so this bit must be
set for backup and migration RSA public key and all its parents including
the master OEM key.

> Note: the same bit must be declared in the key description
> in CONFIG_KEYSTORE_OEM_KEY_IDENTIFIER, otherwise keystore will not find
> the backup and migration RSA key in the keyring.

### Preparation

host/utilities/manifest_chain_of_trust_ca utility provides scripts
simplifying the key and certificate preparation.

#### Master certificate

The master OEM certificate is used to verfiy certificates for app
authentication and backup and migration operations so it must be
present in .manifest_keyring when keystore is used.

The script makecert from manifest_chain_of_trust_ca utility can be used
to create master OEM certificate, for example:

    ./makecert -n OEM_Attestation -d 7300 -k ../oem_attestation_key/public/res/oem_attestation_rsa_private.pem master

Before issuing the above command the OEM private key should be placed in the
conf/oem_attestation_rsa_private.pem file. The created certificate can
be found in master/cert.pem and master/cert.der files.

The cert.der must be copied to the box and inserted into the keyring using:

    MK=0x`cat /proc/keys | grep .manifest_keyring | cut -f 1 -d' '`
    keyctl padd asymmetric "" $MK < master_cert.der

The contents of the manifest keyring can be listed using the command:

    /usr/bin/keyctl list $MK

This certificate could be be installed on the filesystem
and injected into the kernel on boot using e.g. a systemd service.

#### Backup and migration

The script:

    ./makecert -n Keystore keystore

from manifest_chain_of_trust_ca utility creates both the key and the
certificate for backup and migration operations. The created key can be found
in keystore/key.pem and the certificate can be found in keystore/cert.pem and
keystore/cert.der files.

The migration ECC keys can be created using host/utilities/keystore_migration
utility. Before using it, keystore/key.pem from manifest_chain_of_trust_ca
location must be copied to master_rsa/priv.pem file in keystore_migration utility location. The script:

    ./prepare_backup_request

creates ECC key pair and signature. The files backup_request_ecc/pub.raw and
backup_request_ecc/pub.sig must be copied to the box.

In order to allow performing backup operation keystore/cert.der from
manifest_chain_of_trust_ca location must be inserted
into .manifest_keyring on the target. This can be automated
using a systemd service with the following commands:

    MK=0x`cat /proc/keys | grep .manifest_keyring | cut -f 1 -d' '`
    keyctl padd asymmetric "" $MK < keystore_cert.der

#### App authentication

The script:

    ./makecert -n AppAuth app_auth

from manifest_chain_of_trust_ca utility creates both the key and the
certificate for creating app manifests. The utility for creating
app manifests can be found in host/utilities/app_authentication.

