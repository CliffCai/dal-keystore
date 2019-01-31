# Overview {#overview}

## Introduction

Keystore is a Linux kernel module which provides a key wrapping service for user-space
and kernel application. The keys used to wrap application seeds are derived from
unique device seed values in TEE.

The wrapped keys can be used to perform cryptographic operations inside the kernel
such as encryption and decryption. This offers increased security as the unwrapped
application keys are only exposed inside the kernel. Wrapped keys can only be
unwrapped on the device they were wrapped on, and only by the application they
were wrapped with.

> Note: The keystore module does not store wrapped keys internally.
> It is up to the client application to provide an appropriate persistency
> mechanism for storing wrapped keys.

## Keystore User-Space Interface

Keystore can be accessed by providing ioctl commands to the `/dev/keystore` device.
The **keystore_lib** library provides a user-space library interface to the
keystore device. It is provided as a static library only.

Two interfaces are currently provided:

  * The ias_keystore.h C interface (recommended)
  * The IasKeystoreLib.hpp C++ interface (deprecated)

More information can be found on the relevant interface page.
