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
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "keystore_api_user.h"

#include "ias_keystore.h"

static char keystore_dev[] = "/dev/keystore";
const char *_dev_name = keystore_dev;

void ias_keystore_set_device(const char* dev_name)
{
  _dev_name = dev_name;
}

/**
 * @brief Helper function, executes ioctl request.
 *
 * @param[in] cmd IOCTL command to execute.
 * @param[in] request Pointer to the request data structure.
 * @param[in] size Size of request data structure in bytes.
 *
 * @return >=0 if OK or negative error code (see errno.h).
 * Positive values returned depend on the request type.
 */
static int keystore_ioctl(unsigned int cmd, void *request)
{
  int res, fd;

  fd = open(_dev_name, O_RDWR);
  if (fd == -1)
  {
    return -errno;
  }

  if (request == NULL)
  {
    res = ioctl(fd, cmd);
  }
  else
  {
    res = ioctl(fd, cmd, request);
  }

  if (res < 0)
  {
    res = -errno;
    printf("Error: %d (errno: %d) for command 0x%x\n", res, errno, cmd);
  }

  close(fd);
  return res;
}

/**
 * @brief Helper function, provides a local memcpy interface
 *
 * @param[in] dst Destination pointer
 * @param[in] src Source pointer
 * @param[in] size Number of bytes to copy
 *
 * @return 0 if OK or negative error code (see errno.h).
 */
int keystore_memcpy(void* dst, const void* src, unsigned int size)
{
    if ((NULL == dst) || (NULL == src))
        return -EFAULT;
    if (((char *)src < ((char *)dst + size)) && ((char *)dst < ((char *)src + size)))
        return -EFAULT;

    memcpy(dst, src, size);

    return 0;
}

int ias_keystore_register_client(enum keystore_seed_type seed_type, uint8_t *client_ticket)
{
  struct ias_keystore_register request;
  int res;

  if (!client_ticket)
  {
    return -EFAULT;
  }

  memset(&request, 0, sizeof(request));

  request.seed_type = seed_type;

  res = keystore_ioctl(KEYSTORE_IOC_REGISTER, &request);
  if (res)
    return res;

  res = keystore_memcpy(client_ticket, request.client_ticket, sizeof(request.client_ticket));

  return res;
}

int ias_keystore_unregister_client(const uint8_t *client_ticket)
{
  struct ias_keystore_unregister request;
  int res;

  if (!client_ticket) {
    return -EFAULT;
  }

  memset(&request, 0, sizeof(request));

  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  res = keystore_ioctl(KEYSTORE_IOC_UNREGISTER, &request);

  return res;
}

int ias_keystore_wrapped_key_size(enum keystore_key_spec key_spec,
                                    size_t *wrapped_key_size,
                                    size_t *unwrapped_key_size)
{
    struct ias_keystore_wrapped_key_size request;
    int res;

    memset(&request, 0, sizeof(request));

    request.key_spec = (uint32_t) key_spec;
    res = keystore_ioctl(KEYSTORE_IOC_WRAPPED_KEYSIZE, &request);
    if (res)
      return res;

    if (wrapped_key_size)
      *wrapped_key_size = request.key_size;

    if (unwrapped_key_size)
      *unwrapped_key_size = request.unwrapped_key_size;

    return res;
}

int ias_keystore_generate_key(const uint8_t *client_ticket,
                              enum keystore_key_spec key_spec,
                              uint8_t *wrapped_key)
{

  struct ias_keystore_generate_key request;
  int res;

  if (!client_ticket || !wrapped_key)
  {
    return -EFAULT;
  }

  memset(&request, 0, sizeof(request));

  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.key_spec = (uint32_t) key_spec;
  request.wrapped_key = wrapped_key;

  res = keystore_ioctl(KEYSTORE_IOC_GENERATE_KEY, &request);

  return res;
}

int ias_keystore_wrap_key(const uint8_t *client_ticket,
                          const uint8_t *app_key, size_t app_key_size,
                          enum keystore_key_spec key_spec,
                          uint8_t *wrapped_key)
{
  struct ias_keystore_wrap_key request;
  int res;

  if (!client_ticket || !app_key || !wrapped_key)
    return -EFAULT;

  memset(&request, 0, sizeof(request));

  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.key_spec = (uint32_t) key_spec;
  request.app_key = app_key;
  request.app_key_size = (uint32_t) app_key_size;
  request.wrapped_key = wrapped_key;

  res = keystore_ioctl(KEYSTORE_IOC_WRAP_KEY, &request);

  return res;
}

int ias_keystore_load_key(const uint8_t *client_ticket,
                          uint8_t *wrapped_key,
                          size_t wrapped_key_size,
                          uint32_t *slot_id)
{
  struct ias_keystore_load_key request;
  int res;

  if (!client_ticket || !wrapped_key || !slot_id)
    return -EFAULT;

  memset(&request, 0, sizeof(request));

  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.wrapped_key = wrapped_key;
  request.wrapped_key_size = (uint32_t)wrapped_key_size;

  res = keystore_ioctl(KEYSTORE_IOC_LOAD_KEY, &request);
  if (res)
    return res;

  *slot_id = request.slot_id;

  return res;
}

int ias_keystore_unload_key(const void *client_ticket, uint32_t slot_id)
{
  struct ias_keystore_unload_key request;
  int res;

  if (!client_ticket)
    return -EFAULT;

  memset(&request, 0, sizeof(request));
  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.slot_id = slot_id;

  res = keystore_ioctl(KEYSTORE_IOC_UNLOAD_KEY, &request);

  return res;
}

int ias_keystore_encrypt_size(enum keystore_algo_spec algo_spec,
                              size_t input_size, size_t *output_size)
{
  int res;
  struct ias_keystore_crypto_size request;

  if (!output_size)
    return -EFAULT;

  memset(&request, 0, sizeof(request));

  request.algospec = algo_spec;
  request.input_size = (uint32_t)input_size;

  res = keystore_ioctl(KEYSTORE_IOC_ENCRYPT_SIZE, &request);
  if (res)
    return res;

  *output_size = (size_t)request.output_size;

  return res;
}

int ias_keystore_encrypt(const uint8_t *client_ticket, uint32_t slot_id,
                         enum keystore_algo_spec algo_spec,
                         const uint8_t *iv, size_t iv_size,
                         const uint8_t *input, size_t input_size,
                         uint8_t *output)
{
  struct ias_keystore_encrypt_decrypt request;
  int res;

  /* Do not check the IV as it allowed to be null */
  if (!client_ticket || !input || !output)
    return -EFAULT;

  memset(&request, 0, sizeof(request));
  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.slot_id = slot_id;
  request.algospec = (uint32_t)algo_spec;
  request.iv = iv;
  request.iv_size = (uint32_t)iv_size;
  request.input = input;
  request.input_size = (uint32_t)input_size;
  request.output = output;

  res = keystore_ioctl(KEYSTORE_IOC_ENCRYPT, &request);

  return res;
}

int ias_keystore_decrypt_size(enum keystore_algo_spec algo_spec,
                              size_t input_size, size_t *output_size)
{
  int res;
  struct ias_keystore_crypto_size request;

  if (!output_size)
    return -EFAULT;

  memset(&request, 0, sizeof(request));

  request.algospec = algo_spec;
  request.input_size = (uint32_t)input_size;

  res = keystore_ioctl(KEYSTORE_IOC_DECRYPT_SIZE, &request);
  if (res)
    return res;

  *output_size = (size_t)request.output_size;

  return res;
}

int ias_keystore_decrypt(const uint8_t *client_ticket, uint32_t slot_id,
                         enum keystore_algo_spec algo_spec,
                         const uint8_t *iv, size_t iv_size,
                         const uint8_t *input, size_t input_size,
                         uint8_t *output)

{
  struct ias_keystore_encrypt_decrypt request;
  int res;

  /* Do not check the IV as it allowed to be null */
  if (!client_ticket || !input || !output)
    return -EFAULT;

  memset(&request, 0, sizeof(request));
  res = keystore_memcpy(request.client_ticket, client_ticket, sizeof(request.client_ticket));
  if (res)
    return res;

  request.slot_id = slot_id;
  request.algospec = (uint32_t)algo_spec;
  request.iv = iv;
  request.iv_size = (uint32_t)iv_size;
  request.input = input;
  request.input_size = (uint32_t)input_size;
  request.output = output;

  res = keystore_ioctl(KEYSTORE_IOC_DECRYPT, &request);

  return res;
}
/* end of file */
