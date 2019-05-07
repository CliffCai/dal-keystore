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

#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <cstdlib>
#include <sys/stat.h>

#include "ias_keystore.h"
#include "ks_smoke.h"

#define MAX_DATA_LEN 65536
#define MAX_ENC_DEC_DATA_LEN (16384 * 1024)
#define DUMP_LIMIT 65536

struct command_t {
  const char *cmd;
  int (*fn)(char *argv[]);
  int numArgs;
  const char *cmdDescr;
  const char *argDescr;
};

static int cmdReg(char *argv[]);
static int cmdUnreg(char *argv[]);
static int cmdGen(char *argv[]);
static int cmdWrap(char *argv[]);
static int cmdLoad(char *argv[]);
static int cmdUnload(char *argv[]);
static int cmdInitVec(char *argv[]);
static int cmdEncrypt(char *argv[]);
static int cmdDecrypt(char *argv[]);
static int cmdTest(char *argv[]);

static struct command_t commands[] = {
  {"reg",     cmdReg,        2, "register client",      "[device | user] <*ticket-file>"},
  {"unreg",   cmdUnreg,      1, "unregister client",    "<ticket-file>"},
  {"gen",     cmdGen,        3, "generate wrapped key", "<ticket-file> aes128|aes256|ecc <*key-file>"},
  {"wrap",    cmdWrap,       4, "wrap application key", "<ticket-file> aes128|aes256|ecc <app-key-file> <*key-file>"},
  {"load",    cmdLoad,       4, "load key to slot",     "<ticket-file> aes128|aes256|ecc <key-file> <*slot-file>"},
  {"unload",  cmdUnload,     2, "unload key from slot", "<ticket-file> <slot-file>"},
  {"initvec", cmdInitVec,    2, "create init vector",   "aes_gcm|aes_ccm <*initvec-file>"},
  {"encrypt", cmdEncrypt,    6, "encrypt data",         "<ticket-file> <slot-file> aes_gcm|aes_ccm|ecc <initvec-file> <in-file> <*out-file>"},
  {"decrypt", cmdDecrypt,    5, "decrypt data",         "<ticket-file> <slot-file> aes_gcm|aes_ccm|ecc <in-file> <*out-file>"},
  {"test", cmdTest, 0, "Run tests", ""},
  {NULL, NULL, 0, NULL, NULL}
};


#ifdef DEBUG

#define MAX_LINE_LEN 16

/*
 * Function prints buffer in special formated way 0x<value>
 * @param txt data spacing string
 * @param ptr input buffer
 * @param size input buffer size
 * @param buffer printed line buffer
 */
void hexDumpInternal(const char *txt, const uint8_t *ptr, size_t size)
{
  unsigned int lineLen = 0;

  printf("%s: size: %zu ptr: 0x%p\n", txt, size, (void *) ptr);

  while (size--)
  {
    // The data bytes
    printf("%02x ", *ptr++);

    ++lineLen;

    // Fixed line length or until we run out of data
    if ((lineLen == MAX_LINE_LEN) || (size == 0))
    {
      printf("\n");
      lineLen = 0;
    }
  }
}
#endif /* DEBUG */

#ifdef DEBUG
#define ks_fprintf(...) fprintf(__VA_ARGS__)
#else
#define ks_fprintf(...)
#endif

/*
 * Hexdump buffer
 * @param txt splitter string
 * @param ptr input buffer
 * @param size input buffer size
 */
static inline void ksutilHexdump(const char *txt, const void *ptr, size_t size)
{
#ifdef DEBUG
  const uint8_t *p = (const uint8_t *) ptr;
  hexDumpInternal(txt, p, size);
#else
  (void) txt;
  (void) ptr;
  (void) size;
#endif
}

/*
 * Dump limit
 * @param size requested size
 */
static inline size_t dumpLimit(size_t size)
{
  return size < DUMP_LIMIT ? size : DUMP_LIMIT;
}

/*
 * Print usage information
 *
 * @returns 2 error code
 */
int usage()
{
  for (int i = 0; commands[i].cmd != NULL; i++)
  {
    printf("  %s:\n    ksutil %s %s\n", commands[i].cmdDescr, commands[i].cmd, commands[i].argDescr);
  }
  printf("\n  \"*\" marks output file\n");
  printf("  \"-\" used as filename means stdin or stdout\n\n");

  return 2;
}

/*
 * Main function for unit test keep ksutil for local build main.
 * @param argc common argc
 * @param argv common argv
 */
int main(int argc, char *argv[])
{
  if (argc > 1)
  {
    for (int i = 0; commands[i].cmd != NULL; i++)
    {
      if (!strcmp(argv[1], commands[i].cmd))
      {
        if (argc != commands[i].numArgs + 2)
        {
          printf("  %s:\n    ksutil %s %s\n", commands[i].cmdDescr, commands[i].cmd, commands[i].argDescr);
          return 2;
        }
        int res = (*commands[i].fn)(argv + 2);
        return (res < 0) ? 1 : res;
      }
    }
  }
  return usage();
}

/*
* Write binary data to file
* @param fileName file name
* @param data input buffer
* @param size input size
*
* @returns 0 on success
*/
int writeDataToFile(const char *fileName, const void *data, size_t size)
{
  int res = -1;
  FILE *file = stdout;

  if (fileName == NULL)
  {
     return res;
  }

  if (strcmp(fileName, "-") != 0)
  {
    file = fopen(fileName, "w");
    if (!file)
    {
      printf("%s: cannot open output file: %s\n", __FUNCTION__, fileName);
      return res;
    }
  }

  if (fwrite(data, 1, size, file) == size)
  {
    res = 0;
  }

  if (file != stdout)
  {
    fclose(file);
  }

  return res;
}

/*
 * Write number to file
 * @param fileName file name
 * @param num input number
 * @returns 0 on success
 */
int writeNumToFile(const char *fileName, unsigned int num)
{
  return writeDataToFile(fileName, &num, sizeof(num));
}

/*
 * Gets file size
 * @param fileName file name
 * @returns file size on success or -1
 */
off_t getFileSize(const char *filename) {
    struct stat st;

    if (!stat(filename, &st))
        return st.st_size;

    return -1;
}

/*
 * Read data from file
 * @param fileName file name
 * @param data input buffer
 * @param maxSize input size
 *
 * @returns 0 on success
 */
int readAllDataFromFile(const char *fileName, void *data, size_t maxSize)
{
  int res = -1;
  FILE *file = stdin;

  if ((fileName == NULL) || (data == NULL))
  {
     return res;
  }

  if (maxSize > 0)
  {
    memset(data, 0, maxSize);
  }

  if (strcmp(fileName, "-") != 0)
  {
    file = fopen(fileName, "r");
    if (!file)
    {
      printf("%s - cannot open file: %s\n", __FUNCTION__, fileName);
      return res;
    }
  }

  res = (int) fread(data, 1, maxSize, file);

  if (file != stdin)
  {
    fclose(file);
  }

  return res;
}

/*
 * Read data from file
 * @param fileName file name
 * @param data input buffer
 * @param size input buffer size
 *
 * @returns 0 on success
 */
int readDataFromFile(const char *fileName, void *data, size_t size)
{
  int res = 0;

  res = readAllDataFromFile(fileName, data, size);
  if (res > 0 && (size_t) res == size)
  {
    res = 0;
  }

  return res;
}

/*
 * Read number from file
 * @param fileName file name
 * @param numptr reference to int in which number will be kept
 *
 * @returns 0 on success
 */
int readNumFromFile(const char *fileName, unsigned int *numptr)
{
  int res = -1;
  res = readDataFromFile(fileName, numptr, sizeof(unsigned int));
  if (res != 0)
  {
    res = -1;
  }

  return res;
}

int isAES_CCM(const char *str)
{
  return !strcmp(str, "aes_ccm") || !strcmp(str, "AES_CCM");
}

int isAES_GCM(const char *str)
{
  return !strcmp(str, "aes_gcm") || !strcmp(str, "AES_GCM");
}

/*
 * Check if string is as expected
 * @param str input string
 * @returns 0 on success
 */
int isAES128(const char *str)
{
  return !strcmp(str, "aes128") || !strcmp(str, "AES128");
}

/*
 * Check if string is as expected
 * @param str input string
 * @returns 0 on success
 */
int isAES256(const char *str)
{
  return !strcmp(str, "aes256") || !strcmp(str, "AES256");
}

int isEcc(const char* str)
{
  return !strcmp(str, "ecc") || !strcmp(str, "ECC");
}

/*
 * Check if string is as expected
 * @param res error code
 * @param apiName API name
 * @returns 0 or code below 0
 */
int errApi(int res, const char *apiName)
{
  if (res < 0)
  {
    fprintf(stderr, "error: %s returned %d\n", apiName, res);
  }

  return res < 0;
}

/*
 * Informing about writing errors
 * @param res return code
 * @param fileName file name
 * @returns 0 or code below 0
 */
int errWrite(int res, const char *fileName)
{
  if (res < 0)
  {
    fprintf(stderr, "error: cannot write to file %s\n", fileName);
  }

  return res < 0;
}

/*
 * Informing about reading errors
 * @param res return code
 * @param numBytes
 * @param fileName file name
 * @returns 0 or code below 0
 */
int errRead(int res, size_t numBytes, const char *fileName)
{
  if (res < 0)
  {
    fprintf(stderr, "error: cannot read (%zu bytes) from file %s\n", numBytes, fileName);
  }

  return res < 0;
}

/*
 * Informing about writing errors
 * @param res return code
 * @param fileName file name
 * @returns 0 or code below 0
 */
int errReadAll(int res, const char *fileName)
{
  if (res < 0)
  {
    fprintf(stderr, "error: cannot read from file %s\n", fileName);
  }

  return res < 0;
}

/*
 * Informing about reading errors
 * @param res return code
 * @param fileName file name
 * @returns 0 or code below 0
 */
int errReadNum(int res, const char *fileName)
{
  if (res < 0)
  {
    fprintf(stderr, "error: cannot read number from file %s\n", fileName);
  }

  return res < 0;
}

/*
 * Informing about unrecognized key specification
 * @param str error string
 * @returns -1
 */
int errKeySpec(const char *str)
{
  fprintf(stderr, "error: unrecognized keyspec \"%s\"\n", str);
  return -1;
}

/*
 * Informing about unrecognized algorithm
 * @param str error string
 * @returns -1
 */
int errAlgo(const char *str)
{
  fprintf(stderr, "error: unrecognized algorithm \"%s\"\n", str);
  return -1;
}

/*
 * Prints info about reaching read limit
 */
void warnDataSize(const char *fileName)
{
  fprintf(stderr, "warning: %d bytes limit reached when reading from %s (file too big)\n", MAX_DATA_LEN, fileName);
}

static const char *resToString(int res)
{
  return res ? "Fail" : "Pass";
}

int cmdTest(char *argv[])
{
  (void)argv;
  int res = 0;
  int any_fail = 0;
 
  res = ks_smoke_encrypt(SEED_TYPE_USER, KEYSPEC_LENGTH_128, ALGOSPEC_AES_GCM);
  fprintf(stdout, "Seed: %s\tKey Length: %u\tAlgo: %s\tStatus: %s\n",
          "User", 128, "GCM", resToString(res));
  any_fail |= res;

  res = ks_smoke_encrypt(SEED_TYPE_DEVICE, KEYSPEC_LENGTH_128, ALGOSPEC_AES_GCM);
  fprintf(stdout, "Seed: %s\tKey Length: %u\tAlgo: %s\tStatus: %s\n",
          "Device", 128, "GCM", resToString(res));
  any_fail |= res;

  res = ks_smoke_encrypt(SEED_TYPE_DEVICE, KEYSPEC_LENGTH_256, ALGOSPEC_AES_GCM);
  fprintf(stdout, "Seed: %s\tKey Length: %u\tAlgo: %s\tStatus: %s\n",
          "Device", 256, "GCM", resToString(res));
  any_fail |= res;
 
  return res;
}

/*
 * Register with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdReg(char *argv[])
{
  int arg, res;
  enum keystore_seed_type seed_type = SEED_TYPE_DEVICE;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];

  /* arg 1: seed type */
  /* api: registerClient */
  arg = 0;
  if (argv[arg] == NULL)
  {
     return -1;
  }

  if (strcasecmp(argv[arg], "device") == 0)
  {
     seed_type = SEED_TYPE_DEVICE;
  }
  else if (strcasecmp(argv[arg], "user") == 0)
  {
     seed_type = SEED_TYPE_USER;
  }
  else
  {
     fprintf(stderr, "Unknown SEED type (expect device or user, got: %s)\n", argv[arg]);
     fprintf(stderr, "Will assume a DEVICE seed is required.\n");
     seed_type = SEED_TYPE_DEVICE;
  }

  res = ias_keystore_register_client(seed_type, clientTicket);

  ks_fprintf(stderr, "registerClient result: %d\n", res);

  if (errApi(res, "registerClient"))
  {
    return res;
  }
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));

  /* arg 2: *client_ticket */
  arg++;
  res = writeDataToFile(argv[arg], clientTicket, sizeof(clientTicket));

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Unregister with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdUnreg(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* api: unregisterClient */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  res = ias_keystore_unregister_client(clientTicket);
  ks_fprintf(stderr, "unregisterClient result: %d\n", res);

  errApi(res, "unregisterClient");

  return res;
}

/*
 * Generater key with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdGen(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  enum keystore_key_spec keySpec;
  size_t wrappedKeySize = 0;

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: key_spec */
  arg++;
  if (isAES128(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_128;
  }
  else if (isAES256(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_256;
  }
  else if (isEcc(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_ECC_PAIR;
  }
  else
  {
    return errKeySpec(argv[arg]);
  }

  res = ias_keystore_wrapped_key_size(keySpec, &wrappedKeySize, NULL);
  if (res)
  {
    return res;
  }
  ks_fprintf(stderr, "Generating new key with size: %zu\n", wrappedKeySize);

  uint8_t wrappedKey[wrappedKeySize];

  /* api: generateKey */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("keySpec", (uint8_t*) &keySpec, sizeof(keySpec));
  res = ias_keystore_generate_key(clientTicket, keySpec, wrappedKey);

  ks_fprintf(stderr, "generateKey result: %d\n", res);

  if (errApi(res, "generateKey"))
  {
    return res;
  }

  ksutilHexdump("wrappedKey", wrappedKey, wrappedKeySize);

  /* arg 3: *wrapped_key */
  arg++;

  res = writeDataToFile(argv[arg], wrappedKey, wrappedKeySize);

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Wrap key with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdWrap(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  enum keystore_key_spec keySpec;
  size_t wrappedKeySize = 0;
  size_t appKeySize = 0;

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: key_spec */
  arg++;
  if (isAES128(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_128;
    appKeySize = 16;
  }
  else if (isAES256(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_256;
    appKeySize = 32;
  }
  else if (isEcc(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_ECC_PAIR;
    appKeySize = sizeof(struct ias_keystore_ecc_keypair);
  }
  else
  {
    return errKeySpec(argv[arg]);
  }

  /* Wrapped Key */
  res = ias_keystore_wrapped_key_size(keySpec, &wrappedKeySize, NULL);
  if (res)
  {
    return res;
  }
  ks_fprintf(stderr, "Wrapped key size: %zu\n", wrappedKeySize);

  uint8_t wrappedKey[wrappedKeySize];


  /* arg 3: app_key */
  uint8_t appKey[appKeySize];
  arg++;
  res = readDataFromFile(argv[arg], appKey, sizeof(appKey));
  if (errRead(res, appKeySize, argv[arg]))
    return res;

  /* api: wrapKey */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("appKey", appKey, appKeySize);
  ksutilHexdump("keySpec", (uint8_t*) &keySpec, sizeof(keySpec));
  res = ias_keystore_wrap_key(clientTicket, appKey, appKeySize, keySpec, wrappedKey);

  ks_fprintf(stderr, "wrapKey result: %d\n", res);

  if (errApi(res, "wrapKey"))
  {
    return res;
  }

  ksutilHexdump("wrappedKey", wrappedKey, wrappedKeySize);

  /* arg 4: *wrapped_key */
  arg++;

  res = writeDataToFile(argv[arg], wrappedKey, wrappedKeySize);

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Load key into keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdLoad(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  enum keystore_key_spec keySpec;
  size_t wrappedKeySize = 0;
  uint32_t slotId;

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: key_spec */
  arg++;
  if (isAES128(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_128;
  }
  else if (isAES256(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_256;
  }
  else if (isEcc(argv[arg]))
  {
    keySpec = KEYSPEC_LENGTH_ECC_PAIR;
  }
  else
  {
    return errKeySpec(argv[arg]);
  }
  /* Wrapped Key */
  res = ias_keystore_wrapped_key_size(keySpec, &wrappedKeySize, NULL);
  if (res)
  {
    return res;
  }
  uint8_t wrappedKey[wrappedKeySize];


  /* arg 3: wrapped_key */
  arg++;

  res = readDataFromFile(argv[arg], wrappedKey, wrappedKeySize);
  if (errRead(res, wrappedKeySize, argv[arg]))
    return res;

  ks_fprintf(stderr, "Wrapped key size: %zu\n", wrappedKeySize);

  /* api: loadKey */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("wrappedKey", wrappedKey, wrappedKeySize);
  res = ias_keystore_load_key(clientTicket, wrappedKey, wrappedKeySize, &slotId);

  ks_fprintf(stderr, "loadKey result: %d\n", res);

  if (errApi(res, "loadKey"))
  {
    if (res == -EAGAIN) {
      ksutilHexdump("re-wrappedKey", wrappedKey, wrappedKeySize);
      writeDataToFile(argv[arg], wrappedKey, wrappedKeySize);
    }

    return res;
  }

  ksutilHexdump("slotId", (uint8_t*) &slotId, sizeof(slotId));

  /* arg 4: *slot_file */
  arg++;
  res = writeNumToFile(argv[arg], slotId);

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Unload key from keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdUnload(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  uint32_t slotId;

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: slot_id */
  arg++;
  slotId = 0;
  res = readNumFromFile(argv[arg], &slotId);
  if (errReadNum(res, argv[arg]))
  {
    return res;
  }

  /* api: unloadKey */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("slotId", &slotId, sizeof(slotId));
  res = ias_keystore_unload_key(clientTicket, slotId);

  ks_fprintf(stderr, "unloadKey result: %d\n", res);

  errApi(res, "unloadKey");

  return res;
}
/*
 * Generater init vector with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdInitVec(char *argv[])
{
  int arg, res;
  uint8_t initVec[DAL_KEYSTORE_GCM_IV_SIZE];
  int initVecSize;

  /* arg 1: algo_spec */
  arg = 0;
  if (isAES_CCM(argv[arg]) || isAES_GCM(argv[arg]))
  {
    initVecSize = DAL_KEYSTORE_GCM_IV_SIZE;
  }
  else
  {
    return errAlgo(argv[arg]);
  }

  /* get random data */
  memset(initVec, 0, sizeof(initVec));
  res = readDataFromFile("/dev/urandom", initVec, sizeof(initVec));
  if (errRead(res, sizeof(initVec), "/dev/urandom"))
  {
    return res;
  }

  /* keystore data is small so let's minimize max message length & maximize nonce size (rfc3610) */
  if (isAES_CCM(argv[arg]))
  {
    initVec[0] = 1;
  }
  ksutilHexdump("initVec", initVec, initVecSize);

  /* arg 2: *init_vec */
  arg++;

  res = writeDataToFile(argv[arg], initVec, initVecSize);

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Encrypt with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdEncrypt(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  enum keystore_algo_spec algoSpec;
  uint32_t slotId;
  uint8_t initVec[DAL_KEYSTORE_GCM_IV_SIZE];
  size_t initVecSize;
  uint8_t *plainData;
  size_t plainDataSize;
  size_t encryptedDataSize;
  size_t encryptedDataBlobSize;
  off_t fileSize;
  uint32_t copy_len = 0;

  memset(initVec, 0, sizeof(initVec));

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: slot_id */
  arg++;
  slotId = -1;
  res = readNumFromFile(argv[arg], &slotId);
  if (errReadNum(res, argv[arg]))
  {
    return res;
  }

  /* arg 3: algo_spec */
  arg++;
  if (isAES_CCM(argv[arg]))
  {
    algoSpec = ALGOSPEC_AES_CCM;
    initVecSize = 16;
  }
  else if (isAES_GCM(argv[arg]))
  {
    algoSpec = ALGOSPEC_AES_GCM;
    initVecSize = 16;
  }
  else if (isEcc(argv[arg]))
  {
    algoSpec = ALGOSPEC_ECIES;
    initVecSize = 0;
  }
  else
  {
    return errAlgo(argv[arg]);
  }

  /* arg 4: init_vec */
  arg++;

  if (initVecSize > 0)
  {
    res = readDataFromFile(argv[arg], initVec, initVecSize);
    if (errRead(res, initVecSize, argv[arg]))
      return res;
  }

  /* arg 5: input data */
  arg++;
  fileSize = getFileSize(argv[arg]);
  plainData = NULL;
  if (fileSize > 0)
    plainData = (uint8_t*) malloc(fileSize);
  res = readAllDataFromFile(argv[arg], plainData, fileSize);
  if (errReadAll(res, argv[arg]))
  {
    free(plainData);
    return res;
  }

  plainDataSize = res;
  if (plainDataSize >= MAX_ENC_DEC_DATA_LEN)
  {
    warnDataSize(argv[arg]);
  }

  res = ias_keystore_encrypt_size(algoSpec, plainDataSize, &encryptedDataSize);
  if (errApi(res, "encrypt_size"))
  {
    free(plainData);
    return res;
  }

  encryptedDataBlobSize = encryptedDataSize + DAL_KEYSTORE_GCM_IV_SIZE + 1;
  uint8_t *encryptedDataBlob = (uint8_t*) malloc(encryptedDataBlobSize);
  if (!encryptedDataBlob)
  {
    free(plainData);
    return -ENOMEM;
  }

  encryptedDataBlob[0] = (uint8_t)algoSpec;
  copy_len = sizeof(initVec); 
  if (encryptedDataBlobSize - 1 < copy_len)  
    copy_len = encryptedDataBlobSize - 1;  
 
if (0 != keystore_memcpy(&encryptedDataBlob[1], initVec, copy_len))
  {
    free(plainData);
    free(encryptedDataBlob);
    return -EFAULT;
  }

  uint8_t *encryptedData = &encryptedDataBlob[DAL_KEYSTORE_GCM_IV_SIZE + 1];

  /* api: encrypt */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("slotId", (uint8_t*) &slotId, sizeof(slotId));
  ksutilHexdump("algoSpec", (uint8_t*) &algoSpec, sizeof(algoSpec));
  ksutilHexdump("initVec", initVec, initVecSize);
  ksutilHexdump("plainData", plainData, dumpLimit(plainDataSize));

  res = ias_keystore_encrypt(clientTicket, slotId, algoSpec,
                             (initVecSize > 0) ? initVec : 0, initVecSize,
                             plainData, plainDataSize, encryptedData);

  ks_fprintf(stderr, "encrypt result: %d\n", res);

  free(plainData);

  if (errApi(res, "encrypt"))
  {
    free(encryptedDataBlob);
    return res;
  }

  ksutilHexdump("encryptedData", encryptedData, dumpLimit(plainDataSize));
  ksutilHexdump("encryptedDataBlob", encryptedDataBlob, dumpLimit(encryptedDataBlobSize));

  /* arg 6: *output data */
  arg++;

  res = writeDataToFile(argv[arg], encryptedDataBlob, encryptedDataBlobSize);
  free(encryptedDataBlob);

  errWrite(res, argv[arg]);

  return res;
}

/*
 * Decrypt key with keystore
 * @param argv arguments entry use ksutil to get more info
 * @return 0 on success or error code
 */
int cmdDecrypt(char *argv[])
{
  int arg, res;
  uint8_t clientTicket[KEYSTORE_CLIENT_TICKET_SIZE];
  enum keystore_algo_spec algoSpec;
  uint32_t slotId;
  uint8_t *initVec = NULL;
  size_t initVecSize;
  uint8_t *encryptedDataBlob;
  uint8_t *encryptedData;
  size_t encryptedDataSize;
  size_t encryptedDataBlobSize;
  size_t plainDataSize;
  off_t fileSize;

  /* arg 1: client_ticket */
  arg = 0;

  res = readDataFromFile(argv[arg], clientTicket, sizeof(clientTicket));
  if (errRead(res, sizeof(clientTicket), argv[arg]))
    return res;

  /* arg 2: slot_id */
  arg++;
  slotId = -1;
  res = readNumFromFile(argv[arg], &slotId);
  if (errReadNum(res, argv[arg]))
  {
    return res;
  }

  /* arg 3: algo_spec */
  arg++;
  if (isAES_CCM(argv[arg]))
  {
    algoSpec = ALGOSPEC_AES_CCM;
    initVecSize = 16;
  }
  else if (isAES_GCM(argv[arg]))
  {
    algoSpec = ALGOSPEC_AES_GCM;
    initVecSize = 16;
  }
  else if (isEcc(argv[arg]))
  {
    algoSpec = ALGOSPEC_ECIES;
    initVecSize = 0;
  }
  else
  {
    return errAlgo(argv[arg]);
  }

  /* arg 4: input data */
  arg++;
  fileSize = getFileSize(argv[arg]);
  encryptedDataBlob = NULL;
  if (fileSize > 0)
    encryptedDataBlob = (uint8_t*) malloc(fileSize);
  res = readAllDataFromFile(argv[arg], encryptedDataBlob, fileSize);
  if (errReadAll(res, argv[arg]))
  {
    free(encryptedDataBlob);
    return res;
  }

  encryptedDataBlobSize = res;
  if (encryptedDataBlobSize >= MAX_ENC_DEC_DATA_LEN)
  {
    warnDataSize(argv[arg]);
  }

  initVec = &encryptedDataBlob[1];
  encryptedData = &encryptedDataBlob[DAL_KEYSTORE_GCM_IV_SIZE + 1];
  encryptedDataSize = encryptedDataBlobSize - DAL_KEYSTORE_GCM_IV_SIZE - 1;
  plainDataSize = encryptedDataSize - 8;

  res = ias_keystore_decrypt_size(algoSpec, encryptedDataSize, &plainDataSize);
  if (errApi(res, "decrypt_size"))
  {
    free(encryptedDataBlob);
    return res;
  }

  uint8_t *plainData = (uint8_t*) malloc(plainDataSize);
  if (!plainData)
  {
    free(encryptedDataBlob);
    return -ENOMEM;
  }

  /* api: decrypt */
  ksutilHexdump("clientTicket", clientTicket, sizeof(clientTicket));
  ksutilHexdump("slotId", (uint8_t*) &slotId, sizeof(slotId));
  ksutilHexdump("algoSpec", (uint8_t*) &algoSpec, sizeof(algoSpec));
  ksutilHexdump("initVec", initVec, initVecSize);
  ksutilHexdump("encryptedDataBlob", encryptedDataBlob, dumpLimit(encryptedDataBlobSize));
  ksutilHexdump("encryptedData", encryptedData, dumpLimit(encryptedDataSize));

  res = ias_keystore_decrypt(clientTicket, slotId, algoSpec,
                             (initVecSize > 0) ? initVec : NULL, initVecSize,
                             encryptedData, encryptedDataSize, plainData);

  ks_fprintf(stderr, "decrypt result: %d\n", res);

  free(encryptedDataBlob);

  if (errApi(res, "decrypt"))
  {
    free(plainData);
    return res;
  }

  ksutilHexdump("plainData", plainData, dumpLimit(plainDataSize));

  /* arg 5: *output data */
  arg++;

  res = writeDataToFile(argv[arg], plainData, plainDataSize);
  free(plainData);

  errWrite(res, argv[arg]);

  return res;
}

/* end of file */
