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

#ifndef IAS_SECURITY_KSUTIL_HPP
#define IAS_SECURITY_KSUTIL_HPP

#include <stddef.h>
#include <stdint.h>

int usage();

int writeDataToFile(const char *fileName, const void *data, size_t size);

int writeNumToFile(const char *fileName, unsigned int num);

int readAllDataFromFile(const char *fileName, void *data, size_t maxSize);

int readDataFromFile(const char *fileName, void *data, size_t size);

int readNumFromFile(const char *fileName, unsigned int *numPtr);

int isAES_CCM(const char *str);

int isAES_GCM(const char *str);

int isAES128(const char *str);

int isAES256(const char *str);

int isBlowfish(const char *str);

int isBlowfish128(const char *str);

int errApi(int res, const char *apiname);

int errWrite(int res, const char *fileName);

int errRead(int res, int numBytes, const char *fileName);

int errReadAll(int res, const char *fileName);

int errReadNum(int res, const char *fileName);

int errKeySpec(const char *str);

int errAlgo(const char *str);

void warnDataSize(const char *fileName);

#endif  // IAS_SECURITY_KSUTIL_HPP
