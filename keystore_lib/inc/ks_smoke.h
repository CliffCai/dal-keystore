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

#ifndef IAS_KS_SMOKE_H
#define IAS_KS_SMOKE_H

#ifdef __cplusplus
extern "C"
{
#endif

int ks_smoke_encrypt(enum keystore_seed_type seed_type,
                     enum keystore_key_spec key_spec,
                     enum keystore_algo_spec algo_spec);

int ks_smoke_sign(enum keystore_seed_type seed_type,
                  enum keystore_key_spec key_spec,
                  enum keystore_algo_spec algo_spec);

#ifdef __cplusplus
}
#endif

#endif /* IAS_KS_SMOKE_H */
