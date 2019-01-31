/* Copyright 2019 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#pragma once

#include <sgx_attributes.h>

// Note: below definitions are taken from common/inc/internal/tseal_migration_attr.h
// of the SGX SDK (v2.4.1).

/* Set the bits which have no security implications to 0 for sealed data migration */
/* Bits which have no security implications in attributes.flags:
 *    Reserved bit[55:6]  - 0xFFFFFFFFFFFFC0ULL
 *    SGX_FLAGS_MODE64BIT
 *    SGX_FLAGS_PROVISION_KEY
 *    SGX_FLAGS_EINITTOKEN_KEY */
#define FLAGS_NON_SECURITY_BITS     (0xFFFFFFFFFFFFC0ULL | SGX_FLAGS_MODE64BIT | SGX_FLAGS_PROVISION_KEY| SGX_FLAGS_EINITTOKEN_KEY)
#define TSEAL_DEFAULT_FLAGSMASK     (~FLAGS_NON_SECURITY_BITS)

#define MISC_NON_SECURITY_BITS      0x0FFFFFFF  /* bit[27:0]: have no security implications */
#define TSEAL_DEFAULT_MISCMASK      (~MISC_NON_SECURITY_BITS)


// key-policy, attribute-mask, xfrm & misc mask as used in PDO seal and attestation
// (keep attestation and seal-policy consistent for easier reasoning ..)

#define PDO_SGX_ATTRIBUTTE_MASK	    (sgx_attributes_t){TSEAL_DEFAULT_FLAGSMASK | SGX_FLAGS_MODE64BIT, 0x0}
// As we are in a multi-pary security case, we do not make the assumption, though,
// that there is no way to write a binary which is at same time valid 32-bit code
// and valid 64-bit code (of different behaviour). Additionally, we do not require
// mixed mode binaries. Hence and different to sdk, we set the SGX_FLAGS_MODE64BIT flag.
#define PDO_SGX_MISCMASK            TSEAL_DEFAULT_MISCMASK
#define PDO_SGX_KEYPOLICY           SGX_KEYPOLICY_MRENCLAVE
