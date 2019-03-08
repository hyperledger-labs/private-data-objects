/* Copyright 2018 Intel Corporation
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

#include "pdo_error.h"
#include "types.h"

// The default time in seconds that a new block will be held
// in the storage service, one minute might be excessive but
// is certainly reasonable
#define MINIMUM_EXPIRATION_TIME 60

namespace pdo
{
    namespace lmdb_block_store
    {
        /**
         * Initialize the block store - must be called before performing gets/puts
         * Primary expected use: python / untrusted side
         *
         * @param db_path
         *   The path to the LMDB (lightning memory mapped database) which provides
         *   the back-end to this block store implementation
         *
         * @return
         *  Success (return PDO_SUCCESS) - Block store ready to use
         *  Failure (return nonzero) - Block store is unusable
         */
        void BlockStoreOpen(const std::string& db_path);

        /**
         * Close the block store and flush the data to disk
         */
        void BlockStoreClose();
    } /* contract */
} /* pdo */
