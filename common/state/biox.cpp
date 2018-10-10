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

#include "state_status.h"
#include <string>
#include <vector>
#include "crypto.h"
#include "zero.h"
#include "types.h"
#include "error.h"

#if _UNTRUSTED_ == 1
#if defined (__cplusplus)
extern "C"
{
#endif
    #include "u_state.h"
#if defined (__cplusplus)
} // extern "C"
#endif

#else // _UNTRUSTED_ == 0
    #include "wrapper_untrusted_cache.h"
#endif // _UNTRUSTED_

/*
    BIOX is the Block I/O interface

    Notation:
        uas: untrusted address space
        tas: trusted address space
*/

state_status_t biox_in(
    uint8_t* tas_destination,
    size_t tas_destination_size,
    uint8_t* uas_source,
    size_t uas_source_size) {
    if(uas_source_size > tas_destination_size)
        return STATE_ERR_OVERFLOW;
   
    int r; 
    r = memcpy_s(tas_destination, tas_destination_size, uas_source, uas_source_size);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(r != 0, "memcpy_s failed"); 
    return STATE_SUCCESS;       
}

state_status_t biox_out(
    uint8_t* uas_destination,
    uint8_t* tas_source,
    size_t tas_source_size) {
    //ASSUMPTION: enough memory has been allocated at destination
    int r;
    size_t uas_destination_size = tas_source_size;
    r = memcpy_s(uas_destination, uas_destination_size, tas_source, tas_source_size);
    pdo::error::ThrowIf<pdo::error::RuntimeError>(r != 0, "memcpy_s failed"); 
    return STATE_SUCCESS;
}

void biox_sync() {
    wrapper_untrusted_cache_sync();
}
