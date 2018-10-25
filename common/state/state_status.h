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

typedef enum {
    STATE_SUCCESS=0,
    STATE_ERR_UNKNOWN=-1,
    STATE_ERR_MEMORY=-2,
    STATE_ERR_IO =-3,
    STATE_ERR_RUNTIME=-4,
    STATE_ERR_INDEX=-5,
    STATE_ERR_DIVIDE_BY_ZERO=-6,
    STATE_ERR_OVERFLOW =-7,
    STATE_ERR_VALUE =-8,
    STATE_ERR_SYSTEM =-9,
    STATE_ERR_UNIMPLEMENTED =-10,
    STATE_ERR_NOT_FOUND =-11,
    STATE_ERR_BLOCK_AUTHENTICATION =-12,
    STATE_EOD =-13
} state_status_t;
