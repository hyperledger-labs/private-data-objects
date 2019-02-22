# Copyright 2019 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import os
import json
import pdo.common.crypto as crypto

import logging
logger = logging.getLogger(__name__)

def TamperWithStateBlockOrder(state_object) :
    """
    swaps the first two blocks of the state, leaving any authentication info unchanged
    """
    if len(state_object.component_block_ids) < 2 :
        raise Exception('cannot tamper with state block order')

    temp_id = state_object.component_block_ids[0]
    state_object.component_block_ids[0] = state_object.component_block_ids[1]
    state_object.component_block_ids[1] = temp_id

    # get the original block and modify it
    b64_decoded_byte_array = crypto.base64_to_byte_array(state_object.encrypted_state)
    b64_decoded_string = crypto.byte_array_to_string(b64_decoded_byte_array).rstrip('\0')
    json_main_state_block = json.loads(b64_decoded_string)
    json_main_state_block['BlockIds'] = state_object.component_block_ids

    #re-store the tampered main state block
    new_main_state_block = json.dumps(json_main_state_block)
    new_main_state_block_byte_array = crypto.string_to_byte_array(new_main_state_block)
    state_object.update_state(crypto.byte_array_to_base64(new_main_state_block_byte_array))
    state_object.save_to_cache()
