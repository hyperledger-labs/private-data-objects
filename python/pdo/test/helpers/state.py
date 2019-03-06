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

    block_ids = state_object.component_block_ids

    temp_id = block_ids[0]
    block_ids[0] = block_ids[1]
    block_ids[1] = temp_id

    # get the original block and modify it
    decoded_state = state_object.decode_state()
    decoded_state['BlockIds'] = block_ids

    #re-store the tampered main state block
    state_object.raw_state = json.dumps(decoded_state).encode('utf8')
    state_object.component_block_ids = block_ids
    state_object.save_to_cache()
