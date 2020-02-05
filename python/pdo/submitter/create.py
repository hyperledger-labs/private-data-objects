# Copyright 2020 Intel Corporation
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

import logging
import os

logger = logging.getLogger(__name__)

import pdo.submitter.sawtooth.sawtooth_submitter as sw_sub
import pdo.submitter.ccf.ccf_submitter as ccf_sub

# -----------------------------------------------------------------
#   Create a new Submitter
# -----------------------------------------------------------------

def create_submitter(ledger_config, *args, **kwargs) :
    ledger_type = ledger_config.get('LedgerType', os.environ.get('PDO_LEDGER_TYPE'))

    if ledger_type == 'sawtooth':
        return sw_sub.SawtoothSubmitter(ledger_config, *args, **kwargs)
    elif ledger_type == 'ccf':
        return ccf_sub.CCFSubmitter(ledger_config, *args, **kwargs)
    else:
        logger.error("Invalid Ledger Type. Must be either 'sawtooth' or 'ccf'")
        raise Exception("Invalid Ledger Type. Must be either 'sawtooth' or 'ccf'")