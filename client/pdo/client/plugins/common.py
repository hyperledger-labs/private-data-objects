# Copyright 2022 Intel Corporation
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

from pdo.contract import invocation_request

import pdo.client.builder as pbuilder
import pdo.client.builder.contract as pcontract
import pdo.client.commands.contract as pcontract_cmd

__all__ = [
    'op_get_verifying_key',
    'op_get_ledger_key',
    'op_get_contract_metadata',
    'op_get_contract_code_metadata',
    'op_add_endpoint',
]

logger = logging.getLogger(__name__)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_get_verifying_key(pcontract.contract_op_base) :

    name = "get_verifying_key"
    help = "get the verifying key for a contract object"

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_verifying_key')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_get_ledger_key(pcontract.contract_op_base) :

    name = "get_ledger_key"
    help = "for contracts that support attestation, get the configured root of trust"

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_ledger_key')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_get_contract_metadata(pcontract.contract_op_base) :

    name = "get_contract_metadata"
    help = "get the verifying and encryption keys for interacting with a contract object"

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_contract_metadata')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_get_contract_code_metadata(pcontract.contract_op_base) :

    name = "get_contract_code_metadata"
    help = "get hash code for the contract object"

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        session_params['commit'] = False

        message = invocation_request('get_contract_code_metadata')
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result

## -----------------------------------------------------------------
## -----------------------------------------------------------------
class op_add_endpoint(pcontract.contract_op_base) :

    name = "add_endpoint"
    help = "add an attested contract object endpoint to the contract"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--code-metadata',
            help='contract code metadata',
            type=pbuilder.invocation_parameter, required=True)
        subparser.add_argument(
            '-i', '--contract-id',
            help='contract identifier',
            type=str, required=True)
        subparser.add_argument(
            '-l', '--ledger-attestation',
            help='attestation from the ledger',
            type=pbuilder.invocation_parameter, required=True)
        subparser.add_argument(
            '-m', '--contract-metadata',
            help='contract metadata',
            type=pbuilder.invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, contract_id, ledger_attestation, contract_metadata, code_metadata, **kwargs) :
        session_params['commit'] = True

        message = invocation_request(
            'add_endpoint',
            contract_id=contract_id,
            ledger_attestation=ledger_attestation,
            contract_metadata=contract_metadata,
            contract_code_metadata=code_metadata)
        cls.log_invocation(message, True)
        result = pcontract_cmd.send_to_contract(state, message, **session_params)
        cls.log_invocation(message, result)

        return result
