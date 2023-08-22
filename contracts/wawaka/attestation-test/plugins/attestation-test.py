# Copyright 2018 Intel Corporation
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

import argparse
import json
import logging

logger = logging.getLogger(__name__)

import pdo.client.builder.shell as pshell
import pdo.client.builder.contract as pcontract

from pdo.client.commands.contract import send_to_contract
from pdo.contract import invocation_request
from pdo.client.builder import invocation_parameter

__all__ = [
    'contract_op_initialize',
    'contract_op_get_contract_metadata',
    'contract_op_get_contract_code_metadata',
    'contract_op_add_endpoint',
    'contract_op_send_secret',
    'contract_op_recv_secret',
    'contract_op_reveal_secret',
    'contract_op_verify_sgx_report',
    'do_attestation_test',
    'load_commands',
]

## -----------------------------------------------------------------
class contract_op_initialize(pcontract.contract_op_base) :
    name = "initialize"
    help = "initialize the attestation test contract with the ledger key"

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-l', '--ledger-key', help='ledger verifying key', required=True, type=str)

    @classmethod
    def invoke(cls, state, session_params, ledger_key, **kwargs) :
        session_params = session_params.clone(commit=True)

        message = invocation_request('initialize', ledger_verifying_key=ledger_key)
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_get_contract_metadata(pcontract.contract_op_base) :
    name = "get-contract-metadata"
    help = ""

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        message = invocation_request('get_contract_metadata')
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_get_contract_code_metadata(pcontract.contract_op_base) :
    name = "get-contract-code-metadata"
    help = ""

    @classmethod
    def invoke(cls, state, session_params, **kwargs) :
        message = invocation_request('get_contract_code_metadata')
        result = send_to_contract(state, message, **session_params)
        return result


## -----------------------------------------------------------------
class contract_op_add_endpoint(pcontract.contract_op_base) :
    name = "add-endpoint"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-c', '--code-metadata',
            help='contract code metadata',
            type=invocation_parameter, required=True)
        subparser.add_argument(
            '-i', '--contract-id',
            help='contract identifier',
            type=str, required=True)
        subparser.add_argument(
            '-l', '--ledger-attestation',
            help='attestation from the ledger',
            type=invocation_parameter, required=True)
        subparser.add_argument(
            '-m', '--contract-metadata',
            help='contract metadata',
            type=invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, code_metadata, contract_id, ledger_attestation, contract_metadata, **kwargs) :
        session_params = session_params.clone(commit=True)

        message = invocation_request(
            'add_endpoint',
            contract_id=contract_id,
            ledger_attestation=ledger_attestation,
            contract_metadata=contract_metadata,
            contract_code_metadata=code_metadata)

        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_send_secret(pcontract.contract_op_base) :
    name = "send-secret"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-i', '--contract-id', help='contract identifier', type=str, required=True)

    @classmethod
    def invoke(cls, state, session_params, contract_id, **kwargs) :
        message = invocation_request('send_secret', contract_id=contract_id)
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_recv_secret(pcontract.contract_op_base) :
    name = "recv-secret"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('--secret', help='contract secret', type=invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, secret, **kwargs) :
        session_params = session_params.clone(commit=True)

        message = invocation_request('recv_secret', **secret)
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_reveal_secret(pcontract.contract_op_base) :
    name = "reveal-secret"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument(
            '-a', '--state-attestation',
            help='ledger signature for current state attestation',
            type=invocation_parameter, required=True)

    @classmethod
    def invoke(cls, state, session_params, state_attestation, **kwargs) :
        message = invocation_request('reveal_secret', ledger_signature=state_attestation)
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
class contract_op_verify_sgx_report(pcontract.contract_op_base) :
    name = "verify-sgx-report"
    help = ""

    @classmethod
    def add_arguments(cls, subparser) :
        subparser.add_argument('-c', '--certificate', help='IAS verification certificate', type=str, required=True)
        subparser.add_argument('-i', '--ias-signature', help='IAS signature', type=str, required=True)
        subparser.add_argument('-r', '--report', help='IAS signed verification report', type=str, required=True)

    @classmethod
    def invoke(cls, state, session_params, certificate, ias_signature, report, **kwargs) :
        message = invocation_request(
            'verify_sgx_report',
            certificate=certificate.rstrip(),
            report=report.rstrip(),
            signature=ias_signature.rstrip())
        result = send_to_contract(state, message, **session_params)
        return result

## -----------------------------------------------------------------
## Create the generic, shell independent version of the aggregate command
## -----------------------------------------------------------------
__subcommands__ = [
    contract_op_initialize,
    contract_op_get_contract_metadata,
    contract_op_get_contract_code_metadata,
    contract_op_add_endpoint,
    contract_op_send_secret,
    contract_op_recv_secret,
    contract_op_reveal_secret,
    contract_op_verify_sgx_report,
]
do_attestation_test = pcontract.create_shell_command('attestation_test_contract', __subcommands__)

## -----------------------------------------------------------------
## Enable binding of the shell independent version to a pdo-shell command
## -----------------------------------------------------------------
def load_commands(cmdclass) :
    pshell.bind_shell_command(cmdclass, 'attestation_test_contract', do_attestation_test)
