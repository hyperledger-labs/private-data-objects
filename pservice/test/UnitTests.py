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

import sys, os
import argparse
import json
import requests

import logging

pdo_path = os.path.dirname(os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
sys.path.insert(0, os.path.join(pdo_path, 'python'))

import pdo.common.logger as plogger
import pdo.common.crypto as crypto
from pdo.service_client.provisioning import ProvisioningServiceClient

logger = logging.getLogger(__name__)

def UnitTestRequest(contractid, enclaveid, opk, signature, url) :
    # Sends a secret request to the Provisioning Service and recieves a response: Either the Provisioning Services
    # Public Key (PSPK) and an accompanying Secret or None if the request has failed

    # Code to create valid Signature for request
    # goodsig = self.SigningKey.SignMessage(crypto.string_to_byte_array(enclave_id + contract_id))
    # goodsig = crypto.byte_array_to_hex(goodsig)
    # logger.warn('Good sig: %s', goodsig)

    provclient = ProvisioningServiceClient(url)
    secret_info = provclient.get_secret(enclaveid, contractid, opk, signature)

    if secret_info:
        print (secret_info)
    else:
        print ('Secret Request Failed')


# PASSING TESTS
def unit_test_1_1(url):
    # Unpack the request from the user and make sure all required fields are present
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


# FAILING TESTS
def unit_test_2_1_1(url):
    # Unpack the request from the user and make sure all required fields are present, but 'enclave_id' will be empty
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = None
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '3044022057C83F58E207EBD294F83B5599EB068B167DEEE5A13B2DD45D1F76B7B00E4B5402200309A6F126A555EF5F18988F22E8938E8C5CAF4AD7435F23BC991BB7A72A3B89'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_1_2(url):
    # Unpack the request from the user and make sure all required fields are present, but 'contract_id' will be empty
    contractid = None
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)



def unit_test_2_1_3(url):
    # Unpack the request from the user and make sure all required fields are present, but 'OPK' will be empty
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = None
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_1_4(url):
    # Unpack the request from the user and make sure all required fields are present, but 'signature' field will be empty
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = None

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_2_1(url):
    # Request signature is not signed by the contract owner (OPK is incorrect)
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAkYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO8SsVzOa0n\nLPjQRDRaYuL5bvV0Aijs2tV+hBWGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_2_2(url):
    # Request signature is not signed by the contract owner (OPK is incorrect and in wrong format)
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "MFYwEAYHKoZIzj0CAkYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO8SsVzOa0nLPjQRDRaYuL5bvV0Aijs2tV+hBWGXB8yw10BTqrey1yhR2YBtYHo1A=="
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_2_3(url):
    # Retrieving the contract registration transaction from the ledger for a contract that exists, but contract
    # owner's public key does not match the signer of the request (OPK).
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0BAQYFK4EEABoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '304402201C46256A38C71D391C58B2BD95A9E1597E4D4AE3D5C04125C1ED00EE028C023502505C86453C0B36E24C042CC3C01C4DDE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_3_1(url):
    # Retrieving the Enclave Encryption Key from the ledger for an enclave that does not exist
    contractid = "a462631b5ff4e93ca2565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYRK4EEqAoDQgAEQ0yTyah/yTnWbgOgRiG6eZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsikOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)


def unit_test_2_3_2(url):
    # Retrieving the contract registration transaction from the ledger for a contract that does not exist
    contractid = "z462631b5ff4e93ca4565c7842c9fb677412bddfa2bb3d0e8f04da0aff2159dd72cd8f275d773af6fffaad490b5149e813773780659253202eefa5ba9b229e2d"
    enclaveid = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAEQ0yTyah/yTnWbgOgRiGgeZFj2nqEFN+e\nCndwEmqkG/VGhK8++/VrsijOfCMy0Vcn/GvY6UhWCCyL4cmUtWqPhg==\n-----END PUBLIC KEY-----\n"
    opk = "-----BEGIN PUBLIC KEY-----\nMFYwEAYHKoZIzj0CAQYFK4EEAAoDQgAE/fTQnu8L/Bjb8R2ej7vhwNO3SsVzOa0n\nLLjQRDRaYuL5bvV0Aijs2tV+hBQGXB8yw10BTqrey1yhR2YBtYHo1A==\n-----END PUBLIC KEY-----\n"
    signature = '304402201C46256A38C71D391C58B2BD95B9E1597E4D4AE3D5C04125C1ED00EE028C023502205C86453C0B36E24C042CC3C01C4ADE2E3D3CFD96392327B07F54E86DD6EDAC7C0000'

    UnitTestRequest(contractid, enclaveid, opk, signature, url)





def Main() :
    # Some unit tests have been deprecated and removed because of changes to the Provisioning Service

    parser = argparse.ArgumentParser()
    parser.add_argument("--test", help='test number you would like to run')
    parser.add_argument("--url", help='url of Provisioning Service', default='http://127.0.0.1:7800')
    args = parser.parse_args()
    url = args.url
    test = args.test

    if test == '1.1':
        unit_test_1_1(url)

    elif test == '2.1.1':
        unit_test_2_1_1(url)
    elif test == '2.1.2':
        unit_test_2_1_2(url)
    elif test == '2.1.3':
        unit_test_2_1_3(url)
    elif test == '2.1.4':
        unit_test_2_1_4(url)

    elif test == '2.2.1':
        unit_test_2_2_1(url)
    elif test == '2.2.2':
        unit_test_2_2_2(url)
    elif test == '2.2.3':
        unit_test_2_2_3(url)

    elif test == '2.3.1':
        unit_test_2_3_1(url)
    elif test == '2.3.2':
        unit_test_2_3_2(url)

    else:
        print ("You did not enter a valid test number")


Main()
