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

import logging
import hashlib
import base64
import json
import binascii

from cryptography.hazmat import backends
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

from common.sgx.sawtooth_poet_common.sgx_structs._sgx_quote import SgxQuote
from common.sgx.sawtooth_poet_common.sgx_structs._sgx_report_data import SgxReportData

from common.sawtooth_signing import create_context
from common.sawtooth_signing import CryptoFactory
from common.sawtooth_signing.secp256k1 import Secp256k1PublicKey
from common.sawtooth_signing.secp256k1 import Secp256k1PrivateKey


LOGGER = logging.getLogger(__name__)

_spec256k1_curve_order = 115792089237316195423570985008687907852837564279074904382605163141518161494337


def generate_private_key_as_hex():
    private_key = Secp256k1PrivateKey.new_random()
    return private_key.as_hex()


def get_public_key_as_hex(private_key_as_hex):
    private_key = Secp256k1PrivateKey.from_hex(private_key_as_hex)
    signer = CryptoFactory(create_context('secp256k1')).new_signer(private_key)
    return signer.get_public_key().as_hex()


def pem_to_bytes(pem_str):
    pem_str = pem_str.strip(" \t\r\n")
    start_index = pem_str.find("\n") + 1
    end_index = pem_str.rfind("\n")
    data_base64 = pem_str[start_index:end_index]
    data_base64 = data_base64.replace("\n", "")
    data_bytes = base64.b64decode(data_base64)

    return data_bytes


def public_key_from_pem(pem_str, compressed=False):
    pem_bytes = pem_to_bytes(pem_str)

    # Public key tag is a at the end of the DER and its total length is
    # either 68 for uncompressed or 36 for compressed key
    key_hex = None

    l = len(pem_bytes)
    if l >= 68 and pem_bytes[-68:-64] == b'\x03\x42\x00\x04':
        key_bytes = pem_bytes[-65:]
        key_hex = key_bytes.hex()

    if not key_hex:
        # try compressed key
        if l >= 36 and pem_bytes[-36:-32] == b'\x03\x22\x00\x03':
            key_bytes = pem_bytes[-33:]
            key_hex = key_bytes.hex()
        elif l >= 36 and pem_bytes[-36:-32] == b'\x03\x22\x00\x02':
            key_bytes = pem_bytes[-33:]
            key_hex = key_bytes.hex()

    if not key_hex:
        return ""

    if not compressed:
        return key_hex

    if key_hex[129] in ['0', '2', '4', '6', '8', 'a', 'A', 'c', 'C', 'e', 'E']:
        key_hex = '02' + key_hex[2:66]
    else:
        key_hex = '03' + key_hex[2:66]

    return key_hex


def signature_from_der_hex(der_str, base64_encoded=True):
    if base64_encoded:
        der = base64.b64decode(der_str.encode())
    else:
        der = binascii.unhexlify(der_str)

    # get s as int
    if der[3] <= 32:
        r_bytes = der[4:4 + der[3]]
        s_index = 4 + der[3] + 2
    else:
        r_index = 4 + (der[3] - 32)
        r_bytes = der[r_index:r_index + 32]
        s_index = r_index + 32 + 2

    r_hex = r_bytes.hex()
    # make sure it is 64 bytes long
    if len(r_hex) < 64:
        prefix = '0' * (64 - len(r_hex))
        r_hex = prefix + r_hex

    s_len = der[s_index - 1]
    if s_len > 32:
        s_index = s_index + (s_len - 32)
        s_len = 32

    s_bytes = der[s_index:s_index + s_len]

    s = int.from_bytes(s_bytes, byteorder='big')
    # make canonical signature if s > N/2, than s = N - s
    if s > (_spec256k1_curve_order / 2):
        s = _spec256k1_curve_order - s

    s_hex = hex(s)
    s_hex = s_hex[2:]  # remove leading 0x

    # make sure it is 64 bytes long
    if len(s_hex) < 64:
        prefix = '0' * (64 - len(s_hex))
        s_hex = prefix + s_hex

    signature_hex = r_hex + s_hex

    return signature_hex


def verify_secp256k1_signature_ex(message_str, signature_str, public_key_str):
    context = create_context('secp256k1')

    if len(public_key_str) > 130:
        public_key_str = public_key_from_pem(public_key_str)

    public_key = Secp256k1PublicKey.from_hex(public_key_str)

    try:
        # try raw signature as HEX string if its size is right
        if len(signature_str) == 128:
            if context.verify(signature_str, message_str.encode(), public_key):
                return True
    except:
        pass

    try:
        # try DER signature as HEX string if its size is right
        if len(signature_str) == 140 or len(signature_str) == 142 or len(signature_str) == 144:
            sig = signature_from_der_hex(signature_str, False)
            if context.verify(sig, message_str.encode(), public_key):
                return True
    except:
        pass

    # try DER signature as base64 string, it can be long due to a padding at the end
    sig = signature_from_der_hex(signature_str)
    return context.verify(sig, message_str.encode(), public_key)


def verify_secp256k1_signature(message, signature_str, public_key_str, message_digest=False):
    if len(public_key_str) > 130:
        public_key_str = public_key_from_pem(public_key_str)

    public_key = Secp256k1PublicKey.from_hex(public_key_str)

    if len(signature_str) != 128:
        sig = signature_from_der_hex(signature_str)
    else:
        sig = signature_str

    if message_digest:
        sig_bytes = bytes.fromhex(sig)
        sig_compact = public_key.secp256k1_public_key.ecdsa_deserialize_compact(sig_bytes)
        return public_key.secp256k1_public_key.ecdsa_verify(message, sig_compact, raw=True)
    else:
        context = create_context('secp256k1')
        if isinstance(message, bytes):
            return context.verify(sig, message, public_key)
        else:
            return context.verify(sig, message.encode(), public_key)


def make_ccl_transaction_hash_input(payload, contract_code_hash, pdo_contract_creator_pem_key):
    update = payload.state_update
    hash_input = bytes(payload.channel_id, "UTF-8", "ignore") +\
                 bytes(update.contract_id, "UTF-8", "ignore") +\
                 bytes(pdo_contract_creator_pem_key, "UTF-8", "ignore") + \
                 base64.b64decode(contract_code_hash) + \
                 base64.b64decode(update.message_hash) + \
                 base64.b64decode(update.current_state_hash) + \
                 base64.b64decode(update.previous_state_hash)

    for d in update.dependency_list:
        hash_input += bytes(d.contract_id, "UTF-8", "ignore") + bytes(d.state_hash, "UTF-8", "ignore")

    return hash_input


def verify_ccl_transaction_signature(payload, contract):
    try:
        hash_input = make_ccl_transaction_hash_input(
            payload,
            contract.contract_code_hash,
            contract.pdo_contract_creator_pem_key
        )

        return verify_secp256k1_signature(
            hash_input,
            payload.contract_enclave_signature,
            payload.contract_enclave_id)
    except:
        return ""


def make_ccl_transaction_pdo_hash_input(payload, contract):
    hash_input = bytes(payload.contract_enclave_id, "UTF-8", "ignore") + \
                 base64.b64decode(payload.contract_enclave_signature) + \
                 make_ccl_transaction_hash_input(
                     payload,
                     contract.contract_code_hash,
                     contract.pdo_contract_creator_pem_key
                 )

    d = hashlib.sha256(hash_input).hexdigest()
    return hash_input


def verify_ccl_transaction_pdo_signature(payload, contract):
    try:
        hash_input = make_ccl_transaction_pdo_hash_input(
            payload,
            contract
        )

        return verify_secp256k1_signature(
            hash_input,
            payload.pdo_signature,
            contract.pdo_contract_creator_pem_key
        )

    except:
        return False


def sign_ccl_transaction(payload, contract, enclave_signing_key):
    hash_input = make_ccl_transaction_hash_input(
        payload,
        contract.contract_code_hash,
        contract.pdo_contract_creator_pem_key
    )
    context = create_context('secp256k1')
    private_key = Secp256k1PrivateKey.from_hex(enclave_signing_key)
    return context.sign(hash_input, private_key)


def append_add_enclave_to_contract_hash_input(add_enclave_info, contract, pdo_signature=False):
    if not pdo_signature:
        hash_input = '{0}{1}'.format(contract.contract_id, contract.pdo_contract_creator_pem_key)
    else:
        hash_input = ""

    prev_index = -1
    while True:
        index = -1
        key = ""
        secret = ""
        for m in add_enclave_info.enclaves_map:
            if prev_index < 0 or prev_index < m.index:
                if index < 0 or index > m.index:
                    index = m.index
                    key = m.provisioning_service_public_key
                    secret = m.provisioning_contract_state_secret
        if index < 0:
            break
        prev_index = index
        hash_input = '{0}{1}{2}'.format(hash_input, key, secret)

    hash_input = '{0}{1}'.format(
        hash_input,
        add_enclave_info.encrypted_contract_state_encryption_key)

    return hash_input


def make_add_enclave_to_contract_hash_input(add_enclave_info, contract):
    message = tuple(bytes(contract.contract_id, 'ascii'))
    message += tuple(bytes(contract.pdo_contract_creator_pem_key, 'ascii'))

    prev_index = -1
    while True:
        index = -1
        key = ""
        secret = ""
        for m in add_enclave_info.enclaves_map:
            if prev_index < 0 or prev_index < m.index:
                if index < 0 or index > m.index:
                    index = m.index
                    key = m.provisioning_service_public_key
                    secret = m.provisioning_contract_state_secret
        if index < 0:
            break
        prev_index = index
        message += tuple(bytes(key, 'ascii')) + tuple(bytes(secret, 'ascii'))

    message += tuple(base64.b64decode(add_enclave_info.encrypted_contract_state_encryption_key))
    message = bytes(message)

    return message


def verify_add_enclave_to_contract_signature(add_enclave_info, contract):
    try:
        hash_input = \
            make_add_enclave_to_contract_hash_input(add_enclave_info, contract)

        res = verify_secp256k1_signature(
            hash_input,
            add_enclave_info.enclave_signature,
            add_enclave_info.contract_enclave_id)
        return res
    except:
        return False


def make_add_enclave_to_contract_pdo_hash_input(txn_details, contract, txn_signer):
    hash_input = '{0}{1}'.format(txn_signer, contract.contract_id)

    for e in txn_details.enclaves_info:
        hash_input = '{0}{1}{2}'.format(
            hash_input,
            append_add_enclave_to_contract_hash_input(e, contract, True),
            e.enclave_signature
        )

    return hash_input


def verify_add_enclave_to_contract_pdo_signature(txn_details, contract, txn_signer):
    try:
        hash_input = \
            make_add_enclave_to_contract_pdo_hash_input(txn_details, contract, txn_signer)

        return verify_secp256k1_signature(
            hash_input,
            txn_details.pdo_signature,
            contract.pdo_contract_creator_pem_key)

    except:
        return False


def make_contract_register_hash_input(txn_details, txn_signer):
    hash_input = '{0}{1}'.format(txn_signer, txn_details.contract_code_hash)

    for p in txn_details.provisioning_service_ids:
        hash_input = '{0}{1}'.format(hash_input, p)

    return hash_input


def verify_contract_register_signature(txn_details, txn_signer):
    try:
        hash_input = \
            make_contract_register_hash_input(txn_details, txn_signer)

        return verify_secp256k1_signature(
            hash_input,
            txn_details.pdo_signature,
            txn_details.pdo_contract_creator_pem_key)

    except:
        return False


def secp256k1_sign(message, private_key_str):
    context = create_context('secp256k1')
    private_key = Secp256k1PrivateKey.from_hex(private_key_str)
    try:
        if isinstance(message, bytes):
            return context.sign(message, private_key)
        else:
            return context.sign(message.encode(), private_key)
    except:
        return None


def verify_enclave_registration_info(connect,
                                     payload,
                                     details,
                                     originator_public_key_hash,
                                     context,
                                     report_public_key_pem,
                                     valid_measurements,
                                     valid_basenames,
                                     verify_pse_manifest=False):
    # Verify the attestation verification report signature
    proof_data_dict = json.loads(details.proof_data)
    verification_report = proof_data_dict.get('verification_report')
    if verification_report is None:
        raise ValueError('Verification report is missing from proof data')

    signature = proof_data_dict.get('signature')
    if signature is None:
        raise ValueError('Signature is missing from proof data')

    # If we cannot parse it, fail verification.
    try:
        report_public_key = \
            serialization.load_pem_public_key(
                report_public_key_pem.encode(),
                backend=backends.default_backend())
    except (TypeError, ValueError) as error:
        raise ValueError('Failed to parse public key: {}'.format(error))

    # Convert the comma-delimited list of valid enclave measurement values.
    # If it is not there, or fails to parse correctly, fail verification.
    try:
        valid_enclave_measurements = \
            [bytes.fromhex(m) for m in valid_measurements.split(',')]
    except ValueError as error:
        raise \
            ValueError(
                'Failed to parse enclave measurement: {}'.format(error))

    # Convert the comma-delimited list of valid enclave basename values.
    # If it is not there, or fails to parse correctly, fail verification.
    try:
        valid_enclave_basenames = \
            [bytes.fromhex(b) for b in valid_basenames.split(',')]
    except ValueError as error:
        raise \
            ValueError(
                'Failed to parse enclave basename: {}'.format(error))

    try:
        report_public_key.verify(
            base64.b64decode(signature.encode()),
            verification_report.encode(),
            padding.PKCS1v15(),
            hashes.SHA256())
    except InvalidSignature:
        raise ValueError('Verification report signature is invalid')

    verification_report_dict = json.loads(verification_report)

    # Verify that the verification report contains an ID field
    if 'id' not in verification_report_dict:
        raise ValueError('Verification report does not contain an ID')

    # Verify that the verification report contains an EPID pseudonym and
    # that it matches the enclave_persistent_id
    epid_pseudonym = verification_report_dict.get('epidPseudonym')
    if epid_pseudonym is None:
        raise \
            ValueError(
                'Verification report does not contain an EPID pseudonym')

    if epid_pseudonym != details.enclave_persistent_id:
        raise \
            ValueError(
                'The epid pseudonym in the verification report [{0}] does '
                'not match the one contained in the registration information '
                '[{1}]'.format(
                    epid_pseudonym,
                    details.enclave_persistent_id))

    if verify_pse_manifest:
        # Verify that the verification report contains a PSE manifest status
        # and it is OK
        pse_manifest_status = \
            verification_report_dict.get('pseManifestStatus')
        if pse_manifest_status is None:
            raise \
                ValueError(
                    'Verification report does not contain a PSE manifest '
                    'status')
        if pse_manifest_status.upper() != 'OK':
            if pse_manifest_status.upper() == 'OUT_OF_DATE':
                LOGGER.warning('Peer has out of date (but not revoked)'
                               ' hardware, pseManifestStatus: %s',
                               pse_manifest_status)
            else:
                raise \
                    ValueError(
                        'PSE manifest status is {} (i.e., not OK)'.format(
                            pse_manifest_status))

        # Verify that the verification report contains a PSE manifest hash
        pse_manifest_hash = \
            verification_report_dict.get('pseManifestHash')
        if pse_manifest_hash is None:
            raise \
                ValueError(
                    'Verification report does not contain a PSE manifest '
                'hash')
    else:
        pse_manifest_hash = ""

    if verify_pse_manifest:
        # Verify that the proof data contains evidence payload
        evidence_payload = proof_data_dict.get('evidence_payload')
        if evidence_payload is None:
            raise ValueError('Evidence payload is missing from proof data')
        # Verify that the evidence payload contains a PSE manifest and then
        # use it to make sure that the PSE manifest hash is what we expect
        pse_manifest = evidence_payload.get('pse_manifest')
        if pse_manifest is None:
            raise ValueError('Evidence payload does not include PSE manifest')

        expected_pse_manifest_hash = \
            hashlib.sha256(
                base64.b64decode(pse_manifest.encode())).hexdigest()
        if pse_manifest_hash.upper() != expected_pse_manifest_hash.upper():
            raise \
                ValueError(
                    'PSE manifest hash {0} does not match {1}'.format(
                        pse_manifest_hash,
                        expected_pse_manifest_hash))

    # Verify that the verification report contains an enclave quote and
    # that its status is OK
    enclave_quote_status = \
        verification_report_dict.get('isvEnclaveQuoteStatus')
    if enclave_quote_status is None:
        raise \
            ValueError(
                'Verification report does not contain an enclave quote '
                'status')
    if enclave_quote_status.upper() != 'OK':
        if enclave_quote_status.upper() == 'GROUP_OUT_OF_DATE':
            LOGGER.warning('Peer has out of date (but not revoked)'
                           ' hardware, isvEnclaveQuoteStatus: %s',
                           str(enclave_quote_status))
        else:
            raise \
                ValueError(
                    'Enclave quote status is {} (i.e., not OK)'.format(
                        enclave_quote_status))

    # Verify that the verification report contains an enclave quote
    enclave_quote = verification_report_dict.get('isvEnclaveQuoteBody')
    if enclave_quote is None:
        raise \
            ValueError(
                'Verification report does not contain an enclave quote')

    # The ISV enclave quote body is base 64 encoded, so decode it and then
    # create an SGX quote structure from it so we can inspect
    sgx_quote = SgxQuote()
    sgx_quote.parse_from_bytes(base64.b64decode(enclave_quote))

    # NOTE - since the code that created the report data is in the enclave
    # code, this code needs to be kept in sync with it.  Any changes to how
    # the report data is created, needs to be reflected in how we re-create
    # the report data for verification.

    hash_input = \
        '{0}{1}{2}'.format(
            payload.verifying_key,
            details.encryption_key,
            originator_public_key_hash).encode()
    LOGGER.debug("quote hash input: %s", hash_input)

    hash_value = hashlib.sha256(hash_input).digest()
    expected_report_data = \
        hash_value + \
        (b'\x00' *
        (SgxReportData.STRUCT_SIZE - len(hash_value)))

    if sgx_quote.report_body.report_data.d != expected_report_data:
        raise \
            ValueError(
                'AVR report data [{0}] not equal to [{1}]'.format(
                    sgx_quote.report_body.report_data.d.hex(),
                    expected_report_data.hex()))

    # Verify that the enclave measurement is in the list of valid
    # enclave measurements.
    if sgx_quote.report_body.mr_enclave.m not in \
            valid_enclave_measurements:
        raise \
            ValueError(
                'AVR enclave measurement [{}] not in list of valid '
                'enclave measurements [{}]'.format(
                    sgx_quote.report_body.mr_enclave.m.hex(),
                    valid_measurements))

    # Verify that the enclave basename is in the list of valid
    # enclave basenames
    if sgx_quote.basename.name not in valid_enclave_basenames:
        raise \
            ValueError(
                'AVR enclave basename [{}] not in list of valid '
                'enclave basenames [{}]'.format(
                    sgx_quote.basename.name.hex(),
                    valid_basenames))

    # Verify that the nonce in the verification report matches
    # registration_block_context in the transaction payload submitted
    nonce = verification_report_dict.get('nonce', '')
    if nonce != details.registration_block_context:
        raise \
            ValueError(
                'AVR nonce [{0}] does not match registration_block_context in the '
                'registration info [{1}]'.format(
                    nonce,
                    details.registration_block_context))
