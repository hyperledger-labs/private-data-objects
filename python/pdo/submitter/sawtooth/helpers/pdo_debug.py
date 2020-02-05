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

import json
from google.protobuf.json_format import MessageToDict


from pdo.submitter.sawtooth.pdo_protos.pdo_contract_registry_pb2 import\
    PdoContractRegister,\
    PdoContractAddEnclaves,\
    PdoContractRemoveEnclaves

from pdo.submitter.sawtooth.pdo_protos.pdo_contract_enclave_registry_pb2 import\
    PdoContractEnclaveRegister,\
    PdoContractEnclaveUpdate


# hardcoded valid basename to test enclave proof date signature verification
__VALID_BASENAME__ = \
        'b785c58b77152cbe7fd55ee3851c4990'\
        '00000000000000000000000000000000'

# 'b785c58b77152cbe7fd55ee3851c499000000000000000000000000000000000'

# hardcoded enclave measurement to test enclave proof date signature verification
__VALID_ENCLAVE_MEASUREMENT__ = \
        'c99f21955e38dbb03d2ca838d3af6e43'\
        'ef438926ed02db4cc729380c8c7a174e'
# 'c99f21955e38dbb03d2ca838d3af6e43ef438926ed02db4cc729380c8c7a174e'

# hardcoded report private key PEM to test enclave proof date signature verification
__REPORT_PRIVATE_KEY_PEM__ = \
    '-----BEGIN PRIVATE KEY-----\n' \
    'MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCsy/NmLwZP6Uj0\n' \
    'p5mIiefgK8VOK7KJ34g3h0/X6aFOd/Ff4j+e23wtQpkxsjVHWLM5SjElGhfpVDhL\n' \
    '1WAMsQI9bpCWR4sjV6p7gOJhv34nkA2Grj5eSHCAJRQXCl+pJ9dYIeKaNoaxkdtq\n' \
    '+Xme//ohtkkv/ZjMTfsjMl0RLXokJ+YhSuTpNSovRaCtZfLB5MihVJuV3Qzb2ROh\n' \
    'KQxcuyPy9tBtOIrBWJaFiXOLRxAijs+ICyzrqUBbRfoAztkljIBx9KNItHiC4zPv\n' \
    'o6DxpGSO2yMQSSrs13PkfyGWVZSgenEYOouEz07X+H5B29PPuW5mCl4nkoH3a9gv\n' \
    'rI6VLEx9AgMBAAECggEAImfFge4RCq4/eX85gcc7pRXyBjuLJAqe+7d0fWAmXxJg\n' \
    'vB+3XTEEi5p8GDoMg7U0kk6kdGe6pRnAz9CffEduU78FCPcbzCCzcD3cVWwkeUok\n' \
    'd1GQV4OC6vD3DBNjsrGdHg45KU18CjUphCZCQhdjvXynG+gZmWxZecuYXkg4zqPT\n' \
    'LwOkcdWBPhJ9CbjtiYOtKDZbhcbdfnb2fkxmvnAoz1OWNfVFXh+x7651FrmL2Pga\n' \
    'xGz5XoxFYYT6DWW1fL6GNuVrd97wkcYUcjazMgunuUMC+6XFxqK+BoqnxeaxnsSt\n' \
    'G2r0sdVaCyK1sU41ftbEQsc5oYeQ3v5frGZL+BgrYQKBgQDgZnjqnVI/B+9iarx1\n' \
    'MjAFyhurcKvFvlBtGKUg9Q62V6wI4VZvPnzA2zEaR1J0cZPB1lCcMsFACpuQF2Mr\n' \
    '3VDyJbnpSG9q05POBtfLjGQdXKtGb8cfXY2SwjzLH/tvxHm3SP+RxvLICQcLX2/y\n' \
    'GTJ+mY9C6Hs6jIVLOnMWkRWamQKBgQDFITE3Qs3Y0ZwkKfGQMKuqJLRw29Tyzw0n\n' \
    'XKaVmO/pEzYcXZMPBrFhGvdmNcJLo2fcsmGZnmit8RP4ChwHUlD11dH1Ffqw9FWc\n' \
    '387i0chlE5FhQPirSM8sWFVmjt2sxC4qFWJoAD/COQtKHgEaVKVc4sH/yRostL1C\n' \
    'r+7aWuqzhQKBgQDcuC5LJr8VPGrbtPz1kY3mw+r/cG2krRNSm6Egj6oO9KFEgtCP\n' \
    'zzjKQU9E985EtsqNKI5VdR7cLRLiYf6r0J6j7zO0IAlnXADP768miUqYDuRw/dUw\n' \
    'JsbwCZneefDI+Mp325d1/egjla2WJCNqUBp4p/Zf62f6KOmbGzzEf6RuUQKBgG2y\n' \
    'E8YRiaTOt5m0MXUwcEZk2Hg5DF31c/dkalqy2UYU57aPJ8djzQ8hR2x8G9ulWaWJ\n' \
    'KiCm8s9gaOFNFt3II785NfWxPmh7/qwmKuUzIdWFNxAsbHQ8NvURTqyccaSzIpFO\n' \
    'hw0inlhBEBQ1cB2r3r06fgQNb2BTT0Itzrd5gkNVAoGBAJcMgeKdBMukT8dKxb4R\n' \
    '1PgQtFlR3COu2+B00pDyUpROFhHYLw/KlUv5TKrH1k3+E0KM+winVUIcZHlmFyuy\n' \
    'Ilquaova1YSFXP5cpD+PKtxRV76Qlqt6o+aPywm81licdOAXotT4JyJhrgz9ISnn\n' \
    'J13KkHoAZ9qd0rX7s37czb3O\n' \
    '-----END PRIVATE KEY-----'

# hardcoded report public key PEM to test enclave proof date signature verification
__REPORT_PUBLIC_KEY_PEM__ = '''-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEArMvzZi8GT+lI9KeZiInn
4CvFTiuyid+IN4dP1+mhTnfxX+I/ntt8LUKZMbI1R1izOUoxJRoX6VQ4S9VgDLEC
PW6QlkeLI1eqe4DiYb9+J5ANhq4+XkhwgCUUFwpfqSfXWCHimjaGsZHbavl5nv/6
IbZJL/2YzE37IzJdES16JCfmIUrk6TUqL0WgrWXyweTIoVSbld0M29kToSkMXLsj
8vbQbTiKwViWhYlzi0cQIo7PiAss66lAW0X6AM7ZJYyAcfSjSLR4guMz76Og8aRk
jtsjEEkq7Ndz5H8hllWUoHpxGDqLhM9O1/h+QdvTz7luZgpeJ5KB92vYL6yOlSxM
fQIDAQAB
-----END PUBLIC KEY-----'''


class PdoDbgDump:
    def __init__(self, logger=None):
        self._LOGGER = logger

    def _dump_str(self, str):
        if self._LOGGER == None:
            print(str)
        else:
            self._LOGGER.debug(str)

    def dump_str(self, str):
        self._dump_str(str)

    def dump_ccl_transaction(self, txn, prompt = "CCL_TransactionPayload:"):
        self._dump_str(prompt)
        self._dump_str("verb: {}".format(txn.verb))
        self._dump_str("contract_enclave_id: {}".format(txn.contract_enclave_id))
        self._dump_str("contract_enclave_signature: {}".format(
            txn.contract_enclave_signature))
        self._dump_str("channel_id: {}".format(txn.channel_id))
        self.dump_state_update(txn.state_update)
        self._dump_str("pdo_signature: {}".format(txn.pdo_signature))

    def dump_state_update(self, update, promt="CCL_ContractStateUpdate:"):
        self._dump_str(promt)
        self._dump_str("  contract_id: {}".format(update.contract_id))
        self._dump_str("  current_state_hash: {}".format(update.current_state_hash))
        self._dump_str("  previous_state_hash: {}".format(update.previous_state_hash))
        self._dump_str("  message_hash: {}".format(update.message_hash))
        self._dump_str("  encrypted_state: {}".format(update.encrypted_state))
        for r in update.dependency_list:
            self._dump_str("  CCL_ContractStateReference (dependency):")
            self._dump_str("    contract_id: {}".format(r.contract_id))
            self._dump_str("    state_hash: {}".format(r.state_hash))

    def dump_state_reference(self, ref, promt="CCL_ContractStateReference:"):
        self._dump_str(promt)
        self._dump_str("  contract_id: {}".format(ref.contract_id))
        self._dump_str("  state_hash: {}".format(ref.state_hash))

    def dump_ccl_state(self, state, prompt = "CCL_ContractState:"):
        self._dump_str(prompt)
        self._dump_str("transaction_id: {}".format(state.transaction_id))
        self.dump_state_update(state.state_update)

    def dump_ccl_info(self, info, prompt = "CCL_ContractInformation:"):
        self._dump_str(prompt)
        self._dump_str("is_active: {}".format(info.is_active))
        self._dump_str("contract_id: {}".format(info.contract_id))
        self.dump_state_reference(info.current_state)

    def dump_contract_state(self, state, prompt="PdoContractState:"):
        self._dump_str("")
        self._dump_str(prompt)
        self._dump_str("contract_id: {}".format(state.contract_id))
        self._dump_str("contract_code_hash: {}".format(state.contract_code_hash))
        self._dump_str("pdo_contract_creator_pem_key: {}".format(state.pdo_contract_creator_pem_key))

        index = 1
        for id in state.provisioning_service_ids:
            self._dump_str("  provisioning_service_ids[{0}]: {1}".format(index, id))
            index += 1

        for e in state.enclaves_info:
            self._dump_str("  contract_enclave_id: {}".format(e.contract_enclave_id))
            self._dump_str("    encrypted_contract_state_encryption_key: {}".format(
                e.encrypted_contract_state_encryption_key))
            self._dump_str("    enclave_signature: {}".format(e.enclave_signature))
            for m in e.enclaves_map:
                self._dump_str("      provisioning_service_public_key: {}".format(
                    m.provisioning_service_public_key))
                self._dump_str("      provisioning_contract_state_secret: {}".format(
                    m.provisioning_contract_state_secret))
                self._dump_str("      index: {}".format(m.index))

    def dump_contract_transaction(self, payload):
        self._dump_str("")
        self._dump_str("PdoContractTransaction:")
        self._dump_str("verb:  {}".format(payload.verb))
        self._dump_str("contract_id:  {}".format(payload.contract_id))
        self._dump_str("TransactionDetails:")
        if payload.verb == 'register':
            details = PdoContractRegister()
            details.ParseFromString(payload.transaction_details)
            self._dump_str("  contract_code_hash:  {}".format(details.contract_code_hash))
            self._dump_str("pdo_contract_creator_pem_key: {}".format(details.pdo_contract_creator_pem_key))
            self._dump_str("pdo_signature: {}".format(details.pdo_signature))
            index = 1
            for id in details.provisioning_service_ids:
                self._dump_str("  provisioning_service_id[{0}]: {1}".format(index, id))
                index += 1

        elif payload.verb == "add-enclaves":
            details = PdoContractAddEnclaves()
            details.ParseFromString(payload.transaction_details)
            self._dump_str("pdo_signature: {}".format(details.pdo_signature))
            for e in details.enclaves_info:
                self._dump_str("  contract_enclave_id:  {}".format(e.contract_enclave_id))
                self._dump_str("    encrypted_contract_state_encryption_key: {}".format(
                             e.encrypted_contract_state_encryption_key))
                self._dump_str("    enclave_signature: {}".format(e.enclave_signature))
                for m in e.enclaves_map:
                    self._dump_str("      provisioning_service_public_key: {}".format(
                                 m.provisioning_service_public_key))
                    self._dump_str("      provisioning_contract_state_secret: {}".format(
                                 m.provisioning_contract_state_secret))
                    self._dump_str("      index: {}".format(m.index))

        elif payload.verb == "remove-enclaves":
            details = PdoContractRemoveEnclaves()
            details.ParseFromString(payload.transaction_details)
            index = 1
            for id in details.contract_enclave_ids:
                self._dump_str("  contract_enclave_id[{0}]: {1}".format(index, id))
                index += 1

        elif payload.verb != "delete":
            self._dump_str("  invalid transaction verb")

    def dump_contract_enclave_state(self, state, prompt="PdoContractEnclaveState:"):
        self._dump_str("")
        self._dump_str(prompt)
        self._dump_str("verifying_key: {}".format(state.verifying_key))
        self._dump_str("encryption_key: {}".format(state.encryption_key))
        self._dump_str("owner_id: {}".format(state.owner_id))
        self._dump_str("last_registration_block_context: {}".format(state.last_registration_block_context))
        self._dump_str("registration_transaction_id: {}".format(state.registration_transaction_id))
        self._dump_str("proof_data: {}".format(state.proof_data))

    def dump_contract_enclave_transaction(self, payload):
        self._dump_str("")
        self._dump_str("PdoContractEnclaveTransaction:")
        self._dump_str("verb: {}".format(payload.verb))
        self._dump_str("verifying_key: {}".format(payload.verifying_key))
        self._dump_str("TransactionDetails:")
        if payload.verb == 'register':
            details = PdoContractEnclaveRegister()
            details.ParseFromString(payload.transaction_details)

            self._dump_str("  organizational_info: {}".format(details.organizational_info))
            self._dump_str("  encryption_key: {}".format(details.encryption_key))
            self._dump_str("  proof_data: {}".format(details.proof_data))
            self._dump_str("  enclave_persistent_id: {}".format(details.enclave_persistent_id))
            self._dump_str("  registration_block_context: {}".format(details.registration_block_context))

        elif payload.verb == "update":
            details = PdoContractEnclaveUpdate()
            details.ParseFromString(payload.transaction_details)
            self._dump_str("  registration_block_context: {}".format(details.registration_block_context))

        elif payload.verb != "delete":
            self._dump_str("  invalid transaction verb")

    def dump_ccl_transaction_protobuf_message_to_json(self, msg, family=None):
        txn_dict = MessageToDict(
            msg,
            including_default_value_fields=True,
            preserving_proto_field_name=True)

        if family:
            txn_dict["af"] = family
        print()
        print(json.dumps(txn_dict, indent=2))
        print()

    def dump_enclave_transaction_protobuf_message_to_json(self, msg, family=None):
        txn_dict = {}
        details= None

        if msg.verb == 'register':
            details = PdoContractEnclaveRegister()
        elif msg.verb == "update":
            details = PdoContractEnclaveUpdate()
        elif msg.verb != "delete":
            txn_dict["error"] = "invalid transaction verb"

        if details:
            details.ParseFromString(msg.transaction_details)
            txn_dict = MessageToDict(
                details,
                including_default_value_fields=True,
                preserving_proto_field_name=True)

        if family:
            txn_dict["af"] = family
        txn_dict["verb"] = msg.verb
        txn_dict["verifying_key"] = msg.verifying_key
        print()
        print(json.dumps(txn_dict, indent=2))
        print()

    def dump_contract_transaction_protobuf_message_to_json(self, msg, family=None):
        txn_dict = {}
        details= None

        if msg.verb == 'register':
            details = PdoContractRegister()
        elif msg.verb == "add-enclaves":
            details = PdoContractAddEnclaves()
        elif msg.verb == "remove-enclaves":
            details = PdoContractRemoveEnclaves()
        elif msg.verb != "delete":
            txn_dict["error"] = "invalid transaction verb"

        if details:
            details.ParseFromString(msg.transaction_details)
            txn_dict = MessageToDict(
                details,
                including_default_value_fields=True,
                preserving_proto_field_name=True)

        if family:
            txn_dict["af"] = family

        txn_dict["verb"] = msg.verb
        txn_dict["contract_id"] = msg.contract_id
        print()
        print(json.dumps(txn_dict, indent=2))
        print()
