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

import hashlib
import pdo.common.crypto as crypto
import pdo.common.utility as putils

import logging
logger = logging.getLogger(__name__)

import binascii
import secp256k1

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class TransactionKeys(object) :
    """
    Wrapper for managing Sawtooth transaction keys
    """

    @classmethod
    def read_from_file(cls, file_name, search_path = ['.', './keys']) :
        full_file = putils.find_file_in_path(file_name, search_path)
        with open(full_file, "r") as ff :
            hex_encoded_private_key = ff.read()

        priv = binascii.unhexlify(hex_encoded_private_key)
        return cls(secp256k1.PrivateKey(priv))

    @classmethod
    def from_hex(cls, hex_encoded_private_key) :
        priv = binascii.unhexlify(hex_encoded_private_key)
        return cls(secp256k1.PrivateKey(priv))

    def __init__(self, private_key = None) :
        if private_key == None :
            private_key = secp256k1.PrivateKey()

        self.public_key = private_key.pubkey
        self.private_key = private_key

    @property
    def hashed_identity(self) :
        key_byte_array = crypto.string_to_byte_array(self.txn_public)
        hashed_txn_key = crypto.compute_message_hash(key_byte_array)
        encoded_hashed_key = crypto.byte_array_to_hex(hashed_txn_key)
        encoded_hashed_key = encoded_hashed_key.lower()
        return encoded_hashed_key

    @property
    def txn_private(self) :
        return self.private_key.serialize()

    @property
    def txn_public(self) :
        return self.public_key.serialize().hex()


# -----------------------------------------------------------------
# -----------------------------------------------------------------
class EnclaveKeys(object) :
    """
    Wrapper for managing the enclave's keys, the verifying_key is an
    ECDSA public key used to verify enclave signatures, the
    encryption_key is an RSA public key for encrypting message to the
    enclave.
    """

    # -------------------------------------------------------
    def __init__(self, verifying_key, encryption_key) :
        """
        initialize the object

        :param verifying_key: PEM encoded ECDSA verifying key
        :param encryption_key: PEM encoded RSA encryption key
        """
        self._verifying_key = crypto.SIG_PublicKey(verifying_key)
        self._encryption_key = crypto.PKENC_PublicKey(encryption_key)

    # -------------------------------------------------------
    @property
    def identity(self) :
        return self._verifying_key.Serialize()

    # -------------------------------------------------------
    @property
    def hashed_identity(self) :
        return hashlib.sha256(self.identity.encode('utf8')).hexdigest()[:16]

    # -------------------------------------------------------
    def serialize(self) :
        result = dict()
        result['verifying_key'] = self._verifying_key.Serialize()
        result['encryption_key'] = self._encryption_key.Serialize()
        return result

    # -------------------------------------------------------
    def verify(self, message, encoded_signature, encoding='b64') :
        """
        verify a signature that was created by the enclave

        :param message: the message for verification, no encoding
        :param signature: encoded signature
        :param encoding: the encoding used for the signature; one of raw, hex, b64
        """
        logger.debug("signature for verification: %s", encoded_signature)

        if type(message) is bytes :
            message_byte_array = message
        elif type(message) is tuple :
            message_byte_array = message
        else :
            message_byte_array = bytes(message, 'ascii')

        if encoding == 'raw' :
            decoded_signature = encoded_signature
        elif encoding == 'hex' :
            decoded_signature = crypto.hex_to_byte_array(encoded_signature)
        elif encoding == 'b64' :
            decoded_signature = crypto.base64_to_byte_array(encoded_signature)
        else :
            raise ValueError('unknown encoding; {0}'.format(encoding))

        logger.debug("verifying key: %s", self._verifying_key.Serialize())
        logger.debug("signature for verification: %s", crypto.byte_array_to_hex(decoded_signature))

        result = self._verifying_key.VerifySignature(message_byte_array, decoded_signature)
        if result < 0 :
            raise Error('malformed signature');

        return result

    # -------------------------------------------------------
    def encrypt(self, message, encoding = 'raw') :
        """
        encrypt a message to send privately to the enclave

        :param message: text to encrypt
        :param encoding: encoding for the encrypted cipher text, one of raw, hex, b64
        """

        if type(message) is bytes :
            message_byte_array = message
        elif type(message) is tuple :
            message_byte_array = message
        else :
            message_byte_array = bytes(message, 'ascii')

        encrypted_byte_array = self._encryption_key.EncryptMessage(message_byte_array)
        if encoding == 'raw' :
            encoded_bytes = encrypted_byte_array
        elif encoding == 'hex' :
            encoded_bytes = crypto.byte_array_to_hex(encrypted_byte_array)
        elif encoding == 'b64' :
            encoded_bytes = crypto.byte_array_to_base64(encrypted_byte_array)
        else :
            raise ValueError('unknown encoding; {0}'.format(encoding))

        logger.debug("message: %s", message)
        logger.debug("encrypted message: %s", encoded_bytes)

        return encoded_bytes

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ServiceKeys(object) :
    """
    Wrapper for ECDSA keys used to identify a service or other agent; distinct
    from the transaction keys because keys are PEM encoded
    """

    @classmethod
    def read_from_file(cls, file_name, search_path = ['.', './keys']) :
        full_file = putils.find_file_in_path(file_name, search_path)
        with open(full_file, "r") as ff :
            pem_encoded_signing_key = ff.read()

        return cls(crypto.SIG_PrivateKey(pem_encoded_signing_key))

    # -------------------------------------------------------
    @classmethod
    def create_service_keys(cls) :
        signing_key = crypto.SIG_PrivateKey()
        signing_key.Generate()
        return cls(signing_key)

    # -------------------------------------------------------
    def __init__(self, signing_key) :
        self._signing_key = signing_key
        self._verifying_key = self._signing_key.GetPublicKey()

    # -------------------------------------------------------
    @property
    def identity(self) :
        return self._verifying_key.Serialize()

    # -------------------------------------------------------
    @property
    def verifying_key(self) :
        return self._verifying_key.Serialize()

    # -------------------------------------------------------
    @property
    def signing_key(self) :
        return self._signing_key.Serialize()

    # -------------------------------------------------------
    @property
    def hashed_identity(self) :
        return hashlib.sha256(self.identity.encode('utf8')).hexdigest()[:16]

    # -------------------------------------------------------
    def verify(self, message, encoded_signature, encoding = 'hex') :
        """
        verify the signature of a message from the agent

        :param message: the message for verification, no encoding
        :param signature: encoded signature
        :param encoding: the encoding used for the signature; one of raw, hex, b64
        """
        logger.debug("signature for verification: %s", encoded_signature)

        if type(message) is bytes :
            message_byte_array = message
        elif type(message) is tuple :
            message_byte_array = message
        else :
            message_byte_array = bytes(message, 'ascii')

        if encoding == 'raw' :
            decoded_signature = encoded_signature
        elif encoding == 'hex' :
            decoded_signature = crypto.hex_to_byte_array(encoded_signature)
        elif encoding == 'b64' :
            decoded_signature = crypto.base64_to_byte_array(encoded_signature)
        else :
            raise ValueError('unknown encoding; {0}'.format(encoding))

        result = self._verifying_key.VerifySignature(message_byte_array, decoded_signature)
        if result < 0 :
            raise Error('malformed signature')

        return

    # -------------------------------------------------------
    def sign(self, message, encoding='hex') :
        """
        sign a message from the agent

        :param message: the message for verification, no encoding
        :param encoding: the encoding used for the signature; one of raw, hex, b64
        """

        if type(message) is bytes :
            message_byte_array = message
        elif type(message) is tuple :
            message_byte_array = message
        else :
            message_byte_array = bytes(message, 'ascii')

        signature = self._signing_key.SignMessage(message_byte_array)
        if encoding == 'raw' :
            encoded_signature = signature
        elif encoding == 'hex' :
            encoded_signature = crypto.byte_array_to_hex(signature)
        elif encoding == 'b64' :
            encoded_signature = crypto.byte_array_to_base64(signature)
        else :
            raise ValueError('unknown encoding; {0}'.format(encoding))

        logger.debug("message: %s", message)
        logger.debug("signature: %s", encoded_signature)

        return encoded_signature
