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

#include <set>
#include <string>
#include <vector>

#include "sgx_tcrypto.h"
#include "sgx_utils.h"

#include "error.h"
#include "pdo_error.h"

#include "crypto.h"
#include "jsonvalue.h"
#include "packages/base64/base64.h"
#include "parson.h"
#include "types.h"
#include "zero.h"

#include "hex_string.h"

#include "contract_secrets.h"
#include "enclave_utils.h"


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
static void VerifySecretSignature(const std::string& inEnclaveId,
    const std::string& inContractId,
    const std::string& inCreatorId,
    const std::string& pspk,
    const std::string& encoded_secret,
    const ByteArray& signature)
{
    pdo::crypto::sig::PublicKey ps_public_key(pspk);

    ByteArray message_array;
    std::copy(encoded_secret.begin(), encoded_secret.end(), std::back_inserter(message_array));
    std::copy(inEnclaveId.begin(), inEnclaveId.end(), std::back_inserter(message_array));
    std::copy(inContractId.begin(), inContractId.end(), std::back_inserter(message_array));
    std::copy(inCreatorId.begin(), inCreatorId.end(), std::back_inserter(message_array));

    std::string msg = encoded_secret + inEnclaveId + inContractId + inCreatorId;
    SAFE_LOG(PDO_LOG_DEBUG, "MESSAGE: <%s>\n", msg.c_str());

    int result = ps_public_key.VerifySignature(message_array, signature);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        result <= 0, "failed to verify the secret signature");
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t CreateEnclaveStateEncryptionKey(const EnclaveData& enclave_data,
    const std::string& inContractId,
    const std::string& inCreatorId,
    const std::string& inSerializedSecretList,
    ByteArray& contractStateEncryptionKey,
    ByteArray& message)
{
    pdo_err_t result = PDO_SUCCESS;

    const std::string enclave_id = enclave_data.get_enclave_id();

    std::copy(inContractId.begin(), inContractId.end(), std::back_inserter(message));
    std::copy(inCreatorId.begin(), inCreatorId.end(), std::back_inserter(message));

    // Parse the incoming wait certificate
    JsonValue parsed(json_parse_string(inSerializedSecretList.c_str()));
    pdo::error::ThrowIfNull(parsed.value, "Failed to parse the secret list, badly formed JSON");

    JSON_Array* secret_array = json_value_get_array(parsed);
    pdo::error::ThrowIfNull(secret_array, "Failed to parse the secret list, expecting array");

    ByteArray accumulator(ENCODED_SECRET_SIZE / 2, 0);
    const char* svalue = nullptr;

    int secret_count = json_array_get_count(secret_array);
    pdo::error::ThrowIf<pdo::error::ValueError>(
        secret_count < 1, "there must be at least one secret provided");

    std::set<std::string> pspk_list;
    for (int i = 0; i < secret_count; i++)
    {
        JSON_Object* secret_object = json_array_get_object(secret_array, i);
        pdo::error::ThrowIfNull(secret_object, "Invalid secret, expecting object");

        svalue = json_object_dotget_string(secret_object, "pspk");
        pdo::error::ThrowIfNull(svalue, "Invalid provisioning service public key");
        const std::string pspk = svalue;

        pdo::error::ThrowIf<pdo::error::ValueError>(
            pspk_list.find(pspk) != pspk_list.end(),
            "Multiple secrets from the same provisioning service");

        pspk_list.insert(pspk);

        svalue = json_object_dotget_string(secret_object, "encrypted_secret");
        pdo::error::ThrowIfNull(svalue, "Invalid encrypted secret");
        const std::string encrypted_ps_secret = svalue;

        std::copy(pspk.begin(), pspk.end(), std::back_inserter(message));
        std::copy(
            encrypted_ps_secret.begin(), encrypted_ps_secret.end(), std::back_inserter(message));

        // TODO: decrypt encrypted_ps_secret
        ByteArray encrypted_secret_buffer = Base64EncodedStringToByteArray(encrypted_ps_secret);
        ByteArray decrypted_secret = enclave_data.decrypt_message(encrypted_secret_buffer);
        const std::string decrypted_ps_secret = ByteArrayToString(decrypted_secret);

        pdo::error::ThrowIf<pdo::error::ValueError>(
            decrypted_ps_secret.length() < ENCODED_SECRET_SIZE + ENCODED_SECRET_SIGNATURE_SIZE,
            "Invalid secret, wrong length");

        const std::string encoded_secret = decrypted_ps_secret.substr(0, ENCODED_SECRET_SIZE);

        SAFE_LOG(PDO_LOG_DEBUG, "Secret: %s\nSignature: %s\n",
            decrypted_ps_secret.substr(0, ENCODED_SECRET_SIZE).c_str(),
            decrypted_ps_secret.substr(ENCODED_SECRET_SIZE).c_str());

        ByteArray secret =
            HexEncodedStringToByteArray(decrypted_ps_secret.substr(0, ENCODED_SECRET_SIZE));
        ByteArray signature =
            HexEncodedStringToByteArray(decrypted_ps_secret.substr(ENCODED_SECRET_SIZE));

        VerifySecretSignature(
            enclave_id, inContractId, inCreatorId, pspk, encoded_secret, signature);

        // XOR the secrets together
        for (int i = 0; i < ENCODED_SECRET_SIZE / 2; i++)
            accumulator[i] = accumulator[i] ^ secret[i];
    }

    // inContractStateEncryptionKey = Common::AES::GenerateEncodedKey(accumulator);
    contractStateEncryptionKey = accumulator;

    return result;
}



// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// encrypt/decrypt state encryption key
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray EncryptStateEncryptionKey(
    const std::string& inContractId, const ByteArray& inContractStateEncryptionKey)
{

  uint32_t aadSize = inContractId.size(); // Note: we exclude terminating NULL ..
  uint32_t keySize = inContractStateEncryptionKey.size();
  uint32_t sealedBlobSize = sgx_calc_sealed_data_size(aadSize, keySize);
  pdo::error::ThrowIf<pdo::error::RuntimeError>(
    (sealedBlobSize == 0xFFFFFFFF),
    "Failed to get valid size for sealed Blob of state encryption key");
  ByteArray sealedBlob(sealedBlobSize);

  // Seal up the state encryption key
  // See comments on seal for ecall_CreateEnclaveData in
  // eservice/lib/libpdo_enclave/signup_enclave.cpp
  // for some important notes ...
  // Note: AAD=ContractID is stored in visible form inside sealed blob ...

  sgx_status_t ret = sgx_seal_data_ex(
    PDO_SGX_KEYPOLICY, PDO_SGX_ATTRIBUTTE_MASK, PDO_SGX_MISCMASK,
    aadSize, reinterpret_cast<const uint8_t*>(inContractId.c_str()),  // Additional Authentication Info
    keySize, inContractStateEncryptionKey.data(), // encrypted payload
    sealedBlob.size(), reinterpret_cast<sgx_sealed_data_t*>(sealedBlob.data()));
  pdo::error::ThrowSgxError(ret, "Failed to seal contract state encryption key");

  return sealedBlob;
}

// Note: Below function is not used as asymmetrically we do the base64 encoding
// outside of the enclave when we create the encrypted blob but do decode
// it inside enclave (in ContractRequest::ContractRequest) when
// we do transactions. Still kept implementation here for symmetry reasons ..
Base64EncodedString EncryptAndEncodeStateEncryptionKey(
  const std::string& inContractId, const ByteArray& inContractStateEncryptionKey)
{
    ByteArray encrypted_state_encryption_key =
        EncryptStateEncryptionKey(inContractId, inContractStateEncryptionKey);

    return base64_encode(encrypted_state_encryption_key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
ByteArray DecryptStateEncryptionKey(
    const std::string& inContractId, const ByteArray& inEncryptedStateEncryptionKey)
{

  const sgx_sealed_data_t* sealedBlob = reinterpret_cast<const sgx_sealed_data_t*>(inEncryptedStateEncryptionKey.data());

  uint32_t aadLen = sgx_get_add_mac_txt_len(sealedBlob);
  uint32_t keyLen = sgx_get_encrypt_txt_len(sealedBlob);

  ByteArray aad(aadLen);
  ByteArray decryptedStateEncryptionKey(keyLen);

  sgx_status_t ret = sgx_unseal_data(
    sealedBlob,
    aad.data(), &aadLen,
    decryptedStateEncryptionKey.data(), &keyLen);
  pdo::error::ThrowSgxError(ret, "Failed to unseal contract state encryption key");

  pdo::error::ThrowIf<pdo::error::ValueError>(
    ( (aadLen != inContractId.size()) || (0 != memcmp(inContractId.c_str(), aad.data(), aadLen)) ),
    "ContractID mismatch while decrypting contract state encryption key");

  return decryptedStateEncryptionKey;
}

ByteArray DecodeAndDecryptStateEncryptionKey(const std::string& inContractId,
    const Base64EncodedString& inEncodedEncryptedStateEncryptionKey)
{
    ByteArray encrypted_state_encryption_key = base64_decode(inEncodedEncryptedStateEncryptionKey);
    return DecryptStateEncryptionKey(inContractId, encrypted_state_encryption_key);
}
