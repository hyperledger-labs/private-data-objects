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

#include <map>
#include <string>
#include <vector>

#include "error.h"
#include "jsonvalue.h"
#include "packages/parson/parson.h"
#include "pdo_error.h"
#include "swig_utils.h"
#include "types.h"

#include "enclave/base.h"
#include "enclave/secret.h"

#include "secret_info.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t EnclaveInfo::DeserializeEnclaveInfo(
    const std::string& serialized_enclave_info
    )
{
    pdo_err_t presult = PDO_SUCCESS;

    try
    {
        const char* pvalue = nullptr;

        // Parse the incoming wait certificate
        JsonValue parsed(json_parse_string(serialized_enclave_info.c_str()));
        pdo::error::ThrowIfNull(parsed.value, "failed to parse serialized enclave info; badly formed JSON");

        JSON_Object* data_object = json_value_get_object(parsed);
        pdo::error::ThrowIfNull(data_object, "invalid serialized enclave info; missing root object");

        // --------------- verifying key ---------------
        pvalue = json_object_dotget_string(data_object, "verifying_key");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized enclave info; missing verifying_key");

        verifying_key.assign(pvalue);

        // --------------- encryption key ---------------
        pvalue = json_object_dotget_string(data_object, "encryption_key");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized enclave info; missing encryption_key");

        encryption_key.assign(pvalue);

        // --------------- proof data ---------------
        pvalue = json_object_dotget_string(data_object, "proof_data");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized enclave info; missing proof_data");

        proof_data.assign(pvalue);

        // --------------- enclave id ---------------
        pvalue = json_object_dotget_string(data_object, "enclave_persistent_id");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized enclave info; missing enclave_persistent_id");

        enclave_persistent_id.assign(pvalue);
    }
    catch (pdo::error::Error& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        presult = e.error_code();
    }
    catch(std::exception& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        presult = PDO_ERR_UNKNOWN;
    }
    catch(...)
    {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        presult = PDO_ERR_UNKNOWN;
    }

    return presult;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EnclaveInfo::EnclaveInfo(
    const std::string& serialized_enclave_info
    ) :
    serialized_(serialized_enclave_info)
{
    pdo_err_t result = DeserializeEnclaveInfo(serialized_enclave_info);
    ThrowPDOError(result);
} // EnclaveInfo::EnclaveInfo

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
EnclaveInfo* deserialize_enclave_info(
    const std::string&  serialized_enclave_info
    )
{
    return new EnclaveInfo(serialized_enclave_info);
} // deserialize_enclave_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// the parallel serialization is in enclave_data.cpp
static pdo_err_t DeserializePublicEnclaveData(
    const std::string& public_enclave_data,
    std::string& verifying_key,
    std::string& encryption_key
    )
{
    pdo_err_t result = PDO_SUCCESS;

    try
    {
        const char* pvalue = nullptr;

        // Parse the incoming wait certificate
        JsonValue parsed(json_parse_string(public_enclave_data.c_str()));
        pdo::error::ThrowIfNull(parsed.value, "failed to parse the public enclave data, badly formed JSON");

        JSON_Object* data_object = json_value_get_object(parsed);
        pdo::error::ThrowIfNull(data_object, "invalid public enclave data; missing root object");

        // --------------- verifying key ---------------
        pvalue = json_object_dotget_string(data_object, "VerifyingKey");
        pdo::error::ThrowIfNull(pvalue, "invalid public enclave data; missing VerifyingKey");

        verifying_key.assign(pvalue);

        // --------------- encryption key ---------------
        pvalue = json_object_dotget_string(data_object, "EncryptionKey");
        pdo::error::ThrowIfNull(pvalue, "invalid public enclave data; missing EncryptionKey");

        encryption_key.assign(pvalue);
    }
    catch (pdo::error::Error& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = e.error_code();
    }
    catch(std::exception& e)
    {
        pdo::enclave_api::base::SetLastError(e.what());
        result = PDO_ERR_UNKNOWN;
    }
    catch(...)
    {
        pdo::enclave_api::base::SetLastError("Unexpected exception");
        result = PDO_ERR_UNKNOWN;
    }

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> create_enclave_data()
{
    pdo_err_t presult;

    // Create some buffers for receiving the output parameters
    StringArray public_enclave_data(0); // CreateEnclaveData will resize appropriately
    Base64EncodedString sealed_enclave_data;
    Base64EncodedString enclave_quote;

    // Create the enclave data
    presult = pdo::enclave_api::enclave_data::CreateEnclaveData(
        public_enclave_data,
        sealed_enclave_data,
        enclave_quote);
    ThrowPDOError(presult);

    PyLog(PDO_LOG_DEBUG, public_enclave_data.str().c_str());

    // parse the json and save the verifying and encryption keys
    std::string verifying_key;
    std::string encryption_key;

    presult = DeserializePublicEnclaveData(
        public_enclave_data.str(),
        verifying_key,
        encryption_key);
    ThrowPDOError(presult);

    // save the information
    std::map<std::string, std::string> result;
    result["verifying_key"] = verifying_key;
    result["encryption_key"] = encryption_key;
    result["sealed_enclave_data"] = sealed_enclave_data;
    result["enclave_quote"] = enclave_quote;

    return result;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> unseal_enclave_data(
    const std::string& sealed_enclave_data
    )
{
    pdo_err_t presult;
    StringArray public_enclave_data(0); // UnsealEnclaveData will resize appropriately

    presult = pdo::enclave_api::enclave_data::UnsealEnclaveData(
        sealed_enclave_data,
        public_enclave_data);
    ThrowPDOError(presult);

    // parse the json and save the verifying and encryption keys
    std::string verifying_key;
    std::string encryption_key;

    presult = DeserializePublicEnclaveData(
        public_enclave_data.str(),
        verifying_key,
        encryption_key);
    ThrowPDOError(presult);

    std::map<std::string, std::string> result;
    result["verifying_key"] = verifying_key;
    result["encryption_key"] = encryption_key;

    return result;
} // _unseal_enclave_data


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> create_sealed_secret(
    const int key_len
    )
{
    pdo_err_t presult;


    Base64EncodedString sealed_secret;

    presult = pdo::enclave_api::enclave_data::CreateSealedSecret(
        key_len,
        sealed_secret);
    ThrowPDOError(presult);

    PyLog(PDO_LOG_DEBUG,  ("Sealed Secret: "+sealed_secret).c_str());

    // save the information
    std::map<std::string, std::string> result;
    result["sealed_secret"] = sealed_secret;

    return result;
}// _create_secret


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> unseal_secret(
    const std::string& sealed_secret
    )
{
    pdo_err_t presult;

    HexEncodedString plain_secret;
    // std::string plain_secret;

    presult = pdo::enclave_api::enclave_data::UnsealSecret(
        sealed_secret,
        plain_secret);
    ThrowPDOError(presult);

    PyLog(PDO_LOG_DEBUG, ("Sealed Secret: " + sealed_secret + "\nPlain Secret: " + plain_secret).c_str());

    std::map<std::string, std::string> result;
    result["plain_secret"] = plain_secret;

    return result;
} // _unseal_secret


// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
std::map<std::string, std::string> generate_enclave_secret(
    const std::string& sealed_enclave_data,
    const std::string& sealed_secret,
    const std::string& contract_id,
    const std::string& opk,
    const std::string& enclave_info
    )
{
    pdo_err_t presult;

    Base64EncodedString enclave_secret;

    presult = pdo::enclave_api::enclave_data::GenerateEnclaveSecret(
        sealed_enclave_data,
        sealed_secret,
        contract_id,
        opk,
        enclave_info,
        enclave_secret);
    ThrowPDOError(presult);

    PyLog(PDO_LOG_DEBUG, ("Enclave Encrypted Secret: " + enclave_secret).c_str());

    std::map<std::string, std::string> result;
    result["enclave_secret"] = enclave_secret;

    return result;
} // _generate_enclave_secret

