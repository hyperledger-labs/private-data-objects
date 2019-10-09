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
#include "log.h"
#include "packages/parson/parson.h"
#include "pdo_error.h"
#include "swig_utils.h"
#include "types.h"

#include "enclave/base.h"
#include "enclave/signup.h"

#include "signup_info.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
pdo_err_t SignupInfo::DeserializeSignupInfo(
    const std::string& serialized_signup_info
    )
{
    pdo_err_t presult = PDO_SUCCESS;

    try
    {
        const char* pvalue = nullptr;

        // Parse the incoming wait certificate
        JsonValue parsed(json_parse_string(serialized_signup_info.c_str()));
        pdo::error::ThrowIfNull(parsed.value, "failed to parse serialized signup info; badly formed JSON");

        JSON_Object* data_object = json_value_get_object(parsed);
        pdo::error::ThrowIfNull(data_object, "invalid serialized signup info; missing root object");

        // --------------- interpreter ---------------
        pvalue = json_object_dotget_string(data_object, "interpreter");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing interpreter");

        interpreter.assign(pvalue);

        // --------------- verifying key ---------------
        pvalue = json_object_dotget_string(data_object, "verifying_key");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing verifying_key");

        verifying_key.assign(pvalue);

        // --------------- encryption key ---------------
        pvalue = json_object_dotget_string(data_object, "encryption_key");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing encryption_key");

        encryption_key.assign(pvalue);

        // --------------- proof data ---------------
        pvalue = json_object_dotget_string(data_object, "proof_data");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing proof_data");

        proof_data.assign(pvalue);

        // --------------- enclave id ---------------
        pvalue = json_object_dotget_string(data_object, "enclave_persistent_id");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing enclave_persistent_id");

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
SignupInfo::SignupInfo(
    const std::string& serialized_signup_info
    ) :
    serialized_(serialized_signup_info)
{
    pdo_err_t result = DeserializeSignupInfo(serialized_signup_info);
    ThrowPDOError(result);
} // SignupInfo::SignupInfo

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
SignupInfo* deserialize_signup_info(
    const std::string&  serialized_signup_info
    )
{
    return new SignupInfo(serialized_signup_info);
} // deserialize_signup_info

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// the parallel serialization is in enclave_data.cpp
static pdo_err_t DeserializePublicEnclaveData(
    const std::string& public_enclave_data,
    std::string& interpreter,
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

        // --------------- interpreter ---------------
        pvalue = json_object_dotget_string(data_object, "Interpreter");
        pdo::error::ThrowIfNull(pvalue, "invalid serialized signup info; missing interpreter");

        interpreter.assign(pvalue);

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
std::map<std::string, std::string> create_enclave_data(
    const std::string& originator_public_key_hash
    )
{
    pdo_err_t presult;

    // Create some buffers for receiving the output parameters
    StringArray public_enclave_data(0); // CreateEnclaveData will resize appropriately
    Base64EncodedString sealed_enclave_data;
    Base64EncodedString enclave_quote;

    // Create the signup data
    presult = pdo::enclave_api::enclave_data::CreateEnclaveData(
        originator_public_key_hash,
        public_enclave_data,
        sealed_enclave_data,
        enclave_quote);
    ThrowPDOError(presult);

    SAFE_LOG(PDO_LOG_DEBUG, public_enclave_data.str().c_str());

    // parse the json and save the verifying and encryption keys
    std::string interpreter;
    std::string verifying_key;
    std::string encryption_key;

    presult = DeserializePublicEnclaveData(
        public_enclave_data.str(),
        interpreter,
        verifying_key,
        encryption_key);
    ThrowPDOError(presult);

    // save the information
    std::map<std::string, std::string> result;
    result["interpreter"] = interpreter;
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
    std::string interpreter;
    std::string verifying_key;
    std::string encryption_key;

    presult = DeserializePublicEnclaveData(
        public_enclave_data.str(),
        interpreter,
        verifying_key,
        encryption_key);
    ThrowPDOError(presult);

    std::map<std::string, std::string> result;
    result["interpreter"] = interpreter;
    result["verifying_key"] = verifying_key;
    result["encryption_key"] = encryption_key;

    return result;
} // _unseal_signup_data
