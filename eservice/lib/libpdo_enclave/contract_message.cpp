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

#include <string>
#include <vector>

#include "error.h"
#include "pdo_error.h"

#include "crypto.h"
#include "jsonvalue.h"
#include "packages/base64/base64.h"
#include "parson.h"

#include "contract_message.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// See ${PDO_SOURCE_ROOT}/eservice/docs/contract.json for format
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool ContractMessage::VerifySignature(const ByteArray& signature) const
{
    // verify the signature in the message came from the originator
    pdo::crypto::sig::PublicKey verifying_key(originator_verifying_key_);

    std::string serialized = expression_ + channel_verifying_key_ + nonce_;
    ByteArray message(serialized.begin(), serialized.end());
    return verifying_key.VerifySignature(message, signature) > 0;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractMessage::Unpack(const JSON_Object* object)
{
    std::string svalue;
    const char* pvalue = nullptr;
    JSON_Object* ovalue = nullptr;

    // contract message
    pvalue = json_object_dotget_string(object, "InvocationRequest");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Request");
    expression_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "OriginatorVerifyingKey");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve OriginatorVerifyingKey");
    originator_verifying_key_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "ChannelVerifyingKey");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve ChannelVerifyingKey");
    channel_verifying_key_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "Nonce");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Nonce");
    nonce_.assign(pvalue);

    pvalue = json_object_dotget_string(object, "Signature");
    pdo::error::ThrowIf<pdo::error::ValueError>(
        !pvalue, "invalid request; failed to retrieve Signature");
    ByteArray decoded_signature = base64_decode(pvalue);

    pdo::error::ThrowIf<pdo::error::ValueError>(
        !VerifySignature(decoded_signature), "unable to verify the source of the message");

    ComputeHash(message_hash_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void ContractMessage::ComputeHash(ByteArray& message_hash) const
{
    std::string serialized = expression_ + nonce_;
    ByteArray message(serialized.begin(), serialized.end());
    message_hash = pdo::crypto::ComputeMessageHash(message);
}
