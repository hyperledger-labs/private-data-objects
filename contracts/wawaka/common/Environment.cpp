/* Copyright 2019 Intel Corporation
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

#include <stdlib.h>
#include <string.h>

#include "jsonvalue.h"
#include "parson.h"

#include "Environment.h"

#define SAFE_GET_STRING(o, k, v)                        \
    const char* __ ## v = json_object_dotget_string(o, k);  \
    if (__ ## v == NULL)                                    \
        return false;                                   \
    v = strdup(__## v);                                    \
    if (v == NULL)                                      \
        return false;

#define SAFE_FREE_STRING(v) \
    if (v != NULL)              \
        free(v);

Environment::Environment(void)
{
    // nothing for now
}

Environment::~Environment(void)
{
    SAFE_FREE_STRING(contract_id_);
    SAFE_FREE_STRING(creator_id_);
    SAFE_FREE_STRING(originator_id_);
    SAFE_FREE_STRING(state_hash_);
    SAFE_FREE_STRING(message_hash_);
    SAFE_FREE_STRING(contract_code_name_);
    SAFE_FREE_STRING(contract_code_hash_);
}

bool Environment::deserialize(
    const char* contract_environment
    )
{
    // Parse the contract request
    JsonValue parsed(json_parse_string(contract_environment));
    if (parsed == NULL)
        return false;

    JSON_Object* parsed_object = json_value_get_object(parsed);
    if (parsed_object == NULL)
        return false;

    SAFE_GET_STRING(parsed_object, "ContractID", contract_id_);
    SAFE_GET_STRING(parsed_object, "CreatorID", creator_id_);
    SAFE_GET_STRING(parsed_object, "OriginatorID", originator_id_);
    SAFE_GET_STRING(parsed_object, "StateHash", state_hash_);
    SAFE_GET_STRING(parsed_object, "MessageHash", message_hash_);
    SAFE_GET_STRING(parsed_object, "ContractCodeName", contract_code_name_);
    SAFE_GET_STRING(parsed_object, "ContractCodeHash", contract_code_hash_);

    return true;
}
