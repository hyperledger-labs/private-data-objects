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

#include "Response.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Response::Response(void)
{
    status_ = false;
    state_changed_ = false;
    result_ = NULL;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Response::~Response(void)
{
    if (result_ != NULL)
        free(result_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void Response::set_result(const char* result)
{
    result_ = strdup(result);
    status_ = true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
void Response::set_error_result(const char* result)
{
    result_ = strdup(result);
    status_ = false;
    state_changed_ = false;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
char *Response::serialize(void)
{
    // Create the response structure
    JsonValue contract_response_value(json_value_init_object());
    if (! contract_response_value.value)
        return NULL;

    JSON_Object* contract_response_object = json_value_get_object(contract_response_value);
    if (contract_response_object == NULL)
        return NULL;

    JSON_Status jret;

    // --------------- status ---------------
    jret = json_object_dotset_boolean(contract_response_object, "Status", status_);
    if (jret != JSONSuccess)
        return NULL;

    // --------------- state updated ---------------
    jret = json_object_dotset_boolean(contract_response_object, "StateChanged", state_changed_);
    if (jret != JSONSuccess)
        return NULL;

    // --------------- result ---------------
    jret = json_object_dotset_string(contract_response_object, "Result", result_);
    if (jret != JSONSuccess)
        return NULL;

    // serialize the result
    size_t serialized_size = json_serialization_size(contract_response_value);
    char *serialized_response = (char *)malloc(serialized_size + 1);
    if (serialized_response == NULL)
        return NULL;

    jret = json_serialize_to_buffer(contract_response_value, serialized_response, serialized_size + 1);
    if (jret != JSONSuccess)
    {
        free(serialized_response);
        return NULL;
    }

    return serialized_response;
}
