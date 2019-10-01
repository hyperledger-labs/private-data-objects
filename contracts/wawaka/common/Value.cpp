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

#include "Value.h"

Value::Value(const char* value)
{
    value_ = json_value_init_string(value);
}

Value::Value(const double value)
{
    value_ = json_value_init_number(value);
}

Value::Value(const bool value)
{
    value_ = json_value_init_boolean(value);
}

Value::Value(const JSON_Value *value)
{
    // this copy is just to make sure that we can free
    // memory cleanly
    value_ = json_value_deep_copy(value);
}

Value::~Value(void)
{
    if (value_ != NULL)
        json_value_free(value_);
}

char* Value::serialize(void)
{
    // serialize the result
    size_t serialized_size = json_serialization_size(value_);
    char *serialized_response = (char *)malloc(serialized_size + 1);
    if (serialized_response == NULL)
        return NULL;

    JSON_Status jret = json_serialize_to_buffer(value_, serialized_response, serialized_size + 1);
    if (jret != JSONSuccess)
    {
        free(serialized_response);
        return NULL;
    }

    return serialized_response;
}
