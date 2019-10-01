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

#include "jsonvalue.h"
#include "parson.h"

#include "Message.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Message::Message(void)
{
    parsed_message = NULL;
    root = NULL;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
Message::~Message(void)
{
    if (parsed_message != NULL)
        json_value_free(parsed_message);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
bool Message::deserialize(const char* message)
{
    // Parse the contract request
    parsed_message = json_parse_string(message);
    if (parsed_message == NULL)
        return false;

    root = json_value_get_object(parsed_message);
    if (root == NULL)
        return false;

    // TODO: run some sanity checks here

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const char* Message::get_string(const char* key) const
{
    if (root == NULL)
        return NULL;

    return json_object_dotget_string(root, key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
double Message::get_number(const char* key) const
{
    if (root == NULL)
        return 0.0;

    return json_object_dotget_number(root, key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int Message::get_boolean(const char* key) const
{
    if (root == NULL)
        return -1;

    return json_object_dotget_boolean(root, key);
}
