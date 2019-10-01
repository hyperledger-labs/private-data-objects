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

#pragma once

#include "jsonvalue.h"
#include "parson.h"

class Message
{
private:
    JSON_Value *parsed_message;
    JSON_Object *root;

public:

    Message(void);
    ~Message(void);

    bool deserialize(const char *message);

    const char* get_string(const char* key) const;
    double get_number(const char* key) const;
    int get_boolean(const char* key) const;
};
