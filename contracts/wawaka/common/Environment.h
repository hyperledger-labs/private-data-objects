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

class Environment
{
public :
    char *contract_id_;
    char *creator_id_;
    char *originator_id_;
    char *state_hash_;
    char *message_hash_;
    char *contract_code_name_;
    char *contract_code_hash_;

    Environment(void);
    ~Environment(void);

    bool deserialize(const char* contract_environment);
};
