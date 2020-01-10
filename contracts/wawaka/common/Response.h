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

#include "Value.h"

class Response : public ww::value::Object
{
public:
    Response(void);

    bool set_response(const ww::value::Value& response);
    bool set_state_changed(bool state_changed);
    bool set_status(bool status);
    bool add_dependency(const char* contract_id, const char* state_hash);

    bool value(const ww::value::Value& v, bool changed)
    {
        set_status(true);
        set_state_changed(changed);
        set_response(v);

        return true;
    };

    bool success(bool changed)
    {
        ww::value::Boolean response(true);
        value(response, changed);

        return true;
    };

    bool error(const char* msg)
    {
        ww::value::String response(msg);
        set_status(false);
        set_state_changed(false);
        set_response(response);

        return false;
    };
};
