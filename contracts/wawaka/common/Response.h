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

class Response
{
private:
    bool status_;
    bool state_changed_;
    char *result_;
    // something about dependencies

public:

    Response(void);
    ~Response(void);

    void set_result(const char* result);
    void set_error_result(const char* result);
    void mark_state_modified(void) { state_changed_ = true; };
    void mark_state_unmodified(void) { state_changed_ = false; };

    char *serialize(void);
};
