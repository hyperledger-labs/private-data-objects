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

#pragma once

#include "types.h"
#include "state.h"

namespace pdo
{
    namespace state
    {
        class Interpreter_KV : public Basic_KV_Plus
        {
        protected:
            State_KV kv_;

            ByteArray Get(const ByteArray& key);
            void Put(const ByteArray& key, const ByteArray& value);
            void Delete(const ByteArray& key);

        public:
            Interpreter_KV(StateBlockId& id);
            Interpreter_KV(const StateBlockId& id, const ByteArray& encryption_key);
            Interpreter_KV(const ByteArray& encryption_key);
            ~Interpreter_KV();

            void Finalize(ByteArray& id);

            void PrivilegedPut(const ByteArray& key, const ByteArray& value);
            ByteArray PrivilegedGet(const ByteArray& key);
            void PrivilegedDelete(const ByteArray& key);

            void UnprivilegedPut(const ByteArray& key, const ByteArray& value);
            ByteArray UnprivilegedGet(const ByteArray& key);
            void UnprivilegedDelete(const ByteArray& key);
        };
    }
}
