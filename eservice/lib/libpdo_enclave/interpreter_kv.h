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
#include "basic_kv.h"

namespace pdo 
{
    namespace state
    {
        class Interpreter_KV : public Basic_KV
        {
        protected:
            Basic_KV* kv_;
        public:
            Interpreter_KV(ByteArray& id);
            ~Interpreter_KV();
            void Uninit(ByteArray& id);
            ByteArray Get(ByteArray& key);
            void Put(ByteArray& key, ByteArray& value);
            void Delete(ByteArray& key);
        };
    }
}
