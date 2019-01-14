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

namespace pdo
{
namespace state
{
    class Basic_KV
    {
    protected:
        void* handle;

    public:
        virtual ~Basic_KV() {}
        virtual void Finalize(ByteArray& id) = 0;
        virtual ByteArray Get(const ByteArray& key) = 0;
        virtual void Put(const ByteArray& key, const ByteArray& value) = 0;
        virtual void Delete(const ByteArray& key) = 0;
    };

    class Basic_KV_Plus : public Basic_KV
    {
    public:
        virtual ByteArray PrivilegedGet(const ByteArray& key) = 0;
        virtual void PrivilegedPut(const ByteArray& key, const ByteArray& value) = 0;
        virtual ByteArray UnprivilegedGet(const ByteArray& key) = 0;
        virtual void UnprivilegedPut(const ByteArray& key, const ByteArray& value) = 0;
    };
}
}
