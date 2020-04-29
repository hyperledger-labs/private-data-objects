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

#include "parson.h"
#include "StringArray.h"

namespace ww
{
namespace value
{
    class Value
    {
        // storage associated value_ is owned by this value and must be free'd
    protected:
        void clear_value(void);

        JSON_Value_Type expected_value_type_;
        JSON_Value *value_;

    public:
        Value(void);
        ~Value(void);

        char *serialize(void) const;
        bool serialize(StringArray& result) const;
        bool deserialize(const char *message);

        JSON_Value_Type get_type(void) const;
        const JSON_Value* get(void) const;
        const JSON_Value* set(const JSON_Value *value);

        bool is_null(void) const { return value_ == NULL; };
    };

    class Boolean : public Value
    {
    public:
        Boolean(const bool value);
        bool get(void) const;
        bool set(bool value);
    };

    class String : public Value
    {
    public:
        String(const char* value);
        const char* get(void) const;
        const char* set(const char* value);
    };

    class Number : public Value
    {
    public:
        Number(const double value);
        double get(void) const;
        double set(double value);
    };

    class Object : public Value
    {
    public:
        Object(void);
        Object(const Object& source);

        const char* get_string(const char* key) const;
        double get_number(const char* key) const;
        int get_boolean(const char* key) const;

        bool get_value(const char* name, Value& value) const;

        //bool set_string(const char* name, const char* value);
        //bool set_number(const char* name, const double value);
        //bool set_boolean(const char* name, const bool value);
        bool set_value(const char* name, const Value& value);

        // pass in a schema object, true if the value has the same
        // structure as the schema object
        bool validate_schema(const Value& schema) const;
        bool validate_schema(const char* schema) const;
    };

    class Structure : public Object
    {
    public:
        Structure(const char* schema);

        bool set_value(const char* name, const Value& value);
    };

    class Array : public Value
    {
    public:
        Array(void);

        size_t get_count(void) const;

        const char* get_string(const size_t index) const;
        double get_number(const size_t index) const;
        int get_boolean(const size_t index) const;

        bool get_value(const size_t index, Value& value) const;

        //bool set_string(const size_t index, const char* value);
        //bool set_number(const size_t index, const double value);
        //bool set_boolean(const size_t index, const bool value);
        bool append_value(const Value& value);
    };
};
}
