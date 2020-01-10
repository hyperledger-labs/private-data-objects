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

#include "parson.h"

#include "Value.h"
#include "WasmExtensions.h"

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: pdo.Value.Value
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::Value::Value(void)
{
    value_ = json_value_init_null();
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
}

// -----------------------------------------------------------------
ww::value::Value::~Value(void)
{
    if (value_ != NULL)
        json_value_free(value_);
}

// -----------------------------------------------------------------
JSON_Value_Type ww::value::Value::get_type(void) const
{
    return expected_value_type_;
}

// -----------------------------------------------------------------
const JSON_Value* ww::value::Value::get(void) const
{
    return value_;
}

// -----------------------------------------------------------------
const JSON_Value* ww::value::Value::set(const JSON_Value *value)
{
    if (value_ != NULL)
        json_value_free(value_);

    if (value == NULL) {
        value_ = json_value_init_null();
        expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
    } else {
        value_ = json_value_deep_copy(value);
        expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
    }

    return value_;
}

// -----------------------------------------------------------------
bool ww::value::Value::deserialize(const char* value)
{
    if (value == NULL)
        return false;

    JSON_Value* json_value = json_parse_string(value);
    if (json_value == NULL)
        return false;

    // this forces a bit of correctness checking on JSON lookups in that
    // the incoming value object has to match the one in the object
    if (json_value_get_type(json_value) != expected_value_type_)
    {
        free(json_value);
        return false;
    }

    value_ = json_value;
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));

    return true;
}

// -----------------------------------------------------------------
char* ww::value::Value::serialize(void) const
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

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::value::Boolean
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::Boolean::Boolean(const bool value)
{
    value_ = json_value_init_boolean(value);
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
}

// -----------------------------------------------------------------
bool ww::value::Boolean::get(void) const
{
    return json_boolean(value_);
}

// -----------------------------------------------------------------
bool ww::value::Boolean::set(bool value)
{
    if (value_ != NULL)
        json_value_free(value_);

    value_ = json_value_init_boolean(value);
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));

    return json_boolean(value_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::value::String
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::String::String(const char* value)
{
    value_ = json_value_init_string(value);
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
}

// -----------------------------------------------------------------
const char* ww::value::String::get(void) const
{
    return json_string(value_);
}

// -----------------------------------------------------------------
const char* ww::value::String::set(const char* value)
{
    if (value_ != NULL)
        json_value_free(value_);

    value_ = json_value_init_string(value);
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));

    return json_string(value_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::value::Number
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::Number::Number(const double value)
{
    value_ = json_value_init_number(value);
    expected_value_type_ = json_value_get_type(value_);
}

// -----------------------------------------------------------------
double ww::value::Number::get(void) const
{
    return json_number(value_);
}

// -----------------------------------------------------------------
double ww::value::Number::set(double value)
{
    if (value_ != NULL)
        json_value_free(value_);

    value_ = json_value_init_number(value);
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));

    return json_number(value_);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::value::Object
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::Object::Object(void)
{
    value_ = json_value_init_object();
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const char* ww::value::Object::get_string(const char* key) const
{
     return json_object_dotget_string(json_object(value_), key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
double ww::value::Object::get_number(const char* key) const
{
    return json_object_dotget_number(json_object(value_), key);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int ww::value::Object::get_boolean(const char* key) const
{
    return json_object_dotget_boolean(json_object(value_), key);
}

// -----------------------------------------------------------------
bool ww::value::Object::get_value(const char* name, ww::value::Value& value) const
{
    const JSON_Value *json_value = json_object_get_value(json_object(value_), name);
    if (json_value == NULL)
        return false;

    // this forces a bit of correctness checking on JSON lookups in that
    // the incoming value object has to match the one in the object
    if (json_value_get_type(json_value) != value.get_type())
        return false;

    value.set(json_value);
    return true;
}

// -----------------------------------------------------------------
bool ww::value::Object::set_value(const char* name, const ww::value::Value& value)
{
    if (name == NULL)
        return false;

    JSON_Value *json_value = json_value_deep_copy(value.get());
    if (json_value == NULL)
        return false;

    if (json_object_set_value(json_object(value_), name, json_value) != JSONSuccess)
    {
        free(json_value);
        return false;
    }

    return true;
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
// Class: ww::value::Array
// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

// -----------------------------------------------------------------
ww::value::Array::Array(void)
{
    value_ = json_value_init_array();
    expected_value_type_ = (value_ == NULL ? JSONError : json_value_get_type(value_));
}

// -----------------------------------------------------------------
size_t ww::value::Array::get_count(void) const
{
    return json_array_get_count(json_array(value_));
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
const char* ww::value::Array::get_string(size_t index) const
{
     return json_array_get_string(json_array(value_), index);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
double ww::value::Array::get_number(size_t index) const
{
    return json_array_get_number(json_array(value_), index);
}

// XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
int ww::value::Array::get_boolean(size_t index) const
{
    return json_array_get_boolean(json_array(value_), index);
}

// -----------------------------------------------------------------
bool ww::value::Array::get_value(const size_t index, ww::value::Value& value) const
{
    const JSON_Value *json_value = json_array_get_value(json_array(value_), index);
    if (json_value == NULL)
        return false;

    // this forces a bit of correctness checking on JSON lookups in that
    // the incoming value object has to match the one in the object
    if (json_value_get_type(json_value) != value.get_type())
        return false;

    value.set(json_value);
    return true;
}

// -----------------------------------------------------------------
bool ww::value::Array::append_value(const ww::value::Value& value)
{
    JSON_Value *json_value = json_value_deep_copy(value.get());
    if (json_value == NULL)
        return false;

    if (json_array_append_value(json_array(value_), json_value) != JSONSuccess)
    {
        free(json_value);
        return false;
    }

    return true;
}
