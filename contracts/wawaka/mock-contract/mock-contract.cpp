#include <malloc.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#include "Dispatch.h"

#include "KeyValue.h"
#include "Environment.h"
#include "Message.h"
#include "Response.h"
#include "StringArray.h"
#include "Value.h"
#include "WasmExtensions.h"

static KeyValueStore value_store("values");
const StringArray test_key("test");

bool initialize(const Message& msg, const Environment& env, Response& rsp)
{
    const uint32_t value = 0;

    if (! value_store.set(test_key, value))
    {
        rsp.set_error_result("failed to create the test key");
        return false;
    }

    Value v(true);

    rsp.mark_state_modified();
    rsp.set_result(v.serialize());

    return true;
}

bool inc_value(const Message& msg, const Environment& env, Response& rsp)
{
    uint32_t value;
    if (! value_store.get(test_key, value))
    {
        rsp.set_error_result("no such key");
        return false;
    }

    value += 1;
    if (! value_store.set(test_key, value))
    {
        rsp.set_error_result("failed to save the new value");
        return false;
    }

    Value v((double)value);

    rsp.mark_state_modified();
    rsp.set_result(v.serialize());

    return true;
}

bool get_value(const Message& msg, const Environment& env, Response& rsp)
{
    uint32_t value;
    if (! value_store.get(test_key, value))
    {
        rsp.set_error_result("no such key");
        return false;
    }

    Value v((double)value);

    rsp.mark_state_unmodified();
    rsp.set_result(v.serialize());

    return true;
}

contract_method_reference_t contract_method_dispatch_table[] = {
    CONTRACT_METHOD(initialize),
    CONTRACT_METHOD(inc_value),
    CONTRACT_METHOD(get_value),
    { NULL, NULL }
};
