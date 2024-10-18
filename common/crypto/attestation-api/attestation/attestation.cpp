/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include <string.h>
#include "attestation.h"
#include "attestation_tags.h"
#include "base64/base64.h"
#include "error.h"
#include "logging.h"
#include "types/types.h"
#include "epid.h"
#include "dcap.h"

// < JSON include
#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;
// JSON include >

/**********************************************************************************************************************
 * Attestation APIs
 * *******************************************************************************************************************/

typedef struct
{
    epid_state_t epid;
    //dcap_state_t dcap_state
} state_u;

typedef struct
{
    bool initialized;
    std::string attestation_type;
    state_u state;
} attestation_state_t;

attestation_state_t g_attestation_state = {0};

bool init_attestation(uint8_t* params, uint32_t params_length)
{
    if(params == NULL)
    {
        LOG_ERROR("bad attestation init params");
        return false;
    }

    // open json
    bool ret = false;
    json root;
    std::string params_string((char*)params, params_length);
    CATCH(ret, root = json::parse(params_string));
    COND2LOGERR(!ret, "invalid attestation params");

    {
        CATCH(ret, g_attestation_state.attestation_type = root[ATTESTATION_TYPE_TAG].template get<std::string>());
        COND2LOGERR(!ret, "invalid attestation type field");

        // check for simulated type
        if (g_attestation_state.attestation_type.compare(SIMULATED_TYPE_TAG) == 0)
        {
            // terminate init successfully
            goto init_success;
        }

        //check for epid type
        if (g_attestation_state.attestation_type.compare(0, strlen(EPID_PREFIX_TAG), EPID_PREFIX_TAG) == 0)
        {
            COND2ERR(!init_epid(params, params_length, &g_attestation_state.state.epid));
            goto init_success;
        }

        //check for dcap type
        if (g_attestation_state.attestation_type.compare(0, strlen(DCAP_PREFIX_TAG), DCAP_PREFIX_TAG) == 0)
        {
            COND2ERR(!init_dcap(params, params_length));
            goto init_success;
        }
    }

init_success:
    g_attestation_state.initialized = true;
    return true;

err:
    return false;
}

bool get_attestation(uint8_t* statement,
    uint32_t statement_length,
    uint8_t* attestation,
    uint32_t attestation_max_length,
    uint32_t* attestation_length)
{
    std::string b64attestation;

    COND2LOGERR(!g_attestation_state.initialized, "attestation not initialized");
    COND2LOGERR(statement == NULL, "bad input statement");
    COND2LOGERR(attestation == NULL, "bad input attestation buffer");
    COND2LOGERR(attestation_length == NULL || attestation_max_length == 0,
        "bad input attestation buffer size");

    // attestation type: simulated
    if (g_attestation_state.attestation_type.compare(SIMULATED_TYPE_TAG) == 0)
    {
        std::string zero("0");
        b64attestation = base64_encode((const unsigned char*)zero.c_str(), zero.length());
    }

    // attestation type: epid
    if (g_attestation_state.attestation_type.compare(0, strlen(EPID_PREFIX_TAG), EPID_PREFIX_TAG) == 0)
    {
        COND2ERR(
                !get_epid_attestation(
                    statement,
                    statement_length,
                    &g_attestation_state.state.epid,
                    b64attestation));
    }

    // attestation type: dcap
    if (g_attestation_state.attestation_type.compare(0, strlen(DCAP_PREFIX_TAG), DCAP_PREFIX_TAG) == 0)
    {
        COND2ERR(
                !get_dcap_attestation(
                    statement,
                    statement_length,
                    b64attestation));
    }

    // Got the base64 attestation

    // package the output in json format
    {
        bool ret;
        size_t serialization_size = 0;
        std::string serialized_json;
        json root;

        root[ATTESTATION_TYPE_TAG] = g_attestation_state.attestation_type;
        root[ATTESTATION_TAG] = b64attestation;

        CATCH(ret, serialized_json = root.dump());
        COND2LOGERR(!ret, "error serializing attestation json");

        //serialization_size = json_serialization_size(root_value);
        serialization_size = serialized_json.length();
        COND2LOGERR(
            serialization_size > attestation_max_length,
            "not enough space for b64 conversion: serialization len %d buf len %d",
            serialization_size,
            attestation_max_length);

        std::strncpy((char*)attestation, serialized_json.c_str(), serialization_size);

        *attestation_length = serialization_size;

        LOG_DEBUG("attestation json: %s", serialized_json.c_str());
        LOG_DEBUG("attestation json length: %d", serialization_size);
    }

    return true;

err:
    return false;
}
