/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include "types/types.h"
#include "verify-token.h"
#include "ita-certificates.h"
#include "logging.h"
#include "error.h"

#define JSON_HAS_CPP_11
#define JSON_NO_IO 1
#include <errno.h>
#include "nlohmann/json/single_include/nlohmann/json.hpp"

#define JWT_DISABLE_PICOJSON
#include "jwt-cpp/include/jwt-cpp/traits/nlohmann-json/traits.h"
#include "jwt-cpp/include/jwt-cpp/jwt.h"

bool get_ita_certificate(std::string& certificate)
{
    certificate = std::string(ita_token_signing_ca_cert_jwt);
    return true;
}

verify_status_t verify_ita_token_signature(const std::string token)
{
        
    std::string cert;
    std::string t(token);
    get_ita_certificate(cert);

    COND2LOGERR(cert.length() <= 1, "Unable to verify ITA tokens: ITA root cert not provided");

    try
    {
        auto decoded_token = jwt::decode<jwt::traits::nlohmann_json>(t);
        //auto iat = decoded_token.get_issued_at().time_since_epoch().count();
        //auto exp = decoded_token.get_expires_at().time_since_epoch().count();
        //auto now = std::chrono::system_clock::time_point::clock::now().time_since_epoch().count();
        LOG_DEBUG("token decoded");
        //LOG_DEBUG("iat: %ld", iat);
        //LOG_DEBUG("exp: %ld", exp);
        //LOG_DEBUG("now: %ld", now);
        LOG_DEBUG("keyid: %s", decoded_token.get_key_id().c_str());

        jwt::jwks<jwt::traits::nlohmann_json> jwkeys = jwt::parse_jwks<jwt::traits::nlohmann_json>(cert);
        auto jwkey = jwkeys.get_jwk(decoded_token.get_key_id());
        auto x5cert = jwkey.get_x5c_key_value();
        auto pemkey = jwt::helper::convert_base64_der_to_pem(x5cert);
        LOG_DEBUG("pem: %s", pemkey.c_str());

        auto verifier = jwt::verify<jwt::traits::nlohmann_json>().allow_algorithm(jwt::algorithm::ps384(pemkey, "", "", ""));
        verifier.verify(decoded_token);
        LOG_DEBUG("token verified");
    }
    catch (const std::exception &exc)
    {
        LOG_ERROR("Exception: %s", exc.what());
        if(std::string(exc.what()).compare("token expired") == 0)
        {
            bool b;
            int leeway = 30; // 30 seconds leeway
            auto decoded_token = jwt::decode<jwt::traits::nlohmann_json>(t);
            jwt::jwks<jwt::traits::nlohmann_json> jwkeys = jwt::parse_jwks<jwt::traits::nlohmann_json>(cert);
            auto jwkey = jwkeys.get_jwk(decoded_token.get_key_id());
            auto x5cert = jwkey.get_x5c_key_value();
            auto pemkey = jwt::helper::convert_base64_der_to_pem(x5cert);
            auto verifier = jwt::verify<jwt::traits::nlohmann_json>().allow_algorithm(jwt::algorithm::ps384(pemkey, "", "", ""));
            verifier.leeway(leeway);
            CATCH(b, verifier.verify(decoded_token));
            COND2LOGERR(!b, "failed token verification");

            LOG_DEBUG("token verified, leeway: %d", leeway);
            goto ok;
        }
        goto err;
    }

ok:
    return VERIFY_SUCCESS;


err:
    return VERIFY_FAILURE;
}


bool get_token_payload(const std::string token, std::string& payload)
{
    try
    {
        auto decoded_token = jwt::decode<jwt::traits::nlohmann_json>(token);
        std::string header = decoded_token.get_header();
        LOG_INFO("%s", header.c_str());
        payload = decoded_token.get_payload();
        LOG_INFO("%s", payload.c_str());
    }
    catch (const std::exception &exc)
    {
        LOG_ERROR("Exception: %s", exc.what());
        goto err;
    }

    return true;

err:
    return false;
}

