/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

typedef enum
{
    VERIFY_SUCCESS,
    VERIFY_FAILURE
} verify_status_t;

bool get_ita_certificate(std::string& certificate);
verify_status_t verify_ita_token_signature(std::string token);
bool get_token_payload(std::string token, std::string& payload);

