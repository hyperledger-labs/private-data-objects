/*
 * Copyright 2023 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

bool init_dcap(uint8_t* params, uint32_t params_length);

bool get_dcap_attestation(uint8_t* statement,
    uint32_t statement_length,
    std::string& b64attestation);

