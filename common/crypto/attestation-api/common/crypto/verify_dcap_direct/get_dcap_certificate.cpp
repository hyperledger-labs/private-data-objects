/*
 * Copyright 2024 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string>
#include "dcap-certificates.h"

bool get_dcap_certificate(std::string& certificate)
{
    certificate = std::string(dcap_ca_cert_pem);
    return true;
}
