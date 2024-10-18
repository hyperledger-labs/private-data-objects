/*
 * Copyright 2020 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */

test_verify_enclave.so
{
    global:
        g_global_data_sim;
        g_global_data;
        test_verify_enclave_entry;
    local:
        *;
};
