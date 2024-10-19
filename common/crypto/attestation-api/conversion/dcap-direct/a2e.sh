#!/bin/bash

# Copyright 2024 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -ex

CUR_SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
B64A_2_B64C=${CUR_SCRIPT_PATH}/b64attestation_to_b64collateral

. ${CUR_SCRIPT_PATH}/../tag_to_variable.sh



function b64quote_to_evidence() {
    QUOTE=$1
    COLLATERAL=$(${B64A_2_B64C} $QUOTE)
    UNTRUSTED_TIME_T=$(date +%s)
    tag_to_variable "ATTESTATION_TAG"
    tag_to_variable "COLLATERAL_TAG"
    tag_to_variable "UNTRUSTED_TIME_T_TAG"

    DCAP_EVIDENCE=$(jq -c -n --arg attestation "$QUOTE" --arg collateral "$COLLATERAL" --arg untrusted_time_t "$UNTRUSTED_TIME_T" '{'\"$ATTESTATION_TAG\"': $attestation, '\"$COLLATERAL_TAG\"': $collateral, '\"$UNTRUSTED_TIME_T_TAG\"': $untrusted_time_t}')
}
