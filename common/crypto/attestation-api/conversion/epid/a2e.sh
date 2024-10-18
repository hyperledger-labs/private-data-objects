#!/bin/bash

# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -ex

function check_collateral_folder()
{
    if [[ -z "${COLLATERAL_FOLDER}" ]]; then
        echo "COLLATERAL_FOLDER not set for EPID conversion"
        exit -1
    fi
}

###########################################################
# b64quote_to_iasresponse
#   input:  quote as parameter
#   output: IAS_RESPONSE variable
###########################################################
function b64quote_to_iasresponse() {
    check_collateral_folder

    #get api key
    API_KEY_FILEPATH="${COLLATERAL_FOLDER}/api_key.txt"
    test -f ${API_KEY_FILEPATH} || die "no api key file ${API_KEY_FILEPATH}"
    API_KEY=$(cat $API_KEY_FILEPATH)

    #get verification report
    QUOTE=$1
    # contact IAS to get the verification report
    IAS_RESPONSE=$(curl -s -H "Content-Type: application/json" -H "Ocp-Apim-Subscription-Key:$API_KEY" -X POST -d '{"isvEnclaveQuote":"'$QUOTE'"}' https://api.trustedservices.intel.com/sgx/dev/attestation/v4/report -i)
    # check status (as there may be multiple header, we rather check presence of relevant fields)
    echo "$IAS_RESPONSE" | grep "X-IASReport-Signature"           >/dev/null || die "IAS Response error"
    echo "$IAS_RESPONSE" | grep "X-IASReport-Signing-Certificate" >/dev/null || die "IAS Response error"
}

###########################################################
# iasresponse_to_evidence
#   input:  ias response as parameter
#   output: IAS_EVIDENCE variable
###########################################################
function iasresponse_to_evidence() {
    IAS_RESPONSE="$1"
    UNTRUSTED_TIME_T=$(date +%s)
    tag_to_variable "IAS_SIGNATURE_TAG"
    tag_to_variable "IAS_CERTIFICATES_TAG"
    tag_to_variable "IAS_REPORT_TAG"
    tag_to_variable "UNTRUSTED_TIME_T_TAG"

    #encode relevant info in json format
    IAS_SIGNATURE=$(echo "$IAS_RESPONSE" | grep -Po 'X-IASReport-Signature: \K[^ ]+' | tr -d '\r')
    IAS_CERTIFICATES=$(echo "$IAS_RESPONSE" | grep -Po 'X-IASReport-Signing-Certificate: \K[^ ]+')
    IAS_REPORT=$(echo "$IAS_RESPONSE" | grep -Po '{"id":[^ ]+')
    JSON_IAS_RESPONSE=$(jq -c -n --arg sig "$IAS_SIGNATURE" --arg cer "$IAS_CERTIFICATES" --arg rep "$IAS_REPORT" --arg untrusted_time_t "$UNTRUSTED_TIME_T" '{'\"$IAS_SIGNATURE_TAG\"': $sig, '\"$IAS_CERTIFICATES_TAG\"': $cer, '\"$IAS_REPORT_TAG\"': $rep, '\"$UNTRUSTED_TIME_T_TAG\"': $untrusted_time_t}')
    #set output
    IAS_EVIDENCE=$JSON_IAS_RESPONSE
}
