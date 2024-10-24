#!/bin/bash

# Copyright 2023 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -ex

CUR_SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
. ${CUR_SCRIPT_PATH}/../tag_to_variable.sh

function check_collateral_folder()
{
    if [[ -z "${COLLATERAL_FOLDER}" ]]; then
        echo "COLLATERAL_FOLDER not set for DCAP conversion"
        exit -1
    fi
}

###########################################################
# b64quote_to_iasresponse
#   input:  quote as parameter
#   output: ITA_RESPONSE variable
###########################################################
function b64quote_to_itaresponse() {
    check_collateral_folder

    tag_to_variable "QUOTE_TAG"

    #get api key
    API_KEY_FILEPATH="${COLLATERAL_FOLDER}/ita_api_key.txt"
    test -f ${API_KEY_FILEPATH} || die "no api key file ${API_KEY_FILEPATH}"
    API_KEY=$(cat $API_KEY_FILEPATH)

    #get verification report
    QUOTE=$1
    # contact IAS to get the verification report
    ITA_RESPONSE=$(curl -s -H "Accept: application/json" -H "Content-Type: application/json" -H "x-api-key:$API_KEY" -X POST -d '{"quote":"'$QUOTE'"}' https://api-poc-user1.project-amber-smas.com/appraisal/v1/attest )
}

###########################################################
# itaresponse_to_evidence
#   input:  ita response as parameter
#   output: ITA_EVIDENCE variable
###########################################################
function itaresponse_to_evidence() {
    tag_to_variable "ITA_TOKEN_TAG"
    ITA_RESPONSE="$1"
    ITA_TOKEN=$(echo $ITA_RESPONSE | jq ".token" -r)
    JSON_ITA_RESPONSE=$(jq -c -n --arg tok "$ITA_TOKEN" '{'\"$ITA_TOKEN_TAG\"': $tok}')
    #set output
    ITA_EVIDENCE=$JSON_ITA_RESPONSE
}
