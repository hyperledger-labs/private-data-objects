#!/bin/bash

# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

if [[ -z "${OAA_PATH}" ]]; then
    echo "OAA_PATH not set"
    exit -1
fi

CUR_SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

. ${OAA_PATH}/common/scripts/common_utils.sh
. ${CUR_SCRIPT_PATH}/tag_to_variable.sh
. ${CUR_SCRIPT_PATH}/simulated/a2e.sh
. ${CUR_SCRIPT_PATH}/epid/a2e.sh
. ${CUR_SCRIPT_PATH}/dcap/a2e.sh
. ${CUR_SCRIPT_PATH}/dcap-direct/a2e.sh

tag_to_variable "ATTESTATION_TYPE_TAG"
tag_to_variable "ATTESTATION_TAG"
tag_to_variable "EVIDENCE_TAG"
tag_to_variable "SIMULATED_TYPE_TAG"
tag_to_variable "EPID_LINKABLE_TYPE_TAG"
tag_to_variable "EPID_UNLINKABLE_TYPE_TAG"
tag_to_variable "DCAP_SGX_TYPE_TAG"
tag_to_variable "DCAP_DIRECT_SGX_TYPE_TAG"

###########################################################
# attestation_to_evidence
#   input:  attestation as parameter
#   output: EVIDENCE variable
#
# This is the main function for a2e conversion.
###########################################################
function attestation_to_evidence() {
    if [[ -z "$1" ]]; then
        die "no argument provided"
    fi

    say "Input Attestation: $1"

    ATTESTATION_TYPE=$(echo $1 | jq ".$ATTESTATION_TYPE_TAG" -r)
    ATTESTATION=$(echo $1 | jq ".$ATTESTATION_TAG" -r)

    case "$ATTESTATION_TYPE" in
        $SIMULATED_TYPE_TAG)
            simulated_to_evidence "$ATTESTATION"
            EVIDENCE=$SIMULATED_EVIDENCE
            ;;

        $EPID_LINKABLE_TYPE_TAG)
            ;&
        $EPID_UNLINKABLE_TYPE_TAG)
            b64quote_to_iasresponse "$ATTESTATION"
            iasresponse_to_evidence "$IAS_RESPONSE"
            EVIDENCE=$IAS_EVIDENCE
            ;;
        $DCAP_SGX_TYPE_TAG)
            b64quote_to_itaresponse "$ATTESTATION"
            itaresponse_to_evidence "$ITA_RESPONSE"
            EVIDENCE=$ITA_EVIDENCE
            ;;
        $DCAP_DIRECT_SGX_TYPE_TAG)
            b64quote_to_evidence "$ATTESTATION"
            EVIDENCE=$DCAP_EVIDENCE
            ;;
        *)
            die "error attestation type $ATTESTATION_TYPE"
            ;;
    esac

    #package evidence
    EVIDENCE=$(jq -c -n --arg attestation_type "$ATTESTATION_TYPE" --arg evidence "$EVIDENCE" '{'\"$ATTESTATION_TYPE_TAG\"': $attestation_type, '\"$EVIDENCE_TAG\"': $evidence}')

    say "Output Evidence: $EVIDENCE"
}

###########################################################
# Main (if script is directly called rather than included in other script)
#
# - expects attestation is sole command-line parameter
# - on success, return evidence on stdout
#   Note: evidence is terminated with newline, depending on use-case
#   this might have to be trimmed by consumer
#
###########################################################
(return 0 2>/dev/null) && sourced=1 || sourced=0
if [ $sourced -eq "0" ]; then # i'm directly executed and not sourced in other program
	function say() { # suppress normal output ...
		: 
	}
	attestation_to_evidence $1
	echo "${EVIDENCE}"
fi
