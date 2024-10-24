# Copyright 2020 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

# *** README ***
# This script is meant to run as part of the build.
# The script is transferred to the folder where other test binaries will be located,
# and it will orchestrate the test.
# Orchestration involves: preparing input file for init_attestation,
# calling get_attestation, calling attestation_to_evidence, calling verify_evidence.

set -e

if [[ -z "${OAA_PATH}" ]]; then
    echo "OAA_PATH not set"
    exit -1
fi

. ${OAA_PATH}/common/scripts/common_utils.sh
. ${OAA_PATH}/conversion/tag_to_variable.sh

DEFINES_FILEPATH="${OAA_PATH}/test/common/test-defines.h"
TAGS_FILEPATH="${OAA_PATH}/include/attestation_tags.h"


function init_environment()
{
    . ../conversion/attestation_to_evidence.sh
    . ../conversion/define_to_variable.sh
    . ../conversion/enclave_to_mrenclave.sh
}

function remove_artifacts()
{
    rm -rf *.txt
}

function orchestrate()
{
    #get attestation
    ./get_attestation_app
    define_to_variable "${DEFINES_FILEPATH}" "GET_ATTESTATION_OUTPUT"
    [ -f ${GET_ATTESTATION_OUTPUT} ] || die "no output from get_attestation"

    #translate attestation (note: attestation_to_evidence defines the EVIDENCE variable)
    ATTESTATION=$(cat ${GET_ATTESTATION_OUTPUT})
    attestation_to_evidence "${ATTESTATION}"

    define_to_variable "${DEFINES_FILEPATH}" "EVIDENCE_FILE"
    echo ${EVIDENCE} > ${EVIDENCE_FILE}

    #verify evidence
    ./verify_evidence_app

    #verify evidence in enclave
    ./verify_evidence_app_enclave
}

function check_collateral_epid()
{
    if [[ -z "${COLLATERAL_FOLDER}" ]]; then
        echo "COLLATERAL_FOLDER for EPID not set"
        exit -1
    fi

    SPID_TYPE_FILEPATH="${COLLATERAL_FOLDER}/spid_type.txt"
    test -f ${SPID_TYPE_FILEPATH} || die "no spid type file ${SPID_TYPE_FILEPATH}"

    SPID_FILEPATH="${COLLATERAL_FOLDER}/spid.txt"
    test -f ${SPID_FILEPATH} || die "no spid file ${SPID_FILEPATH}"
}

function epid_test()
{
    say "Testing EPID SGX attestations"

    #check collateral
    check_collateral_epid
    init_environment

    #prepare input
    remove_artifacts
    define_to_variable "${DEFINES_FILEPATH}" "CODE_ID_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT"
    define_to_variable "${DEFINES_FILEPATH}" "INIT_DATA_INPUT"

    define_to_variable "${DEFINES_FILEPATH}" "UNSIGNED_ENCLAVE_FILENAME"
    enclave_to_mrenclave ${UNSIGNED_ENCLAVE_FILENAME} test_enclave.config.xml
    echo -n "$MRENCLAVE" > ${CODE_ID_FILE}
    echo -n ${STATEMENT} > ${STATEMENT_FILE}

    #get spid type
    SPID_TYPE=$(cat $SPID_TYPE_FILEPATH)

    #get spid
    SPID=$(cat $SPID_FILEPATH)

    define_to_variable "${TAGS_FILEPATH}" "SPID_TAG"
    define_to_variable "${TAGS_FILEPATH}" "SIG_RL_TAG"
    echo -n "{\"${ATTESTATION_TYPE_TAG}\": \"$SPID_TYPE\", \"${SPID_TAG}\": \"$SPID\", \"${SIG_RL_TAG}\":\"\"}" > ${INIT_DATA_INPUT}

    #run attestation generation/conversion/verification tests
    orchestrate

    say "Test success"
}

function check_collateral_dcap()
{
    if [[ -z "${COLLATERAL_FOLDER}" ]]; then
        echo "COLLATERAL_FOLDER for DCAP not set"
        exit -1
    fi

    ATTESTATION_TYPE_FILEPATH="${COLLATERAL_FOLDER}/attestation_type.txt"
    test -f ${ATTESTATION_TYPE_FILEPATH} || die "no attestation type file ${ATTESTATION_TYPE_FILEPATH}"

    API_KEY_FILEPATH="${COLLATERAL_FOLDER}/ita_api_key.txt"
    test -f ${API_KEY_FILEPATH} || die "no api key file ${API_KEY_FILEPATH}"
}

function dcap_test()
{
    say "Testing DCAP SGX attestations"

    #check collateral
    check_collateral_dcap
    init_environment

    #prepare input
    remove_artifacts
    define_to_variable "${DEFINES_FILEPATH}" "CODE_ID_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT"
    define_to_variable "${DEFINES_FILEPATH}" "INIT_DATA_INPUT"

    define_to_variable "${DEFINES_FILEPATH}" "UNSIGNED_ENCLAVE_FILENAME"
    enclave_to_mrenclave ${UNSIGNED_ENCLAVE_FILENAME} test_enclave.config.xml
    echo -n "$MRENCLAVE" > ${CODE_ID_FILE}
    echo -n ${STATEMENT} > ${STATEMENT_FILE}

    #get attestation type
    ATTESTATION_TYPE=$(cat $ATTESTATION_TYPE_FILEPATH)

    echo -n "{\"${ATTESTATION_TYPE_TAG}\": \"$ATTESTATION_TYPE\"}" > ${INIT_DATA_INPUT}

    #run attestation generation/conversion/verification tests
    orchestrate

    say "Test success"
}

function dcap_direct_test()
{
    say "Testing DCAP-DIRECT SGX attestations"

    init_environment

    #prepare input
    remove_artifacts
    define_to_variable "${DEFINES_FILEPATH}" "CODE_ID_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT"
    define_to_variable "${DEFINES_FILEPATH}" "INIT_DATA_INPUT"

    define_to_variable "${DEFINES_FILEPATH}" "UNSIGNED_ENCLAVE_FILENAME"
    enclave_to_mrenclave ${UNSIGNED_ENCLAVE_FILENAME} test_enclave.config.xml
    echo -n "$MRENCLAVE" > ${CODE_ID_FILE}
    echo -n ${STATEMENT} > ${STATEMENT_FILE}

    #get attestation type
    tag_to_variable "DCAP_DIRECT_SGX_TYPE_TAG"
    ATTESTATION_TYPE="$DCAP_DIRECT_SGX_TYPE_TAG"

    echo -n "{\"${ATTESTATION_TYPE_TAG}\": \"$ATTESTATION_TYPE\"}" > ${INIT_DATA_INPUT}

    #run attestation generation/conversion/verification tests
    orchestrate

    say "Test success"
}


function simulated_test()
{
    say "Testing simulated attestation"
    init_environment

    #prepare input
    remove_artifacts
    define_to_variable "${DEFINES_FILEPATH}" "CODE_ID_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT_FILE"
    define_to_variable "${DEFINES_FILEPATH}" "STATEMENT"
    define_to_variable "${DEFINES_FILEPATH}" "INIT_DATA_INPUT"

    define_to_variable "${TAGS_FILEPATH}" "ATTESTATION_TYPE_TAG"
    define_to_variable "${TAGS_FILEPATH}" "SIMULATED_TYPE_TAG"

    echo -n "this is ignored" > ${CODE_ID_FILE}
    echo -n "also ignored" > ${STATEMENT_FILE}
    echo -n "{\"${ATTESTATION_TYPE_TAG}\": \"${SIMULATED_TYPE_TAG}\"}" > ${INIT_DATA_INPUT}

    #run attestation generation/conversion/verification tests
    orchestrate

    say "Test success"

}

simulated_test

#######################################
# hw mode test
#######################################
if [[ ${SGX_MODE} == "HW" ]]; then

    if [[ ! -z "${SKIP_TEST_EPID+x}" ]]; then
        say "Skipping EPID attestation test"
    else
        say "Testing HW-mode EPID attestation"
        init_environment
        epid_test
    fi

    if [[ ! -z "${SKIP_TEST_DCAP_DIRECT+x}" ]]; then
        say "Skipping DCAP-DIRECT attestation test"
    else
        say "Testing HW-mode DCAP-DIRECT attestation"
        init_environment
        dcap_direct_test
    fi

    if [[ ! -z "${SKIP_TEST_DCAP+x}" ]]; then
        say "Skipping DCAP attestation test"
    else
        say "Testing HW-mode DCAP attestation"
        init_environment
        dcap_test
    fi

else
    say "Skipping actual attestation test"
fi

say "Test successful."
exit 0
