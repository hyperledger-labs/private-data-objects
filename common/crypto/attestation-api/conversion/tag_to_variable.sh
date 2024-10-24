#!/bin/bash

# Copyright 2024 Intel Corporation
#
# SPDX-License-Identifier: Apache-2.0

set -e

if [[ -z "${OAA_PATH}" ]]; then
    echo "OAA_PATH not set"
    exit -1
fi

CUR_SCRIPT_PATH="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

. ${CUR_SCRIPT_PATH}/define_to_variable.sh

###########################################################
# get_tag_make_variable
#   input:  tag string (e.g, "TAG_X") as parameter
#   output: tag string variable (e.g., TAG_X)
###########################################################
function tag_to_variable() {
    TAGS_PATH="${OAA_PATH}/include/attestation_tags.h"
    define_to_variable "$TAGS_PATH" "$1"
}

