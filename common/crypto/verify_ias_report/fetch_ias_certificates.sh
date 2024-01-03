#!/bin/bash
# Copyright 2023 Intel Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# This script sets up the IAS root certificate for inclusing in the
# verification module.
#
# Two parameters:
# $1 -- the URL where the IAS certificate can be retrieved
# $2 -- the file where the certificate should be written

# -----------------------------------------------------------------
# -----------------------------------------------------------------
source ${PDO_SOURCE_ROOT}/bin/lib/common.sh

IAS_CERTIFICATE_URL=$1

# -----------------------------------------------------------------
# set up the temporary files
# -----------------------------------------------------------------
SAVE_FILE=$(mktemp /tmp/pdo-ias-certificate.XXXXXXXXX)
STRING_FILE=$(mktemp /tmp/pdo-ias-certificate-string.XXXXXXXXX)

function cleanup {
    rm -f ${SAVE_FILE} ${STRING_FILE}
}

trap 'echo "**ERROR - line $LINENO**"; cleanup; exit 1' HUP INT QUIT PIPE TERM ERR

# If there is no requirement for HW support, then we don't need
# a valid certificate; just generate a dummy string
if [ "${SGX_MODE}" != "HW" ]; then
    echo 'R"IASCERT(' > ${STRING_FILE}
    echo 'NO CERTIFICATE REQUIRED' >> ${STRING_FILE}
    echo ')IASCERT"' >> ${STRING_FILE}

    try mv ${STRING_FILE} $2
fi

# -----------------------------------------------------------------
# get the certificate and format it as needed
# -----------------------------------------------------------------

# This is a small hack to make the script work for people
# who would otherwise attempt to retrieve the certficiates
# without a proxy server
if [ "${PDO_FORCE_IAS_PROXY}" == "true" ]; then
    try curl --noproxy '' --retry 3 --max-time 10 -sL --output ${SAVE_FILE} ${IAS_CERTIFICATE_URL}
else
    try curl --retry 3 --max-time 10 -sL --output ${SAVE_FILE} ${IAS_CERTIFICATE_URL}
fi

echo 'R"IASCERT(' > ${STRING_FILE}
cat ${SAVE_FILE} >> ${STRING_FILE}
echo ')IASCERT"' >> ${STRING_FILE}

try mv ${STRING_FILE} $2
