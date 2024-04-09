#!/bin/bash

# Copyright 2024 Intel Corporation
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


# This script prepares the IAS certificate that is necessary for build in HW mode.
# The certificate is downloaded in the repo before the docker build, thus becoming
# part of the "repository". The docker build will then clone the repository in the
# container. As the certificate will be avialable, the build inside docker will not
# attempt to retrieve it.

if [ $# != 2 ] ; then
    echo "$(basename $0 '$<PDO source repo path> <PDO dest repo path')"
    echo "PDO source and dest repo paths are required"
    exit 1
fi

PDO_SOURCE_ROOT=$1
PDO_DEST_ROOT=$2

CERTIFICATES_REL_PATH=common/crypto/verify_ias_report/ias-certificates.txt

source ${PDO_SOURCE_ROOT}/bin/lib/common.sh

# extract the IAS url from the cmake file, since it's already defined there
IAS_CERT_URL=$(awk -F"[\"\"]" '/IAS_CERTIFICATE_URL/{print $2}' ${PDO_SOURCE_ROOT}/build/cmake/SGX.cmake)

cd ${PDO_SOURCE_ROOT}/$(dirname ${CERTIFICATES_REL_PATH})
yell Preparing IAS certificates for docker build from url ${IAS_CERT_URL}
if [ "${PDO_FORCE_IAS_PROXY}" == "true" ]; then
    NO_PROXY='' no_proxy='' PDO_SOURCE_ROOT=${PDO_SOURCE_ROOT} SGX_MODE=HW \
        try ./fetch_ias_certificates.sh "${IAS_CERT_URL}" ${PDO_DEST_ROOT}/${CERTIFICATES_REL_PATH}
else
    PDO_SOURCE_ROOT=${PDO_SOURCE_ROOT} SGX_MODE=HW \
        try ./fetch_ias_certificates.sh "${IAS_CERT_URL}" ${PDO_DEST_ROOT}/${CERTIFICATES_REL_PATH}
fi

exit 0

