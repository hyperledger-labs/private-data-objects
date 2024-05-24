#!/usr/bin/env python

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

import os
import sys
import subprocess
import warnings

# this should only be run with python3
import sys
if sys.version_info[0] < 3:
    print('ERROR: must run with python3')
    sys.exit(1)

from setuptools import setup, find_packages, find_namespace_packages

# -----------------------------------------------------------------
# Versions are tied to tags on the repository; to compute correctly
# it is necessary to be within the repository itself hence the need
# to set the cwd for the bin/get_version command.
# -----------------------------------------------------------------
root_dir = os.environ.get('PDO_SOURCE_ROOT')
if root_dir is None :
    warnings.warn('PDO_SOURCE_ROOT not set')
    sys.exit(-1)

try :
    pdo_version = subprocess.check_output('bin/get_version', cwd=root_dir).decode('ascii').strip()
except Exception as e :
    warnings.warn('Failed to get pdo version, using the default')
    pdo_version = '0.0.0'

## -----------------------------------------------------------------
## -----------------------------------------------------------------
setup(
    name='pdo_ccf_ledger',
    version=pdo_version,
    description='Support functions for PDO integration with CCF ledger',
    author='Mic Bowman, Intel Labs',
    author_email='mic.bowman@intel.com',
    url='http://www.intel.com',
    package_dir = {
        'pdo' : 'pdo',
    },
    packages = [
        'pdo',
        'pdo.ledgers',
        'pdo.ledgers.ccf',
        'pdo.ledgers.ccf.scripts',
    ],
    include_package_data=True,
    install_requires = [
        'ccf==1.0.19',
    ],
    entry_points = {
        'console_scripts' : [
            'ccf_configure_network=pdo.ledgers.ccf.scripts.configure_ccf_network:Main',
            'ccf_ping_test=pdo.ledgers.ccf.scripts.ping_test:Main',
            'ccf_generate_ledger_authority=pdo.ledgers.ccf.scripts.generate_ledger_authority:Main',
            'ccf_fetch_ledger_authority=pdo.ledgers.ccf.scripts.fetch_ledger_authority:Main',
            'ccf_set_attestation_check_flag=pdo.ledgers.ccf.scripts.set_attestation_check_flag:Main',
            'ccf_set_expected_sgx_measurements=pdo.ledgers.ccf.scripts.set_expected_sgx_measurements:Main',
        ]
    }
)
