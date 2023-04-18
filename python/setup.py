#!/usr/bin/env python
# Copyright 2018 Intel Corporation
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

import re

import os
import shutil
import subprocess

# this should only be run with python3
import sys
if sys.version_info[0] < 3:
    print('ERROR: must run with python3')
    sys.exit(1)

from setuptools import setup, find_packages, Extension

script_dir = os.path.dirname(os.path.realpath(__file__))
pdo_root_dir = os.path.abspath(os.path.join(script_dir, '..'))

# bdist_wheel will interpret this as a relative path
install_root_dir = '../../../opt/pdo'
bin_dir = os.path.join(install_root_dir, "bin")
dat_dir = os.path.join(install_root_dir, "data")
etc_dir = os.path.join(install_root_dir, "etc")
log_dir = os.path.join(install_root_dir, "logs")
key_dir = os.path.join(install_root_dir, "keys")

data_files = [
    (bin_dir, []),
    (etc_dir, [])
]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
setup(name='pdo-common',
      version=version,
      description='Common and client library for private objects',
      author='Hyperledger Labs PDO maintainers',
      url='https://github.com/hyperledger-labs/private-data-objects',
      packages=find_packages(),
      install_requires=[],
      python_requires='>3.5',
      data_files=data_files,
      package_data={'pdo.common': ['_crypto.so', '_key_value_swig.so']},
      entry_points = {
          'console_scripts': [
              'pdo-configure-services = pdo.scripts.ConfigureCLI:configure_services',
              'pdo-configure-users = pdo.scripts.ConfigureCLI:configure_users',
              'pdo-configure-ccf = pdo.scripts.ConfigureCLI:configure_ccf',
              'pdo-test-contract = pdo.test.contract:Main',
              'pdo-test-request = pdo.test.request:Main',
              'pdo-test-storage = pdo.test.storage:Main',
          ]
      }
)
