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

from setuptools import setup, find_packages

script_dir = os.path.dirname(os.path.realpath(__file__))
pdo_root_dir = os.path.abspath(os.path.join(script_dir, '..'))

# bdist_wheel will interpret this as a relative path
install_root_dir = '../../../opt/pdo'
bin_dir = os.path.join(install_root_dir, "bin")
etc_dir = os.path.join(install_root_dir, "etc")

data_files = [
    (bin_dir, [ 'bin/pdo-create.psh', 'bin/pdo-invoke.psh' ]),
    (etc_dir, [ 'etc/sample_client.toml' ])
]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
setup(name='pdo',
      version=version,
      description='Common and client library for private data objects',
      author='Hyperledger Labs PDO maintainers',
      url='https://github.com/hyperledger-labs/private-data-objects',
      packages=find_packages(),
      install_requires=[
          'pyparsing',
          'toml'
      ],
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
              'pdo-shell = pdo.client.scripts.ShellCLI:Main',
              'pdo-eservicedb = pdo.client.scripts.EServiceDatabaseCLI:Main'
          ]
      }
)
