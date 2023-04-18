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

import os
import sys
import subprocess

from setuptools import setup, find_packages

script_dir = os.path.dirname(os.path.realpath(__file__))
pdo_root_dir = os.path.realpath(os.path.join(script_dir, '..'))

# bdist_wheel will interpret this as a relative path
install_root_dir = '../../../opt/pdo'
bin_dir = os.path.join(install_root_dir, "bin")
dat_dir = os.path.join(install_root_dir, "data")
etc_dir = os.path.join(install_root_dir, "etc")
log_dir = os.path.join(install_root_dir, "logs")
key_dir = os.path.join(install_root_dir, "keys")

data_files = [
    (bin_dir, [
        'bin/ss-start.sh', 'bin/ss-stop.sh', 'bin/ss-status.sh',
        ]),
    (dat_dir, []),
    (etc_dir, [ 'etc/sample_sservice.toml' ]),
    (log_dir, []),
    (key_dir, []),
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

setup(name='pdo-sservice',
      version = version,
      description = 'Private Data Objects Storage Service',
      author = 'Hyperledger Labs PDO maintainers',
      url = 'https://github.com/hyperledger-labs/private-data-objects',
      packages = find_packages(),
      install_requires = [
          'colorlog',
          'lmdb',
          'requests',
          'toml',
          'twisted',
          'pdo-common'
          ],
      data_files = data_files,
      entry_points = {
          'console_scripts': [
              'sservice = pdo.sservice.scripts.SServiceCLI:Main',
          ]
      }
)
