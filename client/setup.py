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

# this should only be run with python3
import sys
if sys.version_info[0] < 3:
    print('ERROR: must run with python3')
    sys.exit(1)

from setuptools import setup, find_packages, Extension

script_dir = os.path.dirname(os.path.realpath(__file__))
pdo_root_dir = os.path.abspath(os.path.join(script_dir, '..'))

install_root_dir = os.environ.get('PDO_HOME', '/opt/pdo')
bin_dir = os.path.join(install_root_dir, "bin")
dat_dir = os.path.join(install_root_dir, "data")
etc_dir = os.path.join(install_root_dir, "etc")
log_dir = os.path.join(install_root_dir, "logs")
key_dir = os.path.join(install_root_dir, "keys")

data_files = [
    (bin_dir, [ 'bin/pdo-create.psh', 'bin/pdo-invoke.psh' ]),
    (etc_dir, [ 'etc/auction-test.toml', 'etc/sample_client.toml' ])
]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

setup(name='pdo_client',
      version=version,
      description='Client utilities for private contracts',
      author='Mic Bowman, Intel Labs',
      author_email='mic.bowman@intel.com',
      url='http://www.intel.com',
      packages = find_packages(),
      namespace_packages=['pdo'],
      install_requires = [
          'pyparsing',
          'toml',
      ],
      data_files = data_files,
      entry_points = {
          'console_scripts': [
              'pdo-shell = pdo.client.scripts.ShellCLI:Main',
              'pdo-eservicedb = pdo.client.scripts.EServiceDatabaseCLI:Main'
          ]
      }
)
