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
import subprocess

# this should only be run with python3
import sys
if sys.version_info[0] < 3:
    print('ERROR: must run with python3')
    sys.exit(1)

from setuptools import setup, find_packages

script_dir = os.path.dirname(os.path.realpath(__file__))
pdo_root_dir = os.path.abspath(os.path.join(script_dir, '..'))

version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

setup(
    name='pdo_sawtooth_tp',
    version=version,
    description='Sawtooth Transaction Processor and its CLI for PDO',
    author='Hyperledger Labs PDO',
    packages=find_packages(),
    install_requires=[],
    data_files=[],
    # namespace_packages=['pdo'],
    entry_points = {
        'console_scripts': [
            'pdo-cli = pdo_cli.pdo_cli_main:main_wrapper',
            'pdo-tp = transaction_processor.main:main'
        ]
    }
)
