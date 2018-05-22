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
pdo_root_dir = os.path.realpath(os.path.join(script_dir, '..'))

install_root_dir = os.environ.get('CONTRACTHOME', '/opt/pdo')
bin_dir = os.path.join(install_root_dir, "bin")
dat_dir = os.path.join(install_root_dir, "data")
etc_dir = os.path.join(install_root_dir, "etc")
log_dir = os.path.join(install_root_dir, "logs")
key_dir = os.path.join(install_root_dir, "keys")

data_files = [
    (bin_dir, ['bin/es-start.sh', 'bin/es-stop.sh', 'bin/es-status.sh']),
    (dat_dir, []),
    (etc_dir, [ 'etc/sample_eservice.toml' ]),
    (log_dir, []),
    (key_dir, []),
    ('lib', [ os.path.join(script_dir, 'deps/bin/libpdo-enclave.signed.so')])
]

ext_deps = [
    'deps/bin/libpdo-enclave.signed.so'
]

## -----------------------------------------------------------------
## set up the contract enclave
## -----------------------------------------------------------------
module_path = 'pdo/eservice/enclave'
module_src_path = os.path.join(script_dir, module_path)

compile_args = [
    '-std=c++11',
    '-g',
    '-DSGX_SIMULATOR=1',
    '-Wno-switch',
    '-Wno-unused-function',
    '-Wno-unused-variable',
    '-Wno-strict-prototypes',
]

include_dirs = [
    module_src_path,
    os.path.join(script_dir, 'build', module_path),
    os.path.join(pdo_root_dir, 'common'),
    os.path.join(pdo_root_dir, 'common', 'crypto'),
    os.path.join(os.environ['SGX_SDK'],"include")
]

library_dirs = [
    os.path.join(pdo_root_dir, "common", "build"),
    os.path.join(os.environ['SGX_SDK'], 'lib64')
]

libraries = [
    'updo-common',
    'sgx_urts_sim',
    'sgx_uae_service_sim'
]

module_files = [
    os.path.join(module_src_path, 'pdo_enclave_internal.i'),
    os.path.join(module_src_path, 'log.cpp'),
    os.path.join(module_src_path, 'swig_utils.cpp'),
    os.path.join(script_dir, 'build', module_path, 'enclave_u.c'),
    os.path.join(module_src_path, 'enclave/ocall.cpp'),
    os.path.join(module_src_path, 'enclave/base.cpp'),
    os.path.join(module_src_path, 'enclave/contract.cpp'),
    os.path.join(module_src_path, 'enclave/signup.cpp'),
    os.path.join(module_src_path, 'enclave/enclave.cpp'),
    os.path.join(module_src_path, 'enclave_info.cpp'),
    os.path.join(module_src_path, 'signup_info.cpp'),
    os.path.join(module_src_path, 'contract.cpp')
]

enclave_module = Extension(
    'pdo.eservice.enclave._pdo_enclave_internal',
    module_files,
    swig_opts = ['-c++'],
    extra_compile_args = compile_args,
    libraries = libraries,
    include_dirs = include_dirs,
    library_dirs = library_dirs)

## -----------------------------------------------------------------
## -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

setup(name='pdo_eservice',
      version = version,
      description = 'Private Data Objects SGX Contract Enclave',
      author = 'Hyperledger',
      url = 'http://www.intel.com',
      packages = find_packages(exclude='./eservice'),
      namespace_packages=['pdo'],
      install_requires = [
          'colorlog',
          'requests',
          'toml',
          'twisted'
          ],
      ext_modules = [
          enclave_module
      ],
      data_files = data_files,
      entry_points = {
          'console_scripts': [
              'eservice = pdo.eservice.scripts.EServiceCLI:Main'
          ]
      }
)
