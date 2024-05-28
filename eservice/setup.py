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

install_root_dir = os.environ.get('PDO_HOME', '/opt/pdo')
bin_dir = os.path.join(install_root_dir, "bin")
dat_dir = os.path.join(install_root_dir, "data")
etc_dir = os.path.join(install_root_dir, "etc")
log_dir = os.path.join(install_root_dir, "logs")
key_dir = os.path.join(install_root_dir, "keys")

data_files = [
    (bin_dir, [
        'bin/es-start.sh', 'bin/es-stop.sh', 'bin/es-status.sh',
        ]),
    (dat_dir, []),
    (etc_dir, []),
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
debug_flag_env = os.environ.get('PDO_DEBUG_BUILD', '1')
if debug_flag_env not in ['0', '1'] :
    print(f'error: PDO_DEBUG_BUILD must be 0 or 1, current value is {debug_flag_env}')
    sys.exit(2)
debug_flag = debug_flag_env == '1'

sgx_mode_env = os.environ.get('SGX_MODE', 'SIM').upper()
if sgx_mode_env not in ['SIM', 'HW'] :
    print(f'error: SGX_MODE value must be HW or SIM, current value is {sgx_mode_env}')
    sys.exit(2)
sgx_simulator_flag = sgx_mode_env == 'SIM'

module_path = 'pdo/eservice/enclave'
module_src_path = os.path.join(script_dir, module_path)

compile_args = [
    '-std=c++11',
    '-Wno-switch',
    '-Wno-unused-function',
    '-Wno-unused-variable',
]

# by default the extension class adds '-O2' to the compile
# flags, this lets us override since these are appended to
# the compilation switches
if debug_flag :
    compile_args += ['-g']

include_dirs = [
    module_src_path,
    os.path.join(script_dir, 'build', module_path),
    os.path.join(pdo_root_dir, 'common'),
    os.path.join(pdo_root_dir, 'common', 'crypto'),
    os.path.join(pdo_root_dir, 'common', 'state'),
    os.path.join(os.environ['SGX_SDK'],"include")
]

library_dirs = [
    os.path.join(pdo_root_dir, "common", "build"),
    os.path.join(os.environ['SGX_SDK'], 'lib64'),
    os.path.join(os.environ['SGX_SSL'], 'lib64'),
    os.path.join(os.environ['SGX_SSL'], 'lib64', 'release')
]

libraries = [
    'updo-common',
    'pdo-lmdb-block-store',
    'lmdb'
]

if sgx_simulator_flag :
    libraries += ['sgx_urts_sim', 'sgx_uae_service_sim']
else :
    libraries += ['sgx_urts', 'sgx_uae_service']

libraries += ['sgx_usgxssl']

module_files = [
    os.path.join(module_src_path, 'pdo_enclave_internal.i'),
    os.path.join(module_src_path, 'swig_utils.cpp'),
    os.path.join(script_dir, 'build', module_path, 'enclave_u.c'),
    os.path.join(module_src_path, 'enclave/ocall.cpp'),
    os.path.join(module_src_path, 'enclave/base.cpp'),
    os.path.join(module_src_path, 'enclave/contract.cpp'),
    os.path.join(module_src_path, 'enclave/signup.cpp'),
    os.path.join(module_src_path, 'enclave/enclave_queue.cpp'),
    os.path.join(module_src_path, 'enclave/enclave.cpp'),
    os.path.join(module_src_path, 'enclave_info.cpp'),
    os.path.join(module_src_path, 'signup_info.cpp'),
    os.path.join(module_src_path, 'contract.cpp'),
    os.path.join(module_src_path, 'block_store.cpp'),
]

compile_defs = [
    ('_UNTRUSTED_', 1),
    ('PDO_DEBUG_BUILD', 1 if debug_flag else 0),
    ('SGX_SIMULATOR', 1 if sgx_simulator_flag else 0),
]

compile_undefs = []

# When the debug flag (PDO_DEBUG_BUILD) is set, we set the EDEBUG define
# This ensures that the SGX SDK in sgx_urts.h sets the SGX_DEBUG_FLAG to 1.
# Otherwise the SDK sets it to 0.
if debug_flag :
    compile_defs += [('EDEBUG', 1)]
else :
    compile_undefs += ['EDEBUG']

swig_flags = ['-c++', '-threads']

enclave_module = Extension(
    'pdo.eservice.enclave._pdo_enclave_internal',
    module_files,
    swig_opts = swig_flags,
    extra_compile_args = compile_args,
    libraries = libraries,
    include_dirs = include_dirs,
    library_dirs = library_dirs,
    define_macros = compile_defs,
    undef_macros = compile_undefs,
    )

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
      ext_modules = [
          enclave_module
      ],
      data_files = data_files,
      entry_points = {
          'console_scripts': [
              'eservice = pdo.eservice.scripts.EServiceCLI:Main',
              'eservice-enclave-info = pdo.eservice.scripts.EServiceEnclaveInfoCLI:Main'
          ]
      }
)
