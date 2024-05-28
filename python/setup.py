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

install_root_dir = os.environ.get('PDO_HOME', '/opt/pdo')
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
# set up common flags
#
# note that setuptools does not make it easy to pass custom command
# line parameters so we have to use environment variables
# -----------------------------------------------------------------
debug_flag = int(os.environ.get('PDO_DEBUG_BUILD', 1))
if debug_flag :
    print("Build debug")

client_only_flag = int(os.environ.get('BUILD_CLIENT', 0))
if client_only_flag :
    print("Build client")

compile_args = [
    '-std=c++11',
    '-Wno-switch',
    '-Wno-unused-function',
    '-Wno-unused-variable',
    '-D_UNTRUSTED_=1',
]

if debug_flag :
    compile_args += ['-g']

swig_flags = ['-c++', '-threads']

if client_only_flag :
    common_libs = [
        'cpdo-common',
        'cpdo-crypto'
    ]
else :
    common_libs = [
        'updo-common',
        'updo-crypto',
    ]

compile_defs = [
    ('_UNTRUSTED_', 1),
    ('PDO_DEBUG_BUILD', debug_flag),
]

if client_only_flag :
    compile_defs += [ ('_CLIENT_ONLY_', 1) ]


# -----------------------------------------------------------------
# set up the crypto module
# -----------------------------------------------------------------

# openssl related stuff
# make sure we have recent enough version
subprocess.run(['pkg-config', 'openssl', '--atleast-version=1.1.0g']).check_returncode()
openssl_cflags = subprocess.check_output(['pkg-config', 'openssl', '--cflags']).decode('ascii').strip().split()
openssl_include_dirs = list(
    filter(None, re.split('\s*-I', subprocess.check_output(['pkg-config', 'openssl', '--cflags-only-I']).decode('ascii').strip())))
openssl_libs = list(
    filter(None, re.split('\s*-l', subprocess.check_output(['pkg-config', 'openssl', '--libs-only-l']).decode('ascii').strip())))
openssl_lib_dirs = list(
    filter(None, re.split('\s*-L', subprocess.check_output(['pkg-config', 'openssl', '--libs-only-L']).decode('ascii').strip())))

crypto_module_files = [
    "pdo/common/crypto.i"
]

crypto_include_dirs = [
    os.path.join(pdo_root_dir, 'common'),
    os.path.join(pdo_root_dir, 'common/crypto'),
    os.path.join(pdo_root_dir, 'common/state'),
    os.path.join(pdo_root_dir, 'common/packages/base64'),
] + openssl_include_dirs

if not client_only_flag :
    crypto_include_dirs += [ os.path.join(os.environ['SGX_SDK'], "include") ]

crypto_libraries = common_libs + openssl_libs

crypto_library_dirs = [
    os.path.join(pdo_root_dir, "common", "build"),
] + openssl_lib_dirs

crypto_module = Extension(
    name = 'pdo.common._crypto',
    sources = crypto_module_files,
    swig_opts = swig_flags + openssl_cflags + ['-I%s' % i for i in crypto_include_dirs],
    extra_compile_args = compile_args,
    include_dirs = crypto_include_dirs,
    library_dirs = crypto_library_dirs,
    libraries = crypto_libraries,
    define_macros = compile_defs,
    language = 'c++',
    )

# -----------------------------------------------------------------
# -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

# -----------------------------------------------------------------
# set up the key value module
# -----------------------------------------------------------------
key_value_module_files = [
    os.path.join('pdo/common/key_value_swig', 'key_value_swig.i'),
    os.path.join('pdo/common/key_value_swig', 'block_store.cpp'),
    os.path.join('pdo/common/key_value_swig', 'key_value.cpp'),
    os.path.join('pdo/common/key_value_swig', 'swig_utils.cpp'),
    os.path.join(pdo_root_dir, 'common','c11_support.cpp'),
]

key_value_include_dirs = [
    os.path.join(pdo_root_dir, 'common'),
    os.path.join(pdo_root_dir, 'common/crypto'),
    os.path.join(pdo_root_dir, 'common/state'),
]

if not client_only_flag :
    key_value_include_dirs += [ os.path.join(os.environ['SGX_SDK'], "include") ]

key_value_libraries = common_libs + [ 'pdo-lmdb-block-store', 'lmdb' ] + openssl_libs

key_value_library_dirs = [
    os.path.join(pdo_root_dir, "common", "build"),
]

key_value_module = Extension(
    name = 'pdo.common.key_value_swig._key_value_swig',
    sources = key_value_module_files,
    swig_opts = swig_flags,
    extra_compile_args = compile_args,
    include_dirs = key_value_include_dirs,
    library_dirs = key_value_library_dirs,
    libraries = key_value_libraries,
    define_macros = compile_defs,
    language = 'c++',
    )

# -----------------------------------------------------------------
# -----------------------------------------------------------------
setup(name='pdo_common_library',
      version=version,
      description='Common library for private objects',
      author='Intel Labs',
      packages=find_packages(),
      install_requires=[],
      data_files=data_files,
      namespace_packages=['pdo'],
      ext_modules=[crypto_module, key_value_module],
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
