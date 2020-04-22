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
# set up the contract enclave
# -----------------------------------------------------------------
compile_args = ['-std=c++11']

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


include_dirs = [
    os.path.join(os.environ['SGX_SDK'], "include"),
    os.path.join(pdo_root_dir, 'common'),
    os.path.join(pdo_root_dir, 'common/crypto'),
    os.path.join(pdo_root_dir, 'common/packages/base64')
] + openssl_include_dirs

libraries = ['updo-common', 'updo-crypto'] + openssl_libs

library_dirs = [
    os.path.join(pdo_root_dir, 'common/build')
] + openssl_lib_dirs

modulefiles = [
    "pdo/common/crypto.i"
]

cryptomod = Extension(
    'pdo.common._crypto',
    modulefiles,
    swig_opts=['-c++'] + openssl_cflags + ['-I%s' % i for i in include_dirs],
    extra_compile_args=compile_args,
    include_dirs=include_dirs,
    library_dirs=library_dirs,
    libraries=libraries)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
version = subprocess.check_output(
    os.path.join(pdo_root_dir, 'bin/get_version')).decode('ascii').strip()

setup(name='pdo_common_library',
      version=version,
      description='Common library for private objects',
      author='Intel Labs',
      packages=find_packages(),
      install_requires=[],
      data_files=data_files,
      namespace_packages=['pdo'],
      ext_modules=[cryptomod],
      entry_points = {
          'console_scripts': [
              'pdo-test-contract = pdo.test.contract:Main',
              'pdo-test-request = pdo.test.request:Main',
              'pdo-test-storage = pdo.test.storage:Main',
          ]
      }
)

if "clean" in sys.argv and "--all" in sys.argv:
    directory = os.path.dirname(os.path.realpath(__file__))
    for root, directories, files in os.walk(directory):
        if root.endswith('__pycache__'):
            shutil.rmtree(os.path.join(directory, root), ignore_errors=True)

    extrafiles = [
        os.path.join(directory, "pdo", "common", "crypto.py"),
        os.path.join(directory, "pdo", "common", "crypto_wrap.cpp")
    ]

    for filename in extrafiles:
        if os.path.exists(os.path.join(directory, filename)):
            os.remove(os.path.join(directory, filename))

    shutil.rmtree(os.path.join(directory, "pdo_common_library.egg-info"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "deps"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "dist"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "build"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "htmlcov"), ignore_errors=True)
    shutil.rmtree(os.path.join(directory, "deb_dist"), ignore_errors=True)
