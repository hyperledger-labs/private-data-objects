#!/usr/bin/env python

# Copyright 2023 Intel Corporation
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

import argparse
import os
import re
import shutil
import toml

from pdo.common.keys import ServiceKeys
from pdo.common.config import parse_configuration_file, build_configuration_map

config_map = {}

site_information = {
    'EnclaveService' : [],
    'StorageService' : [],
    'ProvisioningService' : []
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def generate_service_keys(keyfile) :
    service_key = ServiceKeys.create_service_keys()
    service_key.save_to_file(keyfile)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def add_service_to_site(service, node, config) :
    global site_information

    service_url = "http://{}:{}".format(config[service]['Host'], config[service]['HttpPort'])
    service_name = "{}/{}".format(config[service]['Host'], config[service]['Identity'])

    site_information[service].append(
        {
            'URL' : service_url,
            'Names' : [ service_name ]
        }
    )

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def expand_helper(options, file_name) :
    filename = os.path.join(options.template_directory, file_name)
    config = parse_configuration_file(filename, config_map)

    filename = os.path.join(options.output_directory, 'etc', file_name)
    with open(filename, 'w') as outfile:
        toml.dump(config, outfile)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def expand_service(options, file_base, service, n) :
    node = file_base + str(n)
    node_map = config_map.copy()

    node_map['identity'] = node
    node_map['_count_'] = n

    filename = os.path.join(options.template_directory, file_base + '.toml')
    config = parse_configuration_file(filename, node_map)

    filename = os.path.join(options.output_directory, 'etc', node + '.toml')
    with open(filename, 'w') as outfile:
        toml.dump(config, outfile)

    generate_service_keys(os.path.join(options.output_directory, 'keys', node))
    add_service_to_site(service, node, config)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def configure_services() :
    parser = argparse.ArgumentParser(description='Script to generate service configuration files from a template')

    parser.add_argument(
        '-c', '--count',
        help='Number of service instances to configure in the format eservice, sservice, pservice',
        default=[5, 5, 5], nargs=3, type=int)

    parser.add_argument(
        '-o', '--output-directory',
        help='Name of the directory where generated configuration files are written',
        default='etc')

    parser.add_argument(
        '-t', '--template-directory',
        help='Directory in which the template configuration will be found',
        default='etc/templates')

    parser.add_argument(
        '--set',
        help='Specify arbitrary configuration options',
        nargs=2, action='append', default=[])

    options = parser.parse_args()

    global config_map
    config_map = build_configuration_map(**dict(options.set))

    if options.set :
        for (k, v) in options.set : config_map[k] = v

    # Set up the directories
    if not os.path.exists(options.output_directory) :
        os.makedirs(options.output_directory)
    if not os.path.exists(os.path.join(options.output_directory,'etc')) :
        os.makedirs(os.path.join(options.output_directory,'etc'))
    if not os.path.exists(os.path.join(options.output_directory,'keys')) :
        os.makedirs(os.path.join(options.output_directory,'keys'))

    # Generate EService configuration files and keys
    for n in range(1, options.count[0]+1) :
        expand_service(options, 'eservice', 'EnclaveService', n)

    # Generate SService configuration files and keys
    for n in range(1, options.count[1]+1) :
        expand_service(options, 'sservice', 'StorageService', n)

    # Generate PService configuration files and keys
    for n in range(1, options.count[2]+1) :
        expand_service(options, 'pservice', 'ProvisioningService', n)

    filename = os.path.join(options.output_directory, 'etc', 'site.toml')
    with open(filename, 'w') as outfile:
        toml.dump(site_information, outfile)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def configure_users() :
    parser = argparse.ArgumentParser(description='Script to generate configuration files from a template')

    parser.add_argument(
        '-b', '--key-base',
        help='Base name for the user keys that will be created',
        default='user', type=str)

    parser.add_argument(
        '-c', '--key-count',
        help='Number of user keys to create',
        default=0, type=int)

    parser.add_argument(
        '--host',
        help='Name of the default host for accessing services',
        default=os.environ.get('PDO_HOSTNAME', os.environ.get("HOSTNAME", "localhost")))

    parser.add_argument(
        '-n', '--key-names',
        help='List of key names to generate',
        default=[], nargs='+', type=str)

    parser.add_argument(
        '-o', '--output-directory',
        help='Name of the directory where generated configuration files are written',
        default='etc')

    parser.add_argument(
        '-t', '--template-directory',
        help='Directory in which the template configuration will be found',
        default='etc/templates')

    parser.add_argument(
        '--set',
        help='Specify arbitrary configuration options',
        nargs=2, action='append', default=[])

    options = parser.parse_args()

    global config_map
    config_map = build_configuration_map(**dict(options.set))

    if options.set :
        for (k, v) in options.set : config_map[k] = v

    # Set up the directories
    if not os.path.exists(options.output_directory) :
        os.makedirs(options.output_directory)
    if not os.path.exists(os.path.join(options.output_directory,'etc')) :
        os.makedirs(os.path.join(options.output_directory,'etc'))
    if not os.path.exists(os.path.join(options.output_directory,'keys')) :
        os.makedirs(os.path.join(options.output_directory,'keys'))

    # Generate enclave configuration file
    expand_helper(options, 'pcontract.toml')

    # Generate the keys
    for u in range(1, options.key_count+1) :
        filename = os.path.join(options.output_directory, 'keys', '{}{}'.format(options.key_base, u))
        generate_service_keys(filename)

    for u in options.key_names :
        filename = os.path.join(options.output_directory, 'keys', u)
        generate_service_keys(filename)

    # Generate the site.psh

    # This will reproduce the current method of creating site.psh but
    # this will need to be rethought in the future. Site.psh is really
    # useful for configuring the test setup, but not representative of
    # the configuration needed for a multi-server deployment.

    input_site_file = os.path.join(options.template_directory, "site.psh")
    with open(input_site_file, "r") as sf :
        lines = sf.readlines()

    output_site_file = os.path.join(options.output_directory, "etc", "site.psh")
    with open(output_site_file, "w") as sf :
        for line in lines:
            sf.write(re.sub(r'SERVICE_HOST', options.host, line))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def configure_ccf() :
    parser = argparse.ArgumentParser(description='Script to generate configuration files from a template')

    parser.add_argument(
        '-o', '--output-directory',
        help='Name of the directory where generated configuration files are written',
        default='etc')

    parser.add_argument(
        '-t', '--template-directory',
        help='Directory in which the template configuration will be found',
        default='etc/templates')

    parser.add_argument(
        '--set',
        help='Specify arbitrary configuration options',
        nargs=2, action='append', default=[])

    options = parser.parse_args()

    global config_map
    config_map = build_configuration_map(**dict(options.set))

    if options.set :
        for (k, v) in options.set : config_map[k] = v

    # Set up the directories
    if not os.path.exists(options.output_directory) :
        os.makedirs(options.output_directory)
    if not os.path.exists(os.path.join(options.output_directory,'etc')) :
        os.makedirs(os.path.join(options.output_directory,'etc'))

    # Generate the cchost file
    expand_helper(options, 'cchost.toml')

    # Copy the constitution
    constitution_input_file = os.path.join(options.template_directory, 'constitution.js')
    constitution_output_file = os.path.join(options.output_directory, 'etc', 'constitution.js')
    shutil.copyfile(constitution_input_file, constitution_output_file)
