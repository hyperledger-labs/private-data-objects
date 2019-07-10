#!/usr/bin/env python

# Copyright 2019 Intel Corporation
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
#

# this is the unit test for eservice database module implementation. Eservices are assuming to be running.

import os
import sys

import argparse
import json

import logging
logger = logging.getLogger(__name__)

import pdo.common.logger as plogger
import pdo.service_client.service_data.eservice as eservice_db
from pdo.common.utility import are_the_urls_same

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--url', help='eservice urls', required=True,  nargs='+')
parser.add_argument('--eservice-db', help='json file for database', required=True, type=str)
parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
parser.add_argument('--logfile', help='Name of the log file', default='__screen__')
parser.add_argument('--ledger', help='Ledger URLName of the log file', required=True, type=str)

options = parser.parse_args()
plogger.setup_loggers({'LogLevel' : options.loglevel.upper(), 'LogFile' : options.logfile})

if len(options.url) < 3 :
    logger.error('minimum of three URLs is required')
    sys.exit(-1)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def compute_database_hash() :
    """compute a hash that we can use to compare two versions
    of the enclave database
    """

    enclave_names = list(eservice_db.get_enclave_names())
    enclave_names.sort()
    serialized_einfo_list = []
    for enclave_name in enclave_names :
        einfo = eservice_db.get_by_name(enclave_name)
        serialized_einfo_list.append(einfo.serialize())

    serialized_db = json.dumps(serialized_einfo_list)
    return hash(serialized_db)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
ledger_config = {'LedgerURL':options.ledger}

# -----------------------------------------------------------------
# logger.info('create and load the database from the provided URLs')
# -----------------------------------------------------------------
names = []
enclave_count = 0
for url in options.url :
    names.append('enclave_{0}'.format(enclave_count))
    eservice_db.add_by_url(ledger_config, url, name=names[enclave_count])
    enclave_count += 1

# -----------------------------------------------------------------
# logger.info('verify that the information in the database is consistent')
# -----------------------------------------------------------------
for e in names:
    einfo_by_name = eservice_db.get_by_name(e)
    einfo_by_enclave_id = eservice_db.get_by_enclave_id(einfo_by_name.client.enclave_id)

    # this can probably be simplified to just a comparison of
    # the two objects
    assert einfo_by_name.name == e
    assert einfo_by_enclave_id.name == e
    assert einfo_by_name.name == einfo_by_enclave_id.name
    assert einfo_by_name.enclave_id == einfo_by_enclave_id.enclave_id

# -----------------------------------------------------------------
# logger.info('verify that database can be saved and loaded')
# -----------------------------------------------------------------
initial_hash = compute_database_hash()
eservice_db.save_database(options.eservice_db, overwrite = True)

#load db freshly and check
eservice_db.load_database(options.eservice_db, merge = False)
assert compute_database_hash() == initial_hash, 'reloaded database has changed, no merge'

#reload db again and check
eservice_db.load_database(options.eservice_db, merge = True)
assert compute_database_hash() == initial_hash, 'reloaded database has changed, merge'

# -----------------------------------------------------------------
# logger.info('test removing entries')
# -----------------------------------------------------------------
einfo0 = eservice_db.get_by_name(names[0])
assert eservice_db.remove_by_name(names[0]), 'error removing by name'
assert eservice_db.get_by_name(names[0]) is None, 'failed to remove by name'

einfo1 = eservice_db.get_by_name(names[1])
assert eservice_db.remove_by_enclave_id(einfo1.enclave_id), 'error removing by enclave id'
assert eservice_db.get_by_enclave_id(einfo1.enclave_id) is None, 'failed to remove by enclave id'

#save file after remove
eservice_db.save_database(options.eservice_db, overwrite = True)

# -----------------------------------------------------------------
# logger.info('test last verified and load merge')
# -----------------------------------------------------------------
# force data to empty
eservice_db.clear_all_data()
assert len(list(eservice_db.get_enclave_ids())) == 0, 'failed to clear database (ids)'
assert len(list(eservice_db.get_enclave_names())) == 0, 'failed to clear database (names)'

# add entry for e1
eservice_db.add_by_url(ledger_config, einfo0.url, name=einfo0.name)
eservice_db.add_by_url(ledger_config, einfo1.url, name=einfo1.name)
assert len(list(eservice_db.get_enclave_ids())) == 2, 'failed to add enclaves (ids)'
assert len(list(eservice_db.get_enclave_names())) == 2, 'failed to add enclaves (names)'

#merge with rest of the entries from file
eservice_db.load_database(options.eservice_db, merge = True)
assert len(list(eservice_db.get_enclave_ids())) == enclave_count, 'failed to merge database'
assert compute_database_hash() != initial_hash, 'last verified times not updated'

# -----------------------------------------------------------------
# logger.info('test some broken inserts')
# -----------------------------------------------------------------
assert not eservice_db.add_by_url(ledger_config, einfo0.url, name=einfo0.name), 'failed to catch duplicate'
assert len(list(eservice_db.get_enclave_ids())) == enclave_count, 'failed insert modified the database (ids)'
assert len(list(eservice_db.get_enclave_names())) == enclave_count, 'failed insert modified the database (names)'

assert not eservice_db.add_by_url(ledger_config, einfo0.url, name=einfo1.name, update=True), 'failed to catch duplicate name'
assert len(list(eservice_db.get_enclave_ids())) == enclave_count, 'failed insert modified the database (ids)'
assert len(list(eservice_db.get_enclave_names())) == enclave_count, 'failed insert modified the database (names)'

# -----------------------------------------------------------------
# logger.info('check rename')
# -----------------------------------------------------------------
einfo = eservice_db.get_by_name(names[0])
assert not eservice_db.rename_enclave(names[0], names[1]), 'failed to prevent duplicate rename'
assert eservice_db.rename_enclave(names[0], names[0] + '_'), 'rename failed'
einfo = eservice_db.get_by_name(names[0] + '_')
assert einfo and einfo.name == names[0] + '_', 'rename failed'

logger.info("All tests passed for service database manager")
sys.exit(0)
