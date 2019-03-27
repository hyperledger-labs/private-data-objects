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
import copy

import argparse
import logging
logger = logging.getLogger(__name__)

import pdo.common.logger as plogger
import pdo.service_client.service_data.eservice as db
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

# -----------------------------------------------------------------
# -----------------------------------------------------------------

ledger_config = {'LedgerURL':options.ledger}

# add new entries by urls
names = []
for index, url in enumerate(options.url):
    names.append('e' + str(index))
    db.add_info_to_database(names[index], url, ledger_config)

#save  file
db.save_database(options.eservice_db, overwrite = True)

for e in names:
    # get service client by name
    c_name = db.get_client_by_name(e)

    # get info by name
    info = db.get_info_by_name(e)
   
    # check info by name
    assert (info['name'] == e) and are_the_urls_same(info['url'], c_name.ServiceURL) and (info['id'] == c_name.enclave_id), "Incorrect info by name"
       
    # get service client by id, id obtained from info
    c_id = db.get_client_by_id(info['id'])
    
    # check if the two clients point to the same service url
    assert are_the_urls_same(c_name.ServiceURL, c_id.ServiceURL), "Not getting the same eservice client using name and id"

    # get info by url
    info = db.get_info_by_url(url = c_id.ServiceURL)
    
    # check info by url
    assert (info['name'] == e) and are_the_urls_same(info['url'], c_name.ServiceURL) and (info['id'] == c_id.enclave_id), "Incorrect info by url"

    # test update info without any change in info
    assert db.update_info_in_database(e, c_name.ServiceURL, ledger_config) is True, "Error while updating same info"

#save  file
db.save_database(options.eservice_db, overwrite = True)

# make a local copy for testing
data_copy = copy.deepcopy(db.__data__)

#load db freshly and check
db.load_database(options.eservice_db, merge = False)

assert db.__data__ == data_copy, "Error loading database"

#reload db again and check
db.load_database(options.eservice_db, merge = True)

assert db.__data__ == data_copy, "Error reloading database with merge"

#remove entry for e1
info = db.get_info_by_name(names[0])
assert db.remove_info_from_database(name = names[0]) == 1, "Error removing entry"
assert db.get_info_by_name(names[0]) is None, "Error removing entry"
assert db.get_info_by_url(info['url']) is None, "Error removing entry"
assert db.get_info_by_id(info['id']) is None, "Error removing entry"

#save file after remove
db.save_database(options.eservice_db, overwrite = True)

# force data to empty 
db.__data__ = {}
# add entry for e1
db.add_info_to_database(info['name'], info['url'], ledger_config)
#merge with rest of the entries from file
db.load_database(options.eservice_db, merge = True)
# the following comparison should fail, since e0's last verification time is different. Expect for this field, everything else is same
assert db.__data__ != data_copy, "Expected the two dbs to be different"

#test update with change in info
info = db.get_info_by_name(names[0])
db.remove_info_from_database(name = names[0])
#change entry of e1 to that of e0
assert db.update_info_in_database(names[1], info['url'], ledger_config) is True, "Error while updating same info"
info2 = db.get_info_by_name(names[1])
assert info['url']==info2['url'] and info['id'] == info2['id'], "error while updating info"

logger.info("All tests passed for service database manager")
