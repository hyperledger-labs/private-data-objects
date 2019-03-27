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
 
# this script tests the service database manager implementation. Eservices are assuming to be running.

import os
import sys

import argparse
import logging
logger = logging.getLogger(__name__)

import pdo.common.logger as plogger
from pdo.service_client.servicedatabase import ServiceDB_Manager
from pdo.common.utility import are_the_urls_same

import argparse

parser = argparse.ArgumentParser()
parser.add_argument('--url', help='service urls', required=True,  nargs='+')
parser.add_argument('--eservice-db', help='json file for database', type=str)
parser.add_argument('--loglevel', help='Set the logging level', default='INFO')
parser.add_argument('--logfile', help='Name of the log file', default='__screen__')

options = parser.parse_args()
plogger.setup_loggers({'LogLevel' : options.loglevel.upper(), 'LogFile' : options.logfile})


# -----------------------------------------------------------------
# -----------------------------------------------------------------

#create an empty db
db = ServiceDB_Manager(service_type='eservice')

# add new entries by urls
names = []
for index, url in enumerate(options.url):
    names.append('e' + str(index))
    db.add_new_info(name = names[index], url=url)

for e in names:
    # get service client by name
    c_name = db.get_serviceclient_by_name(e)

    # get info by name
    info = db.get_info(name = e)
   
    # check info by name
    assert (info['name'] == e) and are_the_urls_same(info['url'], c_name.ServiceURL) and (info['id'] is None), "Incorrect info by name"
       
    # get service client by url, url obtained from info
    c_url = db.get_serviceclient_by_url(info['url'])
    
    # check if the two clients point to the same service url
    assert are_the_urls_same(c_name.ServiceURL, c_url.ServiceURL), "Not getting the same eservice client using name and url"

    # get info by url
    info = db.get_info(url = c_url.ServiceURL)
    
    # check info by url
    assert (info['name'] == e) and are_the_urls_same(info['url'], c_name.ServiceURL) and (info['id'] is None), "Incorrect info by url"

    # update info by adding enclave id
    db.update_info(e, id = c_url.enclave_id)

    # get info by name
    info = db.get_info(name = e)

    # get info by id
    info = db.get_info(id = c_url.enclave_id)

    # check info by id
    assert (info['name'] == e) and are_the_urls_same(info['url'], c_name.ServiceURL) and (info['id'] == c_url.enclave_id), "Incorrect info by url"

    #get client by id
    c_id = db.get_serviceclient_by_id(info['id'])

    #check client by id
    # check if the two clients point to the same service url
    assert are_the_urls_same(c_name.ServiceURL, c_id.ServiceURL), "Not getting the same eservice client using name and url"

#save to file
db.save_data_to_file(options.eservice_db)

#create new db from file
db2 = ServiceDB_Manager(file_name = options.eservice_db, service_type='eservice')

#check the two dbs are the same
assert db.data == db2.data, "Error loading db from json file"

#remove entry for e1, url2
if len(options.url) > 1:
    url2 = options.url[1]
    assert db2.remove_info(name = names[0], url = url2) == 2, "Failed to remove two entries from db"
    assert len(db2.data) == len(names) - 2, "Failed to remove two entries from db"

#remove entry by name alone:
assert db.remove_info(name = names[0]) == 1, "Failed to remove one entry from db"
assert len(db.data) == len(names) -1, "Failed to remove one entry from db"

#save db to file by overwriting old json, no file name given now
db.save_data_to_file()

#reload db2
db2.load_data_from_file()

#check that load succeeded
assert db.data == db2.data

logger.info("All tests passed for service database manager")