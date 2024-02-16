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

"""
Return the number of registered endpoints in the exit status
"""

import argparse
import http
import os
import sys

from ccf.proposal_generator import transition_service_to_open

# pick up the logger used by the rest of CCF
from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def open_network_script(client) :
    # activate the member first
    try:
        r = client.post("/gov/ack/update_state_digest")
        if r.status_code != http.HTTPStatus.OK.value :
            LOG.error('failed to update state digest; {}'.format(r.status_code))
            sys.exit(-1)

        r = client.post("/gov/ack", {"state_digest": r.body.json()["state_digest"]})
        if r.status_code != http.HTTPStatus.OK.value and r.status_code != http.HTTPStatus.NO_CONTENT.value:
            LOG.error('failed to activate the member: {}, code: {}'.format(r.body, r.status_code))
            sys.exit(-1)

    except Exception as e:
        while e.__context__ : e = e.__context__
        LOG.error('failed to activate the member: {}', e)
        sys.exit(-1)

    LOG.info('CCF member activated')

    try:
        proposal, vote = transition_service_to_open()
        r = client.post("/gov/proposals", proposal)

        LOG.info(f'proposal {r}')
        if r.status_code != http.HTTPStatus.OK.value:
            LOG.error('failed to open network: {}, code: {}'.format(r.body, r.status_code))
            sys.exit(-1)

        LOG.info('successfully created proposal to open network with proposal id {}'.format(
            r.body.json()["proposal_id"]))

    except Exception as e:
        while e.__context__ : e = e.__context__
        LOG.error('failed to open network: {}', e)
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    (_, unprocessed_args, member_client) = parse_common_arguments(
        sys.argv[1:], 'Cofigure CCF policies', True)

    try :
        open_network_script(member_client)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        while e.__context__ : e = e.__context__
        LOG.error('configure ccf network failed: {}', str(e))
        sys.exit(-1)

    LOG.info('CCF network ready for use')
    sys.exit(0)
