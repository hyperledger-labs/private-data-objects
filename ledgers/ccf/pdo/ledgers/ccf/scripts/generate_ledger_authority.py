# Copyright 2020 Intel Corporation
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

import http
import sys
import time

from loguru import logger as LOG

from pdo.ledgers.ccf.common import parse_common_arguments

# -----------------------------------------------------------------
def generate_ledger_authority(client):
    try :
        for attempt in range(0,10) :
            r = client.post("/app/generate_signing_key_for_read_payloads", dict())
            if r.status_code == http.HTTPStatus.OK.value :
                return
            if r.body.json()['error']['code'] == 'FrontendNotOpen' :
                LOG.warning('ledger not yet open')
                time.sleep(5)
            else :
                LOG.error("RESPONSE: {}".format(str(r)))
                LOG.error('failed to generate ledger authority the member: {}'.format(r.body))
                sys.exit(-1)

        LOG.error('Ledger unavailable')
        sys.exit(-1)

    except Exception as e:
        LOG.error('failed to generate ledger authority the member: {}'.format(str(e)))
        sys.exit(-1)

# -----------------------------------------------------------------
def Main() :
    (_, _, member_client) = parse_common_arguments(
        sys.argv[1:], 'Fetch the ledger authority key from a CCF server', True)

    try :
        generate_ledger_authority(member_client)
    except Exception as e:
        # this just lets the script get back to the original error
        # that caused the execption
        while e.__context__ : e = e.__context__
        LOG.error('generate ledger authority failed: {}', str(e))
        sys.exit(-1)

    LOG.info('successfully generated ledger authority')
    sys.exit(0)
