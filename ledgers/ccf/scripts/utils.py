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

"""
utils.py -- common utility routines useful for deploying CCF based pdo ledger
"""

import os
from urllib.parse import urlparse

__all__ = [
    'parse_ledger_url',
]

def parse_ledger_url(config = None):
    """Parse Ledger URL into host & port"""

    if config:
        (host, port) = config["rpc-address"].split(':')
        return host, port

    if os.environ.get("PDO_LEDGER_URL") is not None:
       url =  os.environ.get("PDO_LEDGER_URL")
       (host, port) = urlparse(url).netloc.split(':')
       return host, port

    raise Exception("Insufficient info to parse ledger url")
