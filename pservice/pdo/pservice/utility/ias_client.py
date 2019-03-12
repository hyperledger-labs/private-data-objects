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
Provide rest api helper functions for communicating with IAS.
"""

from urllib.parse import urljoin

import requests

import sys
def printf(format, *args):
    sys.stdout.write(format % args)

class IasClient(object):
    """
    Provide rest api helper functions for communicating with IAS.
    """

    def __init__(self, **kwargs):
        self._proxies = {}
        if "HttpsProxy" in kwargs:
            self._proxies["https"] = kwargs["HttpsProxy"]
        if "Spid" in kwargs:
            self._spid = kwargs["Spid"]
        else:
            raise KeyError('Missing Spid setting')
        if "IasServer" in kwargs:
            self._ias_url = kwargs["IasServer"]
        else:
            raise KeyError('Missing IasServer setting')
        if "SpidCert" in kwargs:
            self._cert = kwargs["SpidCert"]
        else:
            raise KeyError('Missing SpidCert setting')
        self._timeout=300

    def get_signature_revocation_lists(self,
                                       gid='',
                                       path='/attestation/sgx/v3/sigrl/'):
        """
        @param gid: Hex, base16 encoded
        @param path: URL path for sigrl request
        @return: Base 64-encoded SigRL for EPID
                group identified by {gid} parameter.
        """

        url = self._ias_url+path+gid[0:8]
        printf("Fetching SigRL from: %s", url)
        result = requests.get(url, proxies= self._proxies,
                              cert=self._cert, verify=False)
        if result.status_code != requests.codes.ok:
            printf("get_signature_revocation_lists HTTP Error code : %d",
                         result.status_code)
            result.raise_for_status()

        return str(result.text)

    def post_verify_attestation(self, quote, manifest=None, nonce=None):
        """
        @param quote: base64 encoded quote attestation
        @return: dictionary of the response from ias.
        """

        path = '/attestation/sgx/v3/report'

        url = urljoin(self._ias_url, path)
        json = {"isvEnclaveQuote": quote}
        if nonce is not None:
            json['nonce'] = nonce

        printf("Posting attestation verification request to: %s\n",url)
        result = requests.post(url,
                               json=json,
                               proxies=self._proxies,
                               cert=self._cert,
                               timeout=self._timeout)
        printf("received attestation result code: %d\n",
                     result.status_code)
        if result.status_code != requests.codes.ok:
            printf("post_verify_attestation HTTP Error code : %d",
                         result.status_code)
            result.raise_for_status()

        return result.json()
