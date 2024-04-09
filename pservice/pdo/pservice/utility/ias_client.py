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

import requests
import sys

import logging
logger = logging.getLogger(__name__)


class IasClient(object):
    """
    Provide rest api helper functions for communicating with IAS.
    """

    def __init__(self, **kwargs):
        logger.info("IAS settings:")
        if "Spid" in kwargs:
            self._spid = kwargs["Spid"]
            logger.info("SPID: " + self._spid)
        else:
            raise KeyError('Missing Spid setting')
        if "IasServer" in kwargs:
            self._ias_url = kwargs["IasServer"]
            logger.info("URL: " + self._ias_url)
        else:
            raise KeyError('Missing IasServer setting')
        if "SpidApiKey" in kwargs:
            self._spid_api_key = kwargs["SpidApiKey"]
            logger.debug("SpidApiKey: " + self._spid_api_key)
        else:
            raise KeyError('Missing SpidApiKey setting')
        self._timeout = 300

    def get_signature_revocation_lists(self,
                                       gid='',
                                       path='/attestation/v4/sigrl/'):
        """
        @param gid: Hex, base16 encoded
        @param path: URL path for sigrl request
        @return: Base 64-encoded SigRL for EPID
                group identified by {gid} parameter.
        """

        url = self._ias_url + path + gid[0:8]
        logger.debug("Fetching SigRL from: %s", url)
        result = requests.get(url,
                              headers={'Ocp-Apim-Subscription-Key': self._spid_api_key})
        if result.status_code != requests.codes.ok:
            logger.debug("get_signature_revocation_lists HTTP Error code : %d",
                         result.status_code)
            result.raise_for_status()

        return str(result.text)

    def post_verify_attestation(self, quote, manifest=None, nonce=None):
        """
        @param quote: base64 encoded quote attestation
        @return: dictionary of the response from ias.
        """

        path = '/attestation/v4/report'

        url = self._ias_url + path
        json = {"isvEnclaveQuote": quote}
        if nonce is not None:
            json['nonce'] = nonce

        logger.debug("Posting attestation verification request to: %s\n", url)
        result = requests.post(url,
                               json=json,
                               headers={'Ocp-Apim-Subscription-Key': self._spid_api_key},
                               timeout=self._timeout)
        logger.debug("result headers: %s\n", result.headers)
        logger.info("received attestation result code: %d\n", result.status_code)
        if result.status_code != requests.codes.ok:
            logger.debug("post_verify_attestation HTTP Error code : %d", result.status_code)
            result.raise_for_status()

        returnblob = {
            'verification_report': result.text,
            'ias_signature': result.headers.get('x-iasreport-signature'),
            'ias_certificates':
                list(filter(None, re.split(r'(?<=-----END CERTIFICATE-----)\n+',
                                           urllib.parse.unquote(result.headers.get('x-iasreport-signing-certificate')),
                                           re.MULTILINE)))
        }
        logger.debug("received ias certificates: %s\n", returnblob['ias_certificates'])
        return returnblob
