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
import json
import os

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class InvocationRequest(dict):
    """Invocation Request that encodes requests in the format
    specified in the interpreter inovcation documentation.
    """
    def __init__(self, method, *args, **kwargs) :
        super(InvocationRequest, self).__init__(**kwargs)

        self.__method__ = method;
        self.__positional_parameters__ = args

    def __repr__(self) :
        return self.serialize()

    def serialize(self) :
        request = dict()
        request['Method'] = self.__method__
        request['PositionalParameters'] = self.__positional_parameters__
        request['KeywordParameters'] = self
        return json.dumps(request)

# -----------------------------------------------------------------
def invocation_request(method, *args, **kwargs) :
    return InvocationRequest(method, *args, **kwargs)

# -----------------------------------------------------------------
def invocation_response(response_string) :
    try :
        return json.loads(response_string)
    except Exception as e:
        return str(response_string)
