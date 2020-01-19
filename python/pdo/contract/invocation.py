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

from pdo.client.SchemeExpression import SchemeExpression

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
# -----------------------------------------------------------------
class GipsyInvocationRequest(InvocationRequest) :
    """Invocation Request that encodes requests as a Scheme
    s-expression. Assumes that all strings have been fully escaped
    in the parameter lists.
    """

    def __init__(self, method, *args, **kwargs) :
        super(GipsyInvocationRequest, self).__init__(method, *args, **kwargs)

    def serialize(self) :
        """construct an s-expression from positional and keyword parameters,
        the expression will have the form '(method pp1 pp2 ... (kw1 v1) (kw2 v2) ..)
        """
        params = list(self.__positional_parameters__)
        for k in self.keys() :
            params.append([k, self[k]])

        params_sexpr = SchemeExpression.make_expression(params)
        sexpr = SchemeExpression.cons(SchemeExpression.make_symbol(self.__method__), params_sexpr)
        sexpr = SchemeExpression.make_list([sexpr])
        sexpr = SchemeExpression.cons(SchemeExpression.make_symbol('quote'), sexpr)

        logger.debug("gipsy invocation expression: {0}".format(str(sexpr)))
        return str(sexpr)

# -----------------------------------------------------------------
def invocation_request(method, *args, **kwargs) :
    if os.environ.get('PDO_INTERPRETER', 'gipsy') == 'gipsy':
        return GipsyInvocationRequest(method, *args, **kwargs)

    return InvocationRequest(method, *args, **kwargs)
