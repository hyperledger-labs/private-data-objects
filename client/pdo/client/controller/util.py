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

import logging
logger = logging.getLogger(__name__)

from pdo.client.SchemeExpression import SchemeExpression


__all__ = ['scheme_expr' , 'scheme_string']

# -----------------------------------------------------------------
def scheme_string(s) :
    """conversion function for parameters that are Scheme strings
    """
    if len(s) == 0 :
        return '""'
    elif s[0] == '"' :
        return s
    else :
        return f'"{s}"'

# -----------------------------------------------------------------
def scheme_expr(s) :
    """conversion function for parameters that are Scheme expressions
    """
    try :
        expr = SchemeExpression.ParseExpression(s)
        return str(expr)
    except :
        raise RuntimeError('invalid scheme expression; {0}'.format(s))
