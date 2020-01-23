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

import json
from pdo.client.SchemeExpression import SchemeExpression

import logging
logger = logging.getLogger(__name__)

__all__ = ['invocation_parameter', 'scheme_parameter']

# -----------------------------------------------------------------
def invocation_parameter(s) :
    """argparse parameter conversion function for invocation request
    parameters, basically these parameters are JSON expressions
    """
    try :
        expr = json.loads(s)
        return expr
    except :
        return str(s)

# -----------------------------------------------------------------
def scheme_parameter(s) :
    """argparse parameter conversion function for scheme objects
    that need to be parsed before being re-used
    """
    try :
        sexpr = SchemeExpression.ParseExpression(str(s))
        return sexpr.value
    except Exception as e:
        return str(s)
