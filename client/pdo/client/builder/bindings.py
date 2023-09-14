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

import copy
from string import Template

import logging
logger = logging.getLogger(__name__)

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class Bindings(object) :
    """
    """

    # --------------------------------------------------
    @classmethod
    def Clone(cls, bindings) :
        binding_map = copy.copy(bindings.__bindings__)

        local_keys = [ key for key in binding_map if key.startswith('_') ]
        for key in local_keys : binding_map.pop(key)

        return cls(bindings=binding_map)

    # --------------------------------------------------
    def __init__(self, bindings = {}) :
        self.__bindings__ = copy.deepcopy(bindings)

    # --------------------------------------------------
    def merge(self, bindings) :
        binding_map = copy.copy(bindings.__bindings__)

        local_keys = [ key for key in binding_map if key.startswith('_') ]
        for key in local_keys : binding_map.pop(key)

        self.__bindings__.update(binding_map)

    # --------------------------------------------------
    def get(self, key, default_value=None) :
        return self.__bindings__.get(key, default_value)

    def __getitem__(self, key):
        return self.__bindings__[key]

    # --------------------------------------------------
    def set(self, key, value) :
        self.__bindings__[key] = value

    def __setitem__(self, key, item):
        self.__bindings__[key] = value

    # --------------------------------------------------
    def bind(self, variable, value) :
        saved = self.__bindings__.get(variable, '')
        self.__bindings__[variable] = value
        return saved

    # --------------------------------------------------
    def isbound(self, variable, default_value=None) :
        return self.__bindings__.get(variable, default_value)

    # --------------------------------------------------
    def expand(self, argstring) :
        template = Template(argstring)
        return template.safe_substitute(self.__bindings__)
