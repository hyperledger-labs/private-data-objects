#!/usr/bin/env python
# Copyright 2022 Intel Corporation
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

import argparse
import os
import sys
import toml

import warnings
warnings.catch_warnings()
warnings.simplefilter("ignore")

import pdo.common.config as pconfig

import logging
logger = logging.getLogger(__name__)

# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class Context(object) :
    """A class for holding contract object configuration

    The context class is intended to provide a means for capturing the
    configuration of a collection of contract objects. For example, an
    asset issuer contract object may require a specific configuration
    that includes a reference to a specific asset type contract
    object. The context object wraps a portion of state with value
    interpretations designed to facilitate references between portions
    of the configuration.

    Where state references are a list of keys, context references are
    a dotted path of keys.
    """

    # --------------------------------------------------
    @staticmethod
    def LoadContextFile(state, bindings, *filenames, prefix='') :
        confpaths = state.get(['Client', 'SearchPath'])
        keylist = ['context']
        if prefix :
            keylist += prefix.split('.')

        for filename in filenames :
            context = pconfig.parse_configuration_files([filename], confpaths, bindings)
            state.merge(context, keylist)

    # --------------------------------------------------
    @staticmethod
    def SaveContextFile(state, filename, prefix='') :
        import tempfile
        keylist = ['context']
        if prefix :
            keylist += prefix.split('.')

        context = state.get(keylist)
        with tempfile.NamedTemporaryFile('w', dir=os.path.dirname(filename), delete=False) as tf:
            toml.dump(context, tf)
            tempname = tf.name

        os.rename(tempname, filename)

    # --------------------------------------------------
    def __init__(self, state, prefix='') :
        self.__path__ = ['context']
        if prefix :
            self.__path__ += prefix.split('.')

        self.__state__ = state

        if type(self.context) is not dict :
            raise ValueError('invalid context reference, {}', self.__path__)

    # --------------------------------------------------
    @property
    def context(self) :
        return self.__state__.get(self.__path__, {})

    # --------------------------------------------------
    @property
    def path(self) :
        """return the path that can be used to get to this context, since
        the context portion of the path is assumed, drop it here
        """
        return '.'.join(self.__path__[1:])

    # --------------------------------------------------
    def __getitem__(self, relative_path):
        return self.get(relative_path)

    def get(self, relative_path, value=None) :
        return self.__state__.expand(self.__path__ + relative_path.split('.'), value)

    # --------------------------------------------------
    def get_context(self, relative_path) :
        keylist = self.__path__ + relative_path.split('.')
        value = self.__state__.get(keylist)
        if value is None :
            raise KeyError('unknown key', '.'.join(keylist))

        (new_context, new_keylist) = self.__state__.__expand__(value, keylist)
        if type(new_context) is not dict :
            ValueError("context must be a dictionary")

        # state works with full key lists, a context is a dotted path
        # rooted at the context key
        return Context(self.__state__, '.'.join(new_keylist[1:]))
        # return Context(self.__state__, new_keylist, new_context)

    # --------------------------------------------------
    def get_value(self, relative_path, value=None) :
        """return the raw, unexpanded value
        """
        return self.__state__.get(self.__path__ + relative_path.split('.'), value)

    # --------------------------------------------------
    def __setitem__(self, relative_path, value):
        return self.set(relative_path, value)

    def set(self, relative_path, value):
        return self.__state__.set(self.__path__ + relative_path.split('.'), value)

    # --------------------------------------------------
    def has_key(self, relative_path) :
        return self.get(relative_path) is not None
