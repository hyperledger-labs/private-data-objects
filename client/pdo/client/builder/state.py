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

import functools
import re

import logging
logger = logging.getLogger(__name__)


# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
# XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
class State(object) :
    """A class to capture the execution state for interacting
    with PDO services (enclave, provisioning, ledger)
    """

    link_pattern = re.compile('^\\@{([._a-zA-Z0-9]+)}|\\@([._a-zA-Z0-9]+)$')
    repl_pattern = re.compile('\\${([._a-zA-Z0-9]+)}|\\$([._a-zA-Z0-9]+)')

    # --------------------------------------------------
    @staticmethod
    def parse_keylist(keylist, string) :
        if not string :
            raise ValueError("empty string paths not supported")

        keylist = keylist[:]
        new_keylist = string.split('.')
        if not new_keylist[-1] :
            raise ValueError("string path must contain at least one element; {}".format(string))

        if new_keylist[0] == '' :
            while new_keylist and new_keylist[0] == '' :
                new_keylist.pop(0)
                keylist.pop(-1)

            return keylist + new_keylist
        else :
            return new_keylist

    # --------------------------------------------------
    @classmethod
    def Clone(cls, state, identity=None, private_key_file=None) :
        if identity is None :
            identity = state.identity
        if private_key_file is None :
            private_key_file = state.private_key_file

        return cls(state.__data__, identity, private_key_file)

    # --------------------------------------------------
    def __init__(self, initial_state, identity=None, private_key_file=None) :
        # note that we do not want this to be a copy, state is a property
        # of the client, not of the shell instance
        self.__data__ = initial_state

        # the one exception is the identity which we want to be
        # specific to each shell instance
        if identity is None :
            identity = self.get(['Client', 'Identity'], "__unknown__")

        self.set_identity(identity, private_key_file)
        self.__identity_stack__ = []

    # --------------------------------------------------
    def set_identity(self, identity, private_key_file=None) :
        if private_key_file is None :
            private_key_file = self.get(['Key', 'FileName'], "{0}_private.pem".format(identity))

        self.identity = identity
        self.private_key_file = private_key_file

    # --------------------------------------------------
    def push_identity(self, identity, private_key_file=None) :
        self.__identity_stack__.append((self.identity, self.private_key_file))
        self.set_identity(identity, private_key_file)

    # --------------------------------------------------
    def pop_identity(self) :
        if self.__identity_stack__ :
            (identity, private_key_file) = self.__identity_stack__.pop()
            self.set_identity(identity, private_key_file)

    # --------------------------------------------------
    def __getitem__(self, keylist):
        # this just makes sure that a single key is extended to a list
        if not (type(keylist) is list or type(keylist) is tuple) :
            keylist = [ keylist ]
        return self.get(keylist)

    # --------------------------------------------------
    def __setitem__(self, keylist, item):
        # this just makes sure that a single key is extended to a list
        if not (type(keylist) is list or type(keylist) is tuple) :
            keylist = [ keylist ]
        self.set(keylist, item)

    # --------------------------------------------------
    def has_key(self, keylist) :
        return self.get(keylist) is not None

    # --------------------------------------------------
    def set(self, keylist, value) :
        current = self.__data__
        for key in keylist[:-1] :
            if key not in current :
                current[key] = {}
            # this can break if the value is not a dict
            # just let the exception happen & handle it elsewhere
            current = current[key]

        current[keylist[-1]] = value
        return value

    # --------------------------------------------------
    def get(self, keylist, default_value=None) :
        current = self.__data__
        for key in keylist :
            if key not in current :
                return default_value
            # this can break if the value is not a dict
            # just let the exception happen & handle it elsewhere
            current = current[key]
        return current

    # --------------------------------------------------
    def __expand__(self, value, keylist) :
        ## only need to expand string values
        if type(value) not in [str] :
            return (value, keylist)

        # first check to see if the value is a link reference, a link
        # is expanded to the value pointed to by the keys in the link
        m = State.link_pattern.fullmatch(value)
        if m :
            new_keylist = State.parse_keylist(keylist, (m.group(1) or m.group(2)))
            new_value = self.get(new_keylist)
            if type(new_value) is dict :
                return (new_value, new_keylist)
            else :
                return self.__expand__(new_value, new_keylist)

        # and now look for string substitutions that are references
        # to other entries in the state
        while True :
            subs = []
            for m in State.repl_pattern.finditer(value) :
                new_keylist = State.parse_keylist(keylist, (m.group(1) or m.group(2)))
                replacement_value = self.expand(new_keylist)
                if not replacement_value :
                    raise ValueError("failed to expand reference {}".format('.'.join(new_keylist)))
                if type(replacement_value) is not str :
                    raise ValueError("substitution reference must be a string {}".format(replacement_value))

                subs.append((m.group(0), replacement_value))

            if not subs :
                return (value, keylist)

            value = functools.reduce(lambda x, y : x.replace(*y), subs, value)
            keylist = new_keylist

    def expand(self, keylist, default_value=None) :
        """look up the value by path and expand all references
        """
        value = self.get(keylist)
        if value is not None :
            (value, new_keylist) = self.__expand__(value, keylist)
        return value or default_value

    # --------------------------------------------------
    def merge(self, state, path = []) :
        if isinstance(state, dict) :
            for key in state:
                keylist = path + [key]
                if self.has_key(keylist) :
                    self.merge(state[key], keylist)
                else :
                    self.set(keylist, state[key])
        else :
            self.set(path, state)
