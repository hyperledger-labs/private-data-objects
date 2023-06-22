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

## -----------------------------------------------------------------
class SessionParameters(object) :
    __session_keys__ = ('eservice_url', 'save_file', 'wait', 'commit')

    def __init__(self, **kwargs) :
        self.eservice_url = kwargs.get('eservice_url', kwargs.get('enclave'))
        self.save_file = kwargs.get('save_file')
        self.wait = kwargs.get('wait', False)
        self.commit = kwargs.get('commit', False)

    def keys(self):
        return self.__session_keys__

    def values(self):
        return(map(lambda k : self.__getitem__(k), self.__session_keys))

    def clone(self, **kwargs) :
        new_session = SessionParameters(**self.__dict__)
        new_session.__dict__.update(**kwargs)
        return new_session

    def __setattr__(self, key, value):
        if key not in self.__session_keys__ :
            raise TypeError("unable to set key {}".format(key))
        return object.__setattr__(self, key, value)

    def __setitem__(self, key, value):
        if key not in self.__session_keys__ :
            raise TypeError("unable to set key {}".format(key))
        self.__dict__[key] = value

    def __getitem__(self, key):
        return self.__dict__[key]

    def __repr__(self):
        return repr(self.__dict__)

    def __iter__(self):
        return iter(self.keys())
