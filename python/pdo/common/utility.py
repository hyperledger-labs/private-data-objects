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
utility.py -- common utility routines

NOTE: functions defined in this file are designed to be run
before logging is enabled.
"""

import os
import errno
import pdo.common.crypto as crypto

__all__ = [
    'build_file_name',
    'find_file_in_path',
    'from_transaction_signature_to_id'
    ]

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def build_file_name(basename, data_dir = '', extension = '') :
    """build a file name from the basename and directory; this is a
    common operation for scripts that process a configuration file

    :param str basename: base name of a file, may be a full path, may have an extension
    :param str data_dir: directory where the file will be placed
    :param str extension: the extension to add to the file if it doesnt have one
    """

    # os.path.abspath only works for full paths, not relative paths
    # this check should catch './abc'
    if os.path.split(basename)[0] :
        return os.path.realpath(basename)
    if basename[-len(extension):] == extension :
        return os.path.join(data_dir, basename)
    else :
        return os.path.join(data_dir, basename + extension)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def find_file_in_path(filename, search_path) :
    """general utility to search for a file name in a path

    :param str filename: name of the file to locate, absolute path ignores search_path
    :param list(str) search_path: list of directores where the files may be located
    """

    # os.path.abspath only works for full paths, not relative paths
    # this check should catch './abc'
    if os.path.split(filename)[0] :
        if os.path.isfile(filename) :
            return filename
        raise FileNotFoundError(errno.ENOENT, "file does not exist", filename)

    for path in search_path :
        full_filename = os.path.join(path, filename)
        if os.path.isfile(full_filename) :
            return full_filename

    raise FileNotFoundError(errno.ENOENT, "unable to locate file in search path", filename)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def from_transaction_signature_to_id(transaction_signature) :
    """function to transform a hex transaction signature (or transaction identifier)
    into a base64 id which is used (for instance) for a contract id
    """
    id = crypto.byte_array_to_base64(crypto.compute_message_hash(crypto.hex_to_byte_array(transaction_signature)))
    return id

