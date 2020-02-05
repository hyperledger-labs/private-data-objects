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

import logging

from sawtooth_sdk.messaging.future import FutureTimeoutError
from sawtooth_sdk.processor.exceptions import InternalError
from sawtooth_sdk.protobuf.setting_pb2 import Setting

from pdo.submitter.sawtooth.helpers.pdo_address_helper import PdoAddressHelper

LOGGER = logging.getLogger(__name__)
STATE_TIMEOUT_SEC = 10


class PdoTpConnectHelper(PdoAddressHelper):
    def get_state(self, context, address, value_type):
        value = value_type()

        try:
            entries_list = context.get_state([address], timeout=STATE_TIMEOUT_SEC)
            value.ParseFromString(entries_list[0].data)

        except FutureTimeoutError:
            LOGGER.warning('Timeout occurred on context.get_state([%s])', address)
        except InternalError:
            LOGGER.warning('Internal error occurred on context.get_state([%s])', address)
        except:
            LOGGER.warning('Unexpected exception occurred on context.get_state([%s])', address)

        return value

    def delete_state(self, context, address):
        try:
            remove_addresses = list()
            remove_addresses.append(address)
            addresses = list(context.delete_state(
                remove_addresses,
                timeout=STATE_TIMEOUT_SEC))

        except FutureTimeoutError:
            LOGGER.warning(
                'Timeout occurred on state.delete_state([%s, <value>])',
                address)
            raise InternalError(
                'Failed to delete value on address {}'.format(address))
        except:
            raise InternalError(
                'Unexpected exception deleting value on address {}'
                    .format(address))

        if len(addresses) != 1:
            LOGGER.warning(
                'Failed to delete value on address %s', address)
            raise InternalError(
                'Failed to delete value on address {}'.format(address))

    def set_state(self, context, address, data):
        try:
            addresses = list(context.set_state(
                {address: data},
                timeout=STATE_TIMEOUT_SEC)
            )

        except FutureTimeoutError:
            LOGGER.warning(
                'Timeout occurred on context.set_state([%s, <value>])',
                address)
            raise InternalError(
                'Failed to set value on address {}'.format(address))

        if len(addresses) != 1:
            LOGGER.warning(
                'Failed to set value on address %s', address)
            raise InternalError(
                'Failed to set value on address {}'.format(address))

    def get_report_public_key(self, context):
        return self.get_config_setting(
            context,
            self.get_report_public_key_setting_name())

    def get_valid_measurements(self, context):
        return self.get_config_setting(
            context,
            self.get_valid_measurements_setting_name())

    def get_valid_basenames(self, context):
        return self.get_config_setting(
            context,
            self.get_valid_basenames_setting_name())

    def get_config_setting(self, context, key):
        setting = self.get_state(context,
                                 self.get_setting_address(key),
                                 Setting)

        for setting_entry in setting.entries:
            if setting_entry.key == key:
                return setting_entry.value

        raise KeyError('Setting for {} not found'.format(key))
