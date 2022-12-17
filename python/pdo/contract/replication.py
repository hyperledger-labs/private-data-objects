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

import queue
import threading
from concurrent.futures import ThreadPoolExecutor

import pdo.common.block_store_manager as pblocks
from pdo.service_client.storage import StorageServiceClient
from pdo.common.utility import normalize_service_url
import logging
logger = logging.getLogger(__name__)

# we many want to parametrize this later
num_threads_per_storage_service = 2

# -----------------------------------------------------------------
__replication_manager_executor__ = ThreadPoolExecutor(max_workers=1)
__pending_replication_tasks_manager_queue__ = queue.Queue()

# key is service id, value is a ThreadPoolExecutor object that manages the worker threads for this storage service
__replication_workers_executor__ = dict()

# key is service id, value is a queue of pending replication tasks for this storage service
__pending_replication_tasks_workers_queues__ = dict()

# used to notify the parent thread about a new task that got completed (if the parent is waiting)
__condition_variable_for_completed_tasks__ = threading.Condition()

# set of URLs for storage services where connection attempts failed
# at some point we might want to periodically flush this set to make
# another attempt
__services_to_ignore__ = set()

__stop_service__ = False

# -----------------------------------------------------------------
def start_replication_service():

    # start the manager
    __replication_manager_executor__.submit(__replication_manager__)

# -----------------------------------------------------------------
def stop_replication_service():

    global __stop_service__
    __stop_service__ = True

    #shutdown replication executor
    __replication_manager_executor__.shutdown(wait=True)

# -----------------------------------------------------------------
def add_replication_task(task):

    __pending_replication_tasks_manager_queue__.put(task)

# -----------------------------------------------------------------
def __set_up_worker__(service_id):

    __replication_workers_executor__[service_id] = ThreadPoolExecutor(max_workers=num_threads_per_storage_service)
    __pending_replication_tasks_workers_queues__[service_id] = queue.Queue()
    condition_variable_for_setup = threading.Condition()
    for i in range(num_threads_per_storage_service):
        condition_variable_for_setup.acquire()
        task_queue = __pending_replication_tasks_workers_queues__[service_id]
        __replication_workers_executor__[service_id].submit(
            __replication_worker__, service_id, task_queue, condition_variable_for_setup)

        #wait for the thread to initialize
        condition_variable_for_setup.wait()
        condition_variable_for_setup.release()

# -----------------------------------------------------------------
def __shutdown_workers__():
    """Shutdown all worker threads"""

    #shutdown the worker executors
    for service_id in __replication_workers_executor__.keys():
        __replication_workers_executor__[service_id].shutdown(wait=True)

# -----------------------------------------------------------------
def __replication_manager__():
    """ Manager thread for a replication task"""

    try:
        while True:

            # wait for a new task, task is the response object
            try:
                response = __pending_replication_tasks_manager_queue__.get(timeout=1.0)
            except queue.Empty :
                logger.debug('empty work queue')
                if __stop_service__:
                    return True
                continue
            except Exception as e :
                logger.exception("shutdown exception %s", str(e))
                return False

            replication_request = response.replication_request
            request_id = response.commit_id[2]

            # if there is nothing that requires replication (state didn't change) then we are done
            if replication_request.num_provable_replicas == 0 :
                logger.debug('Skipping replication for request id %d: replication not required', request_id)
                replication_request.mark_as_completed(response.call_back_after_replication)
                continue

            if len(replication_request.blocks_to_replicate) == 0:
                logger.debug('Skipping replication for request id %d: No change set, so nothing to replicate', request_id)
                replication_request.mark_as_completed(response.call_back_after_replication)
                continue

            # ensure that the worker threads and queues are in place for services
            # associated with this replication request
            for service_id in replication_request.service_ids:
                if __replication_workers_executor__.get(service_id) is None:
                    __set_up_worker__(service_id)

            # get the set of services to use with this task
            ids_of_services_to_use = replication_request.service_ids - __services_to_ignore__

            # check that there are enough services for replication, else add to the
            # set of failed tasks and go to the next task
            if len(ids_of_services_to_use) < replication_request.num_provable_replicas:
                logger.error("Replication request %d failed; insufficient storage services; %d/%d",
                             request_id, len(ids_of_services_to_use), replication_request.num_provable_replicas)
                replication_request.mark_as_failed()
                continue

            # add the task to the workers queues
            for service_id in ids_of_services_to_use:
                __pending_replication_tasks_workers_queues__[service_id].put(response)

    except Exception as e:
        logger.exception("replication manager exception %s", str(e))
        return False

    finally :
        __shutdown_workers__()
        logger.debug("exiting replication manager thread")

# -----------------------------------------------------------------
def __replication_worker__(service_id, pending_tasks_queue, condition_variable_for_setup):
    """ Worker thread that replicates to a specific storage service"""
    # set up the service client
    try:
        service_client = StorageServiceClient(service_id)
    except :
        logger.info("Failed to set up service client for service id %s", service_id)
        __services_to_ignore__.add(service_id)
        return
    finally :
        # notify the manager that init was attempted
        condition_variable_for_setup.acquire()
        condition_variable_for_setup.notify()
        condition_variable_for_setup.release()

    try:
        while True:

            # wait for a new task, task is the response object
            try:
                response = pending_tasks_queue.get(timeout=1.0)
            except:
                # check for termination signal
                if __stop_service__:
                    logger.debug("Exiting replication worker thread for service at %s", service_client.ServiceURL)
                    break
                else:
                    continue

            #check if the task is already complete. If so go to the next one
            replication_request = response.replication_request
            if replication_request.is_completed:
                continue

            # replicate now!
            block_data_list = pblocks.local_block_manager().get_blocks(replication_request.blocks_to_replicate)
            expiration = replication_request.availability_duration
            request_id = response.commit_id[2]
            try:
                fail_task = False
                response_from_replication = service_client.store_blocks(block_data_list, expiration)
                if response_from_replication is None :
                    fail_task =  True
                    logger.info("No response from storage service %s for replication request %d",
                                service_client.ServiceURL, request_id)
            except Exception as e:
                fail_task =  True
                logger.info("Replication request %d got an exception from %s: %s",
                            request_id, service_client.ServiceURL, str(e))

            # update the set of services where replication is completed
            replication_request.update_set_of_services_where_replicated(service_id, fail_task)

            # check if the overall task can be marked as successful or failed:
            count_successful = len(replication_request.successful_services)
            count_unsuccessful = len(replication_request.unsuccessful_services)
            if count_successful >= replication_request.num_provable_replicas :
                replication_request.mark_as_completed(response.call_back_after_replication)
            elif count_unsuccessful > len(replication_request.service_ids) - replication_request.num_provable_replicas :
                replication_request.mark_as_failed()

            # Finally, if the task failed, mark the service as unreliable
            # (this may be a bit harsh, we will refine this later based on the nature of the failure)
            if fail_task:
                logger.info("Ignoring service at %s for rest of replication attempts", service_client.ServiceURL)
                __services_to_ignore__.add(service_id)
                #exit the thread
                break

    except Exception as e:
        logger.info("Replication worker exception %s", str(e))

# -----------------------------------------------------------------
class ReplicationRequest(object):
    """ implements the replicator class functionality : used for change-set replication after
    contract update, before commiting transaction."""

    # -----------------------------------------------------------------
    def __init__(self, replication_params, \
                contract_id, blocks_to_replicate, commit_id, data_dir=None):
        """ Create an instance of the ReplicationRequest class: used for replicating
        the current change set. service_ids are the URLs for the storage services that
        are used for replication.
        """

        self.service_ids = set(map(lambda i : normalize_service_url(i), replication_params['replication_set']))
        self.num_provable_replicas = replication_params['num_provable_replicas']
        self.availability_duration = replication_params['availability_duration']
        self.contract_id = contract_id
        self.blocks_to_replicate = blocks_to_replicate
        self.commit_id = commit_id
        self.data_dir = data_dir

        self.is_completed = False
        self.is_failed = False
        self.successful_services = set()
        self.unsuccessful_services = set()

    # -----------------------------------------------------------------
    def mark_as_completed(self, call_back_after_replication=None):
        """ Mark as completed. Notify waiting threads. If successful, invoke the call back method. Multiple notifications and call backs are prevented"""

        if not self.is_completed: # check reduces contention for lock
            __condition_variable_for_completed_tasks__.acquire()
            if not self.is_completed: # yes we check this again, the outside check is only for performance optimization, this check is algorithmic
                self.is_completed = True
                logger.debug("Replication for request number %d successfully completed", self.commit_id[2])
                __condition_variable_for_completed_tasks__.notify()
                if not self.is_failed:
                    call_back_after_replication()
            __condition_variable_for_completed_tasks__.release()

    # -----------------------------------------------------------------
    def mark_as_failed(self):
        self.is_failed = True
        self.mark_as_completed()

    # -----------------------------------------------------------------
    def wait_for_completion(self):
        """ Returns after successful completion of the replication request. Raises exception if the request failed."""

        __condition_variable_for_completed_tasks__.acquire()
        while self.is_completed is False:
            __condition_variable_for_completed_tasks__.wait()

        __condition_variable_for_completed_tasks__.release()

        if self.is_failed:
            raise Exception("Replication task failed for request number %s", str(self.commit_id[2]))

    # -----------------------------------------------------------------
    def update_set_of_services_where_replicated(self, service_id, fail_task):

        if fail_task:
            self.unsuccessful_services.add(service_id)
        else:
            self.successful_services.add(service_id)
