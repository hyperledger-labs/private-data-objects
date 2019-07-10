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

import concurrent.futures
import queue
import threading

from pdo.contract.state import ContractState
import pdo.service_client.service_data.eservice as service_db

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
__replication_manager_executor__ = concurrent.futures.ThreadPoolExecutor(max_workers=1)
__pending_replication_tasks_manager_queue__ = queue.Queue()

__replication_workers_executor__ = dict() #key is service id, value is a ThreadPoolExecutor object that manages the worker threads for this storage service
num_threads_per_storage_service = 2 # we many want to parametrize this later
__pending_replication_tasks_workers_queues__ = dict() #key is service id, value is a queue of pending replication tasks for this storage service

__condition_variable_for_completed_tasks__ = threading.Condition() # used to notify the parent thread about a new task that got completed (if the parent is waiting)

__services_to_ignore__ = set()

__stop_service__ = False

__future_to_manager__ = None
__futures_to_workers__ = dict()

# -----------------------------------------------------------------
def start_replication_service():

    # start the manager
    global __future_to_manager__
    __future_to_manager__ = __replication_manager_executor__.submit(__replication_manager__)

# -----------------------------------------------------------------
def stop_replication_service():

    global __stop_service__
    __stop_service__ = True

    #shutdown replication executor
    __replication_manager_executor__.shutdown(wait=True)

# -----------------------------------------------------------------
def add_replication_task(task):

    if __future_to_manager__.running():
        __pending_replication_tasks_manager_queue__.put(task)
    else:
        raise Exception("Replication manager is not running. Aborting further executions")

# -----------------------------------------------------------------
def __set_up_worker__(service_id):

    global __futures_to_workers__
    __futures_to_workers__[service_id] = set()

    __replication_workers_executor__[service_id] = concurrent.futures.ThreadPoolExecutor(max_workers=num_threads_per_storage_service)
    __pending_replication_tasks_workers_queues__[service_id] = queue.Queue()
    condition_variable_for_setup = threading.Condition()
    for i in range(num_threads_per_storage_service):
        condition_variable_for_setup.acquire()
        future = __replication_workers_executor__[service_id].submit(__replication_worker__, service_id, __pending_replication_tasks_workers_queues__[service_id], \
            condition_variable_for_setup)
        __futures_to_workers__[service_id].add(future)
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


    while True:

        # wait for a new task, task is the response object
        try:
            response = __pending_replication_tasks_manager_queue__.get(timeout=1.0)
        except:
            # check for termination signal
            if __stop_service__:
                __shutdown_workers__()
                logger.info("Exiting Replication manager thread")
                break
            else:
                continue

        replication_request = response.replication_request
        request_id = response.commit_id[2]

        # process the replication request
        try:
            # identify if replication can be skipped, including the case where there is only one provisioned enclave
            if len(replication_request.service_ids) == 1:
                logger.info('Skipping replication for request id %d : Only one provisioned enclave, so nothing to replicate', request_id)
                replication_request.mark_as_completed(response.call_back_after_replication)
                continue

            if len(replication_request.blocks_to_replicate) == 0:
                logger.info('Skipping replication for request id %d: No change set, so nothing to replicate', request_id)
                replication_request.mark_as_completed(response.call_back_after_replication)
                continue

            #ensure that the worker threads and queues are initialized
            for service_id in replication_request.service_ids:
                if __replication_workers_executor__.get(service_id) is None:
                    __set_up_worker__(service_id)
                else:
                    #worker threads were initialized in a previous replciation task, ensure that they are still running, else mark
                    #the corresponding replication service as one to ignore
                    service_usable = False
                    for future in __futures_to_workers__[service_id]:
                        service_usable = service_usable or future.running() #service is usable as long as one worker thread for the service is up
                    if service_usable is False:
                        logger.info("All worker threads for sservice %s have crashed, ignoring sservice for replication", str(service_id))
                        __services_to_ignore__.add(service_id)

            # get the set of services to use with this task
            ids_of_services_to_use = replication_request.service_ids - __services_to_ignore__

            #check that there are enough services for replication, else add to the set of failed tasks and go to the next task
            if len(ids_of_services_to_use) < replication_request.num_provable_replicas:
                logger.error("Replication failed for request number %d. Either not enough reliable storage services or too many worker threads crashed." \
                    , request_id)
                replication_request.mark_as_failed()
                continue

            # add the task to the workers queues
            for service_id in ids_of_services_to_use:
                __pending_replication_tasks_workers_queues__[service_id].put(response)

        except Exception as e:
            logger.info("Replication request could not be processed by the replication manager: %s", str(e))
            # mark the task as failed
            replication_request.mark_as_failed()

# -----------------------------------------------------------------
def __replication_worker__(service_id, pending_tasks_queue, condition_variable_for_setup):
    """ Worker thread that replicates to a specific storage service"""
    # set up the service client
    try:
        einfo = service_db.get_by_enclave_id(service_id)
        service_client = einfo.client
        init_sucess = True
    except:
        logger.info("Failed to set up service client for service id %s", str(service_id))
        # mark the service as unusable
        __services_to_ignore__.add(service_id)
        #exit the thread
        init_sucess = False

    # notify the manager that init was attempted
    condition_variable_for_setup.acquire()
    condition_variable_for_setup.notify()
    condition_variable_for_setup.release()

    # exit the thread if init failed
    if not init_sucess:
        return

    while True:

        # wait for a new task, task is the response object
        try:
            response = pending_tasks_queue.get(timeout=1.0)
        except:
            # check for termination signal
            if __stop_service__:
                logger.info("Exiting Replication worker thread for service at %s", str(service_client.ServiceURL))
                break
            else:
                continue

        #check if the task is already complete. If so go to the next one
        replication_request = response.replication_request
        if replication_request.is_completed:
            continue

        # replicate now!
        try:
            block_data_list = ContractState.block_data_generator(replication_request.contract_id, \
                replication_request.blocks_to_replicate, replication_request.data_dir)
            expiration = replication_request.availability_duration
            request_id = response.commit_id[2]
            fail_task = False
            response_from_replication = service_client.store_blocks(block_data_list, expiration)
            if response_from_replication is None :
                fail_task =  True
                logger.info("No response from storage service %s for replication request %d", str(service_client.ServiceURL), request_id)
        except Exception as e:
            fail_task =  True
            logger.info("Replication request %d got an exception from %s: %s", request_id, str(service_client.ServiceURL), str(e))

        # update the set of services where replication is completed
        replication_request.update_set_of_services_where_replicated(service_id, fail_task)

        # check if the overall task can be marked as successful or failed:
        if len(replication_request.successful_services) >= replication_request.num_provable_replicas:
            replication_request.mark_as_completed(response.call_back_after_replication)
        elif len(replication_request.unsuccessful_services) > len(replication_request.service_ids) - replication_request.num_provable_replicas:
            replication_request.mark_as_failed()

        # Finally, if the task failed, mark the service as unreliable
        # (this may be a bit harsh, we will refine this later based on the nature of the failure)
        if fail_task:
            __services_to_ignore__.add(service_id)
            logger.info("Ignoring service at %s for rest of replication attempts", str(service_client.ServiceURL))
            #exit the thread
            break

# -----------------------------------------------------------------
class ReplicationRequest(object):
    """ implements the replicator class functionality : used for change-set replication after
    contract update, before commiting transaction."""

    # -----------------------------------------------------------------
    def __init__(self, replication_params, \
                contract_id, blocks_to_replicate, commit_id, data_dir=None):
        """ Create an instance of the ReplicationRequest class: used for replicating the current change set.
        eservice_ids can be replaced with sservice_ids after we create an sservice database that can be used to look up the sservice url using the id."""

        self.service_ids = replication_params['service_ids']
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
                __condition_variable_for_completed_tasks__.notify()
                if not self.is_failed:
                    call_back_after_replication()
                    logger.info("Replication for request number %d successfully completed", self.commit_id[2])
            __condition_variable_for_completed_tasks__.release()

    # -----------------------------------------------------------------
    def mark_as_failed(self):
        self.is_failed = True
        logger.error("Replication for request number %d failed", self.commit_id[2])
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
