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

# -----------------------------------------------------------------
replication_threads = []
replication_thread_lock = threading.Lock()

replication_task_queue = None
service_task_queues = {}
service_task_queues_lock = threading.Lock()

number_of_service_threads = 2

# used to notify the parent thread about a new task that got completed (if the parent is waiting)
__condition_variable_for_completed_tasks__ = threading.Condition()

# set of URLs for storage services where connection attempts failed
# at some point we might want to periodically flush this set to make
# another attempt
__services_to_ignore__ = set()

__stop_service__ = False

# -----------------------------------------------------------------
def start_replication_service(config = {}) :
    # make sure the service is only started once
    global replication_task_queue
    with replication_thread_lock :
        if replication_task_queue :
            return
        else :
            replication_task_queue = queue.Queue()

    global number_of_service_threads
    number_of_service_threads = config.get("replication_worker_threads", number_of_service_threads)

    logger.debug('start replication manager threads')
    for i in range(config.get("replication_service_threads", 1)) :
        thread = threading.Thread(target=__replication_manager__)
        thread.daemon = True
        thread.start()

        with replication_thread_lock :
            replication_threads.append(thread)

# -----------------------------------------------------------------
def stop_replication_service() :
    logger.debug("stop replication service")

    global __stop_service__
    __stop_service__ = True

    for thread in replication_threads[:] :
        thread.join(timeout=5.0)

# -----------------------------------------------------------------
def add_replication_task(task):
    replication_task_queue.put(task)

# -----------------------------------------------------------------
def start_service_workers(service_id):
    with service_task_queues_lock :
        global service_task_queues
        if service_task_queues.get(service_id) :
            return
        service_task_queues[service_id] = queue.Queue()

    logger.debug('start service threads for {}'.format(service_id))
    for i in range(number_of_service_threads) :
        thread = threading.Thread(target=__replication_worker__, args=(service_id,))
        thread.daemon = True
        thread.start()

        with replication_thread_lock :
            replication_threads.append(thread)

# -----------------------------------------------------------------
def __replication_manager__() :
    """ Manager thread for a replication task"""

    while True:
        # wait for a new task, task is the response object
        try:
            response = replication_task_queue.get(timeout=1.0)
        except queue.Empty :
            logger.debug('empty work queue')
            if __stop_service__:
                logger.debug('service stop indicated')
                return True
            continue
        except Exception as e :
            logger.exception("shutdown exception %s", str(e))
            return False

        # process the task
        try:
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
                start_service_workers(service_id)   # start the workers if necessary
                service_task_queues[service_id].put(response)

        except Exception as e:
            logger.exception("replication manager exception %s", str(e))
            return False

        finally :
            replication_task_queue.task_done()

# -----------------------------------------------------------------
def __replication_worker__(service_id, *args) :
    """ Worker thread that replicates to a specific storage service"""

    logger.debug("replication worker started with {}".format(service_id))

    # initialize the service connection for this worker
    pending_tasks_queue = service_task_queues[service_id]
    try:
        service_client = StorageServiceClient(service_id)
    except :
        logger.info("Failed to set up service client for service id %s", service_id)
        __services_to_ignore__.add(service_id)
        return

    # start processing tasks
    while True:

        # wait for a new task, task is the response object
        try:
            response = pending_tasks_queue.get(timeout=1.0)
        except:
            # check for termination signal
            if __stop_service__:
                logger.debug("Exiting replication worker thread for service at %s", service_client.ServiceURL)
                return True
            continue

        # process the replication request
        try:
            #check if the task is already complete. If so go to the next one
            replication_request = response.replication_request

            # for the purpose of "correctness", if the replication request is complete
            # then we don't need to finish all of the replication services. however,
            # we WANT state replicated in each location... so if complete we can let the
            # replication manager commit this to the ledger. we should only stop processing
            # if the request fails for some reason.

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
            return False
        finally :
            pending_tasks_queue.task_done()

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
