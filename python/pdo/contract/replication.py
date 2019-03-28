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


import sys
import concurrent.futures
import queue
import threading

from pdo.contract.state import ContractState
from pdo.common.utility import are_the_urls_same

import logging
logger = logging.getLogger(__name__)

class ReplicationException(Exception) :
    """
    A class to capture replication exceptions
    """
    pass

# -----------------------------------------------------------------
# -----------------------------------------------------------------

class Replicator(object):
    """ implements the replicator class functionality : used for change-set replication after contract update, before commiting transaction."""
    
    __urls_of_storage_services_to_ignore__ = []
    __max_num_replicator_threads__ = 2 # max number of replication tasks will be carried out concurrently.
    __queue_of_SSURLS_raising_exceptions__ = queue.Queue()
    replication_executor = concurrent.futures.ThreadPoolExecutor(max_workers=__max_num_replicator_threads__) 
    pending_replications_queue = queue.Queue()
    exceptions_queue = queue.Queue()
    replication_completion_condition = threading.Condition()
    set_of_completed_replications = set()
   
    # -----------------------------------------------------------------
    @classmethod
    def get_max_num_replicator_threads(cls):
        return cls.__max_num_replicator_threads__

    # -----------------------------------------------------------------

    @classmethod
    def replication_worker(cls):
        """ worker function for a replication task"""

        while True:
            # get the task from the job queue
            task = cls.pending_replications_queue.get()

            #check for termination signal
            if task.get('exit_now'):
                logger.info("Exiting Replication worker thread")
                break

            #perform the task
            try:
                task['response_object'].replicate_change_set()
            except Exception as e:
                cls.exceptions_queue.put(str(e))
                logger.exception("Replication task failed %s : Exiting Replication worker thread", str(e))
                break

            #report replication completion in order to add the task to the transaction submission queue
            task['response_object'].report_replication_completion()
    
    # -----------------------------------------------------------------

    @classmethod
    def __update_set_of_unreliable_storage_services__(cls):
        """ Update the set of unreliable storage services based on prior replication attempts. Any service that returned an exception of any kind in 
        the past is considered unreliable for the rest of the execution."""
        
        temp = True

        while temp:
            try: 
                url = cls.__queue_of_SSURLS_raising_exceptions__.get_nowait()
                if url not in cls.__urls_of_storage_services_to_ignore__:
                    cls.__urls_of_storage_services_to_ignore__.append(url)
                    logger.info("Adding Storage Service at %s to the list of unreliable storage services to be ignored for replication", str(url))
            except: 
                temp = False
    
    # -----------------------------------------------------------------

    def __init__(self, replication_params, storage_clients, \
                contract_id, blocks_to_replicate, enclave_service, data_dir=None):
        """ Create an instance of the Replicator class: used for replicating the current change set"""
        
        self.storage_clients_to_replicate = []

        if len(storage_clients) == 0:
            return
        
        self.sservice_url_for_contract = enclave_service.storage_service_url
        self.num_provable_replicas = replication_params['num_provable_replicas']
        self.availability_duration = replication_params['availability_duration']
        self.contract_id = contract_id
        self.blocks_to_replicate = blocks_to_replicate
        self.data_dir = data_dir

        # identify reliable storage services to be used with this instance of Replicator
        Replicator.__update_set_of_unreliable_storage_services__()
        for client in  storage_clients:
            use_client = True
            if are_the_urls_same(client.ServiceURL, self.sservice_url_for_contract):
                use_client = False
            else:
                for url in Replicator.__urls_of_storage_services_to_ignore__:
                    if are_the_urls_same(client.ServiceURL, url):
                        use_client = False
                        break
            if use_client:
                self.storage_clients_to_replicate.append(client)
         
        # make sure that the number of reliable storage services is sufficient for replication 
        if len(self.storage_clients_to_replicate) < replication_params['num_provable_replicas']-1: # -1 since we do not explicitly replicate to 
                    # the sservice associated with the eservice
            logger.exception('Cannot create Replicator instance: Insufficient number of reliable storage services available for replication')
            raise ReplicationException('Cannot create Replicator instance: Insufficient number of reliable storage services available for replication')
    
    # -----------------------------------------------------------------

    def push_blocks_to_storage_service(self, client, block_data_list, expiration):
        """Wrapper around client.store_blocks to handle Exceptions during store_blocks. 
        This is the task function used by a worker-thread that attempts replication to a specific storage service"""
        
        try:
            response = client.store_blocks(block_data_list, expiration)
            if response is None :
                Replicator.__queue_of_SSURLS_raising_exceptions__.put(client.ServiceURL) 
                logger.warn("Adding Storage Service at %s to the set of  bad ones : block_store_list is None", str(client.ServiceURL))
        except Exception as e:
            Replicator.__queue_of_SSURLS_raising_exceptions__.put(client.ServiceURL)
            logger.warn("Adding Storage Service at %s to the set of  bad ones : uknown exception : %s ", str(client.ServiceURL), str(e))
            response = None

        return response
    
    # -----------------------------------------------------------------

    def replicate_change_set(self):
        """ Replicate change set to the set of reliable storage services."""
            
        # identify if replication can be skipped, including the case where there is only one provisioned enclave
        if len(self.storage_clients_to_replicate) == 0:
            logger.info('Skipping replication: Only one provisioned enclave, so nothing to replicate')
            return
       
        if len(self.blocks_to_replicate) == 0:
            logger.info('Skipping replication: No change set, so nothing to replicate')
            return

        # submit individual replication tasks to various storage services asynchronously. Each replica is handled by a separate thread 
        executor = concurrent.futures.ThreadPoolExecutor(max_workers = len(self.storage_clients_to_replicate))
        futures_to_replication_tasks = dict() # to keep track of the tasks
        expiration = self.availability_duration
        for index, client in enumerate(self.storage_clients_to_replicate):
            # get data generator. Optimization: If  this generator can be wrapped to be threadsafe, itertools.tee can be used to create
            # copies without having to read the cache multiple times. Directly using itertools.tee will not work with multi-threadeding
            block_data_list = ContractState.block_data_generator(self.contract_id, self.blocks_to_replicate, self.data_dir)
            future = executor.submit(self.push_blocks_to_storage_service, client, block_data_list, expiration)
            futures_to_replication_tasks[future] = client.ServiceURL
       
        #poll for completed replication tasks, wait until num_provable_replicas number of tasks finish
        urls_of_successful_storage_services = [self.sservice_url_for_contract] #successful by default
        num_successful_replicas = 1
        num_unsuccessful_replicas = 0
        max_allowable_num_unsucessful_replicas = len(self.storage_clients_to_replicate) - self.num_provable_replicas + 1
            # Add 1 since storage_clients_to_replicate does not contain the sservice corresponding to the contract enclave
        
        if num_successful_replicas == self.num_provable_replicas: #covers the case when we only need one proof
            pass
        else:
            for future in concurrent.futures.as_completed(futures_to_replication_tasks):
                url = futures_to_replication_tasks[future]
                try:
                    response = future.result()
                except Exception as e:
                    logger.exception('Unexpected situation: Unable to gather sservice response after what looks like successful replication: %s', str(e))
                    Replicator.exceptions_queue.put('Unexpected situation: Unable to gather sservice response after what looks like successful replication')
                    raise ReplicationException('Unexpected situation: Unable to gather sservice response after what looks like successful replication') from e
            
                if response is not None: # an indication of success, but we also need to examine response and verify the signature: TBD in next PR
                    urls_of_successful_storage_services.append(url)
                    num_successful_replicas+=1
                    if num_successful_replicas == self.num_provable_replicas:
                        break
                else: 
                    num_unsuccessful_replicas+=1
                    if num_successful_replicas > max_allowable_num_unsucessful_replicas:
                        logger.exception('Replication has failed due to too many bad responses from storage services')
                        Replicator.exceptions_queue.put('Replication has failed due to too many bad responses from storage services')
                        raise ReplicationException('Replication has failed due to too many bad responses from storage services')
        
        #replication is successful. 
        logger.info("Successfully replicated change set (%d blocks) at storage services : %s", len(self.blocks_to_replicate), str(urls_of_successful_storage_services))
        
        #shutdown executor asynchronously. With wait=False, outstanding threads will run to completion in the background (including 
        #possibile timeouts and exceptions). Resources will get freed after that. 
        executor.shutdown(wait=False)
