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
import os
import sys
import concurrent.futures
import queue
import time
import threading

import pdo.common.crypto as crypto
import pdo.common.keys as keys

from pdo.submitter.submitter import Submitter
from pdo.contract.state import ContractState
from pdo.contract.replication import ReplicationException
from pdo.contract.replication import Replicator
from sawtooth.helpers.pdo_connect import PdoRegistryHelper

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class Dependencies(object) :

    """
    Class for mapping contract state commits to the corresponding
    ledger transaction. This class facilitates efficient assignment
    of dependencies in PDO transactions.
    """

    ## -------------------------------------------------------
    def __init__(self) :
        self.__depcache = {}

    ## -------------------------------------------------------
    def __key(self, contractid, statehash) :
        return str(contractid) + '$' + str(statehash)

    ## -------------------------------------------------------
    def __set(self, contractid, statehash, txnid) :
        self.__depcache[self.__key(contractid, statehash)] = txnid

    ## -------------------------------------------------------
    def __get(self, contractid, statehash) :
        k = self.__key(contractid, statehash)
        return self.__depcache.get(k)

    ##--------------------------------------------------------
    def FindDependencyLocally(self, contractid, statehash):
        return self.__get(contractid, statehash)

    ## -------------------------------------------------------
    def FindDependency(self, ledger_config, contractid, statehash) :
        logger.debug('find dependency for %s, %s', contractid, statehash)

        txnid = self.__get(contractid, statehash)
        if txnid :
            return txnid

        # no information about this update locally, so go to the
        # ledger to retrieve it
        client = PdoRegistryHelper(ledger_config['LedgerURL'])

        try :
            # this is not very efficient since it pulls all of the state
            # down with the txnid
            contract_state_info = client.get_ccl_state_dict(contractid, statehash)
            txnid = contract_state_info['transaction_id']
            self.__set(contractid, statehash, txnid)
            return txnid
        except Exception as e :
            logger.info('failed to retrieve the transaction: %s', str(e))

        logger.info('unable to find dependency for %s:%s', contractid, statehash)
        return None

    ## -------------------------------------------------------
    def SaveDependency(self, contractid, statehash, txnid) :
        self.__set(contractid, statehash, txnid)


transaction_dependencies = Dependencies()

# -----------------------------------------------------------------
# -----------------------------------------------------------------
class ContractResponse(object) :
    """
    Class for managing the contract operation response from an enclave service
    """

    __start_threads_for_commit__ = True
    transaction_submission_exceptions_queue = queue.Queue()

    transaction_executor = concurrent.futures.ThreadPoolExecutor(max_workers=1) # executor that submit transactions
    pending_transactions_queue = queue.Queue()

    txn_completion_condition = threading.Condition()
    set_of_completed_txns = set()
    
    # -------------------------------------------------------
    @classmethod
    def get_exceptions_from_past_commits(cls):
        """ Return any exception rasied by concurrent Replication and transaction submsission tasks"""

        try:
            e = Replicator.exceptions_queue.get_nowait()
        except:
            try:
                e = cls.transaction_submission_exceptions_queue.get_nowait()
            except:
                e = None

        return e

    # -------------------------------------------------------

    @classmethod
    def wait_for_commit(cls, commit_id, use_ledger=True, shut_down=False):
        """ Wait for completion of the commit task specified by id. Return transaction id if ledger is used, else return None. If shut_down is True,
        send exit singals to replication and transaction threads. The implementation relies on threading.Condition objects"""
        
        if use_ledger:
            cls.txn_completion_condition.acquire()
            while commit_id not in cls.set_of_completed_txns: 
                cls.txn_completion_condition.wait(timeout=1.0)
                e = cls.get_exceptions_from_past_commits()
                if e is not None: 
                    raise Exception(str(e))
                cls.txn_completion_condition.acquire()    
            cls.txn_completion_condition.release()    

            global transaction_dependencies
            contract_id = commit_id[0]
            state_hash = commit_id[1]
            txn_id = transaction_dependencies.FindDependencyLocally(contract_id, crypto.byte_array_to_base64(state_hash))
        
        else: #wait until the replication task for commit_id completes

            Replicator.replication_completion_condition.acquire()
            while commit_id not in Replicator.set_of_completed_replications: 
                Replicator.replication_completion_condition.wait(timeout = 1.0)
                e = cls.get_exceptions_from_past_commits()
                if e is not None:
                    raise Exception(str(e))
                Replicator.replication_completion_condition.acquire()    
            Replicator.replication_completion_condition.release()    

            txn_id = None

        if shut_down:
            cls.exit_commit_workers()
        
        return txn_id

    # -------------------------------------------------------

    @classmethod
    def exit_commit_workers(cls):
        """Shutdown replication exectuor. Send "exit now" message to txn submit thead"""

        # send termination signal to executor thread 
        for i in range(Replicator.get_max_num_replicator_threads()):
            Replicator.pending_replications_queue.put(dict({'exit_now': True}))
        
        #shutdown replication executor
        Replicator.replication_executor.shutdown(wait=True)
        
        # send termination signal to txn_executor thread
        try:
            cls.pending_transactions_queue.put(dict({'exit_now': True}))
        except :
            pass # to cover the case when we run without ledgers, in which case there is no txn thread to terminate 

        #shutdown tx executor
        cls.transaction_executor.shutdown(wait=True) 

    # -------------------------------------------------------

    @classmethod
    def transaction_submission_worker(cls):
        """This is the worker for submitting transactions"""

        def submit_doable_transactions_for_contract(contract_id):
            """ helper function to submit pending transactions for a specific contact. 
            Transactions will be submitted for all pending commits whose commit dependecies are met"""
           
            nonlocal rep_completed_but_txn_not_submitted_updates
            global transaction_dependencies
            submitted_any = False

            pending_requests_numbers = list(rep_completed_but_txn_not_submitted_updates[contract_id].keys())
            pending_requests_numbers.sort()
            for request_number in pending_requests_numbers:
              
                task = rep_completed_but_txn_not_submitted_updates[contract_id][request_number]
                commit_id = task['commit_id']
                response = task['response_object']
                txn_dependencies = []

                # Check for implicit commit dependencies , no need to add them to txn_dependencies, this will be taken care of by the submitter
                txnid = transaction_dependencies.FindDependencyLocally(response.contract_id, crypto.byte_array_to_base64(response.old_state_hash))
                if txnid is None:
                    return submitted_any
              
                # check for explicit commit dependencies (specfied explicitly by the client during the commit call)
                commit_dependencies = response.txn_params['dependency_list_commit_ids']
                fail_explit_commit_dependencies = False
                for commit_id_temp in commit_dependencies:
                    txnid = transaction_dependencies.FindDependencyLocally(commit_id_temp[0], crypto.byte_array_to_base64(commit_id_temp[1]))
                    if txnid :
                        txn_dependencies.append(txnid)
                    else:
                        fail_explit_commit_dependencies = True
                        break
            
                if fail_explit_commit_dependencies:
                    return submitted_any
                    
                # OK, all commit dependencies are met. Add any transaction dependecies explicitly specified by client durind the commit call.
                # these will be checked by the submitter
                for txn_id in response.txn_params['dependency_list_txnids']:
                    txn_dependencies.append(txn_id)                         
                
                # get rest of the info needed to submit txn
                ledger_config = response.txn_params['ledger_config']
                wait = response.txn_params['wait']
            
                # submit txn
                try:
                    txn_id =  response.submit_update_transaction(ledger_config, wait=wait, transaction_dependency_list=txn_dependencies)
                    if txn_id:
                        logger.info("Submitted transaction for request number %d", request_number)
                        submitted_any = True
                        del rep_completed_but_txn_not_submitted_updates[contract_id][request_number] # remove the task from the pending list
                        # acquire lock to the condition varaiable, add the commit_id to completed list, notify, and release the lock
                        cls.txn_completion_condition.acquire()
                        cls.set_of_completed_txns.add(commit_id)
                        cls.txn_completion_condition.notify()
                        cls.txn_completion_condition.release()
                    else:
                        logger.error("Did not get a transaction id after transaction submission,  request nunmber %d", request_number)
                        cls.transaction_submission_exceptions_queue.put("Did not get a transaction id after transaction submission")
                        raise Exception("Did not get a transaction id after transaction submission,  request nunmber %d", request_number)
                except Exception as e:
                    logger.error("Transaction submission failed, request nunmber %d %s", request_number, str(e))
                    cls.transaction_submission_exceptions_queue.put("Transaction submission failed")
                    raise Exception("Transaction submission failed, request nunmber %d %s", request_number, str(e))
            
            return submitted_any

        # -------------------------------------------------------

        rep_completed_but_txn_not_submitted_updates = dict() # key is contract_id, value is dict(k:v). k = request_number from the commit _id
        # and v is everything else needed to submit transaction
        
        poll_next = True
        
        while poll_next:
            task = cls.pending_transactions_queue.get()

            # check if the task corresponds to a termination signal (indicating an exception of any kind)
            if task.get('exit_now'):
                logger.info("Exiting transaction submission woker thread")
                break

            commit_id = task['commit_id']
            contract_id = commit_id[0]
            request_number = commit_id[2]
            
            if rep_completed_but_txn_not_submitted_updates.get(contract_id):
                rep_completed_but_txn_not_submitted_updates[contract_id][request_number] =  task
            else:
                rep_completed_but_txn_not_submitted_updates[contract_id] = dict({request_number: task})
            
            # submit transactions as many as possible for the contract_id just added 
            try:
                submitted_any = submit_doable_transactions_for_contract(contract_id)
            except Exception as e:
                cls.transaction_submission_exceptions_queue("Failure in submit_doable_transactions_for_contract")
                logger.error("Failure in submit_doable_transactions_for_contract, %s", str(e))
                raise Exception("Failure in submit_doable_transactions_for_contract, %s", str(e))
                                
            # loop over all contracts_ids. For each check contract_id, submit transactions as many as possible.
            # Continue looping until no transaction can be submitted for any conrtract_id
            if submitted_any and len(rep_completed_but_txn_not_submitted_updates.keys()) > 1:
                while True:
                    loop_again = False
                    
                    for contract_id in list(rep_completed_but_txn_not_submitted_updates.keys()):
                        try:
                            submitted_any = submit_doable_transactions_for_contract(contract_id)
                        except Exception as e:
                            cls.transaction_submission_exceptions_queue("Failure in submit_doable_transactions_for_contract")
                            logger.error("Failure in submit_doable_transactions_for_contract, %s", str(e))
                            raise Exception("Failure in submit_doable_transactions_for_contract, %s", str(e))
                        loop_again = loop_again or submitted_any
                    
                    if loop_again is False:
                        break    

    # -------------------------------------------------------
    def __init__(self, request, response) :
        """
        Initialize a contract response object

        :param request: the ContractRequest object corresponding to the response
        :param response: diction containing the response from the enclave
        """
        self.status = response['Status']
        self.result = response['Result']
        self.state_changed = response['StateChanged']
        self.new_state_object = request.contract_state
        #if the new state is same as the old state, then change set is empty 
        self.new_state_object.changed_block_ids=[]
        self.replication_params = request.replication_params
        self.storage_clients_for_replication = request.storage_clients_for_replication
        self.request_number = request.request_number
        
        if self.status and self.state_changed :
            self.signature = response['Signature']
            state_hash_b64 = response['StateHash']

            # we have another mismatch between the field names in the enclave
            # and the field names expected in the transaction; this needs to
            # be fixed at some point
            self.dependencies = []
            for dependency in response['Dependencies'] :
                contract_id = dependency['ContractID']
                state_hash = dependency['StateHash']
                self.dependencies.append({'contract_id' : contract_id, 'state_hash' : state_hash})

            # save the information we will need for the transaction
            self.channel_keys = request.channel_keys
            self.contract_id = request.contract_id
            self.creator_id = request.creator_id
            self.code_hash = request.contract_code.compute_hash()
            self.message_hash = request.message.compute_hash()
            self.new_state_hash = crypto.base64_to_byte_array(state_hash_b64)
            
            self.originator_keys = request.originator_keys
            self.enclave_service = request.enclave_service

            self.old_state_hash = ()
            if request.operation != 'initialize' :
                self.old_state_hash = ContractState.compute_hash(request.contract_state.raw_state)

            if not self.__verify_enclave_signature(request.enclave_keys) :
                raise Exception('failed to verify enclave signature')

            self.raw_state = self.enclave_service.get_block(state_hash_b64)
            self.new_state_object = ContractState(self.contract_id, self.raw_state)
            self.new_state_object.pull_state_from_eservice(self.enclave_service)
            
            # compute ids of blocks in the change set (used for replication)
            self.new_state_object.compute_ids_of_newblocks(request.contract_state.component_block_ids)
            self.replicator = Replicator(self.replication_params, self.storage_clients_for_replication, \
                self.contract_id, self.new_state_object.changed_block_ids, request.enclave_service)

    # -------------------------------------------------------
    
    @property
    def commit_id(self):
        if self.status and self.state_changed:
            return (self.contract_id, self.new_state_hash, self.request_number)
        else:
            return None
        
    # -------------------------------------------------------
    def replicate_change_set(self):
        """replicate change set for the current contract state to all provisioned enclaves"""
            
        try:
            self.replicator.replicate_change_set()
        except ReplicationException as e:
            logger.exception("Failed to replicate change set %s", str(e))
            raise Exception("Failed to replicate change set %s", str(e))

    # -------------------------------------------------------    
    def commit_asynchronously(self, ledger_config, wait, dependency_list_txnids=[], dependency_list_commit_ids=[], use_ledger=True):
        """Commit includes two steps: First, replicate the change set to all provisioned encalves. Second, 
        commit the transaction to the ledger. In this method, we add a job to the replication queue to enable the first step. The job will 
        be picked by a replicator thead which after replication will add a sumit txn job to the pending transactions queue for the 
        second step """

        #sanity check: ensure that commit_id is not None
        if self.commit_id is None:
            logger.error('Commiting a response that should not be committed. Perhaps the state did not change? Or a failed update?')
            raise Exception('Commiting a response that should not be committed. Perhaps the state did not change? Or a failed update?')

        #start threads for commiting response if not done before
        if ContractResponse.__start_threads_for_commit__:
            # start replicator threads
            for i in range(Replicator.get_max_num_replicator_threads()):
                Replicator.replication_executor.submit(Replicator.replication_worker)
                
            # start txn submisstion thread
            if use_ledger:
                ContractResponse.transaction_executor.submit(ContractResponse.transaction_submission_worker)
                
            ContractResponse.__start_threads_for_commit__ = False
        
        txn_params = dict()
        txn_params['use_ledger'] = use_ledger
        txn_params['ledger_config'] = ledger_config
        txn_params['wait'] = wait
        txn_params['dependency_list_txnids'] = dependency_list_txnids
        txn_params['dependency_list_commit_ids']=dependency_list_commit_ids
        self.txn_params = txn_params
                
        Replicator.pending_replications_queue.put(dict({'response_object': self}))
        
        return self.commit_id
           
    # -------------------------------------------------------

    def report_replication_completion(self):
        """this is the call back function after replication. This function's job is to add the replication completion status to a queue, 
        which will be processed by a "submit transaction" thread whose job is to submit transactions corresponding to completed replication tasks.
        Such a separate thread to centralize transaction submissions helps easily ensure that a txn is submitted only after 
        txns for all past updates are submitted """
        
        if self.txn_params['use_ledger']: # add the task to the transaction proceesing queue only if ledger is in use
            params = dict()
            params['commit_id'] = self.commit_id
            params['response_object'] = self
            ContractResponse.pending_transactions_queue.put(params)
        else:
            # in this case simply log the commit_id for the completed replication task. this is usual to check the status of completed tasks
            Replicator.replication_completion_condition.acquire()
            Replicator.set_of_completed_replications.add(self.commit_id)
            Replicator.replication_completion_condition.notify()
            Replicator.replication_completion_condition.release()

    # -------------------------------------------------------
    def __verify_enclave_signature(self, enclave_keys) :
        """verify the signature of the response
        """
        message = self.__serialize_for_signing()
        return enclave_keys.verify(message, self.signature, encoding = 'b64')

    # -------------------------------------------------------
    def __serialize_for_signing(self) :
        """serialize the response for enclave signature verification"""

        message = crypto.string_to_byte_array(self.channel_keys.txn_public)
        message += crypto.string_to_byte_array(self.contract_id)
        message += crypto.string_to_byte_array(self.creator_id)

        message += self.code_hash
        message += self.message_hash
        message += self.new_state_hash
        message += self.old_state_hash

        for dependency in self.dependencies :
            message += crypto.string_to_byte_array(dependency['contract_id'])
            message += crypto.string_to_byte_array(dependency['state_hash'])

        return message

    # -------------------------------------------------------
    def submit_initialize_transaction(self, ledger_config, **extra_params) :
        """submit the initialize transaction to the ledger
        """

        if self.status is False :
            raise Exception('attempt to submit failed initialization transactions')

        global transaction_dependencies

        # an initialize operation has no previous state
        assert not self.old_state_hash

        initialize_submitter = Submitter(
            ledger_config['LedgerURL'],
            key_str = self.channel_keys.txn_private)

        b64_message_hash = crypto.byte_array_to_base64(self.message_hash)
        b64_new_state_hash = crypto.byte_array_to_base64(self.new_state_hash)
        b64_code_hash = crypto.byte_array_to_base64(self.code_hash)

        raw_state = self.raw_state
        try :
            raw_state = raw_state.decode()
        except AttributeError :
            pass

        txnid = initialize_submitter.submit_ccl_initialize_from_data(
            self.originator_keys.signing_key,
            self.originator_keys.verifying_key,
            self.channel_keys.txn_public,
            self.enclave_service.enclave_id,
            self.signature,
            self.contract_id,
            b64_message_hash,
            b64_new_state_hash,
            raw_state,
            b64_code_hash,
            **extra_params)

        if txnid :
            transaction_dependencies.SaveDependency(self.contract_id, b64_new_state_hash, txnid)

        return txnid

    # -------------------------------------------------------
    def submit_update_transaction(self, ledger_config, **extra_params):
        """submit the update transaction to the ledger
        """

        if self.status is False :
            raise Exception('attempt to submit failed update transaction')

        global transaction_dependencies

        # there must be a previous state hash if this is
        # an update
        assert self.old_state_hash

        update_submitter = Submitter(
            ledger_config['LedgerURL'],
            key_str = self.channel_keys.txn_private)

        b64_message_hash = crypto.byte_array_to_base64(self.message_hash)
        b64_new_state_hash = crypto.byte_array_to_base64(self.new_state_hash)
        b64_old_state_hash = crypto.byte_array_to_base64(self.old_state_hash)

        # convert contract dependencies into transaction dependencies
        # to ensure that the sawtooth validator does not attempt to
        # re-order the transactions since it is unaware of the semantics
        # of the contract dependencies
        txn_dependencies = set()
        if extra_params.get('transaction_dependency_list') :
            txn_dependencies.update(extra_params['transaction_dependency_list'])

        txnid = transaction_dependencies.FindDependency(ledger_config, self.contract_id, b64_old_state_hash)
        if txnid :
            txn_dependencies.add(txnid)

        for dependency in self.dependencies :
            contract_id = dependency['contract_id']
            state_hash = dependency['state_hash']
            txnid = transaction_dependencies.FindDependency(ledger_config, contract_id, state_hash)
            if txnid :
                txn_dependencies.add(txnid)
            else :
                raise Exception('failed to find dependency; {0}:{1}'.format(contract_id, state_hash))

        if txn_dependencies :
            extra_params['transaction_dependency_list'] = list(txn_dependencies)

        raw_state = self.raw_state
        try :
            raw_state = raw_state.decode()
        except AttributeError :
            pass

        # now send off the transaction to the ledger
        txnid = update_submitter.submit_ccl_update_from_data(
            self.originator_keys.verifying_key,
            self.channel_keys.txn_public,
            self.enclave_service.enclave_id,
            self.signature,
            self.contract_id,
            b64_message_hash,
            b64_new_state_hash,
            b64_old_state_hash,
            raw_state,
            self.dependencies,
            **extra_params)

        if txnid :
            transaction_dependencies.SaveDependency(self.contract_id, b64_new_state_hash, txnid)

        return txnid
