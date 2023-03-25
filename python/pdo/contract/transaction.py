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

import pdo.common.crypto as crypto
import pdo.common.config as pconfig
from pdo.submitter.create import create_submitter

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
transaction_threads = []
transaction_thread_lock = threading.Lock()

transaction_task_queue = None
registry_helper = None

__condition_variable_for_completed_transactions__ = threading.Condition() # used to notify the parent thread about a new task
                                                                          # that got completed (if the parent is waiting)
__stop_service__ = False
__dependencies__ = None

# -----------------------------------------------------------------
class Dependencies(object) :
    """
    Class for mapping contract state commits to the corresponding
    ledger transaction. This class facilitates efficient assignment
    of dependencies in PDO transactions.
    """

    ## -------------------------------------------------------
    def __init__(self, registry_helper) :
        self.__depcache = {}
        self.__lock__ = threading.RLock()
        self.__submitter__ = registry_helper

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

    ## -------------------------------------------------------
    def FindDependency(self, contractid, statehash) :
        logger.debug('find dependency for %s, %s', contractid, statehash)

        with self.__lock__ :
            txnid = self.__get(contractid, statehash)
            if txnid :
                return txnid

            try :
                # this is not very efficient since it pulls all of the state
                # down with the txnid
                contract_state_info = self.__submitter__.get_state_details(contractid, statehash)
                txnid = contract_state_info['transaction_id']
                self.__set(contractid, statehash, txnid)
                return txnid
            except Exception as e :
                logger.info('unable to find dependency for %s:%s; failed to retrieve the transaction', contractid, statehash)
                return None

    ## -------------------------------------------------------
    def SaveDependency(self, contractid, statehash, txnid) :
        with self.__lock__ :
            self.__set(contractid, statehash, txnid)

# -----------------------------------------------------------------
def start_transaction_processing_service(ledger_config = None):
    global transaction_task_queue
    with transaction_thread_lock :
        if transaction_task_queue :
            return
        else :
            transaction_task_queue = queue.Queue()

    if ledger_config is None :
        ledger_config = pconfig.shared_configuration(['Ledger'])

    global registry_helper
    registry_helper = create_submitter(ledger_config)

    global __dependencies__
    __dependencies__ = Dependencies(registry_helper)

    logger.debug('start transaction service threads')
    for i in range(ledger_config.get("transaction_service_threads", 1)) :
        thread = threading.Thread(target=__transaction_worker__)
        thread.daemon = True
        thread.start()

        with transaction_thread_lock :
            transaction_threads.append(thread)

# -----------------------------------------------------------------
def stop_transacion_processing_service():

    global __stop_service__
    __stop_service__ = True

    for thread in transaction_threads[:] :
        thread.join(timeout=5.0)

# -----------------------------------------------------------------
def add_transaction_task(task):
    transaction_task_queue.put(task)

# -----------------------------------------------------------------
def __transaction_worker__():
    """This is the worker for submitting transactions"""

    def submit_doable_transactions_for_contract(contract_id):
        """ helper function to submit pending transactions for a specific contact.
        Transactions will be submitted for all pending commits whose commit dependecies are met"""

        nonlocal rep_completed_but_txn_not_submitted_updates
        submitted_any = False
        pending_requests_numbers = list(rep_completed_but_txn_not_submitted_updates[contract_id].keys())
        pending_requests_numbers.sort()

        for request_number in pending_requests_numbers:

            response = rep_completed_but_txn_not_submitted_updates[contract_id][request_number]
            transaction_request = response.transaction_request

            # Check for depedencies:
            if response.operation != 'initialize' :
                txn_dependencies = []

                #First check if transaction for old state is successful
                txnid = __dependencies__.FindDependency(contract_id, crypto.byte_array_to_base64(response.old_state_hash))
                if txnid == 'pending': # yet to complete the transaction (commit attempted by the same client)
                    break
                elif txnid is None: # either dependency failed or not found (even in ledger)
                    logger.error("Aborting transaction for request %d : unable to find transaction details for old state", request_number)
                    transaction_request.mark_as_failed()
                    del rep_completed_but_txn_not_submitted_updates[contract_id][request_number] # remove the task from the pending list
                    break
                else:
                    txn_dependencies.append(txnid) # we have a valid tx_id, add it to the set of dependencies

                # Next, check for other dependencies mentioned in the response
                fail_dependencies = False
                for dependency in response.dependencies :
                    contract_id_dep = dependency['contract_id']
                    state_hash_dep = dependency['state_hash']
                    txnid = __dependencies__.FindDependency(contract_id_dep, state_hash_dep)
                    if txnid == 'pending': # yet to complete the transaction (commit attempted by the same client)
                        fail_dependencies = True
                        break
                    elif txnid is None: # either dependency failed or not found (even in ledger)
                        logger.error("Aborting transaction for request %d : unable to find transaction details for dependency mentioned in response", \
                            request_number)
                        transaction_request.mark_as_failed()
                        del rep_completed_but_txn_not_submitted_updates[contract_id][request_number] # remove the task from the pending list
                        fail_dependencies = True
                        break
                    else:
                        txn_dependencies.append(txnid) # we have a valid tx_id, add it to the set of dependencies

                if fail_dependencies:
                    break

            # all ready to submit txn. First remove the task from the pending list
            del rep_completed_but_txn_not_submitted_updates[contract_id][request_number] # remove the task from the pending list
            try:
                if response.operation != 'initialize' :
                    txn_id =  __submit_update_transaction__(
                        response,
                        transaction_request.ledger_config,
                        transaction_dependency_list=txn_dependencies)
                else:
                    txn_id = __submit_initialize_transaction__(
                        response,
                        transaction_request.ledger_config)

                if txn_id:
                    logger.debug("Submitted transaction for request %d", request_number)
                    submitted_any = True
                    transaction_request.mark_as_completed()
                else:
                    logger.error("Did not get a transaction id after transaction submission for request %d", request_number)
                    transaction_request.mark_as_failed()
                    break
            except Exception as e:
                logger.error("Transaction submission failed for request number %d: %s", request_number, str(e))
                transaction_request.mark_as_failed()
                break

        return submitted_any

    # -------------------------------------------------------
    # key is contract_id, value is dict(k:v). k = request_number from the commit _id
    # and v is everything else needed to submit transaction
    rep_completed_but_txn_not_submitted_updates = dict()

    while True:

        # wait for a new task. Task is the reponse object for the update
        try:
            response = transaction_task_queue.get(timeout=1.0)
        except queue.Empty :
            logger.debug('empty work queue')
            if __stop_service__:
                logger.debug("Exiting transaction submission thread")
                return True
            else:
                continue
        except:
            logger.exception("shutdown exception %s", str(e))
            return False

        try:
            contract_id = response.commit_id[0]
            request_number = response.commit_id[2]
            logger.debug('received transaction request for request %d', request_number)
            if rep_completed_but_txn_not_submitted_updates.get(contract_id):
                rep_completed_but_txn_not_submitted_updates[contract_id][request_number] =  response
            else:
                rep_completed_but_txn_not_submitted_updates[contract_id] = dict({request_number: response})

            # submit as many transactions as possible for the contract_id just added
            submitted_any = submit_doable_transactions_for_contract(contract_id)

            # loop over all contracts_ids. For each check contract_id, submit as many transactions as possible.
            # Continue looping until no transaction can be submitted for any conrtract_id
            if submitted_any and len(rep_completed_but_txn_not_submitted_updates.keys()) > 1:
                loop_again = True
                while loop_again:
                    loop_again = False
                    for contract_id in rep_completed_but_txn_not_submitted_updates.keys():
                        loop_again = loop_again or submit_doable_transactions_for_contract(contract_id)
        except Exception as e:
            logger.info("transaction submission failed %s", str(e))
            return False
        finally :
            transaction_task_queue.task_done()

# -------------------------------------------------------
def __submit_initialize_transaction__(response, ledger_config, **extra_params):
    """submit the initialize transaction to the ledger
    """

    if response.status is False :
        raise Exception('attempt to submit failed initialization transactions')

    # can't use the global here because we need the pdo_signer set in the submitter
    # this should be fixed later
    initialize_submitter = create_submitter(ledger_config, pdo_signer = response.originator_keys)

    txnid = initialize_submitter.ccl_initialize(
        response.channel_keys,
        response.enclave_service.enclave_id,
        response.signature,
        response.contract_id,
        response.code_hash,
        response.message_hash,
        response.new_state_hash,
        response.metadata_hash,
        **extra_params)

    if txnid :
        __dependencies__.SaveDependency(response.contract_id,
                crypto.byte_array_to_base64(response.new_state_hash), txnid)

    return txnid

# -------------------------------------------------------
def __submit_update_transaction__(response, ledger_config, **extra_params):
    """submit the update transaction to the ledger
    """

    if response.status is False :
        raise Exception('attempt to submit failed update transaction')

    # there must be a previous state hash if this is
    # an update
    assert response.old_state_hash

    # now send off the transaction to the ledgerchannel_keys.txn_public,
    txnid = registry_helper.ccl_update(
        response.channel_keys,
        response.enclave_service.enclave_id,
        response.signature,
        response.contract_id,
        response.message_hash,
        response.new_state_hash,
        response.old_state_hash,
        response.dependencies,
        **extra_params)

    if txnid :
        __dependencies__.SaveDependency(response.contract_id, \
            crypto.byte_array_to_base64(response.new_state_hash), txnid)

    return txnid

# -----------------------------------------------------------------
class TransactionRequest(object):

    def __init__(self, ledger_config, commit_id, wait_parameter_for_ledger = None):

        self.ledger_config = ledger_config
        # add the wait parameter to the ledger config, if there is one.
        # Question: does CCF (or the submitter) use this parameter?
        if wait_parameter_for_ledger:
            self.ledger_config['wait'] = wait_parameter_for_ledger
        self.commit_id = commit_id

        self.is_completed = False
        self.is_failed = False
        self.txn_id = None

        # add a pending status corresponding to the transaction in the dependency cache
        __dependencies__.SaveDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]), 'pending')

    # -----------------------------------------------------------------
    def mark_as_completed(self):
        __condition_variable_for_completed_transactions__.acquire()
        self.is_completed = True

        # add a transaction id field that the application may query for
        if not self.is_failed:
            self.txn_id = __dependencies__.FindDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]))
        else:
            self.txn_id = None

        #notify parent thread (if waiting)
        __condition_variable_for_completed_transactions__.notify()
        __condition_variable_for_completed_transactions__.release()

    # -----------------------------------------------------------------
    def mark_as_failed(self):
        # mark txn_id as None in the dependency cache
        __dependencies__.SaveDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]), None)

        # mark as failed in the request itself so that the application may query the status. Also, mark the task as completed
        self.is_failed = True
        self.mark_as_completed()

    # -----------------------------------------------------------------
    def wait_for_completion(self):
        """ wait until completion of transaction. If success, return txn_id, else raise Exception"""

        __condition_variable_for_completed_transactions__.acquire()
        while self.is_completed is False:
            __condition_variable_for_completed_transactions__.wait()

        __condition_variable_for_completed_transactions__.release()

        if self.is_failed:
            raise Exception("Transaction submission failed for request number %d", self.commit_id[2])

        txn_id = __dependencies__.FindDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]))
        return txn_id
