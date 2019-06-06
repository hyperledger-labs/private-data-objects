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
from sawtooth.helpers.pdo_connect import PdoRegistryHelper
from pdo.submitter.submitter import Submitter

import logging
logger = logging.getLogger(__name__)

# -----------------------------------------------------------------
__transaction_executor__ = concurrent.futures.ThreadPoolExecutor(max_workers=1) # executor that submit transactions
__pending_transactions_queue__ = queue.Queue()
__condition_variable_for_completed_transactions__ = threading.Condition() # used to notify the parent thread about a new task
                                                                          # that got completed (if the parent is waiting)
__stop_service__ = False
__set_of_failed_transactions__ = set()

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

# -----------------------------------------------------------------
__dependencies__ = Dependencies()
__lock_for_dependencies__ = threading.RLock()

# -----------------------------------------------------------------
def start_transaction_processing_service():

    __transaction_executor__.submit(__transaction_worker__)

# -----------------------------------------------------------------
def stop_transacion_processing_service():

    global __stop_service__
    __stop_service__ = True

    #shutdown executor
    __transaction_executor__.shutdown(wait=True)

# -----------------------------------------------------------------
def add_transaction_task(task):

    __pending_transactions_queue__.put(task)

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
            ledger_config = transaction_request.ledger_config

            # Check for depedencies:
            if response.operation != 'initialize' :
                txn_dependencies = []

                #First check if transaction for old state is successful
                txnid = __dependencies__.FindDependency(ledger_config, contract_id, crypto.byte_array_to_base64(response.old_state_hash))
                if txnid is 'pending': # yet to complete the transaction (commit attempted by the same client)
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
                    txnid = __dependencies__.FindDependency(ledger_config, contract_id_dep, state_hash_dep)
                    if txnid is 'pending': # yet to complete the transaction (commit attempted by the same client)
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
                    txn_id =  __submit_update_transaction__(response, transaction_request.ledger_config, wait=transaction_request.wait, \
                        transaction_dependency_list=txn_dependencies)
                else:
                    txn_id = __submit_initialize_transaction__(response, transaction_request.ledger_config, wait=transaction_request.wait)

                if txn_id:
                    logger.info("Submitted transaction for request %d", request_number)
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
    rep_completed_but_txn_not_submitted_updates = dict() # key is contract_id, value is dict(k:v). k = request_number from the commit _id
    # and v is everything else needed to submit transaction

    while True:

        try:# wait for a new task. Task is the reponse object for the update
            try:
                response = __pending_transactions_queue__.get(timeout=1.0)
            except:
                # check for termination signal
                if __stop_service__:
                    logger.info("Exiting transaction submission thread")
                    break
                else:
                    continue

            contract_id = response.commit_id[0]
            request_number = response.commit_id[2]
            logger.info('received transaction request for request %d', request_number)
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

# -------------------------------------------------------
def __submit_initialize_transaction__(response, ledger_config, **extra_params):
    """submit the initialize transaction to the ledger
    """

    if response.status is False :
        raise Exception('attempt to submit failed initialization transactions')

    # an initialize operation has no previous state
    assert not response.old_state_hash

    initialize_submitter = Submitter(
        ledger_config['LedgerURL'],
        key_str = response.channel_keys.txn_private)

    b64_message_hash = crypto.byte_array_to_base64(response.message_hash)
    b64_new_state_hash = crypto.byte_array_to_base64(response.new_state_hash)
    b64_code_hash = crypto.byte_array_to_base64(response.code_hash)

    raw_state = response.raw_state
    try :
        raw_state = raw_state.decode()
    except AttributeError :
        pass

    txnid = initialize_submitter.submit_ccl_initialize_from_data(
        response.originator_keys.signing_key,
        response.originator_keys.verifying_key,
        response.channel_keys.txn_public,
        response.enclave_service.enclave_id,
        response.signature,
        response.contract_id,
        b64_message_hash,
        b64_new_state_hash,
        raw_state,
        b64_code_hash,
        **extra_params)

    if txnid :
        __lock_for_dependencies__.acquire()
        __dependencies__.SaveDependency(response.contract_id, b64_new_state_hash, txnid)
        __lock_for_dependencies__.release()

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

    update_submitter = Submitter(
        ledger_config['LedgerURL'],
        key_str = response.channel_keys.txn_private)

    b64_message_hash = crypto.byte_array_to_base64(response.message_hash)
    b64_new_state_hash = crypto.byte_array_to_base64(response.new_state_hash)
    b64_old_state_hash = crypto.byte_array_to_base64(response.old_state_hash)

    # get transaction dependency list from the input
    txn_dependencies = set()
    if extra_params.get('transaction_dependency_list') :
        txn_dependencies.update(extra_params['transaction_dependency_list'])

    raw_state = response.raw_state
    try :
        raw_state = raw_state.decode()
    except AttributeError :
        pass

    # now send off the transaction to the ledger
    txnid = update_submitter.submit_ccl_update_from_data(
        response.originator_keys.verifying_key,
        response.channel_keys.txn_public,
        response.enclave_service.enclave_id,
        response.signature,
        response.contract_id,
        b64_message_hash,
        b64_new_state_hash,
        b64_old_state_hash,
        raw_state,
        response.dependencies,
        **extra_params)

    if txnid :
        __lock_for_dependencies__.acquire()
        __dependencies__.SaveDependency(response.contract_id, b64_new_state_hash, txnid)
        __lock_for_dependencies__.release()

    return txnid

# -----------------------------------------------------------------
class TransactionRequest(object):

    def __init__(self, ledger_config, commit_id, wait_parameter_for_ledger = 30):

        self.ledger_config = ledger_config
        self.commit_id = commit_id
        self.wait = wait_parameter_for_ledger

        self.is_completed = False
        self.is_failed = False
        self.txn_id = None

        # add a pending status corresponding to the transaction in the dependency cache
        __lock_for_dependencies__.acquire()
        __dependencies__.SaveDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]), 'pending')
        __lock_for_dependencies__.release()

    # -----------------------------------------------------------------
    def mark_as_completed(self):
        __condition_variable_for_completed_transactions__.acquire()
        self.is_completed = True

        # add a transaction id field that the application may query for
        if not self.is_failed:
            self.txn_id = __dependencies__.FindDependency(self.ledger_config, self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]))
        else:
            self.txn_id = None

        #notify parent thread (if waiting)
        __condition_variable_for_completed_transactions__.notify()
        __condition_variable_for_completed_transactions__.release()

    # -----------------------------------------------------------------
    def mark_as_failed(self):
        # mark txn_id as None in the dependency cache
        __lock_for_dependencies__.acquire()
        __dependencies__.SaveDependency(self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]), None)
        __lock_for_dependencies__.release()

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

        txn_id = __dependencies__.FindDependency(self.ledger_config, self.commit_id[0], crypto.byte_array_to_base64(self.commit_id[1]))
        return txn_id
