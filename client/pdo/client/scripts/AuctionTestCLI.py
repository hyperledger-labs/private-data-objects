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

import os, sys
import argparse
import random
from string import Template

import logging
logger = logging.getLogger(__name__)

import pprint
pp = pprint.PrettyPrinter(indent=4)

import pdo.common.crypto as pcrypto
from pdo.client.SchemeExpression import SchemeExpression
from pdo.common.keys import ServiceKeys
from pdo.contract import ContractCode
from pdo.contract import ContractState
from pdo.contract import Contract
from pdo.contract import register_contract
from pdo.contract import add_enclave_to_contract
from pdo.service_client.enclave import EnclaveServiceClient
from pdo.service_client.provisioning import ProvisioningServiceClient

enclave_services_by_url = {}
enclave_services = {}
participant_keys = {}

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def GetEnclaveServiceByURL(url) :
    global enclave_services_by_url, enclave_service

    if url not in enclave_services_by_url :
        eservice = EnclaveServiceClient(url)
        enclave_services_by_url[url] = eservice
        enclave_services[eservice.enclave_id] = eservice

    return enclave_services_by_url[url]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def GetKeysForIdentity(config, identity) :
    key_config = config['Key']

    global participant_keys
    if identity not in participant_keys :
        #keypath = key_config['SearchPath']
        #keyfile = Template(key_config['KeyFileTemplate']).substitute({'identity' : identity })
        #participant_keys[identity] = ServiceKeys.read_from_file(keyfile, keypath)
        participant_keys[identity] = ServiceKeys.create_service_keys()

    return participant_keys[identity]

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def SendMessageAsIdentity(config, contract, invoker_keys, message, fmt = 'python', wait=False) :
    ledger_config = config.get('Sawtooth')
    contract_config = config.get('Contract')

    try :
        logger.info('send message %s to contract %s', message, contract.contract_code.name)
        enclave_id = random.choice(contract.provisioned_enclaves)
        enclave_service = enclave_services[enclave_id]

        request = contract.create_update_request(invoker_keys, enclave_service, message)
        response = request.evaluate()
        logger.info('result: %s, ', response.result)
    except Exception as e :
        logger.error('method invocation failed for message %s: %s', message, str(e))
        sys.exit(-1)

    if response.status is False :
        logger.warn('method invocation failed for %s; %s', message, response.result)
        raise Exception("method invocation failed; {0}".format(response.result))

    # if this operation did not change state then there is nothing
    # to send to the ledger or to save
    if response.state_changed :
        try :
            if wait :
                response.submit_update_transaction(ledger_config, wait=30)
            else :
                response.submit_update_transaction(ledger_config)

            contract.set_state(response.encrypted_state)

            data_dir = contract_config['DataDirectory']
            contract.contract_state.save_to_cache(data_dir=data_dir)
        except Exception as e:
            logger.error('transaction submission failed for message %s; %s', message, str(e))
            sys.exit(-1)

    expression = SchemeExpression.ParseExpression(response.result)
    if fmt == 'scheme' :
        return expression
    elif fmt == 'python' :
        return expression.value
    else :
        raise ValueError('unknown format {}'.format(fmt))

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def CreateAndRegisterContract(config, contract_info, creator_keys) :
    ledger_config = config.get('Sawtooth')
    contract_config = config.get('Contract')

    contract_creator_id = creator_keys.identity

    contract_name = contract_info['Name']
    source_file = contract_info['Source']
    search_path = contract_config['SourceSearchPath']
    contract_code = ContractCode.create_from_scheme_file(contract_name, source_file, search_path = search_path)

    # --------------------------------------------------
    logger.info('register the contract')
    # --------------------------------------------------
    pservice_urls = contract_info.get("ProvisioningServices")
    provisioning_services = list(map(lambda url : ProvisioningServiceClient(url), pservice_urls))
    provisioning_service_keys = list(map(lambda svc : svc.identity, provisioning_services))

    contract_id = register_contract(ledger_config, creator_keys, contract_code, provisioning_service_keys)
    logger.info('registered the contract as %s', contract_id)

    contract_state = ContractState.create_new_state(contract_id)
    contract = Contract(contract_code, contract_state, contract_id, contract_creator_id)

    # --------------------------------------------------
    logger.info('provision enclaves')
    # --------------------------------------------------
    eservice_urls = contract_info.get("EnclaveServices")
    enclave_services = list(map(lambda url : GetEnclaveServiceByURL(url), eservice_urls))

    for eservice in enclave_services :
        secret_list = []
        for pservice in provisioning_services :
            message = pcrypto.string_to_byte_array(eservice.enclave_id + contract_id)
            signature = creator_keys.sign(message)
            secret = pservice.get_secret(eservice.enclave_id, contract_id, creator_keys.verifying_key, signature)
            secret_list.append(secret)

        secretinfo = eservice.verify_secrets(contract_id, contract_creator_id, secret_list)
        encrypted_state_encryption_key = secretinfo['encrypted_state_encryption_key']
        signature = secretinfo['signature']

        txnid = add_enclave_to_contract(
            ledger_config,
            creator_keys,
            contract_id,
            eservice.enclave_id,
            secret_list,
            encrypted_state_encryption_key,
            signature)

        contract.set_state_encryption_key(eservice.enclave_id, encrypted_state_encryption_key)

    # --------------------------------------------------
    logger.info('create the initial contract state')
    # --------------------------------------------------
    eservice = random.choice(enclave_services)
    initialize_request = contract.create_initialize_request(creator_keys, eservice)
    initialize_response = initialize_request.evaluate()
    if initialize_response.status is False :
        emessage = initialize_response.result
        logger.warn('initialization for contract %s failed; %s', contract_name, emessage)
        raise Exception('initialization failed; {}'.format(emessage))

    contract.set_state(initialize_response.encrypted_state)

    logger.info('initial state created')

    # --------------------------------------------------
    logger.info('save the initial state in the ledger')
    # --------------------------------------------------
    txnid = initialize_response.submit_initialize_transaction(ledger_config, wait=30)

    return contract

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def CreateAssetContract(config) :
    asset_config = config['AssetContract']
    contract_config = config['Contract']

    asset_creator_identity = asset_config['Creator']
    asset_creator_keys = GetKeysForIdentity(config, asset_creator_identity)
    contract = CreateAndRegisterContract(config, asset_config, asset_creator_keys)

    data_dir = contract_config['DataDirectory']
    contract.save_to_file(asset_config['Name'], data_dir = data_dir)
    contract.contract_state.save_to_cache(data_dir = data_dir)

    return contract

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def CreateAuctionContract(config) :
    auction_config = config['AuctionContract']
    contract_config = config['Contract']

    auction_creator_identity = auction_config['Creator']
    auction_creator_keys = GetKeysForIdentity(config, auction_creator_identity)
    contract = CreateAndRegisterContract(config, auction_config, auction_creator_keys)

    data_dir = contract_config['DataDirectory']
    contract.save_to_file(auction_config['Name'], data_dir = data_dir)
    contract.contract_state.save_to_cache(data_dir = data_dir)

    return contract

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def CreateRandomAsset(config, asset_contract, invoker_keys, assetname, value = None) :
    params = {}
    params['asset'] = "asset_" + assetname
    params['value'] = random.randint(0, 100) if value is None else value
    message = Template("'(create \"${asset}\" ${value})").substitute(params)

    logger.info('create asset %s with value %s', params['asset'], params['value'])
    result = SendMessageAsIdentity(config, asset_contract, invoker_keys, message)
    if result is None :
        raise Exception('failed to create random asset')

    return params['asset']

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def EscrowAsset(config, asset_contract, invoker_keys, asset, pubkey) :
    ## ( ((key "auction") (value 5) (owner "<ownerid>")) "<signature>" )

    # first pass... escrow the asset and push the transaction
    message = "'(escrow \"{0}\" \"{1}\")".format(asset, pubkey)
    result = SendMessageAsIdentity(config, asset_contract, invoker_keys, message)

    # get the escrow attestation for handoff to the auction
    message = "'(escrow-attestation \"{0}\")".format(asset)
    result = SendMessageAsIdentity(config, asset_contract, invoker_keys, message, fmt='scheme')

    return (str(result.nth(0)), str(result.nth(1)), str(result.nth(2)))

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def CancelBid(config, auction_contract, asset_contract, invoker_keys) :
    try :
        message = "'(cancel-bid)"
        result = SendMessageAsIdentity(config, auction_contract, invoker_keys, message)

        message = "'(cancel-attestation)"
        result = SendMessageAsIdentity(config, auction_contract, invoker_keys, message, fmt='scheme')

        ## should be: (((key "offered") (value X) (owner "<ownerid")) (dependencies) "<signature>")
        assetkey = dict(result.nth(0).value)['key']
        dependencies = str(result.nth(1))
        signature = str(result.nth(2))

        message = "'(disburse \"{0}\" {1} {2})".format(assetkey, dependencies, signature)
        result = SendMessageAsIdentity(config, asset_contract, invoker_keys, message)

    except :
        pass

## -----------------------------------------------------------------
## -----------------------------------------------------------------
def LocalMain(config) :
    asset_config = config['AssetContract']
    auction_config = config['AuctionContract']
    user_config = config['Participants']

    auction_keys = GetKeysForIdentity(config, auction_config['Creator'])
    asset_keys = GetKeysForIdentity(config, asset_config['Creator'])

    # create the asset contract
    asset_contract = CreateAssetContract(config)
    asset_contract_pubkey = SendMessageAsIdentity(config, asset_contract, asset_keys, "'(get-public-signing-key)", fmt='python')

    # ---------- create the asset to use for the auction, minimum bid is 10 ----------
    auction_asset = CreateRandomAsset(config, asset_contract, auction_keys, 'auction', value = 10)

    # ---------- create the assets for each of the identities ----------
    assetmap = {}
    for identity in user_config['Asset'] :
        user_keys = GetKeysForIdentity(config, identity)
        assetmap[identity] = CreateRandomAsset(config, asset_contract, user_keys, identity)

    # ---------- create and initialize the auction contract ----------
    auction_contract = CreateAuctionContract(config)
    auction_contract_pubkey = SendMessageAsIdentity(config, auction_contract, auction_keys, "'(get-public-signing-key)", fmt='python')

    message = "'(initialize \"{0}\")".format(asset_contract_pubkey)
    result = SendMessageAsIdentity(config, auction_contract, auction_keys, message, wait=True)

    # ---------- escrow the auction asset and prime the auction----------
    (ecounter, edependencies, esignature) = EscrowAsset(
        config, asset_contract, auction_keys, auction_asset, str(auction_contract_pubkey))
    message = "'(prime-auction* {0} {1} {2})".format(ecounter, edependencies, esignature)
    result = SendMessageAsIdentity(config, auction_contract, auction_keys, message)

    # ---------- submit bids ----------
    for identity in user_config['Auction'] :
        asset = assetmap[identity]
        user_keys = GetKeysForIdentity(config, identity)
        (ecounter, edependencies, esignature) = EscrowAsset(
            config, asset_contract, user_keys, asset, auction_contract_pubkey)

        message = "'(submit-bid* {0} {1} {2})".format(ecounter, edependencies, esignature)
        result = SendMessageAsIdentity(config, auction_contract, user_keys, message)

    ## =================================================================
    # we have to wait for the transactions to commit before we continue

    #WaitForStateCommit(lwc, PrivateContractTransaction, asset_contract.ContractID, asset_contract.State.ComputeHash())
    #WaitForStateCommit(lwc, PrivateContractTransaction, auction_contract.ContractID, auction_contract.State.ComputeHash())
    ## =================================================================

    # ---------- get the max bid ----------
    message = "'(max-bid)"
    result = SendMessageAsIdentity(config, auction_contract, auction_keys, message)
    logger.info("maximum bid: %s", str(result))

    # ---------- close the bidding and transfer the assets ----------
    message = "'(close-bidding)"
    result = SendMessageAsIdentity(config, auction_contract, auction_keys, message)

    message = "'(exchange-attestation)"
    result = SendMessageAsIdentity(config, auction_contract, auction_keys, message, fmt='scheme')

    ## should be: (((key "offered") (value X) (owner "<ownerid")) ((key "bid") (value X) (owner "<ownerid")) dep sig)
    logger.debug("closed bidding with result: %s", str(result))

    offered = dict(result.nth(0).value)
    maxbid = dict(result.nth(1).value)
    dependencies = str(result.nth(2))
    signature = str(result.nth(3))

    logger.info('exchange ownership of keys %s and %s', offered['key'], maxbid['key'])

    message = "'(exchange-ownership \"{0}\" \"{1}\" {2} {3})".format(offered['key'], maxbid['key'], dependencies, signature)
    result = SendMessageAsIdentity(config, asset_contract, auction_keys, message)

    # ---------- cancel the remaining bids ----------
    for identity in user_config['Auction'] :
        logger.info("attempt to cancel bid for %s", identity)
        user_keys = GetKeysForIdentity(config, identity)
        CancelBid(config, auction_contract, asset_contract, user_keys)

    # ---------- dump the final state of the contract ----------
    result = SendMessageAsIdentity(config, asset_contract, asset_keys, "'(get-state)", fmt='python')
    pp.pprint(result)
    print("auction contract id = {0}".format(auction_contract.contract_id))
    print("asset contract id = {0}".format(asset_contract.contract_id))

    sys.exit(0)

## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## DO NOT MODIFY BELOW THIS LINE
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
## XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX

## -----------------------------------------------------------------
ContractHost = os.environ.get("HOSTNAME", "localhost")
ContractHome = os.environ.get("CONTRACTHOME") or os.path.realpath("/opt/pdo")
ContractEtc = os.environ.get("CONTRACTETC") or os.path.join(ContractHome, "etc")
ContractKeys = os.environ.get("CONTRACTKEYS") or os.path.join(ContractHome, "keys")
ContractLogs = os.environ.get("CONTRACTLOGS") or os.path.join(ContractHome, "logs")
ContractData = os.environ.get("CONTRACTDATA") or os.path.join(ContractHome, "data")
LedgerURL = os.environ.get("LEDGER_URL", "http://127.0.0.1:8008/")
ScriptBase = os.path.splitext(os.path.basename(sys.argv[0]))[0]

config_map = {
    'base' : ScriptBase,
    'data' : ContractData,
    'etc'  : ContractEtc,
    'home' : ContractHome,
    'host' : ContractHost,
    'keys' : ContractKeys,
    'logs' : ContractLogs,
    'ledger' : LedgerURL
}

# -----------------------------------------------------------------
# -----------------------------------------------------------------
def Main() :
    import pdo.common.config as pconfig
    import pdo.common.logger as plogger

    # parse out the configuration file first
    conffiles = [ 'auction-test.toml' ]
    confpaths = [ ".", "./etc", ContractEtc ]

    parser = argparse.ArgumentParser()

    parser.add_argument('--config', help='configuration file', nargs = '+')
    parser.add_argument('--config-dir', help='configuration file', nargs = '+')

    parser.add_argument('--logfile', help='Name of the log file, __screen__ for standard output', type=str)
    parser.add_argument('--loglevel', help='Logging level', type=str)

    parser.add_argument('--ledger', help='URL for the Sawtooth ledger', type=str)

    parser.add_argument('--asset-contract', help='Name of the asset contract', default="integer-key", type = str)
    parser.add_argument('--asset-identity', help='Identity to use for the asset contract', default="ikey-contract", type=str)
    parser.add_argument('--auction-contract', help='Name of the auction contract', default="auction", type = str)
    parser.add_argument('--auction-identity', help='Identity to use for the auction contract', default="auc-contract", type=str)

    parser.add_argument('--key-dir', help='Directories to search for key files', nargs='+')
    parser.add_argument('--contract-dir', help='Directories to search for contract files', nargs='+')

    options = parser.parse_args()

    # first process the options necessary to load the default configuration
    if options.config :
        conffiles = options.config

    if options.config_dir :
        confpaths = options.config_dir

    global config_map
    config_map['assetidentity'] = options.asset_identity
    config_map['assetcontract'] = options.asset_contract
    config_map['auctionidentity'] = options.auction_identity
    config_map['auctioncontract'] = options.auction_contract

    try :
        config = pconfig.parse_configuration_files(conffiles, confpaths, config_map)
    except pconfig.ConfigurationException as e :
        logger.error(str(e))
        sys.exit(-1)

    # set up the logging configuration
    if config.get('Logging') is None :
        config['Logging'] = {
            'LogFile' : '__screen__',
            'LogLevel' : 'INFO'
        }
    if options.logfile :
        config['Logging']['LogFile'] = options.logfile
    if options.loglevel :
        config['Logging']['LogLevel'] = options.loglevel.upper()

    plogger.setup_loggers(config.get('Logging', {}))

    # set up the ledger configuration
    if config.get('Sawtooth') is None :
        config['Sawtooth'] = {
            'LedgerURL' : 'http://localhost:8008',
        }
    if options.ledger :
        config['Sawtooth']['LedgerURL'] = options.ledger

    # set up the key search paths
    if config.get('Key') is None :
        config['Key'] = {
            'SearchPath' : ['.', './keys', ContractKeys]
        }
    if options.key_dir :
        config['Key']['SearchPath'] = options.key_dir

    # set up the data paths
    if config.get('Contract') is None :
        config['Contract'] = {
            'SourceSearchPath' : [ '.', './contract', os.path.join(ContractHome, 'contracts') ]
        }
    if options.contract_dir :
        config['Contract']['SourceSearchPath'] = options.contract_dir

    # GO!
    LocalMain(config)

## -----------------------------------------------------------------
## Entry points
## -----------------------------------------------------------------
Main()
