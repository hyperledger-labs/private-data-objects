<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

A client may maintain a local eservice database that maps known enclave_ids to the corresponding URLs of the hosting eservcies. The database
can be shared across multiple contracts by the same client. The client maitains database as a json file with each entry being a (key, value). key is enclave_id, value is eservice URL.

The test scripts pdo-test-request, pdo-test-contract, pdo-create, pdo-shell provide support for creating and updating the database

Examples:

# In both the following examples, the client updates (or creates if db does not exist) the database by adding the entry corresponding to the enclave hosted at http://127.0.0.1:7101, if this entry is not already present in the database
pdo-test-request --no-ledger   \
    --eservice-url http://127.0.0.1:7101 \
    --enclaveservice-db ${ESERVICE_URL_DB_FILE}

pdo-test-contract --no-ledger --contract integer-key \
    --eservice http://127.0.0.1:7102 \
     --enclaveservice-db ${ESERVICE_URL_DB_FILE}


A client can use the database while peforming contract updates via pdo-update or pdo-shell

Examples:

# In the following example, client updates the contract specified by the save-file. By specifying the enclave as random-db, the contract encalve is picked at random from among the ones listed in the contract file. The corresponding eservice URL is then identified using the database.
pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
    --identity user1 --save-file ${SAVE_FILE}  --enclave random-db --enclaveservice-db ${ESERVICE_URL_DB_FILE} \
    "'(inc-value)"

# Similar usage of database while updating a contract via the pdo-shell
pdo-shell --ledger $PDO_LEDGER_URL eservice-url random-db --enclaveservice-db ${ESERVICE_URL_DB_FILE} \
-s ${SRCDIR}/contracts/exchange/scripts/issue.psh -m color red -m issuee user$p -m count $(($p * 10))

If the client does not prefer randomization in the choice of the enclave, the client can directly provide the eservice URL as the enclave option (eservice-url) in pdo-update (pdo-shell). In this case, the enclaveservice-db option is not required as part of the pdo-update or pdo-shell invocations.

As long as the client is OK with the random choice of contract enclave, the database eliminates the need for the client to track the the specific eservices used for a particular contract. The client only needs to have access to the contact file, and the sharable eservice databasea. 