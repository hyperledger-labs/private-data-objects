<!---
Licensed under Creative Commons Attribution 4.0 International License
https://creativecommons.org/licenses/by/4.0/
--->

A client may maintain a local eservice database that maps known enclave_ids to the corresponding URLs of the hosting eservcies. The database
can be shared across multiple contracts by the same client. The client maitains database as a json file with each entry being a (key, value). key is a short name for the service, value is a dictonary with entries for 'id' and 'url'. 'id' denotes the id of the enclave hosted by the eservice.

Database management is possible via command line using the shell command pdo-eservicedb. Options include create, add, update and remove. The default service_db file name is picked from pcontract.toml. For create, the urls and names are also picked from toml. Any command line option will however override the values in pcontract.toml. For add, update, remove, the urls and names must be provided via command line. The values in toml are not used to prevent inadvertent behaviour.

Name, id (enclave_id) and url are all synonyms for a given eservice. Exceptions will be raised (especially during information retrieval) if there are violations. To fix a broken database, use the remove command to remove multiple or replicated entries for a given identifier from the database. After remove, use the add command to add a unique entry for a given identifier.

Usage Examples:

# Create a new database with 2 entires. The name e1 (e2) gets assocaited with first (second) url. It is assumed that the json file does not exist previously, else creation will fail. The enclave_id will be automatically populated, as long as the eservice@url hosts an enclave
pdo-eservicedb create --eservice-url http://localhost:7101 http://localhost:7102 --eservice-name e1 e2

# Add a new entry to the database. The enclave_id will be automatically populated, as long as the eservice@url hosts an enclave
pdo-eservicedb add --eservice-url http://localhost:7103 --eservice-name e3

# Remove an entry by name from the database.
pdo-eservicedb remove  --eservice-name e3

# Remove an entry by url from the database.
pdo-eservicedb remove   --eservice-url http://localhost:7102

# Update an entry by name. The url associated with name will replaced with the new url. The enclave_id will be updated as well
pdo-eservicedb update --eservice-name e1 --eservice-url http://localhost:7102

# update an entry by url. Use this to update the enclave_id corresponding to eservice@url
pdo-eservicedb update  --eservice-url http://localhost:7102

Pdo test scripts can take advantage of the database to identify an enclave for running the contract. It is enough to provide the name(s) of the eservice(s) to be used for the contract. The exact policy for provisioning or chosing enclaves (if more than one name is passed as input) is outside the scope of the database manager functionality. This gets implemeneted as part of the specific test script, see the individual test script for details.

Usage Examples:

# run mock contract contract with test-request. Contract enclave is provisioned @ e1
pdo-test-request --no-ledger  --eservice-name e1

# run interger key contract with test-contract. Contract enclave is provisioned @ e2
pdo-test-contract --no-ledger --contract integer-key --eservice-name e2

# create a new mock-contract with pdo-create. Provision three enclaves @e1, e2, e3 to contract
pdo-create --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
     --identity user1 --save-file ${SAVE_FILE} \
    --contract mock-contract --source _mock-contract.b64 --eservice-name e1 e2 e3

#update a previously created mock contract. Use enclave @ e3 to run the contract
pdo-update --config ${CONFIG_FILE} --ledger ${PDO_LEDGER_URL} \
                       --identity user1 --save-file ${SAVE_FILE}
                       --eservice-name e3   "'(inc-value)"

# create a contrac via the pdo-shell. Provision 5 encalves@e1, e2, e3, e4, e5 for the contract
pdo-shell --ledger $PDO_LEDGER_URL --eservice-name e1 e2 e3 e4 e5  \
    -s ${SRCDIR}/contracts/exchange/scripts/create.psh -m color red

# update a contract via the pdo-shell. Use enclave@e4 to run the contract
pdo-shell --ledger $PDO_LEDGER_URL --eservice-name e${p}  \
    -s ${SRCDIR}/contracts/exchange/scripts/issue.psh -m color red -m issuee user$p -m count $(($p * 10))
