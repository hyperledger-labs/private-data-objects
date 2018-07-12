 # ADDITION OF NEW INTERPRETTER

PDO code : https://github.com/karthikamurthy/private-data-objects.git , Branch : Addition_Cpp.<br />
This Pull Request contains the following changes:<br />
Added a generic C++ contract interpreter. <br />
>	Implement the generic interpreter and integrate it in the PDO enclave lib <br /> 
>>>	1. Added 4 files IntKeyContractExecuter.h IntKeyContractExcuter.cpp IntKeyContractWrapper.h IntKeyContractWrapper.cpp<br />
>>>	2. Added CmakeList file to include it to the common library.<br />
>>>	3. The new interpretter folder was placed parallel to gipsy foler i.e PDO_DIR/common/interpretter/intKeyFolder<br />
	
>	Implement a client side (python) scripts for testing the interpreter<br />
>>	1. Added 3 test-request-intkey.cpp, contracts/intkey.txt, contract/intkey.exp<br />

>	Integrate interpreter into PDO in simulated SGX mode: <br />
>>	1. Changed python/pdo/contracts/code.py, python/pdo/contract/contract.py<br />

>	Updated PDO build process to allow conditional compilation of the specified interpreter  <br />

>>	1. Used a Environmental variable GIPSY_ENABLED for conditional compilation.<br />
>>	2. Changes 4 Files : common/CMakeLists.txt, common/interpreter/CMakeLists.txt,eservice/lib/libpdo_enclave/CMakeLists.txt,
	pservice/lib/libpdo_enclave/CMakeLists.txt<br />

*****************************************************************************************************************
common/CMakeLists.txt <br />

IF($ENV{GIPSY_ENABLED})  <br />
ADD_SUBDIRECTORY(packages/tinyscheme)  <br />

ENDIF() <br />

*******************************************************************************************************************
common/interpreter/CMakeLists.txt <br />
IF($ENV{GIPSY_ENABLED})<br />
ADD_SUBDIRECTORY (gipsy_scheme) <br />
ELSE()<br />
ADD_SUBDIRECTORY(intkey_cpp_contract_test)<br />
ENDIF()<br />

*******************************************************************************************************************
common/interpreter/intkey_cpp_contract_test/CMakeLists.txt<br />

New File<br />

*******************************************************************************************************************
eservice/lib/libpdo_enclave/CMakeLists.txt<br />

IF($ENV{GIPSY_ENABLED})<br />
INCLUDE_DIRECTORIES(${PDO_TOP_DIR}/common/packages/tinyscheme )<br />
ENDIF()<br />

IF(NOT $ENV{GIPSY_ENABLED})<br />
ADD_DEFINITIONS(-DINTKEY_CPP_CONTRACT_TEST )<br />
ENDIF()<br />

IF($ENV{GIPSY_ENABLED})<br />
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group -ltinyscheme -lgipsy -Wl,--end-group)<br />
ELSE()<br />
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group  -lintkey  -Wl,--end-group)<br />
ENDIF()<br />

*******************************************************************************************************************
pservice/lib/libpdo_enclave/CMakeLists.txt<br />

IF($ENV{GIPSY_ENABLED})<br />
INCLUDE_DIRECTORIES(${PDO_TOP_DIR}/common/packages/tinyscheme )<br />
ENDIF()<br />

IF(NOT $ENV{GIPSY_ENABLED})<br />
ADD_DEFINITIONS(-DINTKEY_CPP_CONTRACT_TEST )<br />
ENDIF()<br />

IF($ENV{GIPSY_ENABLED})<br />
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group -ltinyscheme -lgipsy -Wl,--end-group)<br />
ELSE()<br />
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group  -lintkey  -Wl,--end-group)<br />
ENDIF()<br />

********************************************************************************************************************
eservice/lib/libpdo_enclave/contract_request.cpp<br />

#ifdef INTKEY_CPP_CONTRACT_TEST<br />
    IntKeyCppContractWrapper interpreter;<br />
#else<br />
    GipsyInterpreter interpreter;<br />
#endif<br />

**********************************************************************************************************************

eservice /tests / contracts /intkey.exp <br />
newfile <br />
***********************************************************************************************************************

eservice /tests / contracts / intkey.txt <br />
newfile <br />
***********************************************************************************************************************

python /pdo / contract /<br />
code.py basename = putils.build_file_name(source_name, extension = '.scm')<br />
gipsy_enabled = os.environ.get('GIPSY_ENABLED') <br />
if gipsy_enabled == 'false' : <br />
	basename = putils.build_file_name(source_name, extension ='.txt') <br />
else : <br />
	basename = putils.build_file_name(source_name, extension = '.scm') <br />
************************************************************************************************************************

python / pdo / contract /contract.py <br />
def create_initialize_request(self, request_originator_keys,enclave_service, **kwargs)<br />
************************************************************************************************************************

If Sawtooth and PDO are in different servers, we need to change the IP address of host machine from<br />
        client/etc/auction-test.toml<br />
        client/etc/sample_client.toml<br />
        eservice/etc/sample_eservice.toml<br />
        pservice/etc/sample_pservice.toml<br />

*************************************************************************************************************************
          
