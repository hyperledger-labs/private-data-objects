ADDITION OF NEW INTERPRETTER

PDO code : https://github.com/karthikamurthy/private-data-objects.git , Branch : Addition_Cpp.
This Pull Request contains the following changes:
• Added a generic C++ contract interpreter. 
	Implement the generic interpreter and integrate it in the PDO enclave lib
	1. Added 4 files IntKeyContractExecuter.h IntKeyContractExcuter.cpp IntKeyContractWrapper.h IntKeyContractWrapper.cpp
	2. Added CmakeList file to include it to the common library.
	3. The new interpretter folder was placed parallel to gipsy foler i.e PDO_DIR/common/interpretter/intKeyFolder
	Implement a client side (python) scripts for testing the interpreter
	1. Added 3 test-request-intkey.cpp, contracts/intkey.txt, contract/intkey.exp
	Integrate interpreter into PDO in simulated SGX mode: 
	1. Changed python/pdo/contracts/code.py, python/pdo/contract/contract.py
	Updated PDO build process to allow conditional compilation of the specified interpreter  
	1. Used a Environmental variable GIPSY_ENABLED for conditional compilation.
	2. Changes 4 Files : common/CMakeLists.txt, common/interpreter/CMakeLists.txt,eservice/lib/libpdo_enclave/CMakeLists.txt,
	pservice/lib/libpdo_enclave/CMakeLists.txt

*****************************************************************************************************************

common/CMakeLists.txt
IF($ENV{GIPSY_ENABLED})
ADD_SUBDIRECTORY(packages/tinyscheme)
ENDIF()
*******************************************************************************************************************

common/interpreter/CMakeLists.txt
IF($ENV{GIPSY_ENABLED})
ADD_SUBDIRECTORY (gipsy_scheme)
ELSE()
ADD_SUBDIRECTORY(intkey_cpp_contract_test)
ENDIF()
*******************************************************************************************************************

common/interpreter/intkey_cpp_contract_test/CMakeLists.txt
New File
*******************************************************************************************************************

eservice/lib/libpdo_enclave/CMakeLists.txt

IF($ENV{GIPSY_ENABLED})
INCLUDE_DIRECTORIES(${PDO_TOP_DIR}/common/packages/tinyscheme )
ENDIF()

IF(NOT $ENV{GIPSY_ENABLED})
ADD_DEFINITIONS(-DINTKEY_CPP_CONTRACT_TEST )
ENDIF()

IF($ENV{GIPSY_ENABLED})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group -ltinyscheme -lgipsy -Wl,--end-group)
ELSE()
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group  -lintkey  -Wl,--end-group)
ENDIF()
*******************************************************************************************************************

pservice/lib/libpdo_enclave/CMakeLists.txt

IF($ENV{GIPSY_ENABLED})
INCLUDE_DIRECTORIES(${PDO_TOP_DIR}/common/packages/tinyscheme )
ENDIF()

IF(NOT $ENV{GIPSY_ENABLED})
ADD_DEFINITIONS(-DINTKEY_CPP_CONTRACT_TEST )
ENDIF()

IF($ENV{GIPSY_ENABLED})
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group -ltinyscheme -lgipsy -Wl,--end-group)
ELSE()
TARGET_LINK_LIBRARIES(${PROJECT_NAME} -Wl,--start-group  -lintkey  -Wl,--end-group)
ENDIF()
********************************************************************************************************************

eservice/lib/libpdo_enclave/contract_request.cpp
#ifdef INTKEY_CPP_CONTRACT_TEST
    IntKeyCppContractWrapper interpreter;
#else
    GipsyInterpreter interpreter;
#endif
**********************************************************************************************************************

eservice /tests / contracts /intkey.exp 
newfile 
***********************************************************************************************************************

eservice /tests / contracts / intkey.txt 
newfile 
***********************************************************************************************************************

python /pdo / contract /
code.py basename = putils.build_file_name(source_name, extension = '.scm')
gipsy_enabled = os.environ.get('GIPSY_ENABLED') 
if gipsy_enabled == 'false' : 
	basename = putils.build_file_name(source_name, extension ='.txt') 
else : 
	basename = putils.build_file_name(source_name, extension = '.scm') 
************************************************************************************************************************

python / pdo / contract /contract.py 
def create_initialize_request(self, request_originator_keys,enclave_service, **kwargs)
************************************************************************************************************************

If Sawtooth and PDO are in different servers, we need to change the IP address of host machine from
        client/etc/auction-test.toml
        client/etc/sample_client.toml
        eservice/etc/sample_eservice.toml
        pservice/etc/sample_pservice.toml

*************************************************************************************************************************
          
