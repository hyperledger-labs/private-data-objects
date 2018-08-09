#include "CppProcessor.h"
#include <iostream>
#include <string>

ContractDispatchTableEntry* LookUpContract(std::string contract_code)
{
    for (int i = 0; contractDisptachTable[i].project_name != NULL; i++)
    {
        int l = strlen(contractDisptachTable[i].project_name);
        if (contract_code.compare(contractDisptachTable[i].project_name) == 0)
        {
            return &contractDisptachTable[i];
        }
    }
    // if we are here, the contract is not found -> throw an exception
}

CppProcessor::CppProcessor() {}

CppProcessor::~CppProcessor() {}

void CppProcessor::create_initial_contract_state(const std::string& inContractID,
    const std::string& inCreatorID,
    const pc::ContractCode& inContract,
    const pc::ContractMessage& inMessage,
    pc::ContractState& outContractState)
{
    std::string contractCode = inContract.Code.c_str();
    std::size_t pos = contractCode.find(':');
    std::string enclave_type = contractCode.substr(pos + 1);
    ContractDispatchTableEntry* entry = LookUpContract(enclave_type);
    entry->contract_factory_ptr()->create_initial_contract_state(
        inContractID, inCreatorID, inContract, inMessage, outContractState);
}

void CppProcessor::send_message_to_contract(const std::string& inContractID,
    const std::string& inCreatorID,
    const pc::ContractCode& inContract,
    const pc::ContractMessage& inMessage,
    const pc::ContractState& inContractState,
    pc::ContractState& outContractState,
    std::map<std::string, std::string>& outDependencies,
    std::string& outMessageResult)
{
    ContractDispatchTableEntry* entry = LookUpContract(inContract.Code.c_str());
    entry->contract_factory_ptr()->send_message_to_contract(inContractID, inCreatorID, inContract,
        inMessage, inContractState, outContractState, outDependencies, outMessageResult);
}
