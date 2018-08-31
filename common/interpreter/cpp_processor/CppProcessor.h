#pragma once

#include <map>
#include <string>
#include "ContractInterpreter.h"
#include "CppProcessorHandler.h"

namespace pc = pdo::contracts;

typedef CppContractWrapper* (*contract_factory)();

struct ContractDispatchTableEntry
{
    const char* contract_id;
    contract_factory contract_factory_ptr;
};

class CppProcessor : public pc::ContractInterpreter
{
public:
    CppProcessor(void);
    ~CppProcessor(void);

    virtual void create_initial_contract_state(const std::string& inContractID,
        const std::string& inCreatorID,
        const pc::ContractCode& inContract,
        const pc::ContractMessage& inMessage,
        pc::ContractState& outContractState);

    virtual void send_message_to_contract(const std::string& inContractID,
        const std::string& inCreatorID,
        const pc::ContractCode& inContract,
        const pc::ContractMessage& inMessage,
        const pc::ContractState& inContractState,
        pc::ContractState& outContractState,
        std::map<std::string, std::string>& outDependencies,
        std::string& outMessageResult);
};
