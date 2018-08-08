#pragma once

#include <map>
#include <string>

#include "ContractInterpreter.h"

namespace pc = pdo::contracts;

typedef pc::ContractInterpreter* (*contract_factory)();

struct ContractDispatchTableEntry
{
    const char* project_name;
    contract_factory contract_factory_ptr;
};

extern ContractDispatchTableEntry contractDisptachTable[];

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
