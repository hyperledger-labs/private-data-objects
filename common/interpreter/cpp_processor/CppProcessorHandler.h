#pragma once

#include <map>
#include <string>
using namespace std;
#include "ContractInterpreter.h"
#include "CppProcessor.h"
#include "IntKeyCppContractExecuter.h"
namespace pc = pdo::contracts;

pdo::contracts::ContractInterpreter* intkey_factory();

class IntKeyCppContractWrapperException : public std::exception
{
public:
    IntKeyCppContractWrapperException(const char* msg) : msg_(msg) {}
    virtual char const* what() const noexcept { return msg_.c_str(); }

private:
    std::string msg_;
};

class IntKeyCppContractWrapper : public pc::ContractInterpreter
{
public:
    IntKeyCppContractWrapper(void);
    ~IntKeyCppContractWrapper(void);

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

private:
    void HandleFailure();
    bool HandleFailure_Code();
    bool HandleFailure_Message();
    bool HandleFailure_State();
    IntKeyCppContractExecuter executer;

};
