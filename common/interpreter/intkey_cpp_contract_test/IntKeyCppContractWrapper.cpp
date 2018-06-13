#include "IntKeyCppContractWrapper.h"
#include <stdio.h>
#include <stdlib.h>
extern "C" {
void printf(const char* fmt, ...);
}
IntKeyCppContractWrapper::IntKeyCppContractWrapper()
{
}


IntKeyCppContractWrapper::~IntKeyCppContractWrapper()
{
}


void IntKeyCppContractWrapper::create_initial_contract_state(
	const std::string& inContractID,
	const std::string& inCreatorID,
	const pc::ContractCode& inContract,
	const pc::ContractMessage& inMessage,
	pc::ContractState& outContractState
	)
{
	
	//printf("inContract.Code.c_str() = %s \n",inContract.Code.c_str());
	if(!executer.SetCode(inContract.Code.c_str()))     
          throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper::inContract Code");
          
	 //if(result==9)
         // throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper::inContract string function error");

        if(!executer.SetMessage(inMessage.Message.c_str(), inMessage.OriginatorID.c_str())) {
                 throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper::SetMessage");
		//result = HandleFailure_Message();
        }

        if (!executer.ExecuteMessage(inContractID.c_str(), inCreatorID.c_str()))
        {
                 throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper::ExecuteMessgae");
		//result = HandleFailure_State();
        }
        
                
	try{
		char outStateRaw[MIN_STATE_BUFFER_SIZE];
		
		if(executer.GetOutState(outStateRaw, sizeof(outStateRaw)))
		{
			outContractState.State = outStateRaw;
	}
	}catch(...){
			 throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper::Getoutof state");
		}	


/*	
		bool result = false;

	if (executer.SetCode(inContract.Code.c_str())
			&&
		executer.SetMessage(inMessage.Message.c_str(), inMessage.OriginatorID.c_str())
			&&
		executer.ExecuteMessage(inContractID.c_str(), inCreatorID.c_str()))
	{
		char outStateRaw[MIN_STATE_BUFFER_SIZE];
		
		if (executer.GetOutState(outStateRaw, sizeof(outStateRaw)))
		{
			outContractState.State = outStateRaw;
			result = true;
		}
	}

	if (!result)
		HandleFailure();
*/
}


void IntKeyCppContractWrapper::send_message_to_contract(
	const std::string& inContractID,
	const std::string& inCreatorID,
	const pc::ContractCode& inContract,
	const pc::ContractMessage& inMessage,
	const pc::ContractState& inContractState,
	pc::ContractState& outContractState,
	std::map<std::string, std::string>& outDependencies,
	std::string& outMessageResult
	)
{
	bool result = true;
	//std::cout<<"karthika";

	if (!(executer.SetCode(inContract.Code.c_str()))){
		result = HandleFailure_Code(); 
		
	}
	if (result && (!( executer.SetMessage(inMessage.Message.c_str(), inMessage.OriginatorID.c_str())))){
		result = HandleFailure_Message();
	}
		
	if ( result && ( !(executer.SetInState(inContractState.State.c_str()))) && (!(executer.ExecuteMessage(inContractID.c_str(), inCreatorID.c_str()))))
	{
	 	result = HandleFailure_State();
	}
	else
	{
		result = false;
		char outStateRaw[MIN_RESULT_BUFFER_SIZE];

		if (executer.GetOutState(outStateRaw, sizeof(outStateRaw)))
		{
			char outResultRaw[MIN_RESULT_BUFFER_SIZE];
			
			outContractState.State = outStateRaw;
			
			if (executer.GetResult(outResultRaw, sizeof(outResultRaw)))
			{
				outMessageResult = outResultRaw;
				
				// TODO: Get dependencies
				result = true;
			}
		}
	}

	if (!result)
		HandleFailure();
}


void IntKeyCppContractWrapper::HandleFailure()
{
	// TODO: Through a proper exception defined by the PDO 
	// Initially any exception should work

	throw IntKeyCppContractWrapperException("Action Failed inside Intkey Wrapper");
}
bool IntKeyCppContractWrapper::HandleFailure_Code()
{
	// TODO: Through a proper exception defined by the PDO 
	// Initially any exception should work

	throw IntKeyCppContractWrapperException("Code seeting Failed");
	return false;
}
bool IntKeyCppContractWrapper::HandleFailure_Message()
{
	// TODO: Through a proper exception defined by the PDO 
	// Initially any exception should work

	throw IntKeyCppContractWrapperException("Message setting Failed");
	return false;
}
bool IntKeyCppContractWrapper::HandleFailure_State()
{
	// TODO: Through a proper exception defined by the PDO 
	// Initially any exception should work

	throw IntKeyCppContractWrapperException("State setting failed Failed");
	return false;
}
