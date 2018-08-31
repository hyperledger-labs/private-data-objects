#pragma once

#define ACTION_NONE (0)
#define ACTION_INIT (1)
#define ACTION_INC (2)
#define ACTION_DEC (3)
#define ACTION_TERMINATE (4)

#ifndef NULL
#define NULL (0)
#endif

#include "CppProcessorHandler.h"


struct IntKeyCode
{
    unsigned int min;
    unsigned int max;

    IntKeyCode()
    {
        min = 1;
        max = 1;
    };

    int Init(const char* str);
};

struct IntKeyMessage
{
    unsigned int action;
    unsigned int value;

    IntKeyMessage()
    {
        action = ACTION_NONE;
        value = 0;
    };
    int Init(const char* str);
};

struct IntKeyState
{
    unsigned int terminated;
    unsigned int value;

    IntKeyState()
    {
        terminated = 0;
        value = 0;
    }

    int Init(const char* str);
    int Serialize(char* buf, int bufSize);
};

class IntKeyCppContractException : public CppContractWrapperException
{
public:
    IntKeyCppContractException(const char* msg) :
    CppContractWrapperException(msg)
    {}
    virtual char const* what() const noexcept { return msg_.c_str(); }
};

class IntKeyCppContractExecuter : public CppContractWrapper
{
public:
    IntKeyCppContractExecuter() { result = STUB_INTERPRETOR_NO_ERROR; };

    bool SetCode(const char* codeStr)
    {
        if (result == STUB_INTERPRETOR_NO_ERROR)
            result = code.Init(codeStr);
        return (result == STUB_INTERPRETOR_NO_ERROR);
    };

    bool SetMessage(const char* messageStr, const char* originatorId)
    {
        // TODO: originatorId is not used
        if (result == STUB_INTERPRETOR_NO_ERROR)
            result = message.Init(messageStr);
        return (result == STUB_INTERPRETOR_NO_ERROR);
    };

    bool SetInState(const char* stateStr)
    {
        if (result == STUB_INTERPRETOR_NO_ERROR)
            result = state.Init(stateStr);
        ;
        return (result == STUB_INTERPRETOR_NO_ERROR);
    };

    bool ExecuteMessage(const char* contractId, const char* creatorId);

    bool GetResult(char* buf, int bufSize);

    bool GetOutState(char* buf, int bufSize)
    {
        return (state.Serialize(buf, bufSize) == STUB_INTERPRETOR_NO_ERROR);
    }

    void HandleFailure(const char* msg);

    // TODO: GetDependencies()

private:
    IntKeyCode code;
    IntKeyState state;
    IntKeyMessage message;
    int result;
};
