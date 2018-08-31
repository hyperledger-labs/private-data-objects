#pragma once
#define STUB_INTERPRETOR_NO_ERROR (0)
#define STUB_INTERPRETOR_ERR (1)
#define STUB_INTERPRETOR_ERR_CODE (2)
#define STUB_INTERPRETOR_ERR_MESSAGE (3)
#define STUB_INTERPRETOR_ERR_STATE (4)
#define STUB_INTERPRETOR_ERR_PARAM (5)
#define STUB_INTERPRETOR_ERR_TERMINATED (6)
#define STUB_INTERPRETOR_ERR_RESULT (7)
#define STUB_INTERPRETOR_ERR_STRING_NULL (8)
#define STUB_INTERPRETOR_ERR_STRING_TO_INT (9)

#include <map>
#include <string>
#include <memory>

#define MIN_RESULT_BUFFER_SIZE (100)
#define MIN_STATE_BUFFER_SIZE (13)

struct ErrorInfo
{
    int code;
    const char* message;
};

/*ErrorInfo errorInfo[] = {{STUB_INTERPRETOR_NO_ERROR, "OK"},
    {STUB_INTERPRETOR_ERR, "ERROR: Unknown error"},
    {STUB_INTERPRETOR_ERR_CODE, "ERROR: Invalid Contract Code"},
    {STUB_INTERPRETOR_ERR_MESSAGE, "ERROR: Invalid Contract Message"},
    {STUB_INTERPRETOR_ERR_STATE, "ERROR: Invalid Contract State"},
    {STUB_INTERPRETOR_ERR_PARAM, "ERROR: Invalid Contract Parameter"},
    {STUB_INTERPRETOR_ERR_TERMINATED, "ERROR: Contract Termonated"},
    {STUB_INTERPRETOR_ERR_RESULT, "ERROR: Invalid Result Buffer"},
    {STUB_INTERPRETOR_ERR_STRING_NULL, "ERROR: Codeinit String is NULL"},
    {STUB_INTERPRETOR_ERR_STRING_TO_INT, "ERROR: Codeinit String to Int"}, {0, NULL}};*/

class CppContractWrapper; // Forward decleration

CppContractWrapper* intkey_factory();
CppContractWrapper* echo_factory();

class CppContractWrapperException : public std::exception
{
public:
    CppContractWrapperException(const char* msg) : msg_(msg) {}
    virtual char const* what() const noexcept { return msg_.c_str(); }

protected:
    std::string msg_;
};

class CppContractWrapper
{
public:
    CppContractWrapper(){}

    virtual bool SetCode(const char* codeStr) = 0;
    virtual bool SetMessage(const char* messageStr, const char* originatorId) = 0;
    virtual bool SetInState(const char* stateStr) = 0;
    virtual bool ExecuteMessage(const char* contractId, const char* creatorId) = 0;
    virtual bool GetResult(char* buf, int bufSize) = 0;
    virtual bool GetOutState(char* buf, int bufSize) = 0;
    virtual void HandleFailure(const char* msg) = 0;

    virtual ~CppContractWrapper() {
    }
};
