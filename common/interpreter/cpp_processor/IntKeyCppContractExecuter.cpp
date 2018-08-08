/////IntKeyCppContractExecuter.cpp file
#include "IntKeyCppContractExecuter.h"
#include <stdio.h>
#include <iostream>

using namespace std;
static int StrLen(char* str);
static char* StrCpy(const char* src, char* dst, int size);
static char* UintToStr(unsigned int value, char* buf, int size);
static const char* StrToUint(
    const char* strPtr, unsigned int* ptrVal, const char* terminators = ",");

struct ErrorInfo
{
    int code;
    const char* message;
};

ErrorInfo errorInfo[] = {{STUB_INTERPRETOR_NO_ERROR, "OK"},
    {STUB_INTERPRETOR_ERR, "ERROR: Unknown error"},
    {STUB_INTERPRETOR_ERR_CODE, "ERROR: Invalid Contract Code"},
    {STUB_INTERPRETOR_ERR_MESSAGE, "ERROR: Invalid Contract Message"},
    {STUB_INTERPRETOR_ERR_STATE, "ERROR: Invalid Contract State"},
    {STUB_INTERPRETOR_ERR_PARAM, "ERROR: Invalid Contract Parameter"},
    {STUB_INTERPRETOR_ERR_TERMINATED, "ERROR: Contract Termonated"},
    {STUB_INTERPRETOR_ERR_RESULT, "ERROR: Invalid Result Buffer"},
    {STUB_INTERPRETOR_ERR_STRING_NULL, "ERROR: Codeinit String is NULL"},
    {STUB_INTERPRETOR_ERR_STRING_TO_INT, "ERROR: Codeinit String to Int"}, {0, NULL}};

int IntKeyCode::Init(const char* str)
{
    int result = STUB_INTERPRETOR_ERR_CODE;
    if (str != NULL)
    {
        if ((str = StrToUint(str, &min)) != NULL)
        {
            str++;
            if (StrToUint(str, &max) != NULL)
            {
                if (max >= min)
                {
                    return STUB_INTERPRETOR_NO_ERROR;
                }
            }
        }
    }
    return STUB_INTERPRETOR_ERR_CODE;
}

int IntKeyMessage::Init(const char* str)
{
    int result = STUB_INTERPRETOR_ERR_MESSAGE;
    try
    {
        if (str != NULL)
        {
            if ((str = StrToUint(str, &action)) != NULL)
            {
                str++;
                if (StrToUint(str, &value) != NULL)
                {
                    result = STUB_INTERPRETOR_NO_ERROR;
                }
            }
        }
    }
    catch (...)
    {
        return STUB_INTERPRETOR_ERR_MESSAGE;
    }
    return result;
}

int IntKeyState::Init(const char* str)
{
    int result = STUB_INTERPRETOR_ERR_STATE;
    try
    {
        if (str == NULL)
        {
            terminated = 0;
            value = 0;
            result = STUB_INTERPRETOR_NO_ERROR;
        }
        else if ((str = StrToUint(str, &terminated)) != NULL)
        {
            str++;
            if (StrToUint(str, &value) != NULL)
            {
                result = STUB_INTERPRETOR_NO_ERROR;
            }
        }
    }
    catch (...)
    {
        return STUB_INTERPRETOR_ERR_STATE;
    }

    return result;
}

int IntKeyState::Serialize(char* buf, int bufSize)
{
    int result = STUB_INTERPRETOR_NO_ERROR;

    if (bufSize < MIN_STATE_BUFFER_SIZE)
    {
        result = STUB_INTERPRETOR_ERR_STATE;
    }
    else
    {
        *buf++ = !terminated ? '0' : '1';
        *buf++ = ',';
        UintToStr(value, buf, bufSize - 2);
    }
    return result;
}

bool IntKeyCppContractExecuter::ExecuteMessage(const char* contractId, const char* creatorId)
{
    // TODO: contractId and creatorId are not used

    if (result == STUB_INTERPRETOR_NO_ERROR)
    {
        if (message.action == ACTION_INIT)
        {
            if (message.value < code.min || message.value > code.max)
            {
                result = STUB_INTERPRETOR_ERR_PARAM;
            }
            else
            {
                state.value = message.value;
            }
        }
        else if (state.terminated)
        {
            result = STUB_INTERPRETOR_ERR_TERMINATED;
        }
        else
        {
            switch (message.action)
            {
                case ACTION_INC:
                    if (message.value > (code.max - state.value))
                    {
                        result = STUB_INTERPRETOR_ERR_PARAM;
                    }
                    else
                    {
                        state.value += message.value;
                    }
                    break;
                case ACTION_DEC:
                    if (message.value > (state.value - code.min))
                    {
                        result = STUB_INTERPRETOR_ERR_PARAM;
                    }
                    else
                    {
                        state.value -= message.value;
                    }
                    break;
                case ACTION_TERMINATE:
                    state.terminated = 1;
                    break;
                default:
                    result = STUB_INTERPRETOR_ERR_PARAM;
                    break;
            }
        }
    }

    return (result == STUB_INTERPRETOR_NO_ERROR);
}

bool IntKeyCppContractExecuter::GetResult(char* buf, int bufSize)
{
    if (bufSize < MIN_RESULT_BUFFER_SIZE || result != STUB_INTERPRETOR_NO_ERROR)
    {
        return false;
    }

    if (!UintToStr(state.value, buf, bufSize))
    {
        return false;
    }

    return true;
}

const char* StrToUint(const char* strPtr, unsigned int* ptrVal, const char* terminators)
{
    *ptrVal = 0;
    while (*strPtr >= '0' && *strPtr <= '9')
    {
        *ptrVal = (*ptrVal * 10) + (*strPtr - '0');
        strPtr++;
    }

    if (*strPtr && terminators != NULL)
    {
        while (*terminators)
        {
            if (*strPtr == *terminators++)
            {
                return strPtr;
            }
        }
        return NULL;
    }
    return strPtr;
}

char* UintToStr(unsigned int value, char* buf, int size)
{
    if (buf && size > 1)
    {
        if (!value)
        {
            *buf++ = '0';
            *buf = 0;
        }
        else
        {
            char* ptr = buf;
            unsigned int temp = value;

            while (temp)
            {
                ptr++;
                temp = temp / 10;
            }

            if ((ptr - buf) < size)
            {
                buf = ptr;
                *ptr-- = 0;
                while (value != 0)
                {
                    *ptr-- = value % 10 + '0';
                    value = value / 10;
                }
            }
        }
    }

    return buf;
}

int StrLen(char* str)
{
    int len = 0;

    if (str)
    {
        while (*str++)
        {
            len++;
        }
    }
    return len;
}

char* StrCpy(const char* src, char* dst, int size)
{
    if (src && dst && size)
    {
        while (--size && *src)
        {
            *dst++ = *src++;
        }
        *dst = 0;
    }
    return dst;
}
