/* Copyright 2018 Intel Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

%module block_state

%{
#include "state.h"
#include "types.h"
#include "StateBlock.h"
#include "StateUtils.h"
#include "error.h"
%}

%include <exception.i>

%exception  {
    try
    {
        $function
    }
    catch (pdo::error::CryptoError& e)
    {
        SWIG_exception(SWIG_ValueError, e.what());
    }
    catch (pdo::error::MemoryError& e)
    {
        SWIG_exception(SWIG_MemoryError, e.what());
    }
    catch (pdo::error::IOError& e)
    {
        SWIG_exception(SWIG_IOError, e.what());
    }
    catch (pdo::error::RuntimeError& e)
    {
        SWIG_exception(SWIG_ValueError, e.what());
    }
    catch (pdo::error::IndexError& e)
    {
        SWIG_exception(SWIG_ValueError, e.what());
    }
    catch (pdo::error::DivisionByZero& e)
    {
        SWIG_exception(SWIG_DivisionByZero, e.what());
    }
    catch (pdo::error::OverflowError& e)
    {
        SWIG_exception(SWIG_OverflowError, e.what());
    }
    catch (pdo::error::ValueError& e)
    {
        SWIG_exception(SWIG_ValueError, e.what());
    }
    catch (pdo::error::SystemError& e)
    {
        SWIG_exception(SWIG_SystemError, e.what());
    }
    catch (pdo::error::SystemBusyError& e)
    {
        SWIG_exception(SWIG_SystemError, e.what());
    }
    catch (pdo::error::UnknownError& e) {
        SWIG_exception(SWIG_UnknownError, e.what());
    }
    catch (...)
    {
        SWIG_exception(SWIG_RuntimeError,"Unknown exception");
    }
}


%include "std_string.i"
%include "std_vector.i"
%include "stdint.i"

%rename(STATE_GetStateBlockList) pdo::state::GetStateBlockList;
%rename(STATE_GetMissingBlockId) pdo::state::GetMissingBlockId;
%rename(STATE_WarmUpCache) pdo::state::WarmUpCache;
%rename(STATE_ClearCache) pdo::state::ClearCache;

%rename(STATE_BlockId) pdo::state::StateBlockId;

namespace std {
    %template(__byte_array__) vector<uint8_t>;
    %template(__char_array__) vector<char>;
}

%ignore ByteArrayToString;

%include "types.h"
%include "state.h"
%include "StateBlockList.h"
%include "StateBlock.h"
#include "StateUtils.h"

%pythoncode %{
__all__ = [
    "STATE_GetStateBlockList",
    "STATE_GetMissingBlockId",
    "STATE_WarmUpCache",
    "STATE_ClearCache",
    "STATE_BlockId"
]
%}
