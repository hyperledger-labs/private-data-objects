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

%module crypto

%{
#include "types.h"
#include "crypto.h"
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

%rename(SIG_PrivateKey) pdo::crypto::sig::PrivateKey;
%rename(SIG_PublicKey) pdo::crypto::sig::PublicKey;
%rename(PKENC_PrivateKey) pdo::crypto::pkenc::PrivateKey;
%rename(PKENC_PublicKey) pdo::crypto::pkenc::PublicKey;

%rename(SKENC_GenerateKey) pdo::crypto::skenc::GenerateKey;
%rename(SKENC_GenerateIV) pdo::crypto::skenc::GenerateIV;
%rename(SKENC_EncryptMessage) pdo::crypto::skenc::EncryptMessage;
%rename(SKENC_DecryptMessage) pdo::crypto::skenc::DecryptMessage;

%rename(base64_to_byte_array) Base64EncodedStringToByteArray;
%rename(byte_array_to_base64) ByteArrayToBase64EncodedString;
%rename(hex_to_byte_array) HexEncodedStringToByteArray;
%rename(byte_array_to_hex) ByteArrayToHexEncodedString;
%rename(compute_message_hash) ComputeMessageHash;
%rename(random_bit_string) RandomBitString;

namespace std {
    %template(__byte_array__) vector<uint8_t>;
    %template(__char_array__) vector<char>;
}

%ignore ByteArrayToString;

%include "types.h"
%include "crypto.h"
%include "crypto_utils.h"
%include "crypto_shared.h"
%include "hash.h"
%include "sig.h"
%include "pkenc.h"
%include "skenc.h"
%include "sig_private_key.h"
%include "sig_public_key.h"
%include "pkenc_private_key.h"
%include "pkenc_public_key.h"

%pythoncode %{
__all__ = [
    "SIG_PrivateKey",
    "SIG_PublicKey",
    "PKENC_PrivateKey",
    "PKENC_PublicKey",
    "SKENC_Generate_Key",
    "SKENC_GenerateIV",
    "SKENC_EncryptMessage",
    "SKENC_DecryptMessage",
    "base64_to_byte_array",
    "byte_array_to_base64",
    "hex_to_byte_array",
    "byte_array_to_hex",
    "string_to_byte_array",
    "byte_array_to_string",
    "compute_message_hash",
    "random_bit_string"
]

def string_to_byte_array(s) :
    if type(s) is str :
        return tuple(bytes(s, 'ascii'))
    elif type(s) is bytes :
        return tuple(s)
    elif type(s) is tuple :
        return s
    else :
        raise ValueError('unknown type')

def byte_array_to_string(b) :
    from array import array
    return array('B', b).tobytes().decode('ascii')
%}
